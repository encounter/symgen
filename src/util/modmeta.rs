//! Parser for native mod metadata records.
//!
//! Libraries store an aligned record stream in `modmeta` (ELF/PE) or
//! `__DATA,__modmeta` (Mach-O). Pointer fields are runtime-only; static targets are recovered
//! from relocations, dyld fixups, PE imports, and compiler-generated materializers.
//!
//! ```text
//! Header     { record, abi_version }
//! Import     { record, versions, service_slot, service_id[64] }
//! Export     { record, versions, service,      service_id[64] }
//! HookFn     { record, target, resolved }
//! HookMem    { record, pmf[16], resolved, vtable\0, display\0 }
//! HookMemExt { record, pmf_size, materializer, resolved, vtable\0, display\0 }
//! HookName   { record, resolved, name\0 }
//! ```

use std::{mem::size_of, path::Path};

use anyhow::{Context, Result, bail};
use object::{Architecture, BinaryFormat, Object, ObjectSection, ObjectSymbol, RelocationTarget};
use serde::Serialize;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout,
    little_endian::{U16, U32, U64},
};

use super::{
    macho::MachOImage,
    msvc::{MemberPointerDecoder, MemberTarget},
};

const KIND_PAD: u8 = 0;
const KIND_HEADER: u8 = 1;
const KIND_IMPORT: u8 = 2;
const KIND_EXPORT: u8 = 3;
const KIND_HOOK_FN: u8 = 4;
const KIND_HOOK_MEM: u8 = 5;
const KIND_HOOK_NAME: u8 = 6;
const KIND_HOOK_MEM_EXT: u8 = 7;

const IMPORT_OPTIONAL: u8 = 1;
const EXPORT_DEFERRED: u8 = 1;

#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct RecordHeader {
    size: U16,
    kind: u8,
    flags: u8,
}

#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct HeaderRecord {
    rec: RecordHeader,
    abi_version: U32,
}

#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct ImportRecord {
    rec: RecordHeader,
    major_version: U16,
    min_minor_version: U16,
    slot: U64,
    service_id: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct ExportRecord {
    rec: RecordHeader,
    major_version: U16,
    minor_version: U16,
    service: U64,
    service_id: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct HookFnRecord {
    rec: RecordHeader,
    reserved: U32,
    target: U64,
    resolved: U64,
}

#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct HookMemRecord {
    rec: RecordHeader,
    reserved: U32,
    pmf: [U64; 2],
    resolved: U64,
}

#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct HookMemExtRecord {
    rec: RecordHeader,
    pmf_size: U32,
    materialize: U64,
    resolved: U64,
}

#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct HookNameRecord {
    rec: RecordHeader,
    reserved: U32,
    resolved: U64,
}

crate::static_assert!(size_of::<RecordHeader>() == 4);
crate::static_assert!(size_of::<HeaderRecord>() == 8);
crate::static_assert!(size_of::<ImportRecord>() == 80);
crate::static_assert!(size_of::<ExportRecord>() == 80);
crate::static_assert!(size_of::<HookFnRecord>() == 24);
crate::static_assert!(size_of::<HookMemRecord>() == 32);
crate::static_assert!(size_of::<HookMemExtRecord>() == 24);
crate::static_assert!(size_of::<HookNameRecord>() == 16);

/// One static service import declared by a mod entry library.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Import {
    pub service_id: String,
    pub major: u16,
    pub min_minor: u16,
    pub optional: bool,
}

/// One static service export declared by a mod entry library.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Export {
    pub service_id: String,
    pub major: u16,
    pub minor: u16,
    pub deferred: bool,
}

/// A decoded static hook target.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HookTarget {
    Fn {
        symbol: Option<String>,
    },
    #[serde(rename = "member")]
    Mem {
        vtable: String,
        display: String,
        symbol: Option<String>,
        virtual_slot: Option<u64>,
    },
    Name {
        name: String,
    },
}

/// Parsed object identity and static mod metadata from one entry library.
#[derive(Clone, Debug, Serialize)]
pub struct MetaFile {
    pub format: String,
    pub arch: String,
    pub abi_version: u32,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub hooks: Vec<HookTarget>,
}

struct Fixups {
    binds: Vec<(u64, String)>,
}

impl Fixups {
    fn lookup(&self, address: u64) -> Option<&str> {
        self.binds
            .binary_search_by_key(&address, |&(location, _)| location)
            .ok()
            .map(|index| self.binds[index].1.as_str())
    }
}

/// Parse the static mod metadata embedded in one native entry library.
///
/// This reads object-file structures only; it never loads or executes the library.
pub fn parse_library(data: &[u8]) -> Result<MetaFile> {
    let file = object::File::parse(data)?;
    let section = file
        .section_by_name("modmeta")
        .or_else(|| file.section_by_name("__modmeta"))
        .context("No mod metadata section (is this a mod library?)")?;
    let section_addr = section.address();
    let section_data = section.data()?;
    let fixups = collect_fixups(&file, data, section_addr, section_data.len() as u64)?;
    let msvc_decoder = MemberPointerDecoder::new(&file).unwrap_or_else(|error| {
        log::debug!("Could not index PE imports for extended member hooks: {error:#}");
        MemberPointerDecoder::default()
    });
    let format = file.format();
    let arch = file.architecture();

    let mut meta = MetaFile {
        format: format!("{format:?}").to_lowercase(),
        arch: format!("{arch:?}").to_lowercase(),
        abi_version: 0,
        imports: Vec::new(),
        exports: Vec::new(),
        hooks: Vec::new(),
    };

    let mut header_count = 0usize;
    let mut offset = 0usize;
    while offset < section_data.len() {
        let rest = &section_data[offset..];
        if rest.len() < 8 {
            if rest.iter().all(|&byte| byte == 0) {
                break;
            }
            bail!("Trailing bytes at section offset {offset}");
        }
        if rest[..8] == [0u8; 8] {
            offset += 8;
            continue;
        }
        let (header, _) = RecordHeader::read_from_prefix(rest).unwrap();
        let size = header.size.get() as usize;
        if size < 8 || size % 8 != 0 || size > rest.len() {
            bail!("Bad record size {size} at section offset {offset}");
        }
        let record_data = &rest[..size];
        let field_addr = |field_offset: usize| section_addr + offset as u64 + field_offset as u64;
        match header.kind {
            KIND_PAD => check_flags(&header, 0, offset)?,
            KIND_HEADER => {
                check_flags(&header, 0, offset)?;
                let (record, _) = HeaderRecord::read_from_prefix(record_data)
                    .map_err(|_| truncated_record(offset))?;
                header_count += 1;
                meta.abi_version = record.abi_version.get();
            }
            KIND_IMPORT => {
                check_flags(&header, IMPORT_OPTIONAL, offset)?;
                let (record, _) = ImportRecord::read_from_prefix(record_data)
                    .map_err(|_| truncated_record(offset))?;
                meta.imports.push(Import {
                    service_id: read_service_id(&record.service_id, offset)?,
                    major: record.major_version.get(),
                    min_minor: record.min_minor_version.get(),
                    optional: header.flags & IMPORT_OPTIONAL != 0,
                });
            }
            KIND_EXPORT => {
                check_flags(&header, EXPORT_DEFERRED, offset)?;
                let (record, _) = ExportRecord::read_from_prefix(record_data)
                    .map_err(|_| truncated_record(offset))?;
                meta.exports.push(Export {
                    service_id: read_service_id(&record.service_id, offset)?,
                    major: record.major_version.get(),
                    minor: record.minor_version.get(),
                    deferred: header.flags & EXPORT_DEFERRED != 0,
                });
            }
            KIND_HOOK_FN => {
                check_flags(&header, 0, offset)?;
                HookFnRecord::read_from_prefix(record_data)
                    .map_err(|_| truncated_record(offset))?;
                meta.hooks.push(HookTarget::Fn {
                    symbol: fixups.lookup(field_addr(8)).map(str::to_string),
                });
            }
            KIND_HOOK_MEM => {
                check_flags(&header, 0, offset)?;
                let (record, strings) = HookMemRecord::read_from_prefix(record_data)
                    .map_err(|_| truncated_record(offset))?;
                let (vtable, rest) = read_cstr(strings, offset)?;
                let (display, _) = read_cstr(rest, offset)?;
                let symbol = fixups.lookup(field_addr(8)).map(str::to_string);
                let virtual_slot = symbol
                    .is_none()
                    .then(|| {
                        decode_virtual_slot(arch, format, record.pmf[0].get(), record.pmf[1].get())
                    })
                    .flatten();
                meta.hooks.push(HookTarget::Mem { vtable, display, symbol, virtual_slot });
            }
            KIND_HOOK_MEM_EXT => {
                check_flags(&header, 0, offset)?;
                let (record, strings) = HookMemExtRecord::read_from_prefix(record_data)
                    .map_err(|_| truncated_record(offset))?;
                let pmf_size = record.pmf_size.get();
                if !(17..=24).contains(&pmf_size) {
                    bail!("Bad extended member-pointer size {pmf_size} at section offset {offset}");
                }
                let (vtable, rest) = read_cstr(strings, offset)?;
                let (display, _) = read_cstr(rest, offset)?;
                let (symbol, virtual_slot) =
                    match msvc_decoder.decode_materializer(&file, record.materialize.get()) {
                        Some(MemberTarget::Symbol(symbol)) => (Some(symbol), None),
                        Some(MemberTarget::VirtualSlot(slot)) => (None, Some(slot)),
                        None => (None, None),
                    };
                meta.hooks.push(HookTarget::Mem { vtable, display, symbol, virtual_slot });
            }
            KIND_HOOK_NAME => {
                check_flags(&header, 0, offset)?;
                let (_, name) = HookNameRecord::read_from_prefix(record_data)
                    .map_err(|_| truncated_record(offset))?;
                let (name, _) = read_cstr(name, offset)?;
                meta.hooks.push(HookTarget::Name { name });
            }
            kind => log::debug!("Skipping unknown record kind {kind} at offset {offset}"),
        }
        offset += size;
    }

    if header_count != 1 {
        bail!("Expected exactly 1 header record, found {header_count}");
    }
    Ok(meta)
}

/// Verify the ABI and service-set agreement required across a package's entry libraries.
pub fn check_agreement<T: AsRef<Path>>(files: &[(T, MetaFile)]) -> Result<()> {
    let Some((first_path, first)) = files.first() else {
        bail!("At least one mod metadata file is required");
    };
    let mut first_imports: Vec<_> = first.imports.iter().collect();
    let mut first_exports: Vec<_> = first.exports.iter().collect();
    first_imports.sort_unstable();
    first_exports.sort_unstable();
    for (path, file) in files.iter().skip(1) {
        if file.abi_version != first.abi_version {
            bail!(
                "ABI version mismatch: '{}' has v{}, '{}' has v{}",
                first_path.as_ref().display(),
                first.abi_version,
                path.as_ref().display(),
                file.abi_version
            );
        }
        let mut imports: Vec<_> = file.imports.iter().collect();
        let mut exports: Vec<_> = file.exports.iter().collect();
        imports.sort_unstable();
        exports.sort_unstable();
        if imports != first_imports || exports != first_exports {
            bail!(
                "Service import/export disagreement between '{}' and '{}'",
                first_path.as_ref().display(),
                path.as_ref().display()
            );
        }
    }
    Ok(())
}

fn check_flags(header: &RecordHeader, allowed: u8, offset: usize) -> Result<()> {
    let unknown = header.flags & !allowed;
    if unknown != 0 {
        bail!(
            "Unsupported flags {unknown:#04x} for metadata record kind {} at section offset {offset}",
            header.kind
        );
    }
    Ok(())
}

fn truncated_record(offset: usize) -> anyhow::Error {
    anyhow::anyhow!("Truncated record at section offset {offset}")
}

fn read_service_id(buffer: &[u8; 64], offset: usize) -> Result<String> {
    let Some(length) = buffer.iter().position(|&byte| byte == 0) else {
        bail!("Unterminated service id at section offset {offset}");
    };
    if length == 0 {
        bail!("Empty service id at section offset {offset}");
    }
    let value = std::str::from_utf8(&buffer[..length])
        .with_context(|| format!("Invalid UTF-8 service id at section offset {offset}"))?;
    Ok(value.to_owned())
}

fn read_cstr(buffer: &[u8], offset: usize) -> Result<(String, &[u8])> {
    let Some(length) = buffer.iter().position(|&byte| byte == 0) else {
        bail!("Unterminated string at section offset {offset}");
    };
    let value = std::str::from_utf8(&buffer[..length])
        .with_context(|| format!("Invalid UTF-8 string at section offset {offset}"))?;
    Ok((value.to_owned(), &buffer[length + 1..]))
}

fn decode_virtual_slot(
    arch: Architecture,
    format: BinaryFormat,
    word0: u64,
    word1: u64,
) -> Option<u64> {
    if format == BinaryFormat::Pe {
        return None;
    }
    match arch {
        Architecture::Aarch64 | Architecture::Arm => {
            (word1 & 1 != 0 && word1 >> 1 == 0).then_some(word0)
        }
        _ => (word0 & 1 != 0 && word1 == 0).then_some(word0 - 1),
    }
}

fn collect_fixups(
    file: &object::File<'_>,
    data: &[u8],
    section_addr: u64,
    section_size: u64,
) -> Result<Fixups> {
    let range = section_addr..section_addr + section_size;
    let mut binds = Vec::new();
    match file {
        object::File::Elf64(_) => {
            if let Some(relocations) = file.dynamic_relocations() {
                for (address, relocation) in relocations {
                    if !range.contains(&address) {
                        continue;
                    }
                    if let RelocationTarget::Symbol(index) = relocation.target()
                        && let Ok(symbol) = file.symbol_by_index(index)
                        && let Ok(name) = symbol.name()
                        && !name.is_empty()
                    {
                        binds.push((address, name.to_string()));
                    }
                }
            }
        }
        object::File::MachO64(_) => {
            binds.extend(MachOImage::parse(data)?.bindings_in(&range)?);
        }
        _ => {}
    }
    binds.sort_by_key(|binding| binding.0);
    Ok(Fixups { binds })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(abi_version: u32, service_id: &str) -> MetaFile {
        MetaFile {
            format: "elf".into(),
            arch: "aarch64".into(),
            abi_version,
            imports: vec![Import {
                service_id: service_id.into(),
                major: 1,
                min_minor: 0,
                optional: false,
            }],
            exports: Vec::new(),
            hooks: Vec::new(),
        }
    }

    #[test]
    fn rejects_missing_metadata_section() {
        let error = parse_library(b"not an object").unwrap_err();
        assert!(!error.to_string().is_empty());
    }

    #[test]
    fn rejects_invalid_utf8_strings_and_unknown_flags() {
        let mut service_id = [0u8; 64];
        service_id[0] = 0xff;
        assert!(read_service_id(&service_id, 8).is_err());

        let header = RecordHeader { size: U16::new(8), kind: KIND_HEADER, flags: 0x80 };
        assert!(check_flags(&header, 0, 0).is_err());
    }

    #[test]
    fn verifies_cross_library_agreement() {
        let matching = vec![
            ("linux-aarch64", metadata(1, "dev.example.service")),
            ("windows-arm64", metadata(1, "dev.example.service")),
        ];
        check_agreement(&matching).unwrap();

        let mismatched = vec![
            ("linux-aarch64", metadata(1, "dev.example.service")),
            ("windows-arm64", metadata(2, "dev.example.service")),
        ];
        assert!(check_agreement(&mismatched).is_err());
    }
}
