//! Mod metadata records.
//!
//! A native mod library carries its manifest as a sequence of records in a dedicated section
//! ("modmeta" on ELF/PE, "__DATA,__modmeta" on Mach-O). The records are pure data. Pointer
//! fields are runtime-only and their targets are recovered from the file's relocation/bind
//! entries.
//!
//! Layout (little-endian, 8-byte aligned, record sizes are multiples of 8; parsers skip
//! all-zero 8-byte units and records of unknown kind):
//!
//! ```text
//! RecordHeader { size u16, kind u8, flags u8 }
//! Header   { rec, abi_version u32 }                                                (8 bytes)
//! Import   { rec, major u16, min_minor u16, slot ptr, service_id char[64] }        (80 bytes)
//! Export   { rec, major u16, minor u16, service ptr, service_id char[64] }         (80 bytes)
//! HookFn   { rec, reserved u32, target ptr, resolved ptr }                         (24 bytes)
//! HookMem  { rec, reserved u32, pmf u8[16], resolved ptr }
//!            + vtable symbol NUL + display name NUL                                (>= 40 bytes)
//! HookName { rec, reserved u32, resolved ptr } + symbol name NUL                   (>= 24 bytes)
//! ```

use std::{collections::BTreeSet, fs, mem::size_of, ops::Range, path::PathBuf};

use anyhow::{Context, Result, bail};
use argp::FromArgs;
use object::{
    Architecture, BinaryFormat, Endianness, Object, ObjectSection, ObjectSegment, ObjectSymbol,
    RelocationTarget, macho,
    read::macho::{LoadCommandVariant, MachOFile64},
};
use serde::Serialize;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout,
    little_endian::{U16, U32, U64},
};

use crate::static_assert;

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Dump or verify mod metadata records from native mod libraries.
#[argp(subcommand, name = "modmeta")]
pub struct Args {
    #[argp(positional)]
    /// native mod libraries (ELF, Mach-O, or PE)
    inputs: Vec<PathBuf>,
    #[argp(switch)]
    /// verify well-formedness and cross-library agreement instead of dumping JSON
    check: bool,
    #[argp(option)]
    /// write the JSON dump to a file instead of stdout
    out: Option<PathBuf>,
    #[argp(option)]
    /// verify cross-library agreement, then merge the package-level keys
    /// (abi, imports, exports) into an existing JSON file (e.g. mod.json)
    update_json: Option<PathBuf>,
}

pub fn run(args: Args) -> Result<()> {
    if args.inputs.is_empty() {
        bail!("At least one input library is required");
    }
    let mut files = Vec::new();
    for path in &args.inputs {
        let data =
            fs::read(path).with_context(|| format!("Failed to read '{}'", path.display()))?;
        let file = parse_library(&data)
            .with_context(|| format!("Failed to parse mod metadata in '{}'", path.display()))?;
        files.push((path, file));
    }

    let checked = args.check || args.update_json.is_some();
    if checked {
        check_agreement(&files)?;
    }
    if let Some(path) = &args.update_json {
        update_json(path, &files[0].1)
            .with_context(|| format!("Failed to update '{}'", path.display()))?;
    }
    if args.out.is_some() || !checked {
        #[derive(Serialize)]
        struct FileEntry<'a> {
            path: &'a PathBuf,
            #[serde(flatten)]
            meta: &'a MetaFile,
        }
        #[derive(Serialize)]
        struct Output<'a> {
            files: Vec<FileEntry<'a>>,
        }
        let output =
            Output { files: files.iter().map(|(path, meta)| FileEntry { path, meta }).collect() };
        let text = serde_json::to_string_pretty(&output)?;
        match &args.out {
            Some(path) => fs::write(path, text + "\n")
                .with_context(|| format!("Failed to write '{}'", path.display()))?,
            None => println!("{text}"),
        }
    }
    if checked {
        println!(
            "OK: {} librar{} verified",
            files.len(),
            if files.len() == 1 { "y" } else { "ies" }
        );
    }
    Ok(())
}

/// Merge the verified package-level metadata into an existing JSON object file, preserving
/// unrelated keys. Imports and exports agree across libraries (checked above), so the first
/// library's records are authoritative; hooks are per-binary and excluded.
fn update_json(path: &PathBuf, meta: &MetaFile) -> Result<()> {
    let text = fs::read_to_string(path)?;
    let mut value: serde_json::Value = serde_json::from_str(&text)?;
    let obj = value.as_object_mut().context("JSON root is not an object")?;
    let mut imports: Vec<&Import> = meta.imports.iter().collect();
    imports.sort();
    let mut exports: Vec<&Export> = meta.exports.iter().collect();
    exports.sort();
    obj.insert("abi".to_string(), meta.abi_version.into());
    obj.insert("imports".to_string(), serde_json::to_value(&imports)?);
    obj.insert("exports".to_string(), serde_json::to_value(&exports)?);
    fs::write(path, serde_json::to_string_pretty(&value)? + "\n")?;
    Ok(())
}

const KIND_PAD: u8 = 0;
const KIND_HEADER: u8 = 1;
const KIND_IMPORT: u8 = 2;
const KIND_EXPORT: u8 = 3;
const KIND_HOOK_FN: u8 = 4;
const KIND_HOOK_MEM: u8 = 5;
const KIND_HOOK_NAME: u8 = 6;

const IMPORT_OPTIONAL: u8 = 1;
const EXPORT_DEFERRED: u8 = 1;

#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct RecordHeader {
    /// Total record size in bytes, a multiple of 8
    size: U16,
    /// Record kind
    kind: u8,
    /// Kind-specific flags
    flags: u8,
}

#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct HeaderRecord {
    rec: RecordHeader,
    /// Mod ABI version; also versions the record format
    abi_version: U32,
}

#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct ImportRecord {
    rec: RecordHeader,
    major_version: U16,
    min_minor_version: U16,
    /// Runtime only: the mod's service pointer variable
    slot: U64,
    /// NUL-terminated service id
    service_id: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct ExportRecord {
    rec: RecordHeader,
    major_version: U16,
    minor_version: U16,
    /// Runtime only: the exported service struct (NULL when deferred)
    service: U64,
    /// NUL-terminated service id
    service_id: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct HookFnRecord {
    rec: RecordHeader,
    reserved: U32,
    /// Carries the &fn relocation; read the relocation/bind's symbol
    target: U64,
    /// Runtime only: written by the host at activation
    resolved: U64,
}

#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct HookMemRecord {
    rec: RecordHeader,
    reserved: U32,
    /// The compiler's pointer-to-member representation. Non-virtual: a function address
    /// relocation. Virtual Itanium/AAPCS: literal slot words, readable from the file.
    pmf: [U64; 2],
    /// Runtime only
    resolved: U64,
    // Two NUL-terminated strings follow: class vtable symbol, then display name.
}

#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct HookNameRecord {
    rec: RecordHeader,
    reserved: U32,
    /// Runtime only
    resolved: U64,
    // NUL-terminated symbol name follows: platform mangled or qualified display name.
}

static_assert!(size_of::<RecordHeader>() == 4);
static_assert!(size_of::<HeaderRecord>() == 8);
static_assert!(size_of::<ImportRecord>() == 80);
static_assert!(size_of::<ExportRecord>() == 80);
static_assert!(size_of::<HookFnRecord>() == 24);
static_assert!(size_of::<HookMemRecord>() == 32);
static_assert!(size_of::<HookNameRecord>() == 16);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct Import {
    service_id: String,
    major: u16,
    min_minor: u16,
    optional: bool,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct Export {
    service_id: String,
    major: u16,
    minor: u16,
    deferred: bool,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Hook {
    /// Link-time function target; `symbol` recovered from the relocation/bind at the field.
    Fn { symbol: Option<String> },
    /// Pointer-to-member target: non-virtual carries a relocation, virtual carries literal
    /// slot words decoded per the target ABI.
    #[serde(rename = "member")]
    Mem { vtable: String, display: String, symbol: Option<String>, virtual_slot: Option<u64> },
    /// Symbol-name target, resolved against the game's symbol manifest at load time.
    Name { name: String },
}

#[derive(Serialize)]
struct MetaFile {
    format: String,
    arch: String,
    abi_version: u32,
    imports: Vec<Import>,
    exports: Vec<Export>,
    hooks: Vec<Hook>,
}

/// Symbol bindings for pointer fields in the section, keyed by image/virtual address.
struct Fixups {
    binds: Vec<(u64, String)>,
}

impl Fixups {
    fn lookup(&self, addr: u64) -> Option<&str> {
        self.binds.binary_search_by_key(&addr, |&(a, _)| a).ok().map(|i| self.binds[i].1.as_str())
    }
}

fn parse_library(data: &[u8]) -> Result<MetaFile> {
    let file = object::File::parse(data)?;
    let section = file
        .section_by_name("modmeta")
        .or_else(|| file.section_by_name("__modmeta"))
        .context("No mod metadata section (is this a mod library?)")?;
    let section_addr = section.address();
    let section_data = section.data()?;
    let fixups = collect_fixups(&file, data, section_addr, section_data.len() as u64)?;
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
    let mut off = 0usize;
    while off < section_data.len() {
        let rest = &section_data[off..];
        if rest.len() < 8 {
            if rest.iter().all(|&b| b == 0) {
                break;
            }
            bail!("Trailing bytes at section offset {off}");
        }
        if rest[..8] == [0u8; 8] {
            off += 8; // linker padding / bounds sentinel
            continue;
        }
        let (header, _) = RecordHeader::read_from_prefix(rest).unwrap();
        let size = header.size.get() as usize;
        if size < 8 || size % 8 != 0 || size > rest.len() {
            bail!("Bad record size {size} at section offset {off}");
        }
        let rec = &rest[..size];
        let field_addr = |field_off: usize| section_addr + off as u64 + field_off as u64;
        match header.kind {
            KIND_PAD => {}
            KIND_HEADER => {
                let (record, _) =
                    HeaderRecord::read_from_prefix(rec).map_err(|_| truncated(off))?;
                header_count += 1;
                meta.abi_version = record.abi_version.get();
            }
            KIND_IMPORT => {
                let (record, _) =
                    ImportRecord::read_from_prefix(rec).map_err(|_| truncated(off))?;
                meta.imports.push(Import {
                    service_id: read_service_id(&record.service_id, off)?,
                    major: record.major_version.get(),
                    min_minor: record.min_minor_version.get(),
                    optional: header.flags & IMPORT_OPTIONAL != 0,
                });
            }
            KIND_EXPORT => {
                let (record, _) =
                    ExportRecord::read_from_prefix(rec).map_err(|_| truncated(off))?;
                meta.exports.push(Export {
                    service_id: read_service_id(&record.service_id, off)?,
                    major: record.major_version.get(),
                    minor: record.minor_version.get(),
                    deferred: header.flags & EXPORT_DEFERRED != 0,
                });
            }
            KIND_HOOK_FN => {
                let (_, _) = HookFnRecord::read_from_prefix(rec).map_err(|_| truncated(off))?;
                meta.hooks
                    .push(Hook::Fn { symbol: fixups.lookup(field_addr(8)).map(str::to_string) });
            }
            KIND_HOOK_MEM => {
                let (record, strings) =
                    HookMemRecord::read_from_prefix(rec).map_err(|_| truncated(off))?;
                let (vtable, rest) = read_cstr(strings, off)?;
                let (display, _) = read_cstr(rest, off)?;
                let symbol = fixups.lookup(field_addr(8)).map(str::to_string);
                let virtual_slot = if symbol.is_some() {
                    None
                } else {
                    decode_virtual_slot(arch, format, record.pmf[0].get(), record.pmf[1].get())
                };
                meta.hooks.push(Hook::Mem { vtable, display, symbol, virtual_slot });
            }
            KIND_HOOK_NAME => {
                let (_, name) =
                    HookNameRecord::read_from_prefix(rec).map_err(|_| truncated(off))?;
                let (name, _) = read_cstr(name, off)?;
                meta.hooks.push(Hook::Name { name });
            }
            kind => log::debug!("Skipping unknown record kind {kind} at offset {off}"),
        }
        off += size;
    }

    if header_count != 1 {
        bail!("Expected exactly 1 header record, found {header_count}");
    }
    Ok(meta)
}

fn truncated(off: usize) -> anyhow::Error {
    anyhow::anyhow!("Truncated record at section offset {off}")
}

fn read_service_id(buf: &[u8; 64], off: usize) -> Result<String> {
    let Some(len) = buf.iter().position(|&b| b == 0) else {
        bail!("Unterminated service id at section offset {off}");
    };
    if len == 0 {
        bail!("Empty service id at section offset {off}");
    }
    Ok(String::from_utf8_lossy(&buf[..len]).into_owned())
}

fn read_cstr(buf: &[u8], off: usize) -> Result<(String, &[u8])> {
    let Some(len) = buf.iter().position(|&b| b == 0) else {
        bail!("Unterminated string at section offset {off}");
    };
    Ok((String::from_utf8_lossy(&buf[..len]).into_owned(), &buf[len + 1..]))
}

/// Decode a literal (unrelocated) pointer-to-member as a virtual dispatch slot.
/// Returns the byte offset from the vtable's address point, or None if not decodable.
fn decode_virtual_slot(
    arch: Architecture,
    format: BinaryFormat,
    word0: u64,
    word1: u64,
) -> Option<u64> {
    if format == BinaryFormat::Pe {
        return None; // MSVC vcall thunks live in code; use the display name instead
    }
    match arch {
        // AAPCS64: virtual flag is bit 0 of the adjustment word, ptr is the slot offset.
        Architecture::Aarch64 | Architecture::Arm => {
            (word1 & 1 != 0 && word1 >> 1 == 0).then_some(word0)
        }
        // Itanium: virtual flag is bit 0 of ptr, slot offset is ptr - 1.
        _ => (word0 & 1 != 0 && word1 == 0).then_some(word0 - 1),
    }
}

fn collect_fixups(
    file: &object::File,
    data: &[u8],
    section_addr: u64,
    section_size: u64,
) -> Result<Fixups> {
    let range = section_addr..section_addr + section_size;
    let mut binds = Vec::new();
    match file {
        object::File::Elf64(_) => {
            if let Some(relocations) = file.dynamic_relocations() {
                for (addr, reloc) in relocations {
                    if !range.contains(&addr) {
                        continue;
                    }
                    if let RelocationTarget::Symbol(index) = reloc.target()
                        && let Ok(symbol) = file.symbol_by_index(index)
                        && let Ok(name) = symbol.name()
                        && !name.is_empty()
                    {
                        binds.push((addr, name.to_string()));
                    }
                }
            }
        }
        object::File::MachO64(macho) => {
            collect_macho_binds(macho, data, &range, &mut binds)?;
        }
        // PE: pointer fields statically resolve to import thunks in the mod's own image;
        // recovering names would require disassembling the thunks. Hook records on PE are
        // informational only (the inline display/name strings still identify targets).
        _ => {}
    }
    binds.sort_by_key(|a| a.0);
    Ok(Fixups { binds })
}

/// dyld_chained_fixups_header
#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct ChainedFixupsHeader {
    fixups_version: U32,
    starts_offset: U32,
    imports_offset: U32,
    symbols_offset: U32,
    imports_count: U32,
    imports_format: U32,
    symbols_format: U32,
}

/// dyld_chained_starts_in_segment (page_start[page_count] follows)
#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct ChainedStartsInSegment {
    size: U32,
    page_size: U16,
    pointer_format: U16,
    segment_offset: U64,
    max_valid_pointer: U32,
    page_count: U16,
}

static_assert!(size_of::<ChainedFixupsHeader>() == 28);
static_assert!(size_of::<ChainedStartsInSegment>() == 22);

const DYLD_CHAINED_IMPORT: u32 = 1;
const DYLD_CHAINED_PTR_64: u16 = 2;
const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6;

/// Recover bound symbol names for locations within `range` from Mach-O fixup metadata:
/// LC_DYLD_CHAINED_FIXUPS (modern) or LC_DYLD_INFO bind opcode streams (emitted by ld64 for
/// `-undefined dynamic_lookup` flat-namespace binds, which mod libraries use).
fn collect_macho_binds(
    macho: &MachOFile64<Endianness>,
    data: &[u8],
    range: &Range<u64>,
    binds: &mut Vec<(u64, String)>,
) -> Result<()> {
    let endian = macho.endian();
    let segments: Vec<(u64, u64, u64)> = macho
        .segments()
        .map(|seg| {
            let (file_off, file_size) = seg.file_range();
            (seg.address(), file_off, file_size)
        })
        .collect();
    let vm_to_file = |addr: u64| -> Option<usize> {
        segments.iter().find_map(|&(vmaddr, file_off, file_size)| {
            (addr >= vmaddr && addr < vmaddr + file_size)
                .then(|| (file_off + (addr - vmaddr)) as usize)
        })
    };

    let mut fixups_data: Option<&[u8]> = None;
    let mut commands = macho.macho_load_commands()?;
    while let Some(command) = commands.next()? {
        if command.cmd() == macho::LC_DYLD_CHAINED_FIXUPS
            && let LoadCommandVariant::LinkeditData(linkedit) = command.variant()?
        {
            let off = linkedit.dataoff.get(endian) as usize;
            let size = linkedit.datasize.get(endian) as usize;
            fixups_data = data.get(off..off + size);
        }
        if let LoadCommandVariant::DyldInfo(info) = command.variant()? {
            for (off, size) in [
                (info.bind_off.get(endian), info.bind_size.get(endian)),
                (info.weak_bind_off.get(endian), info.weak_bind_size.get(endian)),
                (info.lazy_bind_off.get(endian), info.lazy_bind_size.get(endian)),
            ] {
                if size != 0
                    && let Some(stream) = data.get(off as usize..(off + size) as usize)
                {
                    run_bind_opcodes(stream, &segments, range, binds)?;
                }
            }
        }
    }
    let Some(blob) = fixups_data else {
        return Ok(()); // opcode-based binds only
    };

    let (header, _) =
        ChainedFixupsHeader::read_from_prefix(blob).map_err(|_| truncated_fixups())?;
    if header.imports_format.get() != DYLD_CHAINED_IMPORT {
        log::warn!(
            "Unsupported chained import format {}; hook symbols not recovered",
            header.imports_format.get()
        );
        return Ok(());
    }
    let imports_offset = header.imports_offset.get() as usize;
    let symbols_offset = header.symbols_offset.get() as usize;

    let import_name = |ordinal: usize| -> Option<String> {
        if ordinal >= header.imports_count.get() as usize {
            return None;
        }
        // dyld_chained_import: lib_ordinal:8, weak_import:1, name_offset:23
        let raw = U32::read_from_prefix(blob.get(imports_offset + ordinal * 4..)?).ok()?.0.get();
        let name = blob.get(symbols_offset + (raw >> 9) as usize..)?;
        let len = name.iter().position(|&b| b == 0)?;
        // Strip the Mach-O leading underscore to match the record/manifest convention.
        let name = &name[..len];
        let name = name.strip_prefix(b"_").unwrap_or(name);
        Some(String::from_utf8_lossy(name).into_owned())
    };

    // dyld_chained_starts_in_image: { seg_count u32, seg_info_offset[seg_count] u32 }
    let starts_offset = header.starts_offset.get() as usize;
    let starts = blob.get(starts_offset..).ok_or_else(truncated_fixups)?;
    let (seg_count, seg_info_offsets) =
        U32::read_from_prefix(starts).map_err(|_| truncated_fixups())?;
    for seg in 0..seg_count.get() as usize {
        let (seg_info_offset, _) =
            U32::read_from_prefix(&seg_info_offsets[seg * 4..]).map_err(|_| truncated_fixups())?;
        if seg_info_offset.get() == 0 {
            continue;
        }
        let seg_data = starts.get(seg_info_offset.get() as usize..).ok_or_else(truncated_fixups)?;
        let (seg_starts, page_starts) =
            ChainedStartsInSegment::read_from_prefix(seg_data).map_err(|_| truncated_fixups())?;
        let pointer_format = seg_starts.pointer_format.get();
        if pointer_format != DYLD_CHAINED_PTR_64 && pointer_format != DYLD_CHAINED_PTR_64_OFFSET {
            log::warn!("Unsupported chained pointer format {pointer_format}");
            continue;
        }
        for page in 0..seg_starts.page_count.get() as usize {
            let (page_start, _) =
                U16::read_from_prefix(&page_starts[page * 2..]).map_err(|_| truncated_fixups())?;
            if page_start.get() == 0xFFFF {
                continue;
            }
            let mut addr = seg_starts.segment_offset.get()
                + page as u64 * seg_starts.page_size.get() as u64
                + page_start.get() as u64;
            loop {
                let file_off = vm_to_file(addr).ok_or_else(truncated_fixups)?;
                let (entry, _) = U64::read_from_prefix(data.get(file_off..).unwrap_or(&[]))
                    .map_err(|_| truncated_fixups())?;
                let entry = entry.get();
                // dyld_chained_ptr_64_bind: ordinal:24, addend:8, reserved:19, next:12, bind:1
                let bind = entry >> 63 != 0;
                if bind
                    && range.contains(&addr)
                    && let Some(name) = import_name((entry & 0xFF_FFFF) as usize)
                {
                    binds.push((addr, name));
                }
                let next = (entry >> 51) & 0xFFF;
                if next == 0 {
                    break;
                }
                addr += next * 4;
            }
        }
    }
    Ok(())
}

fn truncated_fixups() -> anyhow::Error { anyhow::anyhow!("Truncated chained fixups data") }

fn read_uleb(stream: &[u8], pos: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *stream.get(*pos).context("truncated uleb128")?;
        *pos += 1;
        value |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

/// Interpret a dyld bind opcode stream, recording binds that land within `range`.
fn run_bind_opcodes(
    stream: &[u8],
    segments: &[(u64, u64, u64)],
    range: &Range<u64>,
    binds: &mut Vec<(u64, String)>,
) -> Result<()> {
    let mut pos = 0usize;
    let mut symbol = String::new();
    let mut addr = 0u64;
    let mut record = |addr: u64, symbol: &str| {
        if range.contains(&addr) && !symbol.is_empty() {
            let name = symbol.strip_prefix('_').unwrap_or(symbol);
            binds.push((addr, name.to_string()));
        }
    };
    while pos < stream.len() {
        let byte = stream[pos];
        pos += 1;
        let imm = u64::from(byte & 0x0F);
        match byte & 0xF0 {
            0x00 => {}        // DONE (ends one lazy-bind entry; the stream continues)
            0x10 | 0x30 => {} // SET_DYLIB_ORDINAL_IMM / SET_DYLIB_SPECIAL_IMM
            0x20 => {
                read_uleb(stream, &mut pos)?; // SET_DYLIB_ORDINAL_ULEB
            }
            0x40 => {
                // SET_SYMBOL_TRAILING_FLAGS_IMM
                let rest = &stream[pos..];
                let len = rest.iter().position(|&b| b == 0).context("unterminated bind symbol")?;
                symbol = String::from_utf8_lossy(&rest[..len]).into_owned();
                pos += len + 1;
            }
            0x50 => {} // SET_TYPE_IMM
            0x60 => {
                // SET_ADDEND_SLEB
                while *stream.get(pos).context("truncated sleb128")? & 0x80 != 0 {
                    pos += 1;
                }
                pos += 1;
            }
            0x70 => {
                // SET_SEGMENT_AND_OFFSET_ULEB
                let segment_base =
                    segments.get(imm as usize).context("bind segment out of range")?.0;
                addr = segment_base.wrapping_add(read_uleb(stream, &mut pos)?);
            }
            0x80 => {
                addr = addr.wrapping_add(read_uleb(stream, &mut pos)?); // ADD_ADDR_ULEB
            }
            0x90 => {
                // DO_BIND
                record(addr, &symbol);
                addr = addr.wrapping_add(8);
            }
            0xA0 => {
                // DO_BIND_ADD_ADDR_ULEB
                record(addr, &symbol);
                addr = addr.wrapping_add(8).wrapping_add(read_uleb(stream, &mut pos)?);
            }
            0xB0 => {
                // DO_BIND_ADD_ADDR_IMM_SCALED
                record(addr, &symbol);
                addr = addr.wrapping_add(8 + imm * 8);
            }
            0xC0 => {
                // DO_BIND_ULEB_TIMES_SKIPPING_ULEB
                let count = read_uleb(stream, &mut pos)?;
                let skip = read_uleb(stream, &mut pos)?;
                for _ in 0..count {
                    record(addr, &symbol);
                    addr = addr.wrapping_add(8 + skip);
                }
            }
            other => bail!("Unsupported bind opcode {other:#04x}"),
        }
    }
    Ok(())
}

fn check_agreement(files: &[(&PathBuf, MetaFile)]) -> Result<()> {
    let (first_path, first) = &files[0];
    for (path, file) in files {
        if file.abi_version != first.abi_version {
            bail!(
                "ABI version mismatch: '{}' has v{}, '{}' has v{}",
                first_path.display(),
                first.abi_version,
                path.display(),
                file.abi_version
            );
        }
        let key = |f: &MetaFile| -> (BTreeSet<String>, BTreeSet<String>) {
            (
                f.imports.iter().map(|i| format!("{i:?}")).collect(),
                f.exports.iter().map(|e| format!("{e:?}")).collect(),
            )
        };
        if key(file) != key(first) {
            bail!(
                "Service import/export disagreement between '{}' and '{}'",
                first_path.display(),
                path.display()
            );
        }
        // Hook records are per-binary (targets resolve per platform); no agreement required.
    }
    Ok(())
}
