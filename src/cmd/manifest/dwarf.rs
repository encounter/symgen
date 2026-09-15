use std::borrow::Cow;

use anyhow::{Context, Result, bail, ensure};
use gimli::{AttributeValue, Dwarf, Reader, Unit};
use object::{Object, ObjectSection};
use rayon::prelude::*;

use super::aliases::{FunctionRecord, SourceRoot, binary_name};
use crate::util::manifest::{FLAG_CODE, FLAG_DISPLAY, ManifestSymbol};

#[derive(Debug, Default)]
struct Relocations(object::read::RelocationMap);

impl gimli::Relocate for &Relocations {
    fn relocate_address(&self, offset: usize, value: u64) -> gimli::Result<u64> {
        Ok(self.0.relocate(offset as u64, value))
    }

    fn relocate_offset(&self, offset: usize, value: usize) -> gimli::Result<usize> {
        <usize as gimli::ReaderOffset>::from_u64(self.0.relocate(offset as u64, value as u64))
    }
}

#[derive(Default)]
struct Section<'a> {
    data: Cow<'a, [u8]>,
    relocations: Relocations,
}

type DwarfReader<'a> =
    gimli::RelocateReader<gimli::EndianSlice<'a, gimli::RunTimeEndian>, &'a Relocations>;

fn load<'a>(file: &object::File<'a>) -> Result<gimli::DwarfSections<Section<'a>>> {
    gimli::DwarfSections::load(|id| {
        let Some(section) = file.section_by_name(id.name()) else { return Ok(Section::default()) };
        Ok(Section {
            data: section.uncompressed_data().with_context(|| format!("Reading {}", id.name()))?,
            relocations: Relocations(
                section
                    .relocation_map()
                    .with_context(|| format!("Relocations for {}", id.name()))?,
            ),
        })
    })
}

fn borrow<'a>(
    sections: &'a gimli::DwarfSections<Section<'a>>,
    file: &object::File<'_>,
) -> Dwarf<DwarfReader<'a>> {
    let endian = if file.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };
    sections.borrow(|section| {
        gimli::RelocateReader::new(
            gimli::EndianSlice::new(&section.data, endian),
            &section.relocations,
        )
    })
}

fn string<R: Reader>(value: Option<R>) -> Result<String> {
    value
        .map(|s| Ok(std::str::from_utf8(&s.to_slice()?)?.to_owned()))
        .transpose()
        .map(Option::unwrap_or_default)
}

fn source<R: Reader<Offset = usize>>(unit: &Unit<R>, root: &SourceRoot) -> Result<Option<String>> {
    let mut entries = unit.entries();
    let entry = entries.next_dfs()?.context("DWARF compilation unit has no root entry")?;
    let language = entry.attr_value(gimli::DW_AT_language);
    if language.is_none() {
        let name = string(unit.name.clone())?;
        let dir = string(unit.comp_dir.clone())?;
        if !name.is_empty() && root.source(&name, &dir).is_none() {
            return Ok(None);
        }
        bail!(
            "DWARF unit '{name}' has no language metadata; rebuild with full, unsplit C/C++ debug information (TU scope is unknown)"
        );
    }
    let cpp = matches!(
        language,
        Some(AttributeValue::Language(
            gimli::DW_LANG_C
                | gimli::DW_LANG_C89
                | gimli::DW_LANG_C99
                | gimli::DW_LANG_C11
                | gimli::DW_LANG_C17
                | gimli::DW_LANG_C_plus_plus
                | gimli::DW_LANG_C_plus_plus_03
                | gimli::DW_LANG_C_plus_plus_11
                | gimli::DW_LANG_C_plus_plus_14
                | gimli::DW_LANG_C_plus_plus_17
                | gimli::DW_LANG_C_plus_plus_20
        ))
    );
    if !cpp {
        return Ok(None);
    }
    let name = string(unit.name.clone())?;
    ensure!(
        !name.is_empty(),
        "C/C++ DWARF unit is missing its primary source (DW_AT_name); rebuild with debug information"
    );
    Ok(root.source(&name, &string(unit.comp_dir.clone())?))
}

/// Only single-CU C/C++ objects can use debug-map ownership without a DIE/address join.
pub(super) fn object_source(file: &object::File<'_>, root: &SourceRoot) -> Result<Option<String>> {
    let sections = load(file)?;
    let dwarf = borrow(&sections, file);
    let mut units = dwarf.units();
    let mut count = 0;
    let mut selected = None;
    while let Some(header) = units.next()? {
        count += 1;
        let unit = dwarf.unit(header)?;
        if let Some(source) = source(&unit, root)? {
            selected = Some(source);
        }
    }
    if count == 0 {
        bail!(
            "Debug-map object has no DWARF compilation units; rebuild it with debug information (source scope is unknown)"
        );
    }
    ensure!(
        count == 1 || selected.is_none(),
        "In-scope multi-CU object has ambiguous TU ownership; disable LTO for hookable C/C++ sources"
    );
    Ok(selected)
}

/// Resolve only name/origin attributes; type graphs are intentionally not traversed.
fn linkage<R: Reader<Offset = usize>>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    offset: gimli::UnitOffset,
    depth: usize,
) -> Result<Option<String>> {
    ensure!(depth < 32, "Cyclic or excessively deep DWARF subprogram origin");
    let entry = unit.entry(offset)?;
    for attr in [gimli::DW_AT_linkage_name, gimli::DW_AT_MIPS_linkage_name] {
        if let Some(value) = entry.attr_value(attr) {
            return Ok(Some(string(Some(dwarf.attr_string(unit, value)?))?));
        }
    }
    for attr in [gimli::DW_AT_specification, gimli::DW_AT_abstract_origin] {
        match entry.attr_value(attr) {
            Some(AttributeValue::UnitRef(offset)) => {
                return linkage(dwarf, unit, offset, depth + 1);
            }
            Some(AttributeValue::DebugInfoRef(offset)) => {
                let mut headers = dwarf.units();
                while let Some(header) = headers.next()? {
                    if let Some(local) = offset.to_unit_offset(&header) {
                        return linkage(dwarf, &dwarf.unit(header)?, local, depth + 1);
                    }
                }
                bail!("DWARF subprogram origin points outside .debug_info");
            }
            _ => {}
        }
    }
    Ok(None)
}

pub(super) fn elf_aliases(
    file: &object::File<'_>,
    root: &SourceRoot,
    symbols: &[ManifestSymbol],
) -> Result<Vec<ManifestSymbol>> {
    let sections = load(file)?;
    let dwarf = borrow(&sections, file);
    let mut headers = Vec::new();
    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        headers.push(header);
    }
    ensure!(
        !headers.is_empty(),
        "Linked ELF has no embedded DWARF; generate the manifest before debug splitting/stripping and compile with -g"
    );
    let mut code: Vec<_> =
        symbols.iter().filter(|s| s.flags & (FLAG_CODE | FLAG_DISPLAY) == FLAG_CODE).collect();
    code.sort_by_key(|s| s.rva);
    let base = file.relative_address_base();
    let results: Vec<Result<Vec<ManifestSymbol>>> = headers
        .into_par_iter()
        .map(|header| {
            let unit = dwarf.unit(header)?;
            let Some(source) = source(&unit, root)? else { return Ok(Vec::new()) };
            let mut aliases = Vec::new();
            let mut entries = unit.entries();
            while let Some(entry) = entries.next_dfs()? {
                if entry.tag() != gimli::DW_TAG_subprogram {
                    continue;
                }
                let mut ranges = dwarf.die_ranges(&unit, entry)?;
                let mut name = None;
                while let Some(range) = ranges.next()? {
                    // Address zero is the usual tombstone for linker-discarded code.
                    if range.begin == 0 || range.end <= range.begin {
                        continue;
                    }
                    let start = range.begin.wrapping_sub(base);
                    let end = range.end.wrapping_sub(base);
                    let first = code.partition_point(|s| s.rva < start);
                    let last = code.partition_point(|s| s.rva < end);
                    if first == last {
                        continue;
                    }
                    let linkage = match &name {
                        Some(value) => value,
                        None => name.insert(linkage(&dwarf, &unit, entry.offset(), 0)?),
                    };
                    for sym in &code[first..last] {
                        if linkage.as_ref().is_some_and(|name| name != &sym.name) {
                            continue;
                        }
                        let Some(name) = binary_name(&sym.name) else {
                            continue;
                        };
                        if let Some(alias) = (FunctionRecord {
                            source: source.clone(),
                            name,
                            rva: sym.rva,
                            flags: sym.flags,
                            provenance: format!("DWARF {} at {:?}", source, entry.offset()),
                        })
                        .into_alias()
                        {
                            aliases.push(alias);
                        }
                    }
                }
            }
            Ok(aliases)
        })
        .collect();
    let mut aliases = Vec::new();
    for result in results {
        aliases.extend(result?);
    }
    Ok(aliases)
}
