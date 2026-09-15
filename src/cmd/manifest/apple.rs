use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::PathBuf,
};

use anyhow::{Context, Result, ensure};
use object::{Object, ObjectSymbol};
use rayon::prelude::*;

use super::{
    aliases::{FunctionRecord, SourceRoot, binary_name},
    dwarf,
};
use crate::util::{
    file::map_file,
    manifest::{FLAG_CODE, FLAG_DISPLAY, ManifestSymbol},
};

pub(super) fn aliases(
    file: &object::File<'_>,
    root: &SourceRoot,
    symbols: &[ManifestSymbol],
) -> Result<Vec<ManifestSymbol>> {
    let map = file.object_map();
    ensure!(
        !map.objects().is_empty(),
        "Mach-O has no object debug map; generate the manifest before stripping and link with debug information"
    );
    // Preserve every map entry, including repeated archive member identities.
    let mut grouped: BTreeMap<PathBuf, BTreeMap<Option<&[u8]>, Vec<&object::ObjectMapEntry<'_>>>> =
        BTreeMap::new();
    for symbol in map.symbols() {
        let object = symbol.object(&map);
        let path =
            std::str::from_utf8(object.path()).context("Debug-map object path is not UTF-8")?;
        grouped
            .entry(PathBuf::from(path))
            .or_default()
            .entry(object.member())
            .or_default()
            .push(symbol);
    }
    let linked: HashMap<_, _> = symbols
        .iter()
        .filter(|s| s.flags & (FLAG_CODE | FLAG_DISPLAY) == FLAG_CODE)
        .map(|s| ((s.name.as_str(), s.rva), s))
        .collect();
    let base = file.relative_address_base();
    let jobs: Vec<_> = grouped.into_iter().collect();
    let results: Vec<Result<Vec<ManifestSymbol>>> = jobs.par_iter().map(|(path, members)| {
        let bytes = map_file(path).with_context(|| format!("Unreadable debug-map container '{}'; source scope is unknown. Rebuild at the recorded path", path.display()))?;
        let mut aliases = Vec::new();
        let mut inspect = |bytes: &[u8], mapped: &[&object::ObjectMapEntry<'_>], label: &str| -> Result<()> {
            let object = object::File::parse(bytes).with_context(|| format!("Parsing {label}"))?;
            ensure!(object.architecture() == file.architecture(), "Debug-map object architecture differs from the selected executable slice: {label}");
            let Some(source) = dwarf::object_source(&object, root).with_context(|| format!("TU metadata in {label}"))? else { return Ok(()) };
            let names: BTreeSet<_> = object.symbols().filter(|s| s.is_definition() && s.kind() == object::SymbolKind::Text)
                .filter_map(|s| s.name_bytes().ok()).collect();
            for entry in mapped {
                if !names.contains(entry.name()) { continue; }
                let raw = std::str::from_utf8(entry.name()).context("Debug-map function name is not UTF-8")?;
                let raw = raw.strip_prefix('_').unwrap_or(raw);
                let rva = entry.address().wrapping_sub(base);
                let Some(symbol) = linked.get(&(raw, rva)) else { continue; };
                let Some(name) = binary_name(raw) else { continue; };
                if let Some(alias) = (FunctionRecord {
                    source: source.clone(), name, rva, flags: symbol.flags,
                    provenance: label.to_owned(),
                }).into_alias() { aliases.push(alias); }
            }
            Ok(())
        };
        if let Some(mapped) = members.get(&None) {
            inspect(&bytes, mapped, &path.display().to_string())?;
        }
        if members.keys().any(Option::is_some) {
            let archive = object::read::archive::ArchiveFile::parse(&*bytes)
                .with_context(|| format!("Parsing archive {}", path.display()))?;
            ensure!(!archive.is_thin(), "Thin debug-map archive is unsupported: {}", path.display());
            let mut found = BTreeSet::new();
            for member in archive.members() {
                let member = member?;
                if let Some(mapped) = members.get(&Some(member.name())) {
                    found.insert(member.name());
                    inspect(member.data(&*bytes)?, mapped, &format!("{}({})", path.display(), String::from_utf8_lossy(member.name())))?;
                }
            }
            for name in members.keys().flatten() {
                ensure!(found.contains(name), "Missing debug-map archive member {}({}); rebuild the archive", path.display(), String::from_utf8_lossy(name));
            }
        }
        Ok(aliases)
    }).collect();
    let mut aliases = Vec::new();
    for result in results {
        aliases.extend(result?);
    }
    Ok(aliases)
}
