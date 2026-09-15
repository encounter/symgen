use std::collections::{BTreeSet, HashMap};

use anyhow::{Context, Result, bail, ensure};
use pdb::FallibleIterator;

use super::aliases::SourceRoot;

#[derive(Default)]
pub(super) struct BuildInfo {
    arguments: HashMap<u32, Vec<pdb::IdIndex>>,
    strings: HashMap<u32, (Option<pdb::IdIndex>, String)>,
    lists: HashMap<u32, Vec<pdb::TypeIndex>>,
}

impl BuildInfo {
    pub fn read<'s, S: pdb::Source<'s> + 's>(pdb: &mut pdb::PDB<'s, S>) -> Result<Self> {
        let mut result = Self::default();
        let ids = match pdb.id_information() {
            Ok(ids) => ids,
            Err(pdb::Error::StreamNotFound(_)) => return Ok(result),
            Err(error) => return Err(error).context("Reading PDB build-info ID stream"),
        };
        let mut iter = ids.iter();
        while let Some(id) = iter.next()? {
            match id.parse() {
                Ok(pdb::IdData::BuildInfo(info)) => {
                    result.arguments.insert(id.index().0, info.arguments);
                }
                Ok(pdb::IdData::String(s)) => {
                    result
                        .strings
                        .insert(id.index().0, (s.substrings, s.name.to_string().into_owned()));
                }
                Ok(pdb::IdData::StringList(s)) => {
                    result.lists.insert(id.index().0, s.substrings);
                }
                _ => {}
            }
        }
        Ok(result)
    }

    fn string(&self, index: u32, depth: usize) -> Result<String> {
        if index == 0 {
            return Ok(String::new());
        }
        ensure!(depth < 32, "Cyclic or excessively deep PDB build-info string IDs");
        let (prefix, suffix) = self
            .strings
            .get(&index)
            .with_context(|| format!("Missing PDB build-info string ID {index:#x}"))?;
        let mut result = String::new();
        if let Some(prefix) = prefix {
            let list =
                self.lists.get(&prefix.0).context("Missing PDB build-info substring list")?;
            for part in list {
                result.push_str(&self.string(part.0, depth + 1)?);
            }
        }
        result.push_str(suffix);
        Ok(result)
    }

    pub fn source(
        &self,
        module: &pdb::ModuleInfo<'_>,
        strings: Option<&pdb::StringTable<'_>>,
        root: &SourceRoot,
    ) -> Result<Option<String>> {
        let mut cpp = false;
        let mut compile = false;
        let mut procedures = false;
        let mut build_info = None;
        let mut symbols = module.symbols()?;
        while let Some(symbol) = symbols.next()? {
            match symbol.parse() {
                Ok(pdb::SymbolData::CompileFlags(flags)) => {
                    compile = true;
                    cpp =
                        matches!(flags.language, pdb::SourceLanguage::C | pdb::SourceLanguage::Cpp)
                            && !flags
                                .version_string
                                .to_string()
                                .to_ascii_lowercase()
                                .contains("rustc");
                }
                Ok(pdb::SymbolData::BuildInfo(info)) => {
                    build_info = Some(info.id.0);
                }
                Ok(pdb::SymbolData::Procedure(_)) => procedures = true,
                _ => {}
            }
        }
        if !cpp {
            ensure!(
                compile || !procedures,
                "PDB module has emitted procedures but no language compile record; rebuild with /Zi or /Z7 (TU scope is unknown)"
            );
            return Ok(None);
        }
        if let Some(id) = build_info {
            let args = self.arguments.get(&id).context("Missing LF_BUILDINFO for S_BUILDINFO")?;
            ensure!(
                args.len() >= 3,
                "PDB LF_BUILDINFO is missing current-directory/main-source arguments"
            );
            // CodeView BuildInfoRecord: cwd, compiler, main source, PDB, command line.
            let dir = self.string(args[0].0, 0)?;
            let name = self.string(args[2].0, 0)?;
            if !name.is_empty() {
                return Ok(root.source(&name, &dir));
            }
        }
        let mut sources = BTreeSet::new();
        if let Some(strings) = strings {
            let lines = module.line_program()?;
            let mut files = lines.files();
            while let Some(file) = files.next()? {
                let name = strings.get(file.name)?.to_string().into_owned();
                let suffix = name.rsplit('.').next().unwrap_or_default().to_ascii_lowercase();
                if matches!(suffix.as_str(), "c" | "cc" | "cpp" | "cxx" | "c++") {
                    sources.insert(name);
                }
            }
        }
        if sources.len() == 1 {
            return Ok(root.source(sources.first().unwrap(), ""));
        }
        if !sources.is_empty() && sources.iter().all(|s| root.source(s, "").is_none()) {
            return Ok(None);
        }
        bail!(
            "C/C++ PDB module has no primary-source build info and {} possible sources; rebuild with /Zi or /Z7 using a producer that records S_BUILDINFO",
            sources.len()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_info_resolves_string_lists_and_rejects_cycles() {
        let mut info = BuildInfo::default();
        info.strings.insert(1, (None, "C:/checkout/".into()));
        info.strings.insert(2, (Some(pdb::IdIndex(3)), "src/a.cpp".into()));
        info.lists.insert(3, vec![pdb::TypeIndex(1)]);
        assert_eq!(info.string(2, 0).unwrap(), "C:/checkout/src/a.cpp");
        info.lists.insert(3, vec![pdb::TypeIndex(2)]);
        assert!(info.string(2, 0).unwrap_err().to_string().contains("Cyclic"));
        assert!(info.string(4, 0).unwrap_err().to_string().contains("Missing"));
    }
}
