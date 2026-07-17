//! CLI for dumping and validating native mod metadata.

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use argp::FromArgs;
use serde::Serialize;

use crate::util::modmeta::{MetaFile, parse_library};

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
    /// verify cross-library agreement, then merge the package-level keys into a JSON file
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
        write_dump(args.out.as_deref(), &files)?;
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

fn write_dump(path: Option<&Path>, files: &[(&PathBuf, MetaFile)]) -> Result<()> {
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
    let text = serde_json::to_string_pretty(&output)? + "\n";
    match path {
        Some(path) => fs::write(path, text)
            .with_context(|| format!("Failed to write '{}'", path.display()))?,
        None => print!("{text}"),
    }
    Ok(())
}

fn update_json(path: &Path, meta: &MetaFile) -> Result<()> {
    let text = fs::read_to_string(path)?;
    let mut value: serde_json::Value = serde_json::from_str(&text)?;
    let object = value.as_object_mut().context("JSON root is not an object")?;
    let mut imports: Vec<_> = meta.imports.iter().collect();
    imports.sort();
    let mut exports: Vec<_> = meta.exports.iter().collect();
    exports.sort();
    object.insert("abi".to_string(), meta.abi_version.into());
    object.insert("imports".to_string(), serde_json::to_value(&imports)?);
    object.insert("exports".to_string(), serde_json::to_value(&exports)?);
    fs::write(path, serde_json::to_string_pretty(&value)? + "\n")?;
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
        let key = |file: &MetaFile| -> (BTreeSet<String>, BTreeSet<String>) {
            (
                file.imports.iter().map(|import| format!("{import:?}")).collect(),
                file.exports.iter().map(|export| format!("{export:?}")).collect(),
            )
        };
        if key(file) != key(first) {
            bail!(
                "Service import/export disagreement between '{}' and '{}'",
                first_path.display(),
                path.display()
            );
        }
    }
    Ok(())
}
