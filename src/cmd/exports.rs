use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use argp::FromArgs;
use object::{FileKind, Object, ObjectSymbol, SymbolScope, read::archive::ArchiveFile};

use crate::util::file::process_rsp;

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Generate a curated export surface (-exported_symbols_list or ELF version
/// script) from built Mach-O or ELF objects.
#[argp(subcommand, name = "exports")]
pub struct Args {
    #[argp(positional)]
    /// objects and archives to scan; prefix a response file with @
    inputs: Vec<String>,
    #[argp(option, short = 'o')]
    /// output symbol list file
    out: PathBuf,
    #[argp(option)]
    /// static library to scan for C-only (unmangled) exports; repeatable
    sdk_lib: Vec<PathBuf>,
    #[argp(option)]
    /// only scan objects whose path contains this substring; repeatable
    include: Vec<String>,
    #[argp(option)]
    /// skip objects whose path contains this substring; repeatable
    exclude: Vec<String>,
    #[argp(option)]
    /// exclude symbols with this name prefix; repeatable
    exclude_sym: Vec<String>,
    #[argp(option)]
    /// add this name (or glob) to the output verbatim, bypassing the scan;
    /// repeatable
    extra_sym: Vec<String>,
    #[argp(option, default = "OutputFormat::List")]
    /// output format: list (one symbol per line, -exported_symbols_list) or
    /// version-script (ELF version script) (default: list)
    format: OutputFormat,
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum OutputFormat {
    List,
    VersionScript,
}

impl argp::FromArgValue for OutputFormat {
    fn from_arg_value(value: &std::ffi::OsStr) -> Result<Self, String> {
        match value.to_str() {
            Some("list") => Ok(Self::List),
            Some("version-script") => Ok(Self::VersionScript),
            _ => Err("Unknown format (expected list or version-script)".to_string()),
        }
    }
}

#[derive(Default)]
struct Stats {
    objects: usize,
    skipped_weak: usize,
    skipped_name: usize,
    skipped_scope: usize,
    skipped_path: usize,
    sdk_skipped_name: usize,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum ObjFormat {
    MachO,
    Elf,
}

/// Compiler/runtime symbols that are never part of the exported ABI.
/// On Mach-O every listed symbol becomes an initial undefined at link time, so entries
/// must exist in the final image (this also forces extraction of listed archive members,
/// matching PE .def semantics). ELF version scripts are filters instead: names that don't
/// exist are silently ignored and force nothing.
fn is_skip_symbol(format: ObjFormat, name: &str) -> bool {
    const MACHO_PREFIXES: &[&str] = &[
        "_OBJC_",
        "__OBJC_", // ObjC class/ivar metadata
        "___asan",
        "___lsan",
        "___ubsan",
        "___tsan",
        "___sanitizer", // sanitizer runtimes
        "_llvm.",
        "___llvm", // instrumentation
        "l_",
        "L_", // assembler-local labels
    ];
    const MACHO_EXACT: &[&str] = &["_main", "_SDL_main", "__mh_execute_header"];
    const ELF_PREFIXES: &[&str] = &[
        "__asan",
        "__lsan",
        "__ubsan",
        "__tsan",
        "__sanitizer", // sanitizer runtimes
        "llvm.",
        "__llvm", // instrumentation
        ".L",     // assembler-local labels
    ];
    const ELF_EXACT: &[&str] = &["main"];
    let (prefixes, exact) = match format {
        ObjFormat::MachO => (MACHO_PREFIXES, MACHO_EXACT),
        ObjFormat::Elf => (ELF_PREFIXES, ELF_EXACT),
    };
    prefixes.iter().any(|p| name.starts_with(p)) || exact.contains(&name)
}

fn scan_object(
    data: &[u8],
    c_only: bool,
    args: &Args,
    exports: &mut BTreeSet<String>,
    stats: &mut Stats,
) -> Result<(), object::Error> {
    let file = object::File::parse(data)?;
    let format = match file {
        object::File::MachO32(_) | object::File::MachO64(_) => ObjFormat::MachO,
        _ => ObjFormat::Elf,
    };
    stats.objects += 1;

    for sym in file.symbols() {
        if !sym.is_definition() || !sym.is_global() {
            continue; // absolute/common/undefined
        }
        // Weak definitions (inline functions, templates, vtables) exist in every image,
        // mirroring the selectany COMDAT skip in `def`.
        if sym.is_weak() {
            stats.skipped_weak += 1;
            continue;
        }
        // Private extern (hidden visibility) symbols cannot be exported.
        if sym.scope() != SymbolScope::Dynamic {
            stats.skipped_scope += 1;
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        if name.is_empty() {
            continue;
        }
        let mangle_prefix = match format {
            ObjFormat::MachO => "__Z",
            ObjFormat::Elf => "_Z",
        };
        if c_only && name.starts_with(mangle_prefix) {
            stats.sdk_skipped_name += 1;
            continue;
        }
        if is_skip_symbol(format, name)
            || args.exclude_sym.iter().any(|p| name.starts_with(p.as_str()))
        {
            stats.skipped_name += 1;
            continue;
        }
        exports.insert(name.to_string());
    }
    Ok(())
}

fn scan_path(
    path: &Path,
    c_only: bool,
    args: &Args,
    exports: &mut BTreeSet<String>,
    stats: &mut Stats,
) -> Result<()> {
    let data =
        fs::read(path).with_context(|| format!("Failed to read object '{}'", path.display()))?;
    if data.starts_with(b"!<arch>") {
        let archive = ArchiveFile::parse(&*data)
            .with_context(|| format!("Failed to parse archive '{}'", path.display()))?;
        for member in archive.members() {
            let member = member.with_context(|| {
                format!("Failed to read archive member in '{}'", path.display())
            })?;
            let member_data = member.data(&*data).with_context(|| {
                format!("Failed to read archive member in '{}'", path.display())
            })?;
            // Symbol tables and empty members aren't objects; skip quietly.
            let _ = scan_object(member_data, c_only, args, exports, stats);
        }
        Ok(())
    } else {
        match FileKind::parse(&*data) {
            Ok(FileKind::MachO32 | FileKind::MachO64 | FileKind::Elf32 | FileKind::Elf64) => {
                scan_object(&data, c_only, args, exports, stats)
                    .with_context(|| format!("Failed to parse object '{}'", path.display()))
            }
            _ => bail!("'{}' is not a Mach-O/ELF object or archive", path.display()),
        }
    }
}

fn path_included(path: &str, includes: &[String], excludes: &[String]) -> bool {
    if excludes.iter().any(|e| path.contains(e.as_str())) {
        return false;
    }
    includes.is_empty() || includes.iter().any(|i| path.contains(i.as_str()))
}

pub fn run(args: Args) -> Result<()> {
    let mut exports: BTreeSet<String> = BTreeSet::new();
    let mut stats = Stats::default();

    let inputs = process_rsp(&args.inputs)?;
    if inputs.is_empty() {
        bail!("At least one input object or archive is required");
    }
    for path in &inputs {
        if !path_included(path, &args.include, &args.exclude) {
            stats.skipped_path += 1;
            continue;
        }
        scan_path(Path::new(path), false, &args, &mut exports, &mut stats)?;
    }
    for lib in &args.sdk_lib {
        scan_path(lib, true, &args, &mut exports, &mut stats)?;
    }

    for extra in &args.extra_sym {
        exports.insert(extra.clone());
    }
    let mut list = String::new();
    if args.format == OutputFormat::VersionScript {
        list.push_str("{\nglobal:\n");
    }
    for name in &exports {
        list.push_str(name);
        if args.format == OutputFormat::VersionScript {
            list.push(';');
        }
        list.push('\n');
    }
    if args.format == OutputFormat::VersionScript {
        list.push_str("local:\n*;\n};\n");
    }
    fs::write(&args.out, list)
        .with_context(|| format!("Failed to write '{}'", args.out.display()))?;

    log::info!("{} exports from {} objects", exports.len(), stats.objects);
    log::debug!("Skipped {} weak definitions", stats.skipped_weak);
    log::debug!("Skipped {} symbols by name", stats.skipped_name);
    log::debug!("Skipped {} hidden symbols", stats.skipped_scope);
    log::debug!("Skipped {} non-C SDK symbols", stats.sdk_skipped_name);
    log::debug!("Skipped {} path-filtered objects", stats.skipped_path);
    Ok(())
}
