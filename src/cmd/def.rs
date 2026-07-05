use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use argp::FromArgs;
use object::{
    Object, ObjectComdat, ObjectSection, ObjectSymbol, SectionIndex, SectionKind, pe,
    read::{
        archive::ArchiveFile,
        coff::{CoffFile, CoffHeader},
    },
};

type CoffBigFile<'data> = CoffFile<'data, &'data [u8], pe::AnonObjectHeaderBigobj>;

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Generate a curated .def of exportable symbols from built COFF objects.
#[argp(subcommand, name = "def")]
pub struct Args {
    #[argp(option)]
    /// linker response file listing the objects and archives to scan
    /// (newline or ';' separated)
    rsp: PathBuf,
    #[argp(option, short = 'o')]
    /// output .def file
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
    #[argp(option, default = "60000")]
    /// fail if the export count exceeds this value; 0 disables the check
    /// (PE hard limit is 65535)
    max_exports: usize,
}

#[derive(Default)]
struct Stats {
    objects: usize,
    skipped_comdat: usize,
    skipped_name: usize,
    skipped_path: usize,
    sdk_skipped_name: usize,
}

fn norm(path: &str) -> String { path.replace('\\', "/") }

/// Compiler/runtime symbols that are never part of the exported ABI, even when not COMDAT.
fn is_skip_symbol(name: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "??_R",  // RTTI descriptors: MSVC compares by name string across images
        "??_C@", // string literals
        "??__E", "??__F", // dynamic initializer / atexit thunks
        "__real@", "__xmm@", "__ymm@", // float constants
        "_CT??", "_TI",    // EH catchable/throw info
        "__imp_", // import pointers never originate here
        "$",      // pdata/xdata labels
        ".",      // section-name-like symbols
        "@",      // @feat.00, @comp.id
    ];
    const CONTAINS: &[&str] = &["?$TSS", "@std@@"];
    const EXACT: &[&str] = &["main", "SDL_main", "WinMain", "wWinMain", "DllMain"];
    PREFIXES.iter().any(|p| name.starts_with(p))
        || CONTAINS.iter().any(|c| name.contains(c))
        || EXACT.contains(&name)
}

/// COMDAT sections whose members must not be exported: selectany duplicates
/// (inline functions, templates, vtables) exist in every image. NoDuplicates COMDATs
/// (/Gy or -ffunction-sections style) are unique definitions and stay exportable.
fn comdat_excluded_sections<'data, Coff: CoffHeader>(
    file: &CoffFile<'data, &'data [u8], Coff>,
) -> Vec<bool> {
    let max = file.sections().count() + 1;
    let mut excluded = vec![false; max + 1];
    for comdat in file.comdats() {
        if comdat.kind() == object::ComdatKind::NoDuplicates {
            continue;
        }
        for section in comdat.sections() {
            if section.0 < excluded.len() {
                excluded[section.0] = true;
            }
        }
    }
    excluded
}

fn scan_coff(
    data: &[u8],
    c_only: bool,
    args: &Args,
    exports: &mut BTreeMap<String, bool>,
    stats: &mut Stats,
) -> Result<(), object::Error> {
    // MSVC emits both classic COFF and /bigobj extended COFF objects.
    match CoffFile::<&[u8]>::parse(data) {
        Ok(file) => scan_coff_file(&file, c_only, args, exports, stats),
        Err(_) => {
            let file = CoffBigFile::parse(data)?;
            scan_coff_file(&file, c_only, args, exports, stats);
        }
    }
    Ok(())
}

fn scan_coff_file<'data, Coff: CoffHeader>(
    file: &CoffFile<'data, &'data [u8], Coff>,
    c_only: bool,
    args: &Args,
    exports: &mut BTreeMap<String, bool>,
    stats: &mut Stats,
) {
    stats.objects += 1;
    let excluded = comdat_excluded_sections(file);

    for sym in file.symbols() {
        if !sym.is_definition() || !sym.is_global() {
            continue;
        }
        let Some(section_index) = sym.section_index() else {
            continue; // absolute/common
        };
        let Ok(name) = sym.name() else { continue };
        if name.is_empty() {
            continue;
        }
        if c_only && name.starts_with('?') {
            stats.sdk_skipped_name += 1;
            continue;
        }
        if is_skip_symbol(name) || args.exclude_sym.iter().any(|p| name.starts_with(p.as_str())) {
            stats.skipped_name += 1;
            continue;
        }
        if section_index.0 < excluded.len() && excluded[section_index.0] {
            stats.skipped_comdat += 1;
            continue;
        }
        let is_code = file
            .section_by_index(SectionIndex(section_index.0))
            .map(|s| s.kind() == SectionKind::Text)
            .unwrap_or(false);
        if let Some(prev) = exports.get(name) {
            if *prev == is_code {
                log::warn!("{name} classified as both code and data");
            }
            continue;
        }
        exports.insert(name.to_string(), !is_code);
    }
}

fn scan_path(
    path: &Path,
    c_only: bool,
    args: &Args,
    exports: &mut BTreeMap<String, bool>,
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
            // Import libraries and empty members aren't COFF objects; skip quietly.
            let _ = scan_coff(member_data, c_only, args, exports, stats);
        }
        Ok(())
    } else {
        scan_coff(&data, c_only, args, exports, stats)
            .with_context(|| format!("Failed to parse object '{}'", path.display()))
    }
}

fn path_included(path: &str, includes: &[String], excludes: &[String]) -> bool {
    let p = norm(path);
    if excludes.iter().any(|e| p.contains(e.as_str())) {
        return false;
    }
    includes.is_empty() || includes.iter().any(|i| p.contains(i.as_str()))
}

pub fn run(args: Args) -> Result<()> {
    let includes = args.include.iter().map(|s| norm(s)).collect::<Vec<_>>();
    let excludes = args.exclude.iter().map(|s| norm(s)).collect::<Vec<_>>();

    let mut exports: BTreeMap<String, bool> = BTreeMap::new();
    let mut stats = Stats::default();

    let rsp = fs::read_to_string(&args.rsp)
        .with_context(|| format!("Failed to read response file '{}'", args.rsp.display()))?;
    for line in rsp.lines().flat_map(|l| l.split(';')) {
        let path = line.trim();
        if path.is_empty() {
            continue;
        }
        if norm(path).to_lowercase().ends_with(".res") {
            continue; // compiled resources ride along in $<TARGET_OBJECTS>
        }
        if !path_included(path, &includes, &excludes) {
            stats.skipped_path += 1;
            continue;
        }
        scan_path(Path::new(path), false, &args, &mut exports, &mut stats)?;
    }
    for lib in &args.sdk_lib {
        scan_path(lib, true, &args, &mut exports, &mut stats)?;
    }

    let mut def = String::from("EXPORTS\n");
    let mut data_count = 0usize;
    for (name, is_data) in &exports {
        if *is_data {
            data_count += 1;
            def.push_str(&format!("    {name} DATA\n"));
        } else {
            def.push_str(&format!("    {name}\n"));
        }
    }
    fs::write(&args.out, def)
        .with_context(|| format!("Failed to write '{}'", args.out.display()))?;

    log::info!("{} exports ({} data) from {} objects", exports.len(), data_count, stats.objects);
    log::debug!("Skipped {} selectany COMDAT symbols", stats.skipped_comdat);
    log::debug!("Skipped {} symbols by name", stats.skipped_name);
    log::debug!("Skipped {} non-C SDK symbols", stats.sdk_skipped_name);
    log::debug!("Skipped {} path-filtered objects", stats.skipped_path);

    if args.max_exports != 0 && exports.len() > args.max_exports {
        bail!("Export count {} exceeds --max-exports {}", exports.len(), args.max_exports);
    }
    Ok(())
}
