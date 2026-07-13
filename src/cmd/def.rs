use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use argp::FromArgs;
use object::{
    FileKind, Object, ObjectComdat, ObjectSection, ObjectSymbol, SectionIndex, SectionKind, pe,
    read::{
        archive::ArchiveFile,
        coff::{CoffFile, CoffHeader},
    },
};

use crate::util::file::process_rsp;

type CoffBigFile<'data> = CoffFile<'data, &'data [u8], pe::AnonObjectHeaderBigobj>;

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Generate a curated .def of exportable symbols from built COFF objects.
#[argp(subcommand, name = "def")]
pub struct Args {
    #[argp(positional)]
    /// objects and archives to scan; prefix a response file with @
    inputs: Vec<String>,
    #[argp(option, short = 'o')]
    /// output .def file
    out: PathBuf,
    #[argp(option)]
    /// static library to scan for C-only (unmangled) exports; repeatable
    sdk_lib: Vec<PathBuf>,
    #[argp(option)]
    /// PE DLL whose named exports should be re-exported as forwarders; repeatable
    forward_dll: Vec<PathBuf>,
    #[argp(option)]
    /// only forward DLL exports with this symbol prefix; repeatable
    forward_sym_prefix: Vec<String>,
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

fn scan_forward_dll(
    path: &Path,
    prefixes: &[String],
    args: &Args,
    forwarders: &mut BTreeMap<String, String>,
) -> Result<()> {
    let data = fs::read(path)
        .with_context(|| format!("Failed to read forward DLL '{}'", path.display()))?;
    let kind = FileKind::parse(&*data)
        .with_context(|| format!("Failed to identify forward DLL '{}'", path.display()))?;
    if !matches!(kind, FileKind::Pe32 | FileKind::Pe64) {
        bail!("Forward DLL '{}' is not a PE image", path.display());
    }

    let file = object::File::parse(&*data)
        .with_context(|| format!("Failed to parse forward DLL '{}'", path.display()))?;
    let module =
        path.file_stem().and_then(|s| s.to_str()).filter(|s| !s.is_empty()).with_context(|| {
            format!("Forward DLL has no valid module name: '{}'", path.display())
        })?;

    for export in file
        .exports()
        .with_context(|| format!("Failed to read exports from forward DLL '{}'", path.display()))?
    {
        let name = std::str::from_utf8(export.name())
            .with_context(|| format!("Forward DLL '{}' has a non-UTF-8 export", path.display()))?;
        if name.is_empty()
            || (!prefixes.is_empty() && !prefixes.iter().any(|p| name.starts_with(p.as_str())))
            || is_skip_symbol(name)
            || args.exclude_sym.iter().any(|p| name.starts_with(p.as_str()))
        {
            continue;
        }

        let target = format!("{module}.{name}");
        if let Some(existing) = forwarders.get(name) {
            if existing != &target {
                bail!("Forward export '{name}' has conflicting targets: {existing} and {target}");
            }
        } else {
            forwarders.insert(name.to_string(), target);
        }
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum DefExport {
    Local { data: bool },
    Forward { target: String },
}

fn render_def(
    exports: &BTreeMap<String, bool>,
    forwarders: &BTreeMap<String, String>,
) -> Result<String> {
    let mut combined = BTreeMap::new();
    for (name, is_data) in exports {
        combined.insert(name, DefExport::Local { data: *is_data });
    }
    for (name, target) in forwarders {
        if combined.insert(name, DefExport::Forward { target: target.clone() }).is_some() {
            bail!("Forward export '{name}' conflicts with a local export");
        }
    }

    let mut def = String::from("EXPORTS\n");
    for (name, export) in combined {
        match export {
            DefExport::Local { data: true } => def.push_str(&format!("    {name} DATA\n")),
            DefExport::Local { data: false } => def.push_str(&format!("    {name}\n")),
            DefExport::Forward { target } => def.push_str(&format!("    {name}={target}\n")),
        }
    }
    Ok(def)
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

    let inputs = process_rsp(&args.inputs)?;
    if inputs.is_empty() {
        bail!("At least one input object or archive is required");
    }
    for path in &inputs {
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
    let mut forwarders = BTreeMap::new();
    for dll in &args.forward_dll {
        scan_forward_dll(dll, &args.forward_sym_prefix, &args, &mut forwarders)?;
    }

    let def = render_def(&exports, &forwarders)?;
    let data_count = exports.values().filter(|is_data| **is_data).count();
    fs::write(&args.out, def)
        .with_context(|| format!("Failed to write '{}'", args.out.display()))?;

    let export_count = exports.len() + forwarders.len();
    log::info!(
        "{} exports ({} data, {} forwarded) from {} objects",
        export_count,
        data_count,
        forwarders.len(),
        stats.objects
    );
    log::debug!("Skipped {} selectany COMDAT symbols", stats.skipped_comdat);
    log::debug!("Skipped {} symbols by name", stats.skipped_name);
    log::debug!("Skipped {} non-C SDK symbols", stats.sdk_skipped_name);
    log::debug!("Skipped {} path-filtered objects", stats.skipped_path);

    if args.max_exports != 0 && export_count > args.max_exports {
        bail!("Export count {} exceeds --max-exports {}", export_count, args.max_exports);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_forwarded_exports_in_name_order() {
        let exports = BTreeMap::from([
            ("local_data".to_string(), true),
            ("local_function".to_string(), false),
        ]);
        let forwarders = BTreeMap::from([(
            "wgpuDeviceCreateBuffer".to_string(),
            "webgpu_dawn.wgpuDeviceCreateBuffer".to_string(),
        )]);

        assert_eq!(
            render_def(&exports, &forwarders).unwrap(),
            "EXPORTS\n    local_data DATA\n    local_function\n    wgpuDeviceCreateBuffer=webgpu_dawn.wgpuDeviceCreateBuffer\n"
        );
    }

    #[test]
    fn rejects_local_and_forwarded_name_collision() {
        let exports = BTreeMap::from([("same".to_string(), false)]);
        let forwarders = BTreeMap::from([("same".to_string(), "provider.same".to_string())]);

        assert!(render_def(&exports, &forwarders).is_err());
    }
}
