use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use argp::FromArgs;
use pdb::FallibleIterator;

use crate::util::manifest::{
    FLAG_CODE, FLAG_DATA, FLAG_DISPLAY, FLAG_INLINE_SITES, FLAG_LOCAL, ManifestInput,
    ManifestSymbol, build_manifest,
};

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Generate a symbol manifest from a linked binary.
#[argp(subcommand, name = "manifest")]
pub struct Args {
    #[argp(option)]
    /// PDB for the linked executable (Windows)
    pdb: Option<PathBuf>,
    #[argp(option)]
    /// linked ELF or Mach-O binary
    binary: Option<PathBuf>,
    #[argp(option, short = 'o')]
    /// output manifest file
    out: PathBuf,
}

pub fn run(args: Args) -> Result<()> {
    let input = match (&args.pdb, &args.binary) {
        (Some(pdb), _) => read_pdb(pdb)?,
        (None, Some(binary)) => read_binary(binary)?,
        (None, None) => bail!("Either --pdb (Windows) or --binary is required"),
    };
    let (data, entries) = build_manifest(&input)?;
    fs::write(&args.out, &data)
        .with_context(|| format!("Failed to write manifest '{}'", args.out.display()))?;
    log::debug!(
        "Wrote {} entries ({} raw records), {} bytes, build id {}",
        entries,
        input.symbols.len(),
        data.len(),
        input.build_id.iter().map(|b| format!("{b:02x}")).collect::<String>(),
    );
    Ok(())
}

/// Compiler-generated locals that are never hook or link targets
fn is_skip_symbol(name: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "ltmp",
        "l_",
        "L_",                    // assembler-local labels
        "__cxx_global_var_init", // dynamic initializer pieces
        "_GLOBAL__sub_I",        // TU initializer drivers
        "GCC_except_table",
        "__GCC_except_table",
        "__unnamed_",         // anonymous globals
        "OUTLINED_FUNCTION_", // linker/compiler outlining artifacts
        "$",                  // MSVC pdata/xdata labels
        "__imp_",             // import pointers (PDB publics carry these)
        "??_C@",
        "__real@",
        "__xmm@",
        "__ymm@", // literals/constants
    ];
    PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Mangled names whose demangling is not a plain qualified name (vtables, typeinfo,
/// thunks, guard variables, function-scope statics, Rust v0), so no display alias.
fn is_special_mangled(name: &str) -> bool {
    const PREFIXES: &[&str] =
        &["_ZTV", "_ZTI", "_ZTS", "_ZTh", "_ZTv", "_ZTc", "_ZGV", "_ZGR", "_ZGTt", "_ZZ", "_R"];
    PREFIXES.iter().any(|p| name.starts_with(p))
}

/// `Class::method`-style display name for an Itanium-mangled symbol: qualified name
/// only, no parameter list or return type. The PDB path gets the same shape for free
/// from module procedure records.
fn display_name(mangled: &str) -> Option<String> {
    if !mangled.starts_with("_Z") || is_special_mangled(mangled) {
        return None;
    }
    let options = cpp_demangle::DemangleOptions::new().no_params().no_return_type();
    let display =
        cpp_demangle::Symbol::new(mangled.as_bytes()).ok()?.demangle_with_options(&options).ok()?;
    // Rust legacy mangling also parses as Itanium; its hash-suffixed paths are noise.
    if display.is_empty() || display == mangled || is_rust_legacy(&display) {
        return None;
    }
    Some(display)
}

fn is_rust_legacy(display: &str) -> bool {
    display.rfind("::h").is_some_and(|i| {
        let tail = &display[i + 3..];
        tail.len() == 16 && tail.bytes().all(|b| b.is_ascii_hexdigit())
    })
}

/// Symbols + build id from a linked Mach-O / ELF binary's symtab.
fn read_binary(path: &Path) -> Result<ManifestInput> {
    use object::{Object, ObjectSymbol};

    let data =
        fs::read(path).with_context(|| format!("Failed to read binary '{}'", path.display()))?;
    let file = object::File::parse(&*data)
        .with_context(|| format!("Failed to parse binary '{}'", path.display()))?;

    let build_id = if let Ok(Some(uuid)) = file.mach_uuid() {
        uuid.to_vec()
    } else if let Ok(Some(id)) = file.build_id() {
        id.to_vec()
    } else {
        bail!(
            "'{}' has no Mach-O UUID or GNU build-id — cannot key the manifest to the binary",
            path.display()
        );
    };

    let is_macho = file.format() == object::BinaryFormat::MachO;
    let base = file.relative_address_base();
    let mut symbols = Vec::new();
    for sym in file.symbols() {
        if !sym.is_definition() {
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        if name.is_empty() || is_skip_symbol(name) {
            continue;
        }
        let flags = match sym.kind() {
            object::SymbolKind::Text => FLAG_CODE,
            object::SymbolKind::Data | object::SymbolKind::Unknown => FLAG_DATA,
            _ => continue,
        } | if sym.is_local() { FLAG_LOCAL } else { 0 };
        // dlsym-convention names: strip Mach-O's extra leading underscore so lookups
        // use the same spelling on every platform.
        let name = if is_macho { name.strip_prefix('_').unwrap_or(name) } else { name };
        let rva = sym.address().wrapping_sub(base);
        if let Some(display) = display_name(name) {
            symbols.push(ManifestSymbol { name: display, rva, flags: flags | FLAG_DISPLAY });
        }
        symbols.push(ManifestSymbol { name: name.to_string(), rva, flags });
    }
    Ok(ManifestInput { build_id, symbols })
}

/// Symbols + build id from a PDB: publics (linkable surface) plus per-module
/// procedure/data records (statics).
fn read_pdb(path: &Path) -> Result<ManifestInput> {
    let file =
        fs::File::open(path).with_context(|| format!("Failed to open PDB '{}'", path.display()))?;
    let mut pdb = pdb::PDB::open(file)
        .with_context(|| format!("Failed to parse PDB '{}'", path.display()))?;
    let info = pdb.pdb_information()?;
    let dbi = pdb.debug_information()?;
    let age = dbi.age().unwrap_or(info.age);
    let mut build_id = Vec::with_capacity(20);
    build_id.extend_from_slice(info.guid.as_bytes());
    build_id.extend_from_slice(&age.to_le_bytes());

    let address_map = pdb.address_map()?;
    let mut symbols = Vec::new();

    let globals = pdb.global_symbols()?;
    let mut iter = globals.iter();
    while let Some(symbol) = iter.next()? {
        let Ok(data) = symbol.parse() else { continue };
        if let pdb::SymbolData::Public(public) = data {
            let Some(rva) = public.offset.to_rva(&address_map) else { continue };
            let name = public.name.to_string().into_owned();
            if is_skip_symbol(&name) {
                continue;
            }
            let flags = if public.function { FLAG_CODE } else { FLAG_DATA };
            symbols.push(ManifestSymbol { name, rva: u64::from(rva.0), flags });
        }
    }

    let inlined_names = collect_inlined_names(&mut pdb).unwrap_or_else(|e| {
        log::warn!("Inlinee scan unavailable ({e}); no inline-site flags");
        Default::default()
    });

    let mut modules = dbi.modules()?;
    while let Some(module) = modules.next()? {
        let Some(module_info) = pdb.module_info(&module)? else {
            continue;
        };
        let mut sym_iter = module_info.symbols()?;
        while let Some(symbol) = sym_iter.next()? {
            let Ok(data) = symbol.parse() else { continue };
            let (name, offset, flags) = match data {
                pdb::SymbolData::Procedure(proc) => {
                    let local = if proc.global { 0 } else { FLAG_LOCAL };
                    (proc.name, proc.offset, FLAG_CODE | local)
                }
                pdb::SymbolData::Data(data_sym) => {
                    let local = if data_sym.global { 0 } else { FLAG_LOCAL };
                    (data_sym.name, data_sym.offset, FLAG_DATA | local)
                }
                _ => continue,
            };
            let Some(rva) = offset.to_rva(&address_map) else { continue };
            if rva.0 == 0 {
                continue; // stripped/discarded contribution
            }
            let name = name.to_string().into_owned();
            if is_skip_symbol(&name) {
                continue;
            }
            let mut flags = flags;
            if flags & FLAG_CODE != 0 && inlined_names.contains(&name) {
                flags |= FLAG_INLINE_SITES;
            }
            symbols.push(ManifestSymbol { name, rva: u64::from(rva.0), flags });
        }
    }

    // Propagate the inline-site flag across every code record at the same RVA, so the
    // decorated public alias of a flagged procedure carries it too.
    let flagged_rvas: HashSet<u64> =
        symbols.iter().filter(|s| s.flags & FLAG_INLINE_SITES != 0).map(|s| s.rva).collect();
    let mut flagged_count = 0usize;
    for sym in &mut symbols {
        if sym.flags & FLAG_CODE != 0 && flagged_rvas.contains(&sym.rva) {
            sym.flags |= FLAG_INLINE_SITES;
            flagged_count += 1;
        }
    }
    if !flagged_rvas.is_empty() {
        log::debug!(
            "{} functions have inline sites ({} records flagged)",
            flagged_rvas.len(),
            flagged_count
        );
    }

    Ok(ManifestInput { build_id, symbols })
}

/// Qualified names of every function that appears as an inlinee somewhere in the PDB.
fn collect_inlined_names(pdb: &mut pdb::PDB<'_, fs::File>) -> Result<HashSet<String>> {
    // TPI: class/struct names for member-function parents.
    let type_information = pdb.type_information()?;
    let mut class_names: HashMap<u32, String> = HashMap::new();
    let mut type_iter = type_information.iter();
    while let Some(item) = type_iter.next()? {
        if let Ok(pdb::TypeData::Class(class)) = item.parse() {
            class_names.insert(item.index().0, class.name.to_string().into_owned());
        }
    }

    // IPI: function ids (bare name + scope/parent) and scope strings.
    struct FnId {
        name: String,
        scope: Option<u32>,        // IdIndex of a StringId ("ns" / "ns::ns2")
        parent_class: Option<u32>, // TypeIndex of the owning class
    }
    let id_information = pdb.id_information()?;
    let mut fn_ids: HashMap<u32, FnId> = HashMap::new();
    let mut scope_strings: HashMap<u32, String> = HashMap::new();
    let mut id_iter = id_information.iter();
    while let Some(item) = id_iter.next()? {
        let Ok(data) = item.parse() else { continue };
        match data {
            pdb::IdData::Function(f) => {
                fn_ids.insert(item.index().0, FnId {
                    name: f.name.to_string().into_owned(),
                    scope: f.scope.map(|s| s.0),
                    parent_class: None,
                });
            }
            pdb::IdData::MemberFunction(m) => {
                fn_ids.insert(item.index().0, FnId {
                    name: m.name.to_string().into_owned(),
                    scope: None,
                    parent_class: Some(m.parent.0),
                });
            }
            pdb::IdData::String(s) => {
                scope_strings.insert(item.index().0, s.name.to_string().into_owned());
            }
            _ => {}
        }
    }

    let dbi = pdb.debug_information()?;
    let mut names = HashSet::new();
    let mut modules = dbi.modules()?;
    while let Some(module) = modules.next()? {
        let Some(module_info) = pdb.module_info(&module)? else {
            continue;
        };
        let Ok(mut inlinees) = module_info.inlinees() else { continue };
        while let Ok(Some(inlinee)) = inlinees.next() {
            let Some(f) = fn_ids.get(&inlinee.index().0) else { continue };
            let qualified = if let Some(parent) = f.parent_class {
                match class_names.get(&parent) {
                    Some(class) => format!("{}::{}", class, f.name),
                    None => f.name.clone(),
                }
            } else if let Some(scope) = f.scope {
                match scope_strings.get(&scope) {
                    Some(s) => format!("{}::{}", s, f.name),
                    None => f.name.clone(),
                }
            } else {
                f.name.clone()
            };
            names.insert(qualified);
        }
    }
    Ok(names)
}
