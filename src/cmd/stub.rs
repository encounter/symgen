use std::{fs, io::Cursor, path::PathBuf, str::FromStr};

use anyhow::{Context, Result, bail};
use argp::{FromArgValue, FromArgs};
use implib::{Flavor, ImportLibrary, MachineType, def::ModuleDef};
use object::{elf as elf_import, macho, pod::bytes_of};

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Generate a link stub (import library, stub Mach-O executable, or stub ELF
/// shared object) from an export surface.
#[argp(subcommand, name = "stub")]
pub struct Args {
    #[argp(positional)]
    /// input export surface: a .def (implib), an .exp symbol list
    /// (macho/elf), or a built ELF shared object whose dynamic symbols to
    /// mirror (elf)
    input: PathBuf,
    #[argp(option, short = 'o')]
    /// output file
    out: PathBuf,
    #[argp(option, short = 'f')]
    /// output format: implib (COFF short import library), macho (stub
    /// MH_EXECUTE for -bundle_loader), or elf (stub shared object)
    format: Format,
    #[argp(option)]
    /// implib: module name imports bind to (default: LIBRARY line in the .def)
    dll_name: Option<String>,
    #[argp(option)]
    /// elf: DT_SONAME for the stub (e.g. libmain.so); DT_NEEDED entries in
    /// consumers record this name
    soname: Option<String>,
    #[argp(option)]
    /// architecture: arm64 or x86_64/amd64; repeatable for macho to produce a
    /// universal binary (default: x86_64 for implib/elf, platform-dependent
    /// for macho)
    arch: Vec<Arch>,
    #[argp(option, default = "Platform::MacOS")]
    /// macho: platform: macos, ios, or tvos (default: macos)
    platform: Platform,
    #[argp(option, default = "String::from(\"11.0\")")]
    /// macho: minimum OS version (default: 11.0)
    min_os: String,
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum Format {
    Implib,
    Macho,
    Elf,
}

impl FromArgValue for Format {
    fn from_arg_value(value: &std::ffi::OsStr) -> Result<Self, String> {
        String::from_arg_value(value).and_then(|s| s.parse())
    }
}

impl FromStr for Format {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "implib" => Ok(Self::Implib),
            "macho" => Ok(Self::Macho),
            "elf" => Ok(Self::Elf),
            _ => Err(format!("Unknown format '{s}' (expected implib, macho, or elf)")),
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum Arch {
    Arm64,
    X86_64,
}

impl FromArgValue for Arch {
    fn from_arg_value(value: &std::ffi::OsStr) -> Result<Self, String> {
        String::from_arg_value(value).and_then(|s| s.parse())
    }
}

impl FromStr for Arch {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "arm64" | "aarch64" => Ok(Self::Arm64),
            "amd64" | "x86_64" | "x86-64" => Ok(Self::X86_64),
            _ => Err(format!("Unknown arch '{s}' (expected arm64 or x86_64)")),
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum Platform {
    MacOS,
    Ios,
    TvOS,
}

impl FromArgValue for Platform {
    fn from_arg_value(value: &std::ffi::OsStr) -> Result<Self, String> {
        String::from_arg_value(value).and_then(|s| s.parse())
    }
}

impl FromStr for Platform {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "macos" => Ok(Self::MacOS),
            "ios" => Ok(Self::Ios),
            "tvos" => Ok(Self::TvOS),
            _ => Err(format!("Unknown platform '{s}' (expected macos, ios, or tvos)")),
        }
    }
}

fn is_def(text: &str) -> bool {
    text.lines().map(str::trim).any(|l| {
        let upper = l.to_ascii_uppercase();
        upper == "EXPORTS" || upper.starts_with("LIBRARY ") || upper.starts_with("EXPORTS ")
    })
}

fn single_arch(format: Format, arches: &[Arch]) -> Result<Arch> {
    if arches.len() > 1 {
        let format = match format {
            Format::Implib => "implib",
            Format::Macho => "macho",
            Format::Elf => "elf",
        };
        bail!("{format} only supports one --arch");
    }
    Ok(arches.first().copied().unwrap_or(Arch::X86_64))
}

pub fn run(args: Args) -> Result<()> {
    if args.format != Format::Macho {
        single_arch(args.format, &args.arch)?;
    }
    let data = fs::read(&args.input)
        .with_context(|| format!("Failed to read '{}'", args.input.display()))?;
    if args.format == Format::Elf && data.starts_with(&elf_import::ELFMAG) {
        let symbols = elf_dynamic_symbols(&args, &data)?;
        let symbols = symbols.iter().map(String::as_str).collect::<Vec<_>>();
        return write_elf(&args, &symbols);
    }
    let text = String::from_utf8(data)
        .with_context(|| format!("'{}' is not a text export surface", args.input.display()))?;
    match args.format {
        Format::Implib => write_implib(&args, &text),
        Format::Macho => write_macho(&args, &text),
        Format::Elf => {
            let symbols = parse_symbol_list(&args, &text)?;
            write_elf(&args, &symbols)
        }
    }
}

/// Mirror a built shared object's defined dynamic symbols (stubify-style).
fn elf_dynamic_symbols(args: &Args, data: &[u8]) -> Result<Vec<String>> {
    use object::{Object, ObjectSymbol};

    let file = object::File::parse(data)
        .with_context(|| format!("Failed to parse ELF '{}'", args.input.display()))?;
    let mut symbols = file
        .dynamic_symbols()
        .filter(|s| !s.is_undefined() && s.is_global())
        .filter_map(|s| s.name().ok())
        .filter(|n| !n.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    symbols.sort_unstable();
    symbols.dedup();
    if symbols.is_empty() {
        bail!("No dynamic symbols in '{}'", args.input.display());
    }
    Ok(symbols)
}

fn write_implib(args: &Args, text: &str) -> Result<()> {
    if !is_def(text) {
        bail!("implib requires a .def input (symbol lists carry no DATA/forward annotations)");
    }
    let machine = match single_arch(args.format, &args.arch)? {
        Arch::X86_64 => MachineType::AMD64,
        Arch::Arm64 => MachineType::ARM64,
    };
    // Imports don't care where the module forwards an export to, and implib's
    // parser emits members for both sides of "name=target" — keep only the name.
    let text = text
        .lines()
        .map(|l| l.split_once('=').map_or(l, |(name, _)| name))
        .collect::<Vec<_>>()
        .join("\n");
    let mut def = ModuleDef::parse(&text, machine)
        .with_context(|| format!("Failed to parse .def '{}'", args.input.display()))?;
    if let Some(dll_name) = &args.dll_name {
        def.import_name = dll_name.clone();
    }
    if def.import_name.is_empty() {
        bail!("No module name: pass --dll-name or add a LIBRARY line to the .def");
    }
    let export_count = def.exports.len();
    let lib = ImportLibrary::from_def(def, machine, Flavor::Msvc);
    let mut out = Cursor::new(Vec::new());
    lib.write_to(&mut out).context("Failed to generate import library")?;
    fs::write(&args.out, out.into_inner())
        .with_context(|| format!("Failed to write '{}'", args.out.display()))?;
    log::info!("{} imports -> {}", export_count, args.out.display());
    Ok(())
}

fn parse_symbol_list<'text>(args: &Args, text: &'text str) -> Result<Vec<&'text str>> {
    if is_def(text) {
        bail!("This format requires a symbol list (PE-decorated .def names are meaningless here)");
    }
    let mut symbols = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect::<Vec<_>>();
    symbols.sort_unstable();
    symbols.dedup();
    if symbols.is_empty() {
        bail!("No symbols in '{}'", args.input.display());
    }
    Ok(symbols)
}

fn write_macho(args: &Args, text: &str) -> Result<()> {
    let symbols = parse_symbol_list(args, text)?;
    let trie = export_trie(&symbols);

    let min_os = parse_version(&args.min_os)?;
    let platform = match args.platform {
        Platform::MacOS => macho::PLATFORM_MACOS,
        Platform::Ios => macho::PLATFORM_IOS,
        Platform::TvOS => macho::PLATFORM_TVOS,
    };
    let arches = if args.arch.is_empty() {
        match args.platform {
            // Only macOS ships x86_64; embedded platforms are arm64-only.
            Platform::MacOS => vec![Arch::Arm64, Arch::X86_64],
            _ => vec![Arch::Arm64],
        }
    } else {
        args.arch.clone()
    };

    let (symtab, strtab) = symbol_table(&symbols);
    let slices = arches
        .iter()
        .map(|&arch| macho_slice(arch, platform, min_os, &trie, &symtab, &strtab))
        .collect::<Vec<_>>();
    let data = if slices.len() == 1 {
        slices.into_iter().next().unwrap()
    } else {
        fat_binary(&arches, slices)
    };
    fs::write(&args.out, data)
        .with_context(|| format!("Failed to write '{}'", args.out.display()))?;
    log::info!("{} exports, {} arch(es) -> {}", symbols.len(), arches.len(), args.out.display());
    Ok(())
}

/// Stub ELF shared object: SONAME + defined dynamic symbols, no code. Linkers
/// resolve consumers' undefined symbols against it and record a DT_NEEDED on
/// the SONAME; the real library satisfies the binds at runtime.
fn write_elf(args: &Args, symbols: &[&str]) -> Result<()> {
    use object::{U16, U32, U64, elf, endian::LittleEndian as LE};

    let Some(soname) = &args.soname else {
        bail!("elf requires --soname (e.g. libmain.so)");
    };
    let e_machine = match single_arch(args.format, &args.arch)? {
        Arch::X86_64 => elf::EM_X86_64,
        Arch::Arm64 => elf::EM_AARCH64,
    };

    const EHDR_SIZE: u64 = size_of::<elf::FileHeader64<LE>>() as u64;
    const PHENT: u64 = size_of::<elf::ProgramHeader64<LE>>() as u64;
    const SHENT: u64 = size_of::<elf::SectionHeader64<LE>>() as u64;
    const SYMENT: u64 = size_of::<elf::Sym64<LE>>() as u64;
    const DYNENT: u64 = size_of::<elf::Dyn64<LE>>() as u64;

    let mut dynstr = vec![0u8];
    let strx = |name: &str, dynstr: &mut Vec<u8>| -> u32 {
        let offset = dynstr.len() as u32;
        dynstr.extend_from_slice(name.as_bytes());
        dynstr.push(0);
        offset
    };

    let mut dynsym = Vec::new();
    dynsym.extend_from_slice(&[0u8; size_of::<elf::Sym64<LE>>()]);
    for name in symbols {
        let sym = elf::Sym64::<LE> {
            st_name: U32::new(LE, strx(name, &mut dynstr)),
            st_info: (elf::STB_GLOBAL << 4) | elf::STT_FUNC,
            st_other: elf::STV_DEFAULT,
            st_shndx: U16::new(LE, elf::SHN_ABS),
            st_value: U64::new(LE, 0),
            st_size: U64::new(LE, 0),
        };
        dynsym.extend_from_slice(bytes_of(&sym));
    }
    let soname_strx = strx(soname, &mut dynstr);

    // Single R PT_LOAD at vaddr 0 keeps every virtual address equal to its
    // file offset.
    let phoff = EHDR_SIZE;
    let dynsym_off = (phoff + 2 * PHENT).next_multiple_of(8);
    let dynstr_off = dynsym_off + dynsym.len() as u64;
    let dyn_off = (dynstr_off + dynstr.len() as u64).next_multiple_of(8);

    let dyn_entry = |tag: i64, val: u64| elf::Dyn64::<LE> {
        d_tag: object::I64::new(LE, tag),
        d_val: U64::new(LE, val),
    };
    let dyns = [
        dyn_entry(elf::DT_SONAME, soname_strx.into()),
        dyn_entry(elf::DT_SYMTAB, dynsym_off),
        dyn_entry(elf::DT_SYMENT, SYMENT),
        dyn_entry(elf::DT_STRTAB, dynstr_off),
        dyn_entry(elf::DT_STRSZ, dynstr.len() as u64),
        dyn_entry(elf::DT_NULL, 0),
    ];
    let dyn_size = dyns.len() as u64 * DYNENT;

    let shstrtab = b"\0.dynsym\0.dynstr\0.dynamic\0.shstrtab\0";
    let shstrtab_off = dyn_off + dyn_size;
    let shoff = (shstrtab_off + shstrtab.len() as u64).next_multiple_of(8);
    let alloc_size = shstrtab_off; // everything before .shstrtab is SHF_ALLOC

    let ehdr = elf::FileHeader64::<LE> {
        e_ident: elf::Ident {
            magic: elf::ELFMAG,
            class: elf::ELFCLASS64,
            data: elf::ELFDATA2LSB,
            version: elf::EV_CURRENT,
            os_abi: elf::ELFOSABI_NONE,
            abi_version: 0,
            padding: [0; 7],
        },
        e_type: U16::new(LE, elf::ET_DYN),
        e_machine: U16::new(LE, e_machine),
        e_version: U32::new(LE, elf::EV_CURRENT.into()),
        e_entry: U64::new(LE, 0),
        e_phoff: U64::new(LE, phoff),
        e_shoff: U64::new(LE, shoff),
        e_flags: U32::new(LE, 0),
        e_ehsize: U16::new(LE, EHDR_SIZE as u16),
        e_phentsize: U16::new(LE, PHENT as u16),
        e_phnum: U16::new(LE, 2),
        e_shentsize: U16::new(LE, SHENT as u16),
        e_shnum: U16::new(LE, 5),
        e_shstrndx: U16::new(LE, 4),
    };

    let phdr = |p_type: u32, offset: u64, size: u64, align: u64| elf::ProgramHeader64::<LE> {
        p_type: U32::new(LE, p_type),
        p_flags: U32::new(LE, elf::PF_R),
        p_offset: U64::new(LE, offset),
        p_vaddr: U64::new(LE, offset),
        p_paddr: U64::new(LE, offset),
        p_filesz: U64::new(LE, size),
        p_memsz: U64::new(LE, size),
        p_align: U64::new(LE, align),
    };
    let phdrs =
        [phdr(elf::PT_LOAD, 0, alloc_size, 0x1000), phdr(elf::PT_DYNAMIC, dyn_off, dyn_size, 8)];

    let shdr = |name: u32,
                sh_type: u32,
                flags: u64,
                offset: u64,
                size: u64,
                link: u32,
                info: u32,
                align: u64,
                entsize: u64,
                alloc: bool| {
        elf::SectionHeader64::<LE> {
            sh_name: U32::new(LE, name),
            sh_type: U32::new(LE, sh_type),
            sh_flags: U64::new(LE, flags),
            sh_addr: U64::new(LE, if alloc { offset } else { 0 }),
            sh_offset: U64::new(LE, offset),
            sh_size: U64::new(LE, size),
            sh_link: U32::new(LE, link),
            sh_info: U32::new(LE, info),
            sh_addralign: U64::new(LE, align),
            sh_entsize: U64::new(LE, entsize),
        }
    };
    let shdrs = [
        shdr(0, elf::SHT_NULL, 0, 0, 0, 0, 0, 0, 0, false),
        shdr(
            1,
            elf::SHT_DYNSYM,
            elf::SHF_ALLOC.into(),
            dynsym_off,
            dynsym.len() as u64,
            2,
            1,
            8,
            SYMENT,
            true,
        ),
        shdr(
            9,
            elf::SHT_STRTAB,
            elf::SHF_ALLOC.into(),
            dynstr_off,
            dynstr.len() as u64,
            0,
            0,
            1,
            0,
            true,
        ),
        shdr(
            17,
            elf::SHT_DYNAMIC,
            (elf::SHF_ALLOC | elf::SHF_WRITE).into(),
            dyn_off,
            dyn_size,
            2,
            0,
            8,
            DYNENT,
            true,
        ),
        shdr(26, elf::SHT_STRTAB, 0, shstrtab_off, shstrtab.len() as u64, 0, 0, 1, 0, false),
    ];

    let mut data = Vec::with_capacity(shoff as usize + shdrs.len() * SHENT as usize);
    data.extend_from_slice(bytes_of(&ehdr));
    for ph in &phdrs {
        data.extend_from_slice(bytes_of(ph));
    }
    data.resize(dynsym_off as usize, 0);
    data.extend_from_slice(&dynsym);
    data.extend_from_slice(&dynstr);
    data.resize(dyn_off as usize, 0);
    for d in &dyns {
        data.extend_from_slice(bytes_of(d));
    }
    data.extend_from_slice(shstrtab);
    data.resize(shoff as usize, 0);
    for sh in &shdrs {
        data.extend_from_slice(bytes_of(sh));
    }
    fs::write(&args.out, data)
        .with_context(|| format!("Failed to write '{}'", args.out.display()))?;
    log::info!("{} exports -> {}", symbols.len(), args.out.display());
    Ok(())
}

fn parse_version(s: &str) -> Result<u32> {
    let mut parts = s.split('.').map(|p| p.parse::<u32>());
    let major = parts.next().transpose().ok().flatten();
    let minor = parts.next().transpose().ok().flatten().or(Some(0));
    let patch = parts.next().transpose().ok().flatten().or(Some(0));
    match (major, minor, patch) {
        (Some(maj), Some(min), Some(pat)) if maj <= 0xFFFF && min <= 0xFF && pat <= 0xFF => {
            Ok((maj << 16) | (min << 8) | pat)
        }
        _ => bail!("Invalid version '{s}' (expected e.g. 11.0)"),
    }
}

const PAGE_SIZE: u64 = 0x4000;
const TEXT_VMADDR: u64 = 0x1_0000_0000;

/// Absolute external symbols mirroring the export trie: ld-classic reads a
/// bundle_loader executable's exports from LC_SYMTAB, not the trie.
fn symbol_table(symbols: &[&str]) -> (Vec<u8>, Vec<u8>) {
    use object::LittleEndian as LE;

    let mut symtab = Vec::with_capacity(symbols.len() * size_of::<macho::Nlist64<LE>>());
    let mut strtab = vec![0u8]; // index 0 = empty name
    for name in symbols {
        let nlist = macho::Nlist64::<LE> {
            n_strx: object::U32::new(LE, strtab.len() as u32),
            n_type: macho::N_ABS | macho::N_EXT,
            n_sect: macho::NO_SECT,
            n_desc: object::U16::new(LE, 0),
            n_value: object::U64::new(LE, TEXT_VMADDR),
        };
        symtab.extend_from_slice(bytes_of(&nlist));
        strtab.extend_from_slice(name.as_bytes());
        strtab.push(0);
    }
    (symtab, strtab)
}

/// Minimal MH_EXECUTE: no code, just export info for the linker to read via
/// -bundle_loader. dyld never loads it. LC_MAIN and LC_SYMTAB exist only
/// because ld-prime and ld-classic respectively refuse executables without them.
fn macho_slice(
    arch: Arch,
    platform: u32,
    min_os: u32,
    trie: &[u8],
    symtab: &[u8],
    strtab: &[u8],
) -> Vec<u8> {
    use object::LittleEndian as LE;

    let (cputype, cpusubtype) = match arch {
        Arch::Arm64 => (macho::CPU_TYPE_ARM64, macho::CPU_SUBTYPE_ARM64_ALL),
        Arch::X86_64 => (macho::CPU_TYPE_X86_64, macho::CPU_SUBTYPE_X86_64_ALL),
    };
    let ncmds = 7u32;
    let sizeofcmds = (2 * size_of::<macho::SegmentCommand64<LE>>()
        + size_of::<macho::LinkeditDataCommand<LE>>()
        + size_of::<macho::SymtabCommand<LE>>()
        + size_of::<macho::DysymtabCommand<LE>>()
        + size_of::<macho::EntryPointCommand<LE>>()
        + size_of::<macho::BuildVersionCommand<LE>>()) as u32;

    let linkedit_fileoff = PAGE_SIZE;
    let symtab_off = (linkedit_fileoff + trie.len() as u64).next_multiple_of(8);
    let strtab_off = symtab_off + symtab.len() as u64;
    let linkedit_size = strtab_off + strtab.len() as u64 - linkedit_fileoff;

    let header = macho::MachHeader64::<LE> {
        // The magic field is declared big-endian; a little-endian image reads as CIGAM.
        magic: object::U32::new(object::BigEndian, macho::MH_CIGAM_64),
        cputype: object::U32::new(LE, cputype),
        cpusubtype: object::U32::new(LE, cpusubtype),
        filetype: object::U32::new(LE, macho::MH_EXECUTE),
        ncmds: object::U32::new(LE, ncmds),
        sizeofcmds: object::U32::new(LE, sizeofcmds),
        flags: object::U32::new(
            LE,
            macho::MH_NOUNDEFS | macho::MH_DYLDLINK | macho::MH_TWOLEVEL | macho::MH_PIE,
        ),
        reserved: object::U32::new(LE, 0),
    };

    let seg = |name: &[u8], vmaddr: u64, vmsize: u64, fileoff: u64, filesize: u64, prot: u32| {
        let mut segname = [0u8; 16];
        segname[..name.len()].copy_from_slice(name);
        macho::SegmentCommand64::<LE> {
            cmd: object::U32::new(LE, macho::LC_SEGMENT_64),
            cmdsize: object::U32::new(LE, size_of::<macho::SegmentCommand64<LE>>() as u32),
            segname,
            vmaddr: object::U64::new(LE, vmaddr),
            vmsize: object::U64::new(LE, vmsize),
            fileoff: object::U64::new(LE, fileoff),
            filesize: object::U64::new(LE, filesize),
            maxprot: object::U32::new(LE, prot),
            initprot: object::U32::new(LE, prot),
            nsects: object::U32::new(LE, 0),
            flags: object::U32::new(LE, 0),
        }
    };
    const PROT_RX: u32 = 0x1 | 0x4; // VM_PROT_READ | VM_PROT_EXECUTE
    const PROT_R: u32 = 0x1;
    let text = seg(b"__TEXT", TEXT_VMADDR, PAGE_SIZE, 0, PAGE_SIZE, PROT_RX);
    let linkedit = seg(
        b"__LINKEDIT",
        TEXT_VMADDR + PAGE_SIZE,
        linkedit_size.next_multiple_of(PAGE_SIZE),
        linkedit_fileoff,
        linkedit_size,
        PROT_R,
    );
    let exports_trie = macho::LinkeditDataCommand::<LE> {
        cmd: object::U32::new(LE, macho::LC_DYLD_EXPORTS_TRIE),
        cmdsize: object::U32::new(LE, size_of::<macho::LinkeditDataCommand<LE>>() as u32),
        dataoff: object::U32::new(LE, linkedit_fileoff as u32),
        datasize: object::U32::new(LE, trie.len() as u32),
    };
    let nsyms = (symtab.len() / size_of::<macho::Nlist64<LE>>()) as u32;
    let symtab_cmd = macho::SymtabCommand::<LE> {
        cmd: object::U32::new(LE, macho::LC_SYMTAB),
        cmdsize: object::U32::new(LE, size_of::<macho::SymtabCommand<LE>>() as u32),
        symoff: object::U32::new(LE, symtab_off as u32),
        nsyms: object::U32::new(LE, nsyms),
        stroff: object::U32::new(LE, strtab_off as u32),
        strsize: object::U32::new(LE, strtab.len() as u32),
    };
    let zero = object::U32::new(LE, 0);
    let dysymtab_cmd = macho::DysymtabCommand::<LE> {
        cmd: object::U32::new(LE, macho::LC_DYSYMTAB),
        cmdsize: object::U32::new(LE, size_of::<macho::DysymtabCommand<LE>>() as u32),
        ilocalsym: zero,
        nlocalsym: zero,
        iextdefsym: zero,
        nextdefsym: object::U32::new(LE, nsyms),
        iundefsym: object::U32::new(LE, nsyms),
        nundefsym: zero,
        tocoff: zero,
        ntoc: zero,
        modtaboff: zero,
        nmodtab: zero,
        extrefsymoff: zero,
        nextrefsyms: zero,
        indirectsymoff: zero,
        nindirectsyms: zero,
        extreloff: zero,
        nextrel: zero,
        locreloff: zero,
        nlocrel: zero,
    };
    let main_cmd = macho::EntryPointCommand::<LE> {
        cmd: object::U32::new(LE, macho::LC_MAIN),
        cmdsize: object::U32::new(LE, size_of::<macho::EntryPointCommand<LE>>() as u32),
        entryoff: object::U64::new(LE, 0x1000),
        stacksize: object::U64::new(LE, 0),
    };
    let build_version = macho::BuildVersionCommand::<LE> {
        cmd: object::U32::new(LE, macho::LC_BUILD_VERSION),
        cmdsize: object::U32::new(LE, size_of::<macho::BuildVersionCommand<LE>>() as u32),
        platform: object::U32::new(LE, platform),
        minos: object::U32::new(LE, min_os),
        sdk: object::U32::new(LE, min_os),
        ntools: object::U32::new(LE, 0),
    };

    let mut data = Vec::with_capacity((linkedit_fileoff + linkedit_size) as usize);
    data.extend_from_slice(bytes_of(&header));
    data.extend_from_slice(bytes_of(&text));
    data.extend_from_slice(bytes_of(&linkedit));
    data.extend_from_slice(bytes_of(&exports_trie));
    data.extend_from_slice(bytes_of(&symtab_cmd));
    data.extend_from_slice(bytes_of(&dysymtab_cmd));
    data.extend_from_slice(bytes_of(&main_cmd));
    data.extend_from_slice(bytes_of(&build_version));
    data.resize(linkedit_fileoff as usize, 0);
    data.extend_from_slice(trie);
    data.resize(symtab_off as usize, 0);
    data.extend_from_slice(symtab);
    data.extend_from_slice(strtab);
    data
}

fn fat_binary(arches: &[Arch], slices: Vec<Vec<u8>>) -> Vec<u8> {
    use object::BigEndian as BE;

    let mut offsets = Vec::with_capacity(slices.len());
    let mut offset = PAGE_SIZE;
    for slice in &slices {
        offsets.push(offset);
        offset = (offset + slice.len() as u64).next_multiple_of(PAGE_SIZE);
    }

    let header = macho::FatHeader {
        magic: object::U32::new(BE, macho::FAT_MAGIC),
        nfat_arch: object::U32::new(BE, slices.len() as u32),
    };
    let mut data = Vec::new();
    data.extend_from_slice(bytes_of(&header));
    for (i, (&arch, slice)) in arches.iter().zip(&slices).enumerate() {
        let (cputype, cpusubtype) = match arch {
            Arch::Arm64 => (macho::CPU_TYPE_ARM64, macho::CPU_SUBTYPE_ARM64_ALL),
            Arch::X86_64 => (macho::CPU_TYPE_X86_64, macho::CPU_SUBTYPE_X86_64_ALL),
        };
        let fat_arch = macho::FatArch32 {
            cputype: object::U32::new(BE, cputype),
            cpusubtype: object::U32::new(BE, cpusubtype),
            offset: object::U32::new(BE, offsets[i] as u32),
            size: object::U32::new(BE, slice.len() as u32),
            align: object::U32::new(BE, PAGE_SIZE.trailing_zeros()),
        };
        data.extend_from_slice(bytes_of(&fat_arch));
    }
    for (i, slice) in slices.iter().enumerate() {
        data.resize(offsets[i] as usize, 0);
        data.extend_from_slice(slice);
    }
    data
}

/// dyld export trie: compressed prefix tree. Node = terminal payload
/// (uleb size, then flags/address ulebs) + child count + per-child
/// (label cstr, uleb node offset). Offsets are ulebs, so sizing runs to a
/// fixpoint. Every export is a regular symbol at offset 0 — the linker only
/// reads names from a bundle_loader executable, never addresses.
fn export_trie(sorted_symbols: &[&str]) -> Vec<u8> {
    #[derive(Default)]
    struct Node {
        terminal: bool,
        children: Vec<(Vec<u8>, usize)>,
        offset: usize,
    }

    // Nodes land in the arena in pre-order, which is also serialization order.
    fn build(arena: &mut Vec<Node>, symbols: &[&[u8]], depth: usize) -> usize {
        let index = arena.len();
        arena.push(Node::default());
        let mut i = 0;
        while i < symbols.len() {
            let sym = symbols[i];
            if sym.len() == depth {
                arena[index].terminal = true;
                i += 1;
                continue;
            }
            // Group symbols sharing the next byte, then extend the edge label
            // as long as the whole group agrees.
            let first = sym[depth];
            let mut j = i + 1;
            while j < symbols.len() && symbols[j][depth] == first {
                j += 1;
            }
            let group = &symbols[i..j];
            let mut label_end = depth + 1;
            while group[0].len() > label_end
                && group.iter().all(|s| s.len() > label_end && s[label_end] == group[0][label_end])
            {
                label_end += 1;
            }
            let label = group[0][depth..label_end].to_vec();
            let child = build(arena, group, label_end);
            arena[index].children.push((label, child));
            i = j;
        }
        index
    }

    fn uleb_len(mut value: usize) -> usize {
        let mut len = 1;
        while value >= 0x80 {
            value >>= 7;
            len += 1;
        }
        len
    }

    fn push_uleb(out: &mut Vec<u8>, mut value: usize) {
        loop {
            let byte = (value & 0x7F) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
    }

    // Terminal payload: size(2), flags(0) + address(0).
    const TERMINAL: &[u8] = &[2, 0, 0];

    let symbols = sorted_symbols.iter().map(|s| s.as_bytes()).collect::<Vec<_>>();
    let mut arena = Vec::new();
    build(&mut arena, &symbols, 0);

    // Child offsets are ulebs whose byte length depends on the offsets
    // themselves, so size to a fixpoint.
    loop {
        let mut offset = 0;
        let mut stable = true;
        for i in 0..arena.len() {
            if arena[i].offset != offset {
                arena[i].offset = offset;
                stable = false;
            }
            let node = &arena[i];
            offset += if node.terminal { TERMINAL.len() } else { 1 };
            offset += 1; // child count
            for (label, child) in &node.children {
                offset += label.len() + 1 + uleb_len(arena[*child].offset);
            }
        }
        if stable {
            break;
        }
    }

    let mut out = Vec::new();
    for i in 0..arena.len() {
        let node = &arena[i];
        debug_assert_eq!(out.len(), node.offset);
        if node.terminal {
            out.extend_from_slice(TERMINAL);
        } else {
            out.push(0);
        }
        out.push(node.children.len() as u8);
        for (label, child) in &node.children {
            out.extend_from_slice(label);
            out.push(0);
            push_uleb(&mut out, arena[*child].offset);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use object::{Object, ObjectSymbol};

    use super::*;

    #[test]
    fn single_arch_formats_reject_multiple_arches() {
        assert_eq!(single_arch(Format::Implib, &[]).unwrap(), Arch::X86_64);
        assert_eq!(single_arch(Format::Elf, &[Arch::Arm64]).unwrap(), Arch::Arm64);
        assert!(single_arch(Format::Implib, &[Arch::Arm64, Arch::X86_64]).is_err());
        assert!(single_arch(Format::Elf, &[Arch::Arm64, Arch::X86_64]).is_err());
    }

    #[test]
    fn stub_slice_round_trips() {
        let symbols = ["_a", "_ab", "_abcdef", "_b", "_game_func", "_game_var"];
        let trie = export_trie(&symbols);
        let (symtab, strtab) = symbol_table(&symbols);
        let slice =
            macho_slice(Arch::Arm64, macho::PLATFORM_MACOS, 0x000B_0000, &trie, &symtab, &strtab);

        let file = object::File::parse(&*slice).unwrap();
        let mut names = file
            .symbols()
            .filter(|s| s.is_global() && !s.is_undefined())
            .map(|s| s.name().unwrap().to_string())
            .collect::<Vec<_>>();
        names.sort_unstable();
        assert_eq!(names, symbols);

        let mut exports = file
            .exports()
            .unwrap()
            .iter()
            .map(|e| String::from_utf8_lossy(e.name()).into_owned())
            .collect::<Vec<_>>();
        exports.sort_unstable();
        assert_eq!(exports, symbols);
    }
}
