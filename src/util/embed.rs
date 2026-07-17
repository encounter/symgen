//! Post-link injection of a blob into a linked image.
//!
//! A symbol manifest is a post-link artifact (symbol addresses and the build id only exist
//! after the link), so it cannot be embedded at compile time. Instead, the program compiles
//! in a small zeroed descriptor in a dedicated section (`symdbh`), and this module appends
//! the manifest as a new section/segment and patches the descriptor with its address and
//! size. No relocations are created: the runtime computes `image base + rva`.

use std::{fs, path::Path};

use anyhow::{Context, Result, bail};
use object::{
    Object, ObjectSection,
    pod::{bytes_of, from_bytes, slice_from_bytes},
};

use crate::util::file::atomic_replace;

/// "SYMDBHDR", the compile-time value of the descriptor's first field.
const DESCRIPTOR_MAGIC: u64 = u64::from_le_bytes(*b"SYMDBHDR");

/// {u64 magic, u64 rva, u64 size}
const DESCRIPTOR_SIZE: usize = 24;

pub fn embed(path: &Path, blob: &[u8]) -> Result<()> {
    let data =
        fs::read(path).with_context(|| format!("Failed to read image '{}'", path.display()))?;
    let kind = object::FileKind::parse(&*data)
        .with_context(|| format!("Failed to parse image '{}'", path.display()))?;
    let out = match kind {
        object::FileKind::Pe64 => pe_embed(data, blob)?,
        object::FileKind::Elf64 => elf_embed(data, blob)?,
        object::FileKind::MachO64 => macho_embed(data, blob)?,
        _ => bail!("Unsupported image format {kind:?} (need 64-bit PE, ELF, or Mach-O)"),
    };
    atomic_replace(path, &out)
}

fn align_up(value: u64, align: u64) -> u64 { value.next_multiple_of(align.max(1)) }

/// Verify the descriptor's magic and unpatched state, then write {rva, size}.
fn patch_descriptor(data: &mut [u8], offset: usize, rva: u64, size: u64) -> Result<()> {
    let desc = data
        .get_mut(offset..offset + DESCRIPTOR_SIZE)
        .context("Descriptor section is out of the file's bounds")?;
    let magic = u64::from_le_bytes(desc[0..8].try_into().unwrap());
    if magic != DESCRIPTOR_MAGIC {
        bail!("Descriptor magic mismatch (found {magic:#x}); image/descriptor layout skew?");
    }
    if u64::from_le_bytes(desc[8..16].try_into().unwrap()) != 0 {
        bail!("Image already has an embedded manifest; relink before re-embedding");
    }
    desc[8..16].copy_from_slice(&rva.to_le_bytes());
    desc[16..24].copy_from_slice(&size.to_le_bytes());
    Ok(())
}

fn no_descriptor(section: &str) -> anyhow::Error {
    anyhow::anyhow!("Image has no '{section}' descriptor section.")
}

/// Grow a PE image's header block so the section table can take another entry.
fn pe_grow_headers(mut data: Vec<u8>, needed: usize, file_align: u64) -> Result<Vec<u8>> {
    use object::{
        LittleEndian as LE,
        pe::{
            IMAGE_DIRECTORY_ENTRY_DEBUG, ImageDataDirectory, ImageDebugDirectory, ImageDosHeader,
            ImageNtHeaders64, ImageSectionHeader,
        },
    };

    let nt_off = {
        let (dos, _) = from_bytes::<ImageDosHeader>(&data)
            .map_err(|_| anyhow::anyhow!("Truncated DOS header"))?;
        dos.e_lfanew.get(LE) as usize
    };
    let (nt_bytes, _) = object::pod::from_bytes_mut::<ImageNtHeaders64>(&mut data[nt_off..])
        .map_err(|_| anyhow::anyhow!("Truncated NT headers"))?;
    let size_of_headers = nt_bytes.optional_header.size_of_headers.get(LE) as usize;
    let grow = align_up((needed - size_of_headers) as u64, file_align) as usize;
    let nsections = nt_bytes.file_header.number_of_sections.get(LE) as usize;
    let opt_size = nt_bytes.file_header.size_of_optional_header.get(LE) as usize;
    let ndirs = nt_bytes.optional_header.number_of_rva_and_sizes.get(LE) as usize;
    nt_bytes.optional_header.size_of_headers.set(LE, (size_of_headers + grow) as u32);
    let symtab = nt_bytes.file_header.pointer_to_symbol_table.get(LE);
    if symtab != 0 {
        nt_bytes.file_header.pointer_to_symbol_table.set(LE, symtab + grow as u32);
    }

    // The debug directory's entries live in section data and carry file offsets; find them
    // through the pre-shift section table.
    let table_off = nt_off + 4 + size_of::<object::pe::ImageFileHeader>() + opt_size;
    let mut debug_range = None;
    {
        let dirs_off = nt_off + size_of::<ImageNtHeaders64>();
        let (dirs, _) = slice_from_bytes::<ImageDataDirectory>(
            data.get(dirs_off..).context("Truncated data directories")?,
            ndirs,
        )
        .map_err(|_| anyhow::anyhow!("Truncated data directories"))?;
        let (sections, _) = slice_from_bytes::<ImageSectionHeader>(
            data.get(table_off..).context("Truncated section table")?,
            nsections,
        )
        .map_err(|_| anyhow::anyhow!("Truncated section table"))?;
        if let Some(debug) = dirs.get(IMAGE_DIRECTORY_ENTRY_DEBUG)
            && debug.size.get(LE) != 0
        {
            let rva = u64::from(debug.virtual_address.get(LE));
            let section = sections
                .iter()
                .find(|s| {
                    let va = u64::from(s.virtual_address.get(LE));
                    rva >= va && rva - va < u64::from(s.size_of_raw_data.get(LE))
                })
                .context("Debug directory is not in any section")?;
            let off = rva - u64::from(section.virtual_address.get(LE))
                + u64::from(section.pointer_to_raw_data.get(LE));
            debug_range = Some((
                off as usize,
                debug.size.get(LE) as usize / size_of::<ImageDebugDirectory>(),
            ));
        }
    }
    if let Some((off, count)) = debug_range {
        let (entries, _) = object::pod::slice_from_bytes_mut::<ImageDebugDirectory>(
            data.get_mut(off..).context("Truncated debug directory")?,
            count,
        )
        .map_err(|_| anyhow::anyhow!("Truncated debug directory"))?;
        for entry in entries {
            let pointer = entry.pointer_to_raw_data.get(LE);
            if pointer != 0 {
                entry.pointer_to_raw_data.set(LE, pointer + grow as u32);
            }
        }
    }

    let (sections, _) = object::pod::slice_from_bytes_mut::<ImageSectionHeader>(
        data.get_mut(table_off..).context("Truncated section table")?,
        nsections,
    )
    .map_err(|_| anyhow::anyhow!("Truncated section table"))?;
    for section in sections {
        let pointer = section.pointer_to_raw_data.get(LE);
        if pointer != 0 {
            section.pointer_to_raw_data.set(LE, pointer + grow as u32);
        }
    }

    let mut out = Vec::with_capacity(data.len() + grow);
    out.extend_from_slice(&data[..size_of_headers]);
    out.resize(size_of_headers + grow, 0);
    out.extend_from_slice(&data[size_of_headers..]);
    log::debug!("PE: grew headers by {grow} bytes for a section table entry");
    Ok(out)
}

/// PE: append a `.symdb` section. The new header entry goes in the FileAlignment padding
/// after the section table; the data is appended at EOF.
fn pe_embed(mut data: Vec<u8>, blob: &[u8]) -> Result<Vec<u8>> {
    use object::{
        LittleEndian as LE,
        pe::{
            IMAGE_DIRECTORY_ENTRY_SECURITY, IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_NT_SIGNATURE,
            IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ, ImageDataDirectory, ImageDosHeader,
            ImageNtHeaders64, ImageSectionHeader,
        },
    };

    let (dos, _) =
        from_bytes::<ImageDosHeader>(&data).map_err(|_| anyhow::anyhow!("Truncated DOS header"))?;
    let nt_off = dos.e_lfanew.get(LE) as usize;
    let (nt, _) = from_bytes::<ImageNtHeaders64>(data.get(nt_off..).context("Bad e_lfanew")?)
        .map_err(|_| anyhow::anyhow!("Truncated NT headers"))?;
    if nt.signature.get(LE) != IMAGE_NT_SIGNATURE {
        bail!("Bad PE signature");
    }
    if nt.optional_header.magic.get(LE) != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        bail!("Not a PE32+ image");
    }
    let nsections = nt.file_header.number_of_sections.get(LE) as usize;
    let opt_size = nt.file_header.size_of_optional_header.get(LE) as usize;
    let file_align = u64::from(nt.optional_header.file_alignment.get(LE));
    let section_align = u64::from(nt.optional_header.section_alignment.get(LE));
    let size_of_headers = nt.optional_header.size_of_headers.get(LE) as usize;
    let ndirs = nt.optional_header.number_of_rva_and_sizes.get(LE) as usize;

    // An Authenticode signature is an appendix at EOF; appending a section would corrupt it.
    let dirs_off = nt_off + size_of::<ImageNtHeaders64>();
    let (dirs, _) = slice_from_bytes::<ImageDataDirectory>(
        data.get(dirs_off..).context("Truncated data directories")?,
        ndirs,
    )
    .map_err(|_| anyhow::anyhow!("Truncated data directories"))?;
    if let Some(security) = dirs.get(IMAGE_DIRECTORY_ENTRY_SECURITY)
        && security.size.get(LE) != 0
    {
        bail!("Image has an Authenticode signature; embed before signing");
    }

    let table_off = nt_off + 4 + size_of_val(&nt.file_header) + opt_size;
    let (sections, _) = slice_from_bytes::<ImageSectionHeader>(
        data.get(table_off..).context("Truncated section table")?,
        nsections,
    )
    .map_err(|_| anyhow::anyhow!("Truncated section table"))?;

    let mut desc_off = None;
    let mut va_end = 0u64;
    for section in sections {
        if &section.name == b".symdb\0\0" {
            bail!("Image already has a .symdb section; relink before re-embedding");
        }
        if &section.name == b".symdbh\0" {
            if section.virtual_size.get(LE) < DESCRIPTOR_SIZE as u32
                || section.size_of_raw_data.get(LE) < DESCRIPTOR_SIZE as u32
            {
                bail!("Descriptor section .symdbh is too small");
            }
            desc_off = Some(section.pointer_to_raw_data.get(LE) as usize);
        }
        va_end = va_end.max(
            u64::from(section.virtual_address.get(LE)) + u64::from(section.virtual_size.get(LE)),
        );
    }
    let desc_off = desc_off.ok_or_else(|| no_descriptor(".symdbh"))?;

    // Room for one more header entry inside the header block, which must be padding today.
    // link.exe often sizes the header block exactly; grow it when there is no slack.
    let entry_off = table_off + nsections * size_of::<ImageSectionHeader>();
    let entry_end = entry_off + size_of::<ImageSectionHeader>();
    if entry_end > size_of_headers {
        let data = pe_grow_headers(data, entry_end, file_align)?;
        return pe_embed(data, blob);
    }
    if !data[entry_off..entry_end].iter().all(|&b| b == 0) {
        bail!("Section table is not followed by padding");
    }

    let virtual_address = align_up(va_end, section_align);
    let raw_offset = align_up(data.len() as u64, file_align);
    let raw_size = align_up(blob.len() as u64, file_align);

    patch_descriptor(&mut data, desc_off, virtual_address, blob.len() as u64)?;

    let entry = ImageSectionHeader {
        name: *b".symdb\0\0",
        virtual_size: object::U32::new(LE, blob.len() as u32),
        virtual_address: object::U32::new(LE, virtual_address as u32),
        size_of_raw_data: object::U32::new(LE, raw_size as u32),
        pointer_to_raw_data: object::U32::new(LE, raw_offset as u32),
        pointer_to_relocations: object::U32::new(LE, 0),
        pointer_to_linenumbers: object::U32::new(LE, 0),
        number_of_relocations: object::U16::new(LE, 0),
        number_of_linenumbers: object::U16::new(LE, 0),
        characteristics: object::U32::new(LE, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ),
    };
    data[entry_off..entry_end].copy_from_slice(bytes_of(&entry));

    // Re-borrow mutably now that the reads above are done.
    let nt_bytes = &mut data[nt_off..];
    let (nt, _) = object::pod::from_bytes_mut::<ImageNtHeaders64>(nt_bytes)
        .map_err(|_| anyhow::anyhow!("Truncated NT headers"))?;
    nt.file_header.number_of_sections.set(LE, (nsections + 1) as u16);
    nt.optional_header
        .size_of_image
        .set(LE, align_up(virtual_address + blob.len() as u64, section_align) as u32);
    // The checksum is stale either way; zero marks it unset (loaders ignore it for
    // ordinary executables).
    nt.optional_header.check_sum.set(LE, 0);

    data.resize(raw_offset as usize, 0);
    data.extend_from_slice(blob);
    data.resize((raw_offset + raw_size) as usize, 0);
    log::debug!("PE: .symdb at rva {virtual_address:#x}, {} bytes", blob.len());
    Ok(data)
}

/// ELF: append a read-only PT_LOAD at EOF holding the relocated program-header table and
/// the blob. The phdr table cannot grow in place, and loaders (bionic in particular) expect
/// it to be covered by a PT_LOAD, so it moves into the new segment — with `p_vaddr ==
/// p_offset` so a loader that computes `bias + e_phoff` still lands on it. A PT_PHDR entry
/// is updated (or added, for images without one) to point at the moved table.
fn elf_embed(mut data: Vec<u8>, blob: &[u8]) -> Result<Vec<u8>> {
    use object::{
        LittleEndian as LE, U16, U32, U64,
        elf::{
            ELFCLASS64, ELFDATA2LSB, FileHeader64, PF_R, PT_LOAD, PT_PHDR, ProgramHeader64,
            SHF_ALLOC, SHT_PROGBITS, SectionHeader64,
        },
    };

    const PHENT: usize = size_of::<ProgramHeader64<LE>>();
    const SHENT: usize = size_of::<SectionHeader64<LE>>();

    let ehdr = {
        let (ehdr, _) = from_bytes::<FileHeader64<LE>>(&data)
            .map_err(|_| anyhow::anyhow!("Truncated ELF header"))?;
        *ehdr
    };
    if ehdr.e_ident.class != ELFCLASS64 || ehdr.e_ident.data != ELFDATA2LSB {
        bail!("Not a little-endian ELF64 image");
    }
    if ehdr.e_phentsize.get(LE) as usize != PHENT || ehdr.e_shentsize.get(LE) as usize != SHENT {
        bail!("Unexpected ELF header entry sizes");
    }
    let phoff = ehdr.e_phoff.get(LE) as usize;
    let phnum = ehdr.e_phnum.get(LE) as usize;
    let shoff = ehdr.e_shoff.get(LE) as usize;
    let shnum = ehdr.e_shnum.get(LE) as usize;
    let shstrndx = ehdr.e_shstrndx.get(LE) as usize;
    if phnum == 0xffff || shnum == 0 {
        bail!("Extended program/section header counts are unsupported");
    }

    let mut phdrs: Vec<ProgramHeader64<LE>> = {
        let (phdrs, _) = slice_from_bytes::<ProgramHeader64<LE>>(
            data.get(phoff..).context("Truncated program headers")?,
            phnum,
        )
        .map_err(|_| anyhow::anyhow!("Truncated program headers"))?;
        phdrs.to_vec()
    };
    let mut shdrs: Vec<SectionHeader64<LE>> = {
        let (shdrs, _) = slice_from_bytes::<SectionHeader64<LE>>(
            data.get(shoff..).context("Truncated section headers")?,
            shnum,
        )
        .map_err(|_| anyhow::anyhow!("Truncated section headers"))?;
        shdrs.to_vec()
    };

    // Section names via .shstrtab.
    let shstrtab_hdr = shdrs.get(shstrndx).context("Bad e_shstrndx")?;
    let strtab_off = shstrtab_hdr.sh_offset.get(LE) as usize;
    let strtab_len = shstrtab_hdr.sh_size.get(LE) as usize;
    let strtab: Vec<u8> =
        data.get(strtab_off..strtab_off + strtab_len).context("Truncated .shstrtab")?.to_vec();
    let section_name = |name_off: u32| -> &[u8] {
        let start = name_off as usize;
        match strtab.get(start..) {
            Some(rest) => &rest[..rest.iter().position(|&b| b == 0).unwrap_or(rest.len())],
            None => &[],
        }
    };

    let mut desc_off = None;
    for shdr in &shdrs {
        match section_name(shdr.sh_name.get(LE)) {
            b"symdb" => bail!("Image already has a symdb section; relink before re-embedding"),
            b"symdbh" => {
                if shdr.sh_size.get(LE) < DESCRIPTOR_SIZE as u64 {
                    bail!("Descriptor section symdbh is too small");
                }
                desc_off = Some(shdr.sh_offset.get(LE) as usize);
            }
            _ => {}
        }
    }
    let desc_off = desc_off.ok_or_else(|| no_descriptor("symdbh"))?;

    let mut align = 0x1000u64;
    let mut vaddr_end = 0u64;
    for phdr in &phdrs {
        if phdr.p_type.get(LE) == PT_LOAD {
            align = align.max(phdr.p_align.get(LE));
            vaddr_end = vaddr_end.max(phdr.p_vaddr.get(LE) + phdr.p_memsz.get(LE));
        }
    }
    // One address for both p_offset and p_vaddr: past the end of the file *and* of the
    // address space, so the file grows in place and no existing segment overlaps.
    let base = align_up((data.len() as u64).max(vaddr_end), align);

    let phdr_index = phdrs.iter().position(|p| p.p_type.get(LE) == PT_PHDR);
    let new_phnum = phnum + 1 + usize::from(phdr_index.is_none());
    let phdrs_size = (new_phnum * PHENT) as u64;
    let blob_vaddr = base + align_up(phdrs_size, 16);
    let seg_size = (blob_vaddr - base) + blob.len() as u64;

    let make_phdr = |p_type: u32, offset: u64, size: u64, p_align: u64| ProgramHeader64::<LE> {
        p_type: U32::new(LE, p_type),
        p_flags: U32::new(LE, PF_R),
        p_offset: U64::new(LE, offset),
        p_vaddr: U64::new(LE, offset),
        p_paddr: U64::new(LE, offset),
        p_filesz: U64::new(LE, size),
        p_memsz: U64::new(LE, size),
        p_align: U64::new(LE, p_align),
    };
    match phdr_index {
        Some(i) => phdrs[i] = make_phdr(PT_PHDR, base, phdrs_size, 8),
        // PT_PHDR must precede any PT_LOAD.
        None => phdrs.insert(0, make_phdr(PT_PHDR, base, phdrs_size, 8)),
    }
    phdrs.push(make_phdr(PT_LOAD, base, seg_size, align));

    // Rebuilt section metadata (never loaded, appended past the new segment): the extended
    // .shstrtab, then the section table with the shstrtab entry retargeted and a `symdb`
    // entry appended.
    let name_off = strtab.len() as u32;
    let mut new_strtab = strtab.clone();
    new_strtab.extend_from_slice(b"symdb\0");
    let new_strtab_off = blob_vaddr + blob.len() as u64;
    let new_shoff = align_up(new_strtab_off + new_strtab.len() as u64, 8);

    shdrs[shstrndx].sh_offset = U64::new(LE, new_strtab_off);
    shdrs[shstrndx].sh_size = U64::new(LE, new_strtab.len() as u64);
    shdrs.push(SectionHeader64::<LE> {
        sh_name: U32::new(LE, name_off),
        sh_type: U32::new(LE, SHT_PROGBITS),
        sh_flags: U64::new(LE, SHF_ALLOC.into()),
        sh_addr: U64::new(LE, blob_vaddr),
        sh_offset: U64::new(LE, blob_vaddr),
        sh_size: U64::new(LE, blob.len() as u64),
        sh_link: U32::new(LE, 0),
        sh_info: U32::new(LE, 0),
        sh_addralign: U64::new(LE, 16),
        sh_entsize: U64::new(LE, 0),
    });

    patch_descriptor(&mut data, desc_off, blob_vaddr, blob.len() as u64)?;

    {
        let (ehdr, _) = object::pod::from_bytes_mut::<FileHeader64<LE>>(&mut data)
            .map_err(|_| anyhow::anyhow!("Truncated ELF header"))?;
        ehdr.e_phoff = U64::new(LE, base);
        ehdr.e_phnum = U16::new(LE, new_phnum as u16);
        ehdr.e_shoff = U64::new(LE, new_shoff);
        ehdr.e_shnum = U16::new(LE, shdrs.len() as u16);
    }

    data.resize(base as usize, 0);
    for phdr in &phdrs {
        data.extend_from_slice(bytes_of(phdr));
    }
    data.resize(blob_vaddr as usize, 0);
    data.extend_from_slice(blob);
    data.extend_from_slice(&new_strtab);
    data.resize(new_shoff as usize, 0);
    for shdr in &shdrs {
        data.extend_from_slice(bytes_of(shdr));
    }
    log::debug!("ELF: symdb at vaddr {blob_vaddr:#x}, {} bytes", blob.len());
    Ok(data)
}

/// Mach-O: insert a `__SYMDB` segment where `__LINKEDIT` starts (`__LINKEDIT` must stay the
/// last segment), shift every linkedit file offset, and grow the chained fixups blob to
/// cover the added segment. Needs load-command headroom (link with `-headerpad`). Any
/// existing code signature is invalidated; re-sign afterwards.
fn macho_embed(data: Vec<u8>, blob: &[u8]) -> Result<Vec<u8>> {
    let descriptor_offset = {
        let file = object::File::parse(&*data).context("Failed to parse Mach-O image")?;
        if file.section_by_name("__symdb").is_some() {
            bail!("Image already has a __SYMDB segment; relink before re-embedding");
        }
        let section = file.section_by_name("__symdbh").ok_or_else(|| no_descriptor("__symdbh"))?;
        let (offset, size) = section.file_range().context("Descriptor is not file-backed")?;
        if size < DESCRIPTOR_SIZE as u64 {
            bail!("Descriptor section __symdbh is too small");
        }
        usize::try_from(offset).context("Descriptor file offset is too large")?
    };
    let inserted = crate::util::macho::insert_segments(data, &[crate::util::macho::SegmentSpec {
        name: "__SYMDB".into(),
        data: blob.to_vec(),
        max_prot: object::macho::VM_PROT_READ,
        init_prot: object::macho::VM_PROT_READ,
        sections: vec![crate::util::macho::SectionSpec {
            name: "__symdb",
            offset: 0,
            size: blob.len() as u64,
            align: 3,
            flags: object::macho::S_REGULAR,
        }],
    }])?;
    let mut output = inserted.data;
    patch_descriptor(
        &mut output,
        descriptor_offset,
        inserted.segments[0].vmaddr,
        blob.len() as u64,
    )?;
    Ok(output)
}
