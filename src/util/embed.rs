//! Post-link injection of a blob into a linked image.
//!
//! A symbol manifest is a post-link artifact (symbol addresses and the build id only exist
//! after the link), so it cannot be embedded at compile time. Instead, the program compiles
//! in a small zeroed descriptor in a dedicated section (`symdbh`), and this module appends
//! the manifest as a new section/segment and patches the descriptor with its address and
//! size. No relocations are created: the runtime computes `image base + rva`.

use std::{fs, path::Path};

use anyhow::{Context, Result, bail};
use object::pod::{bytes_of, from_bytes, slice_from_bytes};

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
    let tmp = path.with_extension("embed.tmp");
    fs::write(&tmp, &out).with_context(|| format!("Failed to write '{}'", tmp.display()))?;
    let perms = fs::metadata(path)?.permissions();
    fs::set_permissions(&tmp, perms)?;
    fs::rename(&tmp, path)
        .with_context(|| format!("Failed to replace image '{}'", path.display()))?;
    Ok(())
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

/// Rebuild a dyld chained fixups blob for one added (fixup-free) segment: seg_count grows,
/// a zero seg_info_offset entry is inserted at the new segment's index, and everything
/// after the seg_info_offset array shifts by 8 (the entry plus alignment padding).
fn grow_chained_fixups(blob: &[u8], insert_index: usize, nsegs: usize) -> Result<Vec<u8>> {
    let read_u32 = |off: usize| -> Result<u32> {
        Ok(u32::from_le_bytes(
            blob.get(off..off + 4).context("Truncated chained fixups")?.try_into().unwrap(),
        ))
    };
    if read_u32(0)? != 0 {
        bail!("Unknown chained fixups version {}", read_u32(0)?);
    }
    let starts_offset = read_u32(4)? as usize;
    if starts_offset < 28 {
        bail!("Chained fixups starts_offset {starts_offset:#x} overlaps the header");
    }
    let seg_count = read_u32(starts_offset)? as usize;
    if seg_count != nsegs {
        bail!("Chained fixups seg_count {seg_count} does not match {nsegs} segments");
    }
    if insert_index > seg_count {
        bail!("Segment index {insert_index} out of range for {seg_count} segments");
    }
    let array_end = starts_offset + 4 + 4 * seg_count;

    let mut out = Vec::with_capacity(blob.len() + 8);
    out.extend_from_slice(blob.get(..starts_offset).context("Truncated chained fixups")?);
    out.extend_from_slice(&((seg_count + 1) as u32).to_le_bytes());
    for i in 0..=seg_count {
        let entry = match i.cmp(&insert_index) {
            std::cmp::Ordering::Less => read_u32(starts_offset + 4 + 4 * i)?,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => read_u32(starts_offset + 4 + 4 * (i - 1))?,
        };
        // seg_info_offset is relative to the starts_in_image struct; nonzero entries point
        // past the array, which shifts by 8.
        if entry != 0 && (entry as usize) < 4 + 4 * seg_count {
            bail!("Chained fixups seg_info_offset {entry:#x} points into the offset array");
        }
        out.extend_from_slice(&(if entry != 0 { entry + 8 } else { 0 }).to_le_bytes());
    }
    out.extend_from_slice(&[0u8; 4]); // keep the tail's alignment
    out.extend_from_slice(blob.get(array_end..).context("Truncated chained fixups")?);

    // imports_offset/symbols_offset are relative to the header and land in the shifted tail.
    for field in [8usize, 12] {
        let value = read_u32(field)?;
        if value != 0 {
            if (value as usize) < array_end {
                bail!("Chained fixups table offset {value:#x} precedes the segment array");
            }
            out[field..field + 4].copy_from_slice(&(value + 8).to_le_bytes());
        }
    }
    Ok(out)
}

/// Mach-O: insert a `__SYMDB` segment where `__LINKEDIT` starts (`__LINKEDIT` must stay the
/// last segment), shift every linkedit file offset, and grow the chained fixups blob to
/// cover the added segment. Needs load-command headroom (link with `-headerpad`). Any
/// existing code signature is invalidated; re-sign afterwards.
fn macho_embed(mut data: Vec<u8>, blob: &[u8]) -> Result<Vec<u8>> {
    use object::{
        LittleEndian as LE, U32, U64,
        macho::{
            LC_CODE_SIGNATURE, LC_DATA_IN_CODE, LC_DYLD_CHAINED_FIXUPS, LC_DYLD_ENVIRONMENT,
            LC_DYLD_EXPORTS_TRIE, LC_DYLD_INFO, LC_DYLD_INFO_ONLY, LC_DYLIB_CODE_SIGN_DRS,
            LC_DYSYMTAB, LC_FUNCTION_STARTS, LC_ID_DYLIB, LC_LINKER_OPTIMIZATION_HINT,
            LC_LOAD_DYLIB, LC_LOAD_DYLINKER, LC_LOAD_UPWARD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_MAIN,
            LC_REEXPORT_DYLIB, LC_RPATH, LC_SEGMENT_64, LC_SEGMENT_SPLIT_INFO, LC_SOURCE_VERSION,
            LC_SYMTAB, LC_UUID, LC_VERSION_MIN_MACOSX, MH_MAGIC_64, MachHeader64, Section64,
            SegmentCommand64, VM_PROT_READ,
        },
    };

    const LC_BUILD_VERSION: u32 = 0x32;
    const LC_ATOM_INFO: u32 = 0x36;
    const HEADER_SIZE: usize = size_of::<MachHeader64<LE>>();
    const NEW_LC_SIZE: usize = size_of::<SegmentCommand64<LE>>() + size_of::<Section64<LE>>();

    let header = {
        let (header, _) = from_bytes::<MachHeader64<LE>>(&data)
            .map_err(|_| anyhow::anyhow!("Truncated Mach-O header"))?;
        *header
    };
    // The magic field is declared big-endian in the object crate; check the raw bytes.
    if u32::from_le_bytes(data[0..4].try_into().unwrap()) != MH_MAGIC_64 {
        bail!("Not a little-endian 64-bit Mach-O image");
    }
    let page: u64 = match header.cputype.get(LE) {
        object::macho::CPU_TYPE_X86_64 => 0x1000,
        _ => 0x4000,
    };
    let ncmds = header.ncmds.get(LE) as usize;
    let sizeofcmds = header.sizeofcmds.get(LE) as usize;
    let cmds_end = HEADER_SIZE + sizeofcmds;

    // First pass: locate __LINKEDIT, the descriptor section, and the lowest file content,
    // and classify every load command so nothing with a file offset is silently skipped.
    let mut linkedit: Option<(usize, u64, u64, u64)> = None; // (lc offset, vmaddr, fileoff, filesize)
    let mut fixups: Option<(u64, u64)> = None; // (dataoff, datasize)
    let mut desc_off = None;
    let mut min_content = u64::MAX;
    let mut nsegs = 0usize;
    let mut symdb_seg_index = 0usize;
    let mut offset = HEADER_SIZE;
    for _ in 0..ncmds {
        let lc = data.get(offset..offset + 8).context("Truncated load commands")?;
        let cmd = u32::from_le_bytes(lc[0..4].try_into().unwrap());
        let cmdsize = u32::from_le_bytes(lc[4..8].try_into().unwrap()) as usize;
        if cmdsize < 8 || offset + cmdsize > cmds_end {
            bail!("Bad load command size at {offset:#x}");
        }
        match cmd {
            LC_SEGMENT_64 => {
                let (seg, _) = from_bytes::<SegmentCommand64<LE>>(&data[offset..offset + cmdsize])
                    .map_err(|_| anyhow::anyhow!("Truncated segment command"))?;
                match &seg.segname {
                    b"__LINKEDIT\0\0\0\0\0\0" => {
                        // The new segment's LC is inserted here, so it takes this index.
                        symdb_seg_index = nsegs;
                        linkedit = Some((
                            offset,
                            seg.vmaddr.get(LE),
                            seg.fileoff.get(LE),
                            seg.filesize.get(LE),
                        ));
                    }
                    b"__SYMDB\0\0\0\0\0\0\0\0\0" => {
                        bail!("Image already has a __SYMDB segment; relink before re-embedding");
                    }
                    _ => {}
                }
                nsegs += 1;
                let nsects = seg.nsects.get(LE) as usize;
                let sections_off = offset + size_of::<SegmentCommand64<LE>>();
                let (sections, _) = slice_from_bytes::<Section64<LE>>(
                    data.get(sections_off..).context("Truncated section commands")?,
                    nsects,
                )
                .map_err(|_| anyhow::anyhow!("Truncated section commands"))?;
                for section in sections {
                    if &section.sectname == b"__symdbh\0\0\0\0\0\0\0\0" {
                        if section.size.get(LE) < DESCRIPTOR_SIZE as u64 {
                            bail!("Descriptor section __symdbh is too small");
                        }
                        desc_off = Some(section.offset.get(LE) as usize);
                    }
                    if section.offset.get(LE) != 0 {
                        min_content = min_content.min(u64::from(section.offset.get(LE)));
                    }
                }
            }
            LC_DYLD_CHAINED_FIXUPS => {
                let (linkedit_data, _) = from_bytes::<object::macho::LinkeditDataCommand<LE>>(
                    &data[offset..offset + cmdsize],
                )
                .map_err(|_| anyhow::anyhow!("Truncated linkedit data command"))?;
                fixups = Some((
                    u64::from(linkedit_data.dataoff.get(LE)),
                    u64::from(linkedit_data.datasize.get(LE)),
                ));
            }
            // Linkedit-relative offsets handled in the second pass.
            LC_SYMTAB
            | LC_DYSYMTAB
            | LC_DYLD_INFO
            | LC_DYLD_INFO_ONLY
            | LC_CODE_SIGNATURE
            | LC_SEGMENT_SPLIT_INFO
            | LC_FUNCTION_STARTS
            | LC_DATA_IN_CODE
            | LC_DYLIB_CODE_SIGN_DRS
            | LC_LINKER_OPTIMIZATION_HINT
            | LC_DYLD_EXPORTS_TRIE
            | LC_ATOM_INFO => {}
            // Known to carry no file offsets.
            LC_UUID
            | LC_BUILD_VERSION
            | LC_VERSION_MIN_MACOSX
            | LC_SOURCE_VERSION
            | LC_MAIN
            | LC_LOAD_DYLINKER
            | LC_DYLD_ENVIRONMENT
            | LC_ID_DYLIB
            | LC_LOAD_DYLIB
            | LC_LOAD_WEAK_DYLIB
            | LC_REEXPORT_DYLIB
            | LC_LOAD_UPWARD_DYLIB
            | LC_RPATH => {}
            _ => bail!("Unhandled load command {cmd:#x}; refusing to relayout the image"),
        }
        offset += cmdsize;
    }
    let (le_off, le_vmaddr, le_fileoff, le_filesize) =
        linkedit.context("Image has no __LINKEDIT segment")?;
    let desc_off = desc_off.ok_or_else(|| no_descriptor("__symdbh"))?;
    if le_fileoff % page != 0 {
        bail!("__LINKEDIT is not page-aligned");
    }
    if cmds_end + NEW_LC_SIZE > min_content as usize {
        bail!(
            "No load-command headroom for a segment; link with -Wl,-headerpad,{:#x}",
            NEW_LC_SIZE
        );
    }

    let delta = align_up(blob.len() as u64, page);

    // The chained fixups blob records seg_count, which the new segment invalidates (ld
    // refuses such an image as a -bundle_loader input). Grow the blob by 8 bytes, shifting
    // the rest of __LINKEDIT behind it.
    let new_fixups = match fixups {
        Some((dataoff, datasize)) => {
            let range = dataoff as usize..(dataoff + datasize) as usize;
            Some(grow_chained_fixups(
                data.get(range).context("Chained fixups out of file bounds")?,
                symdb_seg_index,
                nsegs,
            )?)
        }
        None => None,
    };
    let grow = if new_fixups.is_some() { 8u64 } else { 0 };
    let fixups_dataoff = fixups.map_or(u64::MAX, |(dataoff, _)| dataoff);

    // Second pass: shift every nonzero linkedit-relative file offset by delta, plus the
    // fixups growth for content behind the fixups blob.
    let shift = |field: &mut U32<LE>, delta: u64| {
        let value = u64::from(field.get(LE));
        if value != 0 {
            let behind_fixups = if value > fixups_dataoff { grow } else { 0 };
            field.set(LE, (value + delta + behind_fixups) as u32);
        }
    };
    let mut offset = HEADER_SIZE;
    for _ in 0..ncmds {
        let cmd = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        let cmdsize = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap()) as usize;
        let body = &mut data[offset..offset + cmdsize];
        match cmd {
            LC_SYMTAB => {
                let (symtab, _) =
                    object::pod::from_bytes_mut::<object::macho::SymtabCommand<LE>>(body)
                        .map_err(|_| anyhow::anyhow!("Truncated symtab command"))?;
                shift(&mut symtab.symoff, delta);
                shift(&mut symtab.stroff, delta);
            }
            LC_DYSYMTAB => {
                let (dysymtab, _) =
                    object::pod::from_bytes_mut::<object::macho::DysymtabCommand<LE>>(body)
                        .map_err(|_| anyhow::anyhow!("Truncated dysymtab command"))?;
                shift(&mut dysymtab.tocoff, delta);
                shift(&mut dysymtab.modtaboff, delta);
                shift(&mut dysymtab.extrefsymoff, delta);
                shift(&mut dysymtab.indirectsymoff, delta);
                shift(&mut dysymtab.extreloff, delta);
                shift(&mut dysymtab.locreloff, delta);
            }
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                let (info, _) =
                    object::pod::from_bytes_mut::<object::macho::DyldInfoCommand<LE>>(body)
                        .map_err(|_| anyhow::anyhow!("Truncated dyld info command"))?;
                shift(&mut info.rebase_off, delta);
                shift(&mut info.bind_off, delta);
                shift(&mut info.weak_bind_off, delta);
                shift(&mut info.lazy_bind_off, delta);
                shift(&mut info.export_off, delta);
            }
            LC_CODE_SIGNATURE
            | LC_SEGMENT_SPLIT_INFO
            | LC_FUNCTION_STARTS
            | LC_DATA_IN_CODE
            | LC_DYLIB_CODE_SIGN_DRS
            | LC_LINKER_OPTIMIZATION_HINT
            | LC_DYLD_EXPORTS_TRIE
            | LC_DYLD_CHAINED_FIXUPS
            | LC_ATOM_INFO => {
                let (linkedit_data, _) =
                    object::pod::from_bytes_mut::<object::macho::LinkeditDataCommand<LE>>(body)
                        .map_err(|_| anyhow::anyhow!("Truncated linkedit data command"))?;
                shift(&mut linkedit_data.dataoff, delta);
                if cmd == LC_DYLD_CHAINED_FIXUPS {
                    let datasize = linkedit_data.datasize.get(LE);
                    linkedit_data.datasize.set(LE, datasize + grow as u32);
                }
            }
            _ => {}
        }
        offset += cmdsize;
    }

    // Shift __LINKEDIT itself.
    {
        let body = &mut data[le_off..le_off + size_of::<SegmentCommand64<LE>>()];
        let (seg, _) = object::pod::from_bytes_mut::<SegmentCommand64<LE>>(body)
            .map_err(|_| anyhow::anyhow!("Truncated segment command"))?;
        seg.vmaddr.set(LE, le_vmaddr + delta);
        seg.fileoff.set(LE, le_fileoff + delta);
        seg.filesize.set(LE, le_filesize + grow);
        let vmsize = seg.vmsize.get(LE).max(align_up(le_filesize + grow, page));
        seg.vmsize.set(LE, vmsize);
    }

    patch_descriptor(&mut data, desc_off, le_vmaddr, blob.len() as u64)?;

    // Insert the new load command where __LINKEDIT's is (keeping commands ordered by
    // vmaddr), sliding the tail commands into the headerpad.
    let new_segment = SegmentCommand64::<LE> {
        cmd: U32::new(LE, LC_SEGMENT_64),
        cmdsize: U32::new(LE, NEW_LC_SIZE as u32),
        segname: *b"__SYMDB\0\0\0\0\0\0\0\0\0",
        vmaddr: U64::new(LE, le_vmaddr),
        vmsize: U64::new(LE, delta),
        fileoff: U64::new(LE, le_fileoff),
        filesize: U64::new(LE, delta),
        maxprot: U32::new(LE, VM_PROT_READ),
        initprot: U32::new(LE, VM_PROT_READ),
        nsects: U32::new(LE, 1),
        flags: U32::new(LE, 0),
    };
    let new_section = Section64::<LE> {
        sectname: *b"__symdb\0\0\0\0\0\0\0\0\0",
        segname: *b"__SYMDB\0\0\0\0\0\0\0\0\0",
        addr: U64::new(LE, le_vmaddr),
        size: U64::new(LE, blob.len() as u64),
        offset: U32::new(LE, le_fileoff as u32),
        align: U32::new(LE, 3),
        reloff: U32::new(LE, 0),
        nreloc: U32::new(LE, 0),
        flags: U32::new(LE, 0),
        reserved1: U32::new(LE, 0),
        reserved2: U32::new(LE, 0),
        reserved3: U32::new(LE, 0),
    };
    data.copy_within(le_off..cmds_end, le_off + NEW_LC_SIZE);
    data[le_off..le_off + size_of::<SegmentCommand64<LE>>()]
        .copy_from_slice(bytes_of(&new_segment));
    data[le_off + size_of::<SegmentCommand64<LE>>()..le_off + NEW_LC_SIZE]
        .copy_from_slice(bytes_of(&new_section));
    {
        let (header, _) = object::pod::from_bytes_mut::<MachHeader64<LE>>(&mut data)
            .map_err(|_| anyhow::anyhow!("Truncated Mach-O header"))?;
        header.ncmds.set(LE, (ncmds + 1) as u32);
        header.sizeofcmds.set(LE, (sizeofcmds + NEW_LC_SIZE) as u32);
    }

    let mut out = Vec::with_capacity(data.len() + (delta + grow) as usize);
    out.extend_from_slice(&data[..le_fileoff as usize]);
    out.extend_from_slice(blob);
    out.resize((le_fileoff + delta) as usize, 0);
    match (new_fixups, fixups) {
        (Some(new_fixups), Some((dataoff, datasize))) => {
            out.extend_from_slice(&data[le_fileoff as usize..dataoff as usize]);
            out.extend_from_slice(&new_fixups);
            out.extend_from_slice(&data[(dataoff + datasize) as usize..]);
        }
        _ => out.extend_from_slice(&data[le_fileoff as usize..]),
    }
    log::debug!("Mach-O: __SYMDB at vmaddr {le_vmaddr:#x}, {} bytes", blob.len());
    Ok(out)
}
