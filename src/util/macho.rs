//! Shared Mach-O inspection, dyld fixup decoding, and strict segment insertion.
//!
//! Existing vmaddrs remain unchanged. New fixup-free segments are inserted immediately before
//! `__LINKEDIT`, which is shifted once along with every load-command file offset that points into
//! it. Unknown load commands are rejected so a newly introduced file-offset field cannot be
//! silently left stale.

use std::{mem::size_of, ops::Range};

use anyhow::{Context, Result, bail};
use object::{
    Endianness, LittleEndian as LE, Object, ObjectSection, U32, U64, macho,
    pod::bytes_of,
    read::macho::{LoadCommandVariant, MachOFile64},
};

#[derive(Clone, Debug)]
pub struct Segment {
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub max_prot: u32,
    pub init_prot: u32,
    pub name: [u8; 16],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FixupTarget {
    Rebase(u64),
    Bind(Option<String>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fixup {
    pub location: u64,
    pub target: FixupTarget,
}

/// Read-only view shared by Mach-O metadata and transformation code.
pub struct MachOImage<'data> {
    data: &'data [u8],
    file: MachOFile64<'data, Endianness>,
    segments: Vec<Segment>,
    preferred_base: u64,
}

impl<'data> MachOImage<'data> {
    pub fn parse(data: &'data [u8]) -> Result<Self> {
        let kind = object::FileKind::parse(data).context("Failed to identify Mach-O image")?;
        if kind != object::FileKind::MachO64 {
            bail!("Expected a thin 64-bit Mach-O image (found {kind:?})");
        }
        let file = MachOFile64::<Endianness>::parse(data).context("Failed to parse Mach-O")?;
        let endian = file.endian();
        let segments: Vec<Segment> = file
            .segments()
            .map(|segment| {
                let raw = segment.macho_segment();
                Segment {
                    vmaddr: raw.vmaddr.get(endian),
                    vmsize: raw.vmsize.get(endian),
                    fileoff: raw.fileoff.get(endian),
                    filesize: raw.filesize.get(endian),
                    max_prot: raw.maxprot.get(endian),
                    init_prot: raw.initprot.get(endian),
                    name: raw.segname,
                }
            })
            .collect();
        let preferred_base = segments
            .iter()
            .filter(|segment| segment.fileoff == 0 && segment.filesize != 0)
            .map(|segment| segment.vmaddr)
            .min()
            .context("Mach-O image has no file-backed segment at offset zero")?;
        Ok(Self { data, file, segments, preferred_base })
    }

    pub fn cpu_type(&self) -> u32 { self.file.macho_header().cputype.get(self.file.endian()) }

    pub fn cpu_subtype(&self) -> u32 { self.file.macho_header().cpusubtype.get(self.file.endian()) }

    pub fn platforms(&self) -> Result<Vec<u32>> {
        let endian = self.file.endian();
        let mut platforms = Vec::new();
        let mut commands = self.file.macho_load_commands()?;
        while let Some(command) = commands.next()? {
            if let LoadCommandVariant::BuildVersion(version) = command.variant()? {
                platforms.push(version.platform.get(endian));
            }
        }
        Ok(platforms)
    }

    pub fn segments(&self) -> &[Segment] { &self.segments }

    pub fn preferred_base(&self) -> u64 { self.preferred_base }

    pub fn vm_to_file(&self, vmaddr: u64, size: u64) -> Result<usize> {
        let end = vmaddr.checked_add(size).context("vmaddr range overflows")?;
        for segment in &self.segments {
            let file_end =
                segment.vmaddr.checked_add(segment.filesize).context("Segment range overflows")?;
            if vmaddr >= segment.vmaddr && end <= file_end {
                let offset = segment
                    .fileoff
                    .checked_add(vmaddr - segment.vmaddr)
                    .context("File offset overflows")?;
                return usize::try_from(offset).context("File offset is too large");
            }
        }
        bail!("vmaddr range {vmaddr:#x}..{end:#x} is not file-backed by the main image")
    }

    pub fn bytes_at(&self, vmaddr: u64, size: usize) -> Result<&'data [u8]> {
        let offset = self.vm_to_file(vmaddr, size as u64)?;
        self.data.get(offset..offset + size).context("Mapped vmaddr is outside the file")
    }

    pub fn section_file_range(&self, name: &str) -> Result<Range<usize>> {
        let section = self
            .file
            .section_by_name(name)
            .with_context(|| format!("Mach-O image has no '{name}' section"))?;
        let (offset, size) = section.file_range().context("Mach-O section is not file-backed")?;
        let start = usize::try_from(offset).context("Mach-O section offset is too large")?;
        let size = usize::try_from(size).context("Mach-O section size is too large")?;
        let end = start.checked_add(size).context("Mach-O section range overflows")?;
        if end > self.data.len() {
            bail!("Mach-O section is outside the file");
        }
        Ok(start..end)
    }

    pub fn linkedit_vmaddr(&self) -> Result<u64> {
        self.segments
            .iter()
            .find(|segment| &segment.name == b"__LINKEDIT\0\0\0\0\0\0")
            .map(|segment| segment.vmaddr)
            .context("Mach-O image has no __LINKEDIT segment")
    }

    pub fn contains_vmaddr(&self, vmaddr: u64) -> bool {
        self.segments
            .iter()
            .any(|segment| vmaddr >= segment.vmaddr && vmaddr - segment.vmaddr < segment.vmsize)
    }

    pub fn bindings_in(&self, range: &Range<u64>) -> Result<Vec<(u64, String)>> {
        Ok(self
            .fixups()?
            .into_iter()
            .filter_map(|fixup| match fixup.target {
                FixupTarget::Bind(Some(symbol)) if range.contains(&fixup.location) => {
                    Some((fixup.location, symbol))
                }
                _ => None,
            })
            .collect())
    }

    pub fn rebased_pointer(&self, location: u64) -> Result<u64> {
        let fixup = self
            .fixups()?
            .into_iter()
            .find(|fixup| fixup.location == location)
            .with_context(|| format!("pointer {location:#x} has no supported dyld fixup"))?;
        let target = match fixup.target {
            FixupTarget::Rebase(target) => target,
            FixupTarget::Bind(_) => bail!("pointer {location:#x} is a bind outside the main image"),
        };
        if !self.contains_vmaddr(target) {
            bail!("pointer target {target:#x} is outside the main image");
        }
        Ok(target)
    }

    pub fn fixups(&self) -> Result<Vec<Fixup>> {
        let mut fixups = self.chained_fixups()?;
        fixups.extend(self.classic_fixups()?);
        Ok(fixups)
    }

    fn chained_fixups(&self) -> Result<Vec<Fixup>> {
        let endian = self.file.endian();
        let mut blob = None;
        let mut commands = self.file.macho_load_commands()?;
        while let Some(command) = commands.next()? {
            if command.cmd() == macho::LC_DYLD_CHAINED_FIXUPS
                && let LoadCommandVariant::LinkeditData(linkedit) = command.variant()?
            {
                let start = linkedit.dataoff.get(endian) as usize;
                let size = linkedit.datasize.get(endian) as usize;
                blob = self.data.get(start..start + size);
            }
        }
        let Some(blob) = blob else { return Ok(Vec::new()) };
        if read_u32(blob, 0)? != 0 {
            bail!("Unsupported chained fixups version {}", read_u32(blob, 0)?);
        }
        let starts_offset = read_u32(blob, 4)? as usize;
        let imports_offset = read_u32(blob, 8)? as usize;
        let symbols_offset = read_u32(blob, 12)? as usize;
        let imports_count = read_u32(blob, 16)? as usize;
        let imports_format = read_u32(blob, 20)?;
        if imports_count != 0 && imports_format != 1 {
            log::warn!(
                "Unsupported chained import format {imports_format}; bound symbols unavailable"
            );
        }
        let import_name = |ordinal: usize| -> Option<String> {
            if imports_format != 1 || ordinal >= imports_count {
                return None;
            }
            let raw = read_u32(blob, imports_offset.checked_add(ordinal.checked_mul(4)?)?).ok()?;
            let name = blob.get(symbols_offset.checked_add((raw >> 9) as usize)?..)?;
            let len = name.iter().position(|&byte| byte == 0)?;
            let name = name[..len].strip_prefix(b"_").unwrap_or(&name[..len]);
            Some(String::from_utf8_lossy(name).into_owned())
        };

        let segment_count = read_u32(blob, starts_offset)? as usize;
        if segment_count != self.segments.len() {
            bail!("Chained fixups segment count does not match Mach-O segments");
        }
        let mut fixups = Vec::new();
        for segment_index in 0..segment_count {
            let info_rel = read_u32(blob, starts_offset + 4 + segment_index * 4)? as usize;
            if info_rel == 0 {
                continue;
            }
            let info = starts_offset.checked_add(info_rel).context("Chained offset overflows")?;
            let size = read_u32(blob, info)? as usize;
            let info_end = info.checked_add(size).context("Chained info range overflows")?;
            if size < 22 || info_end > blob.len() {
                bail!("Truncated chained starts-in-segment data");
            }
            let page_size = u64::from(read_u16(blob, info + 4)?);
            let pointer_format = read_u16(blob, info + 6)?;
            if pointer_format != 2 && pointer_format != 6 {
                log::warn!("Unsupported/authenticated chained pointer format {pointer_format}");
                continue;
            }
            let segment_offset = read_u64(blob, info + 8)?;
            let page_count = read_u16(blob, info + 20)? as usize;
            let page_starts_end = info
                .checked_add(22)
                .and_then(|value| value.checked_add(page_count.checked_mul(2)?))
                .context("Chained page-start array overflows")?;
            if page_size == 0 || page_starts_end > info_end {
                bail!("Truncated chained page-start array");
            }
            for page in 0..page_count {
                let page_start = read_u16(blob, info + 22 + page * 2)?;
                if page_start == 0xffff {
                    continue;
                }
                let mut starts = Vec::new();
                if page_start & 0x8000 == 0 {
                    starts.push(page_start);
                } else {
                    let mut extra_index = usize::from(page_start & 0x7fff);
                    loop {
                        let extra_offset = page_starts_end
                            .checked_add(
                                extra_index.checked_mul(2).context("Chained index overflows")?,
                            )
                            .context("Chained index overflows")?;
                        if extra_offset + 2 > info_end {
                            bail!("Truncated chained multi-start array");
                        }
                        let extra = read_u16(blob, extra_offset)?;
                        starts.push(extra & 0x3fff);
                        if extra & 0x8000 != 0 {
                            break;
                        }
                        extra_index =
                            extra_index.checked_add(1).context("Chained index overflows")?;
                    }
                }
                let page_base = self
                    .preferred_base
                    .checked_add(segment_offset)
                    .and_then(|value| value.checked_add(page as u64 * page_size))
                    .context("Chained page address overflows")?;
                let page_end =
                    page_base.checked_add(page_size).context("Chained page overflows")?;
                for start in starts {
                    let mut location = page_base
                        .checked_add(u64::from(start))
                        .context("Chained address overflows")?;
                    loop {
                        if location.checked_add(8).is_none_or(|end| end > page_end) {
                            bail!("Chained pointer escapes its page");
                        }
                        let raw =
                            u64::from_le_bytes(self.bytes_at(location, 8)?.try_into().unwrap());
                        let target = if raw >> 63 != 0 {
                            FixupTarget::Bind(import_name((raw & 0x00ff_ffff) as usize))
                        } else {
                            let low36 = raw & 0x0000_000f_ffff_ffff;
                            let target_bits = low36 | (((raw >> 36) & 0xff) << 56);
                            let target = if pointer_format == 2 {
                                target_bits
                            } else {
                                self.preferred_base
                                    .checked_add(target_bits)
                                    .context("Chained rebase target overflows")?
                            };
                            FixupTarget::Rebase(target)
                        };
                        fixups.push(Fixup { location, target });
                        let next = (raw >> 51) & 0xfff;
                        if next == 0 {
                            break;
                        }
                        location = location
                            .checked_add(next * 4)
                            .context("Chained pointer address overflows")?;
                    }
                }
            }
        }
        Ok(fixups)
    }

    fn classic_fixups(&self) -> Result<Vec<Fixup>> {
        let endian = self.file.endian();
        let mut fixups = Vec::new();
        let mut commands = self.file.macho_load_commands()?;
        while let Some(command) = commands.next()? {
            if let LoadCommandVariant::DyldInfo(info) = command.variant()? {
                let rebase_off = info.rebase_off.get(endian) as usize;
                let rebase_size = info.rebase_size.get(endian) as usize;
                if rebase_size != 0 {
                    let stream = self
                        .data
                        .get(rebase_off..rebase_off + rebase_size)
                        .context("Classic rebase stream is outside the file")?;
                    for location in parse_rebase_opcodes(stream, &self.segments)? {
                        let target =
                            u64::from_le_bytes(self.bytes_at(location, 8)?.try_into().unwrap());
                        fixups.push(Fixup { location, target: FixupTarget::Rebase(target) });
                    }
                }
                for (off, size) in [
                    (info.bind_off.get(endian), info.bind_size.get(endian)),
                    (info.weak_bind_off.get(endian), info.weak_bind_size.get(endian)),
                    (info.lazy_bind_off.get(endian), info.lazy_bind_size.get(endian)),
                ] {
                    if size != 0 {
                        let stream = self
                            .data
                            .get(off as usize..(off + size) as usize)
                            .context("Classic bind stream is outside the file")?;
                        fixups.extend(parse_bind_opcodes(stream, &self.segments)?);
                    }
                }
            }
        }
        Ok(fixups)
    }
}

fn read_u16(blob: &[u8], off: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        blob.get(off..off + 2).context("Truncated chained fixups")?.try_into().unwrap(),
    ))
}

fn read_u64(blob: &[u8], off: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        blob.get(off..off + 8).context("Truncated chained fixups")?.try_into().unwrap(),
    ))
}

fn read_uleb(stream: &[u8], pos: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *stream.get(*pos).context("Truncated uleb128")?;
        *pos += 1;
        value |= u64::from(byte & 0x7f).checked_shl(shift).context("uleb128 overflows")?;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift = shift.checked_add(7).context("uleb128 overflows")?;
        if shift >= 64 {
            bail!("uleb128 overflows");
        }
    }
}

fn parse_rebase_opcodes(stream: &[u8], segments: &[Segment]) -> Result<Vec<u64>> {
    let mut pos = 0usize;
    let mut address = 0u64;
    let mut rebases = Vec::new();
    while pos < stream.len() {
        let byte = stream[pos];
        pos += 1;
        let immediate = u64::from(byte & 0x0f);
        match byte & 0xf0 {
            0x00 => break,
            0x10 if immediate == 1 => {}
            0x10 => bail!("Unsupported dyld rebase type {immediate}"),
            0x20 => {
                address = segments
                    .get(immediate as usize)
                    .context("Rebase segment index is out of range")?
                    .vmaddr
                    .checked_add(read_uleb(stream, &mut pos)?)
                    .context("Rebase address overflows")?;
            }
            0x30 => {
                address = address
                    .checked_add(read_uleb(stream, &mut pos)?)
                    .context("Rebase address overflows")?
            }
            0x40 => {
                address = address.checked_add(immediate * 8).context("Rebase address overflows")?
            }
            0x50 => record_rebases(&mut rebases, &mut address, immediate, 0)?,
            0x60 => {
                let count = read_uleb(stream, &mut pos)?;
                record_rebases(&mut rebases, &mut address, count, 0)?;
            }
            0x70 => {
                let skip = read_uleb(stream, &mut pos)?;
                record_rebases(&mut rebases, &mut address, 1, skip)?;
            }
            0x80 => {
                let count = read_uleb(stream, &mut pos)?;
                let skip = read_uleb(stream, &mut pos)?;
                record_rebases(&mut rebases, &mut address, count, skip)?;
            }
            opcode => bail!("Unsupported dyld rebase opcode {opcode:#x}"),
        }
    }
    Ok(rebases)
}

fn record_rebases(rebases: &mut Vec<u64>, address: &mut u64, count: u64, skip: u64) -> Result<()> {
    for _ in 0..count {
        rebases.push(*address);
        *address = address.checked_add(8 + skip).context("Rebase address overflows")?;
    }
    Ok(())
}

fn parse_bind_opcodes(stream: &[u8], segments: &[Segment]) -> Result<Vec<Fixup>> {
    let mut pos = 0usize;
    let mut symbol = String::new();
    let mut address = 0u64;
    let mut fixups = Vec::new();
    while pos < stream.len() {
        let byte = stream[pos];
        pos += 1;
        let immediate = u64::from(byte & 0x0f);
        match byte & 0xf0 {
            0x00 | 0x10 | 0x30 | 0x50 => {}
            0x20 => {
                read_uleb(stream, &mut pos)?;
            }
            0x40 => {
                let rest = &stream[pos..];
                let len =
                    rest.iter().position(|&byte| byte == 0).context("Unterminated bind symbol")?;
                symbol = String::from_utf8_lossy(&rest[..len]).into_owned();
                pos += len + 1;
            }
            0x60 => {
                while *stream.get(pos).context("Truncated sleb128")? & 0x80 != 0 {
                    pos += 1;
                }
                pos += 1;
            }
            0x70 => {
                address = segments
                    .get(immediate as usize)
                    .context("Bind segment index is out of range")?
                    .vmaddr
                    .checked_add(read_uleb(stream, &mut pos)?)
                    .context("Bind address overflows")?;
            }
            0x80 => {
                address = address
                    .checked_add(read_uleb(stream, &mut pos)?)
                    .context("Bind address overflows")?;
            }
            0x90 => record_bind(&mut fixups, &mut address, &symbol, 0)?,
            0xa0 => {
                let skip = read_uleb(stream, &mut pos)?;
                record_bind(&mut fixups, &mut address, &symbol, skip)?;
            }
            0xb0 => record_bind(&mut fixups, &mut address, &symbol, immediate * 8)?,
            0xc0 => {
                let count = read_uleb(stream, &mut pos)?;
                let skip = read_uleb(stream, &mut pos)?;
                for _ in 0..count {
                    record_bind(&mut fixups, &mut address, &symbol, skip)?;
                }
            }
            opcode => bail!("Unsupported dyld bind opcode {opcode:#x}"),
        }
    }
    Ok(fixups)
}

fn record_bind(fixups: &mut Vec<Fixup>, address: &mut u64, symbol: &str, skip: u64) -> Result<()> {
    let symbol =
        (!symbol.is_empty()).then(|| symbol.strip_prefix('_').unwrap_or(symbol).to_string());
    fixups.push(Fixup { location: *address, target: FixupTarget::Bind(symbol) });
    *address = address.checked_add(8 + skip).context("Bind address overflows")?;
    Ok(())
}

#[derive(Clone, Debug)]
pub struct SectionSpec {
    pub name: &'static str,
    pub offset: u64,
    pub size: u64,
    pub align: u32,
    pub flags: u32,
}

#[derive(Clone, Debug)]
pub struct SegmentSpec {
    pub name: String,
    pub data: Vec<u8>,
    pub max_prot: u32,
    pub init_prot: u32,
    pub sections: Vec<SectionSpec>,
}

#[derive(Clone, Copy, Debug)]
pub struct InsertedSegment {
    pub vmaddr: u64,
    pub fileoff: u64,
    pub filesize: u64,
}

pub struct InsertResult {
    pub data: Vec<u8>,
    pub segments: Vec<InsertedSegment>,
}

fn align_up(value: u64, align: u64) -> Result<u64> {
    let align = align.max(1);
    let remainder = value % align;
    if remainder == 0 {
        Ok(value)
    } else {
        value.checked_add(align - remainder).context("Aligned size overflows")
    }
}

fn fixed_name(name: &str) -> Result<[u8; 16]> {
    if name.len() > 16 || !name.is_ascii() {
        bail!("Mach-O name '{name}' must be at most 16 ASCII bytes");
    }
    let mut result = [0u8; 16];
    result[..name.len()].copy_from_slice(name.as_bytes());
    Ok(result)
}

/// Remove a trailing embedded code signature from a thin 64-bit Mach-O image.
pub fn remove_code_signature(mut data: Vec<u8>) -> Result<Vec<u8>> {
    use object::{
        macho::{LC_CODE_SIGNATURE, LC_SEGMENT_64, MH_MAGIC_64, MachHeader64, SegmentCommand64},
        pod::{from_bytes, from_bytes_mut},
    };

    const HEADER_SIZE: usize = size_of::<MachHeader64<LE>>();

    let header = {
        let (header, _) = from_bytes::<MachHeader64<LE>>(&data)
            .map_err(|_| anyhow::anyhow!("Truncated Mach-O header"))?;
        *header
    };
    if data.len() < 4 || u32::from_le_bytes(data[..4].try_into().unwrap()) != MH_MAGIC_64 {
        bail!("Not a little-endian 64-bit Mach-O image");
    }
    let ncmds = header.ncmds.get(LE) as usize;
    let sizeofcmds = header.sizeofcmds.get(LE) as usize;
    let cmds_end =
        HEADER_SIZE.checked_add(sizeofcmds).context("Mach-O load-command size overflows")?;
    if cmds_end > data.len() {
        bail!("Mach-O load commands extend past the end of the file");
    }

    let mut linkedit = None; // command offset, fileoff, filesize
    let mut signature = None; // command offset, command size, dataoff, datasize
    let mut offset = HEADER_SIZE;
    for _ in 0..ncmds {
        let lc = data.get(offset..offset + 8).context("Truncated Mach-O load commands")?;
        let cmd = u32::from_le_bytes(lc[..4].try_into().unwrap());
        let cmdsize = u32::from_le_bytes(lc[4..8].try_into().unwrap()) as usize;
        if cmdsize < 8 || offset + cmdsize > cmds_end {
            bail!("Bad Mach-O load command size at {offset:#x}");
        }
        match cmd {
            LC_SEGMENT_64 => {
                let (segment, _) =
                    from_bytes::<SegmentCommand64<LE>>(&data[offset..offset + cmdsize])
                        .map_err(|_| anyhow::anyhow!("Truncated segment command"))?;
                if &segment.segname == b"__LINKEDIT\0\0\0\0\0\0" {
                    if linkedit.is_some() {
                        bail!("Mach-O image has multiple __LINKEDIT segments");
                    }
                    linkedit = Some((offset, segment.fileoff.get(LE), segment.filesize.get(LE)));
                }
            }
            LC_CODE_SIGNATURE => {
                if signature.is_some() {
                    bail!("Mach-O image has multiple LC_CODE_SIGNATURE commands");
                }
                let (command, _) = from_bytes::<object::macho::LinkeditDataCommand<LE>>(
                    &data[offset..offset + cmdsize],
                )
                .map_err(|_| anyhow::anyhow!("Truncated code-signature command"))?;
                signature = Some((
                    offset,
                    cmdsize,
                    u64::from(command.dataoff.get(LE)),
                    u64::from(command.datasize.get(LE)),
                ));
            }
            _ => {}
        }
        offset += cmdsize;
    }
    let Some((signature_command_off, signature_command_size, signature_fileoff, signature_size)) =
        signature
    else {
        return Ok(data);
    };
    let (linkedit_command_off, linkedit_fileoff, linkedit_filesize) =
        linkedit.context("Mach-O image has a code signature but no __LINKEDIT segment")?;
    if signature_fileoff == 0 || signature_size == 0 {
        bail!("Mach-O code signature has an empty file range");
    }
    let signature_end =
        signature_fileoff.checked_add(signature_size).context("Code-signature range overflows")?;
    let linkedit_end =
        linkedit_fileoff.checked_add(linkedit_filesize).context("__LINKEDIT range overflows")?;
    if signature_fileoff < linkedit_fileoff || signature_end > linkedit_end {
        bail!("Mach-O code signature is outside __LINKEDIT");
    }
    if signature_end != data.len() as u64 || linkedit_end != data.len() as u64 {
        bail!("Mach-O code signature is not the final data in __LINKEDIT");
    }

    let new_linkedit_size = signature_fileoff - linkedit_fileoff;
    {
        let (segment, _) = from_bytes_mut::<SegmentCommand64<LE>>(
            &mut data
                [linkedit_command_off..linkedit_command_off + size_of::<SegmentCommand64<LE>>()],
        )
        .map_err(|_| anyhow::anyhow!("Truncated __LINKEDIT command"))?;
        segment.filesize.set(LE, new_linkedit_size);
    }

    data.copy_within(
        signature_command_off + signature_command_size..cmds_end,
        signature_command_off,
    );
    data[cmds_end - signature_command_size..cmds_end].fill(0);
    {
        let (header, _) = from_bytes_mut::<MachHeader64<LE>>(&mut data)
            .map_err(|_| anyhow::anyhow!("Truncated Mach-O header"))?;
        header.ncmds.set(
            LE,
            header.ncmds.get(LE).checked_sub(1).context("Mach-O command count underflows")?,
        );
        header.sizeofcmds.set(
            LE,
            header
                .sizeofcmds
                .get(LE)
                .checked_sub(
                    u32::try_from(signature_command_size)
                        .context("Code-signature command size exceeds u32")?,
                )
                .context("Mach-O load-command size underflows")?,
        );
    }
    data.truncate(
        usize::try_from(signature_fileoff).context("Code-signature offset exceeds host space")?,
    );
    Ok(data)
}

fn read_u32(blob: &[u8], off: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        blob.get(off..off + 4).context("Truncated chained fixups")?.try_into().unwrap(),
    ))
}

/// Add adjacent fixup-free segment entries to dyld's starts-in-image table in one operation.
/// The offset array and its trailing alignment are grown by the exact required byte count.
fn grow_chained_fixups(
    blob: &[u8],
    insert_index: usize,
    add_count: usize,
    segment_count: usize,
) -> Result<(Vec<u8>, usize)> {
    if read_u32(blob, 0)? != 0 {
        bail!("Unknown chained fixups version {}", read_u32(blob, 0)?);
    }
    let starts_offset = read_u32(blob, 4)? as usize;
    if starts_offset < 28 {
        bail!("Chained fixups starts_offset {starts_offset:#x} overlaps the header");
    }
    let old_count = read_u32(blob, starts_offset)? as usize;
    if old_count != segment_count {
        bail!("Chained fixups seg_count {old_count} does not match {segment_count} segments");
    }
    if insert_index > old_count {
        bail!("Segment index {insert_index} is out of range for {old_count} segments");
    }

    let old_array_size = 4usize
        .checked_add(old_count.checked_mul(4).context("Chained fixups array size overflows")?)
        .context("Chained fixups array size overflows")?;
    let old_relative_tail = usize::try_from(align_up(old_array_size as u64, 8)?)
        .context("Chained fixups array size is too large")?;
    let new_count =
        old_count.checked_add(add_count).context("Chained fixups segment count overflows")?;
    let new_count_u32 =
        u32::try_from(new_count).context("Chained fixups segment count exceeds u32")?;
    let new_array_size = 4usize
        .checked_add(new_count.checked_mul(4).context("Chained fixups array size overflows")?)
        .context("Chained fixups array size overflows")?;
    let new_relative_tail = usize::try_from(align_up(new_array_size as u64, 8)?)
        .context("Chained fixups array size is too large")?;
    let growth = new_relative_tail - old_relative_tail;
    let old_tail =
        starts_offset.checked_add(old_relative_tail).context("Chained fixups offset overflows")?;
    let new_tail =
        starts_offset.checked_add(new_relative_tail).context("Chained fixups offset overflows")?;
    if old_tail > blob.len() {
        bail!("Truncated chained fixups segment-offset array");
    }

    let mut out = Vec::with_capacity(
        blob.len().checked_add(growth).context("Chained fixups output size overflows")?,
    );
    out.extend_from_slice(&blob[..starts_offset]);
    out.extend_from_slice(&new_count_u32.to_le_bytes());
    for new_index in 0..new_count {
        let old_index = if new_index < insert_index {
            Some(new_index)
        } else if new_index < insert_index + add_count {
            None
        } else {
            Some(new_index - add_count)
        };
        let mut value = match old_index {
            Some(index) => read_u32(blob, starts_offset + 4 + index * 4)?,
            None => 0,
        };
        if value != 0 {
            if (value as usize) < old_relative_tail {
                bail!("Chained fixups seg_info_offset {value:#x} points into its offset array");
            }
            value = value
                .checked_add(u32::try_from(growth).context("Chained fixups growth exceeds u32")?)
                .context("Chained fixups seg_info_offset overflows")?;
        }
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.resize(new_tail, 0);
    out.extend_from_slice(&blob[old_tail..]);

    // imports_offset and symbols_offset are header-relative pointers into the shifted tail.
    for field in [8usize, 12] {
        let value = read_u32(blob, field)?;
        if value != 0 {
            if (value as usize) < old_tail {
                bail!("Chained fixups table offset {value:#x} precedes the segment array tail");
            }
            out[field..field + 4].copy_from_slice(
                &value
                    .checked_add(
                        u32::try_from(growth).context("Chained fixups growth exceeds u32")?,
                    )
                    .context("Chained fixups table offset overflows")?
                    .to_le_bytes(),
            );
        }
    }
    Ok((out, growth))
}

/// Insert fixup-free segments immediately before `__LINKEDIT` in a thin 64-bit Mach-O image.
pub fn insert_segments(mut data: Vec<u8>, specs: &[SegmentSpec]) -> Result<InsertResult> {
    use object::{
        macho::{
            LC_CODE_SIGNATURE, LC_DATA_IN_CODE, LC_DYLD_CHAINED_FIXUPS, LC_DYLD_ENVIRONMENT,
            LC_DYLD_EXPORTS_TRIE, LC_DYLD_INFO, LC_DYLD_INFO_ONLY, LC_DYLIB_CODE_SIGN_DRS,
            LC_DYSYMTAB, LC_ENCRYPTION_INFO_64, LC_FUNCTION_STARTS, LC_ID_DYLIB,
            LC_LINKER_OPTIMIZATION_HINT, LC_LOAD_DYLIB, LC_LOAD_DYLINKER, LC_LOAD_UPWARD_DYLIB,
            LC_LOAD_WEAK_DYLIB, LC_MAIN, LC_REEXPORT_DYLIB, LC_RPATH, LC_SEGMENT_64,
            LC_SEGMENT_SPLIT_INFO, LC_SOURCE_VERSION, LC_SYMTAB, LC_UUID, LC_VERSION_MIN_MACOSX,
            MH_MAGIC_64, MachHeader64, Section64, SegmentCommand64,
        },
        pod::{from_bytes, from_bytes_mut, slice_from_bytes},
    };

    const LC_BUILD_VERSION: u32 = 0x32;
    const LC_ATOM_INFO: u32 = 0x36;
    const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
    const LC_VERSION_MIN_TVOS: u32 = 0x2f;
    const HEADER_SIZE: usize = size_of::<MachHeader64<LE>>();

    if specs.is_empty() {
        return Ok(InsertResult { data, segments: Vec::new() });
    }
    let header = {
        let (header, _) = from_bytes::<MachHeader64<LE>>(&data)
            .map_err(|_| anyhow::anyhow!("Truncated Mach-O header"))?;
        *header
    };
    if data.len() < 4 || u32::from_le_bytes(data[..4].try_into().unwrap()) != MH_MAGIC_64 {
        bail!("Not a little-endian 64-bit Mach-O image");
    }
    let page = match header.cputype.get(LE) {
        object::macho::CPU_TYPE_X86_64 => 0x1000,
        _ => 0x4000,
    };
    let ncmds = header.ncmds.get(LE) as usize;
    let sizeofcmds = header.sizeofcmds.get(LE) as usize;
    let cmds_end =
        HEADER_SIZE.checked_add(sizeofcmds).context("Mach-O load-command size overflows")?;

    let requested_names: Vec<[u8; 16]> =
        specs.iter().map(|spec| fixed_name(&spec.name)).collect::<Result<_>>()?;
    let mut new_lc_size = 0usize;
    for spec in specs {
        let size = size_of::<SegmentCommand64<LE>>()
            .checked_add(
                spec.sections
                    .len()
                    .checked_mul(size_of::<Section64<LE>>())
                    .context("Mach-O section-command size overflows")?,
            )
            .context("Mach-O segment-command size overflows")?;
        new_lc_size = new_lc_size.checked_add(size).context("Load-command size overflows")?;
    }

    let mut linkedit = None; // command offset, vmaddr, fileoff, filesize
    let mut linkedit_segment_index = 0usize;
    let mut fixups = None; // dataoff, datasize
    let mut minimum_content = u64::MAX;
    let mut segment_count = 0usize;
    let mut saw_linkedit = false;
    let mut offset = HEADER_SIZE;
    for _ in 0..ncmds {
        let lc = data.get(offset..offset + 8).context("Truncated Mach-O load commands")?;
        let cmd = u32::from_le_bytes(lc[..4].try_into().unwrap());
        let cmdsize = u32::from_le_bytes(lc[4..8].try_into().unwrap()) as usize;
        if cmdsize < 8 || offset + cmdsize > cmds_end {
            bail!("Bad Mach-O load command size at {offset:#x}");
        }
        match cmd {
            LC_SEGMENT_64 => {
                let (segment, _) =
                    from_bytes::<SegmentCommand64<LE>>(&data[offset..offset + cmdsize])
                        .map_err(|_| anyhow::anyhow!("Truncated segment command"))?;
                if requested_names.contains(&segment.segname) {
                    let name = String::from_utf8_lossy(&segment.segname);
                    bail!("Image already has segment {}", name.trim_end_matches('\0'));
                }
                if &segment.segname == b"__LINKEDIT\0\0\0\0\0\0" {
                    linkedit_segment_index = segment_count;
                    linkedit = Some((
                        offset,
                        segment.vmaddr.get(LE),
                        segment.fileoff.get(LE),
                        segment.filesize.get(LE),
                    ));
                    saw_linkedit = true;
                } else if saw_linkedit {
                    bail!("__LINKEDIT is not the last Mach-O segment");
                }
                segment_count += 1;
                let section_count = segment.nsects.get(LE) as usize;
                let sections_off = offset + size_of::<SegmentCommand64<LE>>();
                let (sections, _) = slice_from_bytes::<Section64<LE>>(
                    data.get(sections_off..offset + cmdsize)
                        .context("Truncated section commands")?,
                    section_count,
                )
                .map_err(|_| anyhow::anyhow!("Truncated section commands"))?;
                for section in sections {
                    if section.offset.get(LE) != 0 {
                        minimum_content = minimum_content.min(u64::from(section.offset.get(LE)));
                    }
                }
            }
            LC_DYLD_CHAINED_FIXUPS => {
                let (command, _) = from_bytes::<object::macho::LinkeditDataCommand<LE>>(
                    &data[offset..offset + cmdsize],
                )
                .map_err(|_| anyhow::anyhow!("Truncated chained-fixups command"))?;
                fixups =
                    Some((u64::from(command.dataoff.get(LE)), u64::from(command.datasize.get(LE))));
            }
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
            LC_UUID
            | LC_BUILD_VERSION
            | LC_VERSION_MIN_MACOSX
            | LC_VERSION_MIN_IPHONEOS
            | LC_VERSION_MIN_TVOS
            | LC_SOURCE_VERSION
            | LC_MAIN
            | LC_LOAD_DYLINKER
            | LC_DYLD_ENVIRONMENT
            | LC_ID_DYLIB
            | LC_LOAD_DYLIB
            | LC_LOAD_WEAK_DYLIB
            | LC_REEXPORT_DYLIB
            | LC_LOAD_UPWARD_DYLIB
            | LC_RPATH
            | LC_ENCRYPTION_INFO_64 => {}
            _ => bail!("Unhandled load command {cmd:#x}; refusing to relayout the image"),
        }
        offset += cmdsize;
    }

    let (linkedit_command_off, linkedit_vmaddr, linkedit_fileoff, linkedit_filesize) =
        linkedit.context("Image has no __LINKEDIT segment")?;
    if linkedit_fileoff % page != 0 || linkedit_vmaddr % page != 0 {
        bail!("__LINKEDIT is not page-aligned");
    }
    let required_end =
        cmds_end.checked_add(new_lc_size).context("Mach-O load-command size overflows")?;
    if required_end > minimum_content as usize {
        let available = (minimum_content as usize).saturating_sub(cmds_end);
        bail!(
            "Insufficient load-command headroom: need {new_lc_size} bytes, have {available}; \
             increase -headerpad by at least {} bytes",
            new_lc_size - available
        );
    }
    if !data
        .get(cmds_end..required_end)
        .context("Load-command headroom is outside the file")?
        .iter()
        .all(|&byte| byte == 0)
    {
        bail!("Mach-O load-command headroom is not zero-filled padding");
    }

    let mut inserted = Vec::with_capacity(specs.len());
    let mut delta = 0u64;
    for spec in specs {
        if spec.data.is_empty() {
            bail!("Segment {} cannot be empty", spec.name);
        }
        let filesize = align_up(spec.data.len() as u64, page)?;
        let placement = InsertedSegment {
            vmaddr: linkedit_vmaddr
                .checked_add(delta)
                .context("Inserted segment vmaddr overflows")?,
            fileoff: linkedit_fileoff
                .checked_add(delta)
                .context("Inserted segment file offset overflows")?,
            filesize,
        };
        for section in &spec.sections {
            let end =
                section.offset.checked_add(section.size).context("Section range overflows")?;
            if end > spec.data.len() as u64 {
                bail!("Section {},{} exceeds its segment data", spec.name, section.name);
            }
            let alignment =
                1u64.checked_shl(section.align).context("Section alignment is too large")?;
            let section_vmaddr =
                placement.vmaddr.checked_add(section.offset).context("Section vmaddr overflows")?;
            let section_fileoff = placement
                .fileoff
                .checked_add(section.offset)
                .context("Section file offset overflows")?;
            if section_vmaddr % alignment != 0 || section_fileoff % alignment != 0 {
                bail!("Section {},{} is not correctly aligned", spec.name, section.name);
            }
        }
        inserted.push(placement);
        delta = delta.checked_add(filesize).context("Inserted segment sizes overflow")?;
    }

    let (new_fixups, fixups_growth) = match fixups {
        Some((dataoff, datasize)) => {
            let start = usize::try_from(dataoff).context("Chained-fixups offset is too large")?;
            let end = usize::try_from(
                dataoff.checked_add(datasize).context("Chained-fixups range overflows")?,
            )
            .context("Chained-fixups range is too large")?;
            let (blob, growth) = grow_chained_fixups(
                data.get(start..end).context("Chained fixups are outside the file")?,
                linkedit_segment_index,
                specs.len(),
                segment_count,
            )?;
            (Some(blob), growth as u64)
        }
        None => (None, 0),
    };
    let fixups_end = match fixups {
        Some((off, size)) => off.checked_add(size).context("Chained-fixups range overflows")?,
        None => u64::MAX,
    };

    let shift = |field: &mut U32<LE>| -> Result<()> {
        let value = u64::from(field.get(LE));
        if value != 0 {
            let growth = if value >= fixups_end { fixups_growth } else { 0 };
            let shifted = value
                .checked_add(delta)
                .and_then(|v| v.checked_add(growth))
                .context("Mach-O file offset overflows")?;
            field.set(LE, u32::try_from(shifted).context("Mach-O file offset exceeds u32")?);
        }
        Ok(())
    };

    let mut offset = HEADER_SIZE;
    for _ in 0..ncmds {
        let cmd = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        let cmdsize = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap()) as usize;
        let body = &mut data[offset..offset + cmdsize];
        match cmd {
            LC_SYMTAB => {
                let (command, _) = from_bytes_mut::<object::macho::SymtabCommand<LE>>(body)
                    .map_err(|_| anyhow::anyhow!("Truncated symtab command"))?;
                shift(&mut command.symoff)?;
                shift(&mut command.stroff)?;
            }
            LC_DYSYMTAB => {
                let (command, _) = from_bytes_mut::<object::macho::DysymtabCommand<LE>>(body)
                    .map_err(|_| anyhow::anyhow!("Truncated dysymtab command"))?;
                shift(&mut command.tocoff)?;
                shift(&mut command.modtaboff)?;
                shift(&mut command.extrefsymoff)?;
                shift(&mut command.indirectsymoff)?;
                shift(&mut command.extreloff)?;
                shift(&mut command.locreloff)?;
            }
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                let (command, _) = from_bytes_mut::<object::macho::DyldInfoCommand<LE>>(body)
                    .map_err(|_| anyhow::anyhow!("Truncated dyld-info command"))?;
                shift(&mut command.rebase_off)?;
                shift(&mut command.bind_off)?;
                shift(&mut command.weak_bind_off)?;
                shift(&mut command.lazy_bind_off)?;
                shift(&mut command.export_off)?;
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
                let (command, _) =
                    from_bytes_mut::<object::macho::LinkeditDataCommand<LE>>(body)
                        .map_err(|_| anyhow::anyhow!("Truncated linkedit-data command"))?;
                shift(&mut command.dataoff)?;
                if cmd == LC_DYLD_CHAINED_FIXUPS {
                    command.datasize.set(
                        LE,
                        command
                            .datasize
                            .get(LE)
                            .checked_add(fixups_growth as u32)
                            .context("Chained-fixups size overflows")?,
                    );
                }
            }
            _ => {}
        }
        offset += cmdsize;
    }

    {
        let (segment, _) = from_bytes_mut::<SegmentCommand64<LE>>(
            &mut data
                [linkedit_command_off..linkedit_command_off + size_of::<SegmentCommand64<LE>>()],
        )
        .map_err(|_| anyhow::anyhow!("Truncated __LINKEDIT command"))?;
        segment
            .vmaddr
            .set(LE, linkedit_vmaddr.checked_add(delta).context("__LINKEDIT vmaddr overflows")?);
        segment
            .fileoff
            .set(LE, linkedit_fileoff.checked_add(delta).context("__LINKEDIT fileoff overflows")?);
        let filesize =
            linkedit_filesize.checked_add(fixups_growth).context("__LINKEDIT size overflows")?;
        segment.filesize.set(LE, filesize);
        segment.vmsize.set(LE, segment.vmsize.get(LE).max(align_up(filesize, page)?));
    }

    let mut commands = Vec::with_capacity(new_lc_size);
    for ((spec, placement), segment_name) in specs.iter().zip(&inserted).zip(&requested_names) {
        let command_size =
            size_of::<SegmentCommand64<LE>>() + spec.sections.len() * size_of::<Section64<LE>>();
        let command_size = u32::try_from(command_size).context("Segment command exceeds u32")?;
        let section_count =
            u32::try_from(spec.sections.len()).context("Segment section count exceeds u32")?;
        let segment = SegmentCommand64::<LE> {
            cmd: U32::new(LE, LC_SEGMENT_64),
            cmdsize: U32::new(LE, command_size),
            segname: *segment_name,
            vmaddr: U64::new(LE, placement.vmaddr),
            vmsize: U64::new(LE, placement.filesize),
            fileoff: U64::new(LE, placement.fileoff),
            filesize: U64::new(LE, placement.filesize),
            maxprot: U32::new(LE, spec.max_prot),
            initprot: U32::new(LE, spec.init_prot),
            nsects: U32::new(LE, section_count),
            flags: U32::new(LE, 0),
        };
        commands.extend_from_slice(bytes_of(&segment));
        for section in &spec.sections {
            let section_vmaddr =
                placement.vmaddr.checked_add(section.offset).context("Section vmaddr overflows")?;
            let section_fileoff = placement
                .fileoff
                .checked_add(section.offset)
                .context("Section file offset overflows")?;
            let section = Section64::<LE> {
                sectname: fixed_name(section.name)?,
                segname: *segment_name,
                addr: U64::new(LE, section_vmaddr),
                size: U64::new(LE, section.size),
                offset: U32::new(
                    LE,
                    u32::try_from(section_fileoff).context("Section file offset exceeds u32")?,
                ),
                align: U32::new(LE, section.align),
                reloff: U32::new(LE, 0),
                nreloc: U32::new(LE, 0),
                flags: U32::new(LE, section.flags),
                reserved1: U32::new(LE, 0),
                reserved2: U32::new(LE, 0),
                reserved3: U32::new(LE, 0),
            };
            commands.extend_from_slice(bytes_of(&section));
        }
    }
    debug_assert_eq!(commands.len(), new_lc_size);
    data.copy_within(linkedit_command_off..cmds_end, linkedit_command_off + new_lc_size);
    data[linkedit_command_off..linkedit_command_off + new_lc_size].copy_from_slice(&commands);
    {
        let (header, _) = from_bytes_mut::<MachHeader64<LE>>(&mut data)
            .map_err(|_| anyhow::anyhow!("Truncated Mach-O header"))?;
        header.ncmds.set(
            LE,
            header
                .ncmds
                .get(LE)
                .checked_add(
                    u32::try_from(specs.len()).context("Inserted segment count exceeds u32")?,
                )
                .context("Mach-O command count overflows")?,
        );
        header.sizeofcmds.set(
            LE,
            header
                .sizeofcmds
                .get(LE)
                .checked_add(u32::try_from(new_lc_size).context("Load-command growth exceeds u32")?)
                .context("Mach-O load-command size overflows")?,
        );
    }

    let output_growth = usize::try_from(
        delta.checked_add(fixups_growth).context("Mach-O output growth overflows")?,
    )
    .context("Mach-O output growth exceeds host address space")?;
    let mut out = Vec::with_capacity(
        data.len().checked_add(output_growth).context("Mach-O output size overflows")?,
    );
    let linkedit_fileoff = usize::try_from(linkedit_fileoff)
        .context("__LINKEDIT offset exceeds host address space")?;
    out.extend_from_slice(
        data.get(..linkedit_fileoff).context("__LINKEDIT offset is outside the file")?,
    );
    for (spec, placement) in specs.iter().zip(&inserted) {
        debug_assert_eq!(out.len(), placement.fileoff as usize);
        out.extend_from_slice(&spec.data);
        let segment_end = placement
            .fileoff
            .checked_add(placement.filesize)
            .and_then(|value| usize::try_from(value).ok())
            .context("Inserted segment end exceeds host address space")?;
        out.resize(segment_end, 0);
    }
    match (new_fixups, fixups) {
        (Some(blob), Some((dataoff, datasize))) => {
            let dataoff = usize::try_from(dataoff).context("Fixups offset is too large")?;
            let dataend = u64::try_from(dataoff)
                .ok()
                .and_then(|start| start.checked_add(datasize))
                .and_then(|end| usize::try_from(end).ok())
                .context("Fixups range is too large")?;
            out.extend_from_slice(
                data.get(linkedit_fileoff..dataoff)
                    .context("Fixups precede __LINKEDIT or are outside the file")?,
            );
            out.extend_from_slice(&blob);
            out.extend_from_slice(data.get(dataend..).context("Fixups are outside the file")?);
        }
        _ => out.extend_from_slice(
            data.get(linkedit_fileoff..).context("__LINKEDIT offset is outside the file")?,
        ),
    }
    Ok(InsertResult { data: out, segments: inserted })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PAGE: u64 = 0x4000;

    fn segment_command(
        name: &[u8],
        vmaddr: u64,
        fileoff: u64,
        filesize: u64,
        protection: u32,
    ) -> macho::SegmentCommand64<LE> {
        let mut segname = [0u8; 16];
        segname[..name.len()].copy_from_slice(name);
        macho::SegmentCommand64 {
            cmd: U32::new(LE, macho::LC_SEGMENT_64),
            cmdsize: U32::new(LE, size_of::<macho::SegmentCommand64<LE>>() as u32),
            segname,
            vmaddr: U64::new(LE, vmaddr),
            vmsize: U64::new(LE, TEST_PAGE),
            fileoff: U64::new(LE, fileoff),
            filesize: U64::new(LE, filesize),
            maxprot: U32::new(LE, protection),
            initprot: U32::new(LE, protection),
            nsects: U32::new(LE, 0),
            flags: U32::new(LE, 0),
        }
    }

    fn signed_image() -> Vec<u8> {
        let command_size = 2 * size_of::<macho::SegmentCommand64<LE>>()
            + size_of::<macho::LinkeditDataCommand<LE>>();
        let header = macho::MachHeader64::<LE> {
            magic: U32::new(object::BigEndian, macho::MH_CIGAM_64),
            cputype: U32::new(LE, macho::CPU_TYPE_ARM64),
            cpusubtype: U32::new(LE, macho::CPU_SUBTYPE_ARM64_ALL),
            filetype: U32::new(LE, macho::MH_EXECUTE),
            ncmds: U32::new(LE, 3),
            sizeofcmds: U32::new(LE, command_size as u32),
            flags: U32::new(LE, macho::MH_NOUNDEFS | macho::MH_DYLDLINK | macho::MH_PIE),
            reserved: U32::new(LE, 0),
        };
        let text = segment_command(
            b"__TEXT",
            0x1_0000_0000,
            0,
            TEST_PAGE,
            macho::VM_PROT_READ | macho::VM_PROT_EXECUTE,
        );
        let linkedit = segment_command(
            b"__LINKEDIT",
            0x1_0000_0000 + TEST_PAGE,
            TEST_PAGE,
            32,
            macho::VM_PROT_READ,
        );
        let signature = macho::LinkeditDataCommand::<LE> {
            cmd: U32::new(LE, macho::LC_CODE_SIGNATURE),
            cmdsize: U32::new(LE, size_of::<macho::LinkeditDataCommand<LE>>() as u32),
            dataoff: U32::new(LE, TEST_PAGE as u32 + 16),
            datasize: U32::new(LE, 16),
        };

        let mut data = Vec::new();
        data.extend_from_slice(bytes_of(&header));
        data.extend_from_slice(bytes_of(&text));
        data.extend_from_slice(bytes_of(&linkedit));
        data.extend_from_slice(bytes_of(&signature));
        data.resize(TEST_PAGE as usize + 16, 0xaa);
        data.extend_from_slice(&[0xbb; 16]);
        data
    }

    fn test_segment() -> Segment {
        Segment {
            vmaddr: 0x1_0000_0000,
            vmsize: 0x4000,
            fileoff: 0,
            filesize: 0x4000,
            max_prot: macho::VM_PROT_READ | macho::VM_PROT_WRITE,
            init_prot: macho::VM_PROT_READ | macho::VM_PROT_WRITE,
            name: *b"__DATA\0\0\0\0\0\0\0\0\0\0",
        }
    }

    #[test]
    fn classic_fixup_opcodes_are_structured() {
        let segments = [test_segment()];
        let rebases = parse_rebase_opcodes(&[0x11, 0x20, 0x20, 0x51, 0x00], &segments).unwrap();
        assert_eq!(rebases, [0x1_0000_0020]);

        let binds = parse_bind_opcodes(
            &[0x70, 0x28, 0x40, b'_', b'g', b'a', b'm', b'e', 0, 0x90, 0x00],
            &segments,
        )
        .unwrap();
        assert_eq!(binds, [Fixup {
            location: 0x1_0000_0028,
            target: FixupTarget::Bind(Some("game".to_string())),
        }]);
    }

    #[test]
    fn removes_trailing_code_signature() {
        let output = remove_code_signature(signed_image()).unwrap();
        assert_eq!(output.len(), TEST_PAGE as usize + 16);

        let (header, _) = object::pod::from_bytes::<macho::MachHeader64<LE>>(&output).unwrap();
        assert_eq!(header.ncmds.get(LE), 2);
        assert_eq!(
            header.sizeofcmds.get(LE) as usize,
            2 * size_of::<macho::SegmentCommand64<LE>>()
        );

        let linkedit_offset =
            size_of::<macho::MachHeader64<LE>>() + size_of::<macho::SegmentCommand64<LE>>();
        let (linkedit, _) =
            object::pod::from_bytes::<macho::SegmentCommand64<LE>>(&output[linkedit_offset..])
                .unwrap();
        assert_eq!(linkedit.filesize.get(LE), 16);
        assert!(
            output[size_of::<macho::MachHeader64<LE>>()
                + 2 * size_of::<macho::SegmentCommand64<LE>>()
                ..size_of::<macho::MachHeader64<LE>>()
                    + 2 * size_of::<macho::SegmentCommand64<LE>>()
                    + size_of::<macho::LinkeditDataCommand<LE>>()]
                .iter()
                .all(|&byte| byte == 0)
        );

        assert_eq!(remove_code_signature(output.clone()).unwrap(), output);
    }

    #[test]
    fn rejects_code_signature_before_end_of_file() {
        let mut input = signed_image();
        input.push(0);
        assert!(remove_code_signature(input).is_err());
    }

    #[test]
    fn chained_fixup_growth_is_alignment_aware() {
        // Header + starts_in_image with three entries and an 8-byte-aligned tail.
        let mut blob = vec![0u8; 28];
        blob[4..8].copy_from_slice(&28u32.to_le_bytes());
        blob[8..12].copy_from_slice(&44u32.to_le_bytes());
        blob[12..16].copy_from_slice(&48u32.to_le_bytes());
        blob.extend_from_slice(&3u32.to_le_bytes());
        blob.extend_from_slice(&16u32.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&24u32.to_le_bytes());
        blob.extend_from_slice(&[0xaa; 8]);
        let (grown, growth) = grow_chained_fixups(&blob, 2, 2, 3).unwrap();
        assert_eq!(growth, 8);
        assert_eq!(read_u32(&grown, 28).unwrap(), 5);
        assert_eq!(read_u32(&grown, 32).unwrap(), 24);
        assert_eq!(read_u32(&grown, 36).unwrap(), 0);
        assert_eq!(read_u32(&grown, 40).unwrap(), 0);
        assert_eq!(read_u32(&grown, 44).unwrap(), 0);
        assert_eq!(read_u32(&grown, 48).unwrap(), 32);
        assert_eq!(read_u32(&grown, 8).unwrap(), 52);
        assert_eq!(read_u32(&grown, 12).unwrap(), 56);
        assert_eq!(&grown[52..], &[0xaa; 8]);
    }

    #[test]
    fn chained_fixup_growth_reuses_existing_alignment_padding() {
        let mut blob = vec![0u8; 28];
        blob[4..8].copy_from_slice(&28u32.to_le_bytes());
        blob.extend_from_slice(&2u32.to_le_bytes());
        blob.extend_from_slice(&16u32.to_le_bytes());
        blob.extend_from_slice(&24u32.to_le_bytes());
        blob.extend_from_slice(&[0u8; 4]);
        blob.extend_from_slice(&[0xbb; 8]);

        let (grown, growth) = grow_chained_fixups(&blob, 1, 1, 2).unwrap();
        assert_eq!(growth, 0);
        assert_eq!(grown.len(), blob.len());
        assert_eq!(read_u32(&grown, 28).unwrap(), 3);
        assert_eq!(read_u32(&grown, 32).unwrap(), 16);
        assert_eq!(read_u32(&grown, 36).unwrap(), 0);
        assert_eq!(read_u32(&grown, 40).unwrap(), 24);
        assert_eq!(&grown[44..], &[0xbb; 8]);
    }

    #[test]
    fn chained_fixup_growth_rejects_offsets_into_the_array() {
        let mut blob = vec![0u8; 28];
        blob[4..8].copy_from_slice(&28u32.to_le_bytes());
        blob.extend_from_slice(&1u32.to_le_bytes());
        blob.extend_from_slice(&4u32.to_le_bytes());
        assert!(grow_chained_fixups(&blob, 1, 2, 1).is_err());
    }
}
