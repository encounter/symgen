//! Static recovery of targets from MSVC-generated member-pointer helpers and thunks.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use iced_x86::{Decoder as X64Decoder, DecoderOptions, Mnemonic, OpKind, Register};
use object::{
    Architecture, BinaryFormat, Object, ObjectSection,
    read::pe::{ImageThunkData, PeFile64},
};
use yaxpeax_arch::{Arch, Decoder as _, U8Reader};
use yaxpeax_arm::armv8::a64::{
    ARMv8, Instruction as Arm64Instruction, Opcode as Arm64Opcode, Operand as Arm64Operand,
    SizeCode as Arm64Size,
};

/// A statically recovered generalized pointer-to-member target.
pub enum MemberTarget {
    Symbol(String),
    VirtualSlot(u64),
}

/// PE import information shared while decoding all member hooks in one library.
#[derive(Default)]
pub struct MemberPointerDecoder {
    iat_symbols: BTreeMap<u64, String>,
}

impl MemberPointerDecoder {
    pub fn new(file: &object::File<'_>) -> Result<Self> {
        Ok(Self { iat_symbols: collect_pe_iat_symbols(file)? })
    }

    /// Recover the target stored by a MEM_EXT materializer without executing the DLL.
    pub fn decode_materializer(
        &self,
        file: &object::File<'_>,
        materialize: u64,
    ) -> Option<MemberTarget> {
        if file.format() != BinaryFormat::Pe
            || !matches!(file.architecture(), Architecture::X86_64 | Architecture::Aarch64)
            || materialize == 0
        {
            return None;
        }
        let helper = follow_jumps(file, materialize)?;
        let bytes = image_bytes_at(file, helper)?;
        match file.architecture() {
            Architecture::X86_64 => self.decode_x64_materializer(file, helper, bytes),
            Architecture::Aarch64 => self.decode_arm64_materializer(file, helper, bytes),
            _ => None,
        }
    }

    fn decode_member_target(&self, file: &object::File<'_>, address: u64) -> Option<MemberTarget> {
        let address = follow_jumps(file, address)?;
        let bytes = image_bytes_at(file, address)?;
        let (iat, virtual_slot) = match file.architecture() {
            Architecture::X86_64 => {
                (decode_x64_import_thunk_iat(address, bytes), decode_x64_vcall_slot(address, bytes))
            }
            Architecture::Aarch64 => {
                (decode_arm64_import_thunk_iat(address, bytes), decode_arm64_vcall_slot(bytes))
            }
            _ => return None,
        };
        if let Some(symbol) = iat.and_then(|iat| self.iat_symbols.get(&iat)) {
            return Some(MemberTarget::Symbol(symbol.clone()));
        }
        virtual_slot.map(MemberTarget::VirtualSlot)
    }

    fn decode_x64_materializer(
        &self,
        file: &object::File<'_>,
        helper: u64,
        bytes: &[u8],
    ) -> Option<MemberTarget> {
        let mut decoder =
            X64Decoder::with_ip(64, &bytes[..bytes.len().min(192)], helper, DecoderOptions::NONE);
        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.is_invalid() || instruction.mnemonic() == Mnemonic::Ret {
                break;
            }
            let target = match (instruction.mnemonic(), instruction.op1_kind()) {
                (Mnemonic::Lea, OpKind::Memory) if instruction.is_ip_rel_memory_operand() => {
                    Some(instruction.ip_rel_memory_address())
                }
                (Mnemonic::Mov, OpKind::Memory) if instruction.is_ip_rel_memory_operand() => {
                    image_bytes_at(file, instruction.ip_rel_memory_address())
                        .and_then(|data| data.get(..8))
                        .and_then(|data| data.try_into().ok())
                        .map(u64::from_le_bytes)
                }
                (Mnemonic::Mov, OpKind::Immediate64) => Some(instruction.immediate64()),
                _ => None,
            };
            if let Some(decoded) = target.and_then(|target| self.decode_member_target(file, target))
            {
                return Some(decoded);
            }
        }
        None
    }

    fn decode_arm64_materializer(
        &self,
        file: &object::File<'_>,
        helper: u64,
        bytes: &[u8],
    ) -> Option<MemberTarget> {
        let limit = bytes.len().min(192) & !3;
        for offset in (0..limit.saturating_sub(4)).step_by(4) {
            let address = helper.checked_add(offset as u64)?;
            let first = decode_arm64(bytes.get(offset..)?)?;
            let second = decode_arm64(bytes.get(offset + 4..)?)?;
            let Some((page_register, page)) = arm64_adrp(&first, address) else {
                continue;
            };

            let target = if let Some((target_register, base_register, page_offset)) =
                arm64_add_immediate(&second)
                && page_register == base_register
                && target_register != 31
            {
                page.checked_add(page_offset)
            } else if let Some((target_register, base_register, page_offset)) = arm64_load(&second)
                && page_register == base_register
                && target_register != 31
            {
                page.checked_add(page_offset)
                    .and_then(|address| image_bytes_at(file, address))
                    .and_then(|data| data.get(..8))
                    .and_then(|data| data.try_into().ok())
                    .map(u64::from_le_bytes)
            } else {
                None
            };
            if let Some(decoded) = target.and_then(|target| self.decode_member_target(file, target))
            {
                return Some(decoded);
            }
        }
        None
    }
}

/// Map each PE64 import-address-table slot to its imported symbol. A non-virtual game method
/// normally resolves through a local import thunk to one of these slots.
fn collect_pe_iat_symbols(file: &object::File<'_>) -> Result<BTreeMap<u64, String>> {
    let object::File::Pe64(pe) = file else {
        return Ok(BTreeMap::new());
    };
    collect_pe64_iat_symbols(pe)
}

fn collect_pe64_iat_symbols(pe: &PeFile64<'_>) -> Result<BTreeMap<u64, String>> {
    let mut symbols = BTreeMap::new();
    let Some(import_table) = pe.import_table()? else {
        return Ok(symbols);
    };
    let image_base = pe.relative_address_base();
    let mut descriptors = import_table.descriptors()?;
    while let Some(descriptor) = descriptors.next()? {
        let mut lookup_rva = descriptor.original_first_thunk.get(object::LittleEndian);
        let iat_rva = descriptor.first_thunk.get(object::LittleEndian);
        if lookup_rva == 0 {
            lookup_rva = iat_rva;
        }
        let mut thunks = import_table.thunks(lookup_rva)?;
        let mut index = 0u64;
        while let Some(thunk) = thunks.next::<object::pe::ImageNtHeaders64>()? {
            if !thunk.is_ordinal() {
                let (_, name) = import_table.hint_name(thunk.address())?;
                let address = image_base
                    .checked_add(u64::from(iat_rva))
                    .and_then(|value| value.checked_add(index * 8))
                    .context("PE import address overflows")?;
                symbols.insert(address, String::from_utf8_lossy(name).into_owned());
            }
            index += 1;
        }
    }
    Ok(symbols)
}

fn image_bytes_at<'data>(file: &object::File<'data>, address: u64) -> Option<&'data [u8]> {
    for section in file.sections() {
        let start = section.address();
        let Ok(data) = section.data() else {
            continue;
        };
        if address >= start {
            let offset = usize::try_from(address - start).ok()?;
            if offset < data.len() {
                return Some(&data[offset..]);
            }
        }
    }
    None
}

fn decode_x64(address: u64, bytes: &[u8]) -> Option<iced_x86::Instruction> {
    let instruction = X64Decoder::with_ip(64, bytes, address, DecoderOptions::NONE).decode();
    (!instruction.is_invalid()).then_some(instruction)
}

fn x64_jump_target(address: u64, bytes: &[u8]) -> Option<u64> {
    let instruction = decode_x64(address, bytes)?;
    (instruction.mnemonic() == Mnemonic::Jmp
        && matches!(
            instruction.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        ))
    .then(|| instruction.near_branch_target())
}

fn decode_arm64(bytes: &[u8]) -> Option<Arm64Instruction> {
    let bytes = bytes.get(..4)?;
    <ARMv8 as Arch>::Decoder::default().decode(&mut U8Reader::new(bytes)).ok()
}

fn arm64_register(operand: Arm64Operand) -> Option<u16> {
    match operand {
        Arm64Operand::Register(Arm64Size::X, register)
        | Arm64Operand::RegisterOrSP(Arm64Size::X, register) => Some(register),
        _ => None,
    }
}

fn arm64_immediate(operand: Arm64Operand) -> Option<u64> {
    match operand {
        Arm64Operand::Immediate(value) => Some(u64::from(value)),
        Arm64Operand::Imm64(value) => Some(value),
        Arm64Operand::ImmShift(value, shift) => Some(u64::from(value) << shift),
        _ => None,
    }
}

fn arm64_adrp(instruction: &Arm64Instruction, address: u64) -> Option<(u16, u64)> {
    if instruction.opcode != Arm64Opcode::ADRP {
        return None;
    }
    let register = arm64_register(instruction.operands[0])?;
    let Arm64Operand::PCOffset(offset) = instruction.operands[1] else {
        return None;
    };
    Some((register, (address & !0xfff).checked_add_signed(offset)?))
}

fn arm64_add_immediate(instruction: &Arm64Instruction) -> Option<(u16, u16, u64)> {
    if instruction.opcode != Arm64Opcode::ADD {
        return None;
    }
    Some((
        arm64_register(instruction.operands[0])?,
        arm64_register(instruction.operands[1])?,
        arm64_immediate(instruction.operands[2])?,
    ))
}

fn arm64_load(instruction: &Arm64Instruction) -> Option<(u16, u16, u64)> {
    if instruction.opcode != Arm64Opcode::LDR {
        return None;
    }
    let target = arm64_register(instruction.operands[0])?;
    let Arm64Operand::RegPreIndex(base, offset, false) = instruction.operands[1] else {
        return None;
    };
    Some((target, base, u64::try_from(offset).ok()?))
}

fn arm64_branch_register(instruction: &Arm64Instruction) -> Option<u16> {
    (instruction.opcode == Arm64Opcode::BR)
        .then(|| arm64_register(instruction.operands[0]))
        .flatten()
}

fn arm64_jump_target(address: u64, bytes: &[u8]) -> Option<u64> {
    let first = decode_arm64(bytes)?;
    if first.opcode == Arm64Opcode::B
        && let Arm64Operand::PCOffset(offset) = first.operands[0]
    {
        return address.checked_add_signed(offset);
    }

    let second = decode_arm64(bytes.get(4..)?)?;
    let third = decode_arm64(bytes.get(8..)?)?;
    let (page_register, page) = arm64_adrp(&first, address)?;
    let (target_register, base_register, page_offset) = arm64_add_immediate(&second)?;
    let branch_register = arm64_branch_register(&third)?;
    (page_register == base_register && target_register == branch_register)
        .then(|| page.checked_add(page_offset))
        .flatten()
}

/// Follow the jump islands emitted by MSVC incremental linking. Both metadata function pointers
/// and compiler-generated vcall thunks can initially point at these linker-generated stubs.
fn follow_jumps(file: &object::File<'_>, mut address: u64) -> Option<u64> {
    for _ in 0..8 {
        let bytes = image_bytes_at(file, address)?;
        let target = match file.architecture() {
            Architecture::X86_64 => x64_jump_target(address, bytes),
            Architecture::Aarch64 => arm64_jump_target(address, bytes),
            _ => None,
        };
        let Some(target) = target else {
            return Some(address);
        };
        if target == address {
            return None;
        }
        address = target;
    }
    None
}

fn decode_x64_import_thunk_iat(address: u64, bytes: &[u8]) -> Option<u64> {
    let instruction = decode_x64(address, bytes)?;
    (instruction.mnemonic() == Mnemonic::Jmp
        && instruction.op0_kind() == OpKind::Memory
        && instruction.is_ip_rel_memory_operand())
    .then(|| instruction.ip_rel_memory_address())
}

/// Decode `mov rax, [rcx]; jmp qword ptr [rax + slot]`.
fn decode_x64_vcall_slot(address: u64, bytes: &[u8]) -> Option<u64> {
    let first = decode_x64(address, bytes)?;
    if first.mnemonic() != Mnemonic::Mov
        || first.op0_kind() != OpKind::Register
        || first.op0_register() != Register::RAX
        || first.op1_kind() != OpKind::Memory
        || first.memory_base() != Register::RCX
        || first.memory_index() != Register::None
        || first.memory_displacement64() != 0
    {
        return None;
    }
    let second_address = first.next_ip();
    let second = decode_x64(second_address, bytes.get(first.len()..)?)?;
    (second.mnemonic() == Mnemonic::Jmp
        && second.op0_kind() == OpKind::Memory
        && second.memory_base() == Register::RAX
        && second.memory_index() == Register::None)
        .then(|| second.memory_displacement64())
}

fn decode_arm64_import_thunk_iat(address: u64, bytes: &[u8]) -> Option<u64> {
    let first = decode_arm64(bytes)?;
    let second = decode_arm64(bytes.get(4..)?)?;
    let third = decode_arm64(bytes.get(8..)?)?;
    let (page_register, page) = arm64_adrp(&first, address)?;
    let (target_register, base_register, page_offset) = arm64_load(&second)?;
    let branch_register = arm64_branch_register(&third)?;
    (page_register == base_register && target_register == branch_register)
        .then(|| page.checked_add(page_offset))
        .flatten()
}

/// Decode `ldr xN, [x0]; ldr xM, [xN, #slot]; br xM`.
fn decode_arm64_vcall_slot(bytes: &[u8]) -> Option<u64> {
    let first = decode_arm64(bytes)?;
    let second = decode_arm64(bytes.get(4..)?)?;
    let third = decode_arm64(bytes.get(8..)?)?;
    let (vtable_register, this_register, this_offset) = arm64_load(&first)?;
    let (target_register, vtable_base, slot) = arm64_load(&second)?;
    let branch_register = arm64_branch_register(&third)?;
    (this_register == 0
        && this_offset == 0
        && vtable_register == vtable_base
        && target_register == branch_register)
        .then_some(slot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_x64_relative_jumps() {
        assert_eq!(x64_jump_target(0x1000, &[0xe9, 0x20, 0, 0, 0]), Some(0x1025));
        assert_eq!(x64_jump_target(0x1000, &[0xe9, 0xe0, 0xff, 0xff, 0xff]), Some(0xfe5));
        assert_eq!(x64_jump_target(0x1000, &[0xe9, 0, 0]), None);
    }

    #[test]
    fn decodes_x64_import_thunk() {
        let thunk = [0xff, 0x25, 0x58, 0xd5, 0x00, 0x00];
        assert_eq!(decode_x64_import_thunk_iat(0x180001ef2, &thunk), Some(0x18000f450));
        assert_eq!(decode_x64_import_thunk_iat(0x180001ef2, &[0xff, 0x20]), None);
    }

    #[test]
    fn decodes_x64_vcall_thunks() {
        assert_eq!(decode_x64_vcall_slot(0x1000, &[0x48, 0x8b, 0x01, 0xff, 0x20]), Some(0));
        assert_eq!(
            decode_x64_vcall_slot(0x1000, &[0x48, 0x8b, 0x01, 0xff, 0x60, 0x38]),
            Some(0x38)
        );
        assert_eq!(
            decode_x64_vcall_slot(0x1000, &[0x48, 0x8b, 0x01, 0xff, 0xa0, 0x34, 0x01, 0x00, 0x00]),
            Some(0x134)
        );
        assert_eq!(decode_x64_vcall_slot(0x1000, &[0x48, 0x8b, 0x01, 0xc3]), None);
    }

    fn arm64_bytes(instructions: &[u32]) -> Vec<u8> {
        instructions.iter().flat_map(|instruction| instruction.to_le_bytes()).collect()
    }

    #[test]
    fn decodes_arm64_thunks() {
        let jump = arm64_bytes(&[0x9000_0010, 0x913b_2210, 0xd61f_0200]);
        assert_eq!(arm64_jump_target(0x180009000, &jump), Some(0x180009ec8));

        let import = arm64_bytes(&[0xf000_0050, 0xf941_3210, 0xd61f_0200]);
        assert_eq!(decode_arm64_import_thunk_iat(0x180009ec8, &import), Some(0x180014260));

        let vcall = arm64_bytes(&[0xf940_0010, 0xf940_1e10, 0xd61f_0200]);
        assert_eq!(decode_arm64_vcall_slot(&vcall), Some(0x38));
    }
}
