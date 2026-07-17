//! AArch64 gateway instruction assembly.

use aarchmrs_instructions::A64::{
    control::{
        branch_imm::B_only_branch_imm::B_only_branch_imm as encode_b,
        branch_reg::BR_64_branch_reg::BR_64_branch_reg as encode_br,
        compbranch::CBZ_64_compbranch::CBZ_64_compbranch as encode_cbz,
        hints::{
            BTI_HB_hints::BTI_HB_hints as encode_bti, NOP_HI_hints::NOP_HI_hints as encode_nop,
        },
    },
    dpimm::{
        addsub_imm::ADD_64_addsub_imm::ADD_64_addsub_imm as encode_add,
        pcreladdr::ADRP_only_pcreladdr::ADRP_only_pcreladdr as encode_adrp,
    },
    ldst::ldstord::LDAR_LR64_ldstord::LDAR_LR64_ldstord as encode_ldar,
};
use aarchmrs_types::BitValue;
use anyhow::{Result, bail};

fn scaled_signed(displacement: i64, scale: i64, bits: u32, instruction: &str) -> Result<i32> {
    if displacement % scale != 0 {
        bail!("{instruction} displacement {displacement} is not {scale}-byte aligned");
    }
    let value = displacement / scale;
    let min = -(1i64 << (bits - 1));
    let max = (1i64 << (bits - 1)) - 1;
    if value < min || value > max {
        bail!("{instruction} displacement {displacement} is out of range");
    }
    Ok(value as i32)
}

fn displacement(from: u64, to: u64, instruction: &str) -> Result<i64> {
    i64::try_from(i128::from(to) - i128::from(from)).map_err(|_| {
        anyhow::anyhow!("{instruction} displacement from {from:#x} to {to:#x} is out of range")
    })
}

pub fn b(from: u64, to: u64) -> Result<u32> {
    let imm26 = scaled_signed(displacement(from, to, "b")?, 4, 26, "b")?;
    Ok(encode_b(BitValue::new_i32(imm26)).unpack())
}

pub fn adrp_x16(from: u64, to: u64) -> Result<u32> {
    let from_page = from & !0xfff;
    let to_page = to & !0xfff;
    let imm21 = scaled_signed(displacement(from_page, to_page, "adrp")?, 0x1000, 21, "adrp")?;
    let imm21 = BitValue::<21>::new_i32(imm21).into_inner();
    Ok(encode_adrp(
        BitValue::new_u32(imm21 & 3),
        BitValue::new_u32(imm21 >> 2),
        BitValue::new_u32(16),
    )
    .unpack())
}

pub fn add_x16_pageoff(to: u64) -> u32 {
    encode_add(
        BitValue::new_u32(0),
        BitValue::new_u32((to & 0xfff) as u32),
        BitValue::new_u32(16),
        BitValue::new_u32(16),
    )
    .unpack()
}

pub fn ldar_x16_x16() -> u32 { encode_ldar(BitValue::new_u32(16), BitValue::new_u32(16)).unpack() }

pub fn cbz_x16(from: u64, to: u64) -> Result<u32> {
    let imm19 = scaled_signed(displacement(from, to, "cbz")?, 4, 19, "cbz")?;
    Ok(encode_cbz(BitValue::new_i32(imm19), BitValue::new_u32(16)).unpack())
}

pub fn br_x16() -> u32 { encode_br(BitValue::new_u32(16)).unpack() }

pub fn bti_c() -> u32 { encode_bti(BitValue::new_u32(1)).unpack() }

pub fn nop() -> u32 { encode_nop().unpack() }

#[cfg(test)]
mod tests {
    use yaxpeax_arch::{Arch, Decoder, U8Reader};
    use yaxpeax_arm::armv8::a64::{ARMv8, Instruction, Opcode, Operand};

    use super::*;

    fn decode(instruction: u32) -> Instruction {
        let bytes = instruction.to_le_bytes();
        <ARMv8 as Arch>::Decoder::default().decode(&mut U8Reader::new(&bytes)).unwrap()
    }

    fn pc_offset(instruction: u32, opcode: Opcode) -> i64 {
        let instruction = decode(instruction);
        assert_eq!(instruction.opcode, opcode);
        instruction
            .operands
            .iter()
            .find_map(|operand| match operand {
                Operand::PCOffset(offset) => Some(*offset),
                _ => None,
            })
            .unwrap()
    }

    #[test]
    fn known_encodings() {
        assert_eq!(b(0x1000, 0x1004).unwrap(), 0x1400_0001);
        assert_eq!(b(0x1004, 0x1000).unwrap(), 0x17ff_ffff);
        assert_eq!(adrp_x16(0x1234, 0x5008).unwrap(), 0x9000_0030);
        assert_eq!(add_x16_pageoff(0x5abc), 0x912a_f210);
        assert_eq!(cbz_x16(0x1000, 0x1008).unwrap(), 0xb400_0050);
        assert_eq!(ldar_x16_x16(), 0xc8df_fe10);
        assert_eq!(br_x16(), 0xd61f_0200);
        assert_eq!(bti_c(), 0xd503_245f);
        assert_eq!(nop(), 0xd503_201f);
    }

    #[test]
    fn branch_range_is_checked() {
        assert!(b(0, 128 * 1024 * 1024 - 4).is_ok());
        assert!(b(0, 128 * 1024 * 1024).is_err());
        assert!(b(128 * 1024 * 1024, 0).is_ok());
        assert!(b(128 * 1024 * 1024 + 4, 0).is_err());
        assert!(b(0, 2).is_err());

        assert!(cbz_x16(0, 1024 * 1024 - 4).is_ok());
        assert!(cbz_x16(0, 1024 * 1024).is_err());
        assert!(cbz_x16(1024 * 1024, 0).is_ok());
        assert!(cbz_x16(1024 * 1024 + 4, 0).is_err());

        assert!(adrp_x16(0, 4 * 1024 * 1024 * 1024 - 0x1000).is_ok());
        assert!(adrp_x16(0, 4 * 1024 * 1024 * 1024).is_err());
        assert!(adrp_x16(4 * 1024 * 1024 * 1024, 0).is_ok());
        assert!(adrp_x16(4 * 1024 * 1024 * 1024 + 0x1000, 0).is_err());
    }

    #[test]
    fn gateway_encodings_decode_to_the_requested_addresses() {
        let target = 0x1000_4000u64;
        let gateway = 0x1020_0000u64;
        let stub = gateway + 20;
        let slot = 0x1020_4128;

        let adrp = adrp_x16(gateway, slot).unwrap();
        let add = decode(add_x16_pageoff(slot));
        let pageoff = add.operands.iter().find_map(|operand| match operand {
            Operand::Immediate(value) => Some(u64::from(*value)),
            Operand::ImmShift(value, shift) => Some(u64::from(*value) << shift),
            _ => None,
        });
        assert_eq!(
            (gateway & !0xfff).checked_add_signed(pc_offset(adrp, Opcode::ADRP)).unwrap()
                + pageoff.unwrap(),
            slot
        );
        assert_eq!(
            (gateway + 12)
                .checked_add_signed(pc_offset(cbz_x16(gateway + 12, stub).unwrap(), Opcode::CBZ))
                .unwrap(),
            stub
        );
        assert_eq!(
            target.checked_add_signed(pc_offset(b(target, gateway).unwrap(), Opcode::B)).unwrap(),
            gateway
        );
        assert_eq!(
            (stub + 4)
                .checked_add_signed(pc_offset(b(stub + 4, target + 4).unwrap(), Opcode::B))
                .unwrap(),
            target + 4
        );

        let dispatch = |published: u64| if published == 0 { stub } else { published };
        assert_eq!(dispatch(0), stub);
        assert_eq!(dispatch(0x1234_5678), 0x1234_5678);
    }
}
