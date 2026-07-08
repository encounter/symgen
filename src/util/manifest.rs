//! Symbol manifest format.
//!
//! Layout (little-endian):
//!
//! ```text
//! Header  { magic "SYMGEN\0\0", version u32, compression ManifestCompression,
//!           uncompressed_len u64, compressed_len u64,
//!           build_id_len u32, build_id [u8; 32], entry_count u32 } (72 bytes)
//! Payload  compressed_len bytes, optionally zstd-compressed
//! ```
//!
//! The decompressed payload contains the entries and string table:
//!
//! ```text
//! Entry   { hash u64, rva u64, name_off u32, flags u32 }   × entry_count,
//!           sorted by (hash, name_off) — binary-search by hash, resolve
//!           collisions by comparing the name.
//! Strings NUL-terminated names, referenced by name_off.
//! ```
//!
//! The build id keys the manifest to the exact binary: PDB GUID+age on Windows,
//! LC_UUID on Mach-O, GNU build-id on ELF. A stale manifest fails to load.
//! RVAs are relative to the format's image base; the loader adds the module's
//! runtime base.

use std::{collections::BTreeMap, mem::size_of};

use anyhow::{Context, Result};
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout,
    little_endian::{U32, U64},
};

use crate::static_assert;

pub const MAGIC: [u8; 8] = *b"SYMGEN\0\0";
pub const VERSION: u32 = 2;
pub const ZSTD_LEVEL: i32 = 10;

/// Manifest payload compression stored in ManifestHeader::compression.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ManifestCompression {
    None = 0,
    Zstd = 1,
}

impl ManifestCompression {
    pub const fn code(self) -> u32 { self as u32 }

    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Zstd => "zstd",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManifestOptions {
    pub compression: ManifestCompression,
}

impl Default for ManifestOptions {
    fn default() -> Self { Self { compression: ManifestCompression::Zstd } }
}

pub const FLAG_CODE: u32 = 1 << 0;
pub const FLAG_DATA: u32 = 1 << 1;
/// Not externally visible in the linked image (PDB module symbol / local symtab entry):
/// hookable via the manifest, never linkable.
pub const FLAG_LOCAL: u32 = 1 << 2;
/// Multiple names resolved to this RVA (ICF fold or alias): a hook here intercepts
/// every folded function.
pub const FLAG_MULTI_NAME: u32 = 1 << 3;
/// This name maps to more than one RVA (internal-linkage statics with the same name in
/// different TUs). Every RVA is present; a by-name lookup must treat it as ambiguous.
pub const FLAG_DUP_NAME: u32 = 1 << 4;
/// This function was inlined into at least one caller in this build (PDB inlinee
/// records): an entry hook on it only intercepts the calls that were not inlined.
pub const FLAG_INLINE_SITES: u32 = 1 << 5;
/// A demangled display-name alias generated alongside the real (mangled) entry, so
/// `Class::method` resolves on every platform. Excluded from MULTI_NAME accounting,
/// and dropped when it collides with a real symbol's name at a different address.
pub const FLAG_DISPLAY: u32 = 1 << 6;

/// Manifest header.
#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(8))]
pub struct ManifestHeader {
    pub magic: [u8; 8],
    pub version: U32,
    pub compression: U32,
    pub uncompressed_len: U64,
    pub compressed_len: U64,
    pub build_id_len: U32,
    pub build_id: [u8; 32],
    pub entry_count: U32,
}

static_assert!(size_of::<ManifestHeader>() == 72);

/// A single symbol entry.
#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(8))]
pub struct ManifestEntry {
    /// FNV-1a 64-bit hash of the name.
    pub hash: U64,
    /// Address relative to the image base.
    pub rva: U64,
    /// Offset of the NUL-terminated name in the string table.
    pub name_off: U32,
    /// FLAG_* bitfield.
    pub flags: U32,
}

static_assert!(size_of::<ManifestEntry>() == 24);

/// FNV-1a 64-bit hash; the loader hashes lookup names the same way.
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

pub struct ManifestSymbol {
    pub name: String,
    pub rva: u64,
    pub flags: u32,
}

pub struct ManifestInput {
    pub build_id: Vec<u8>,
    pub symbols: Vec<ManifestSymbol>,
}

fn build_id_field(input: &ManifestInput) -> ([u8; 32], u32) {
    let build_id_len = input.build_id.len().min(32);
    let mut build_id = [0u8; 32];
    build_id[..build_id_len].copy_from_slice(&input.build_id[..build_id_len]);
    (build_id, build_id_len as u32)
}

/// Serialize an uncompressed manifest payload.
/// Returns the raw payload bytes and the deduplicated entry count.
pub fn build_manifest_payload(input: &ManifestInput) -> Result<(Vec<u8>, usize)> {
    let mut by_name: BTreeMap<&str, Vec<(u64, u32)>> = BTreeMap::new();
    for sym in &input.symbols {
        let rvas = by_name.entry(&sym.name).or_default();
        match rvas.iter_mut().find(|(rva, _)| *rva == sym.rva) {
            Some((_, flags)) => {
                // A record from any real (non-display, non-local) source clears the
                // corresponding marker on the merged entry.
                if sym.flags & FLAG_LOCAL == 0 {
                    *flags &= !FLAG_LOCAL;
                }
                if sym.flags & FLAG_DISPLAY == 0 {
                    *flags &= !FLAG_DISPLAY;
                }
                *flags |= sym.flags & !(FLAG_LOCAL | FLAG_DISPLAY);
            }
            None => rvas.push((sym.rva, sym.flags)),
        }
    }

    // A display alias that collides with a real symbol's name at a different address
    // would make that real name ambiguous; the real name wins.
    for rvas in by_name.values_mut() {
        if rvas.iter().any(|(_, flags)| flags & FLAG_DISPLAY == 0) {
            rvas.retain(|(_, flags)| flags & FLAG_DISPLAY == 0);
        }
    }

    let mut rva_names: BTreeMap<u64, u32> = BTreeMap::new();
    for rvas in by_name.values() {
        for (rva, flags) in rvas {
            // Display aliases don't count toward MULTI_NAME
            if flags & FLAG_DISPLAY == 0 {
                *rva_names.entry(*rva).or_insert(0) += 1;
            }
        }
    }

    let mut entries: Vec<ManifestEntry> = Vec::with_capacity(by_name.len());
    let mut strings: Vec<u8> = Vec::new();
    let mut dup_names = 0usize;
    for (name, rvas) in &by_name {
        let dup = rvas.len() > 1;
        if dup {
            dup_names += 1;
        }
        let name_off = u32::try_from(strings.len()).ok().context("String table exceeds 4 GiB")?;
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        let hash = fnv1a64(name.as_bytes());
        for &(rva, flags) in rvas {
            let mut flags = flags;
            if dup {
                flags |= FLAG_DUP_NAME;
            }
            if rva_names.get(&rva).copied().unwrap_or(0) > 1 {
                flags |= FLAG_MULTI_NAME;
            }
            entries.push(ManifestEntry {
                hash: U64::new(hash),
                rva: U64::new(rva),
                name_off: U32::new(name_off),
                flags: U32::new(flags),
            });
        }
    }
    entries.sort_unstable_by_key(|e| (e.hash.get(), e.name_off.get(), e.rva.get()));
    if dup_names != 0 {
        log::debug!("{dup_names} names have multiple addresses (flagged DUP_NAME)");
    }

    let strings_off = entries.len() * size_of::<ManifestEntry>();
    let mut out = Vec::with_capacity(strings_off + strings.len());
    out.extend_from_slice(entries.as_slice().as_bytes());
    out.extend_from_slice(&strings);
    Ok((out, entries.len()))
}

/// Serialize a manifest using the default compression.
/// Returns the serialized bytes and the deduplicated entry count.
pub fn build_manifest(input: &ManifestInput) -> Result<(Vec<u8>, usize)> {
    build_manifest_with_options(input, ManifestOptions::default())
}

/// Serialize a manifest.
/// Returns the serialized bytes and the deduplicated entry count.
pub fn build_manifest_with_options(
    input: &ManifestInput,
    options: ManifestOptions,
) -> Result<(Vec<u8>, usize)> {
    let (payload, entries) = build_manifest_payload(input)?;
    let entry_count = u32::try_from(entries).context("Entry count exceeds u32")?;
    let uncompressed_len = payload.len();
    let encoded_payload = match options.compression {
        ManifestCompression::None => payload,
        ManifestCompression::Zstd => zstd::stream::encode_all(payload.as_slice(), ZSTD_LEVEL)
            .context("Failed to zstd-compress manifest")?,
    };
    let (build_id, build_id_len) = build_id_field(input);
    let header = ManifestHeader {
        magic: MAGIC,
        version: U32::new(VERSION),
        compression: U32::new(options.compression.code()),
        uncompressed_len: U64::new(uncompressed_len as u64),
        compressed_len: U64::new(encoded_payload.len() as u64),
        build_id_len: U32::new(build_id_len),
        build_id,
        entry_count: U32::new(entry_count),
    };

    let mut out = Vec::with_capacity(size_of::<ManifestHeader>() + encoded_payload.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(&encoded_payload);
    Ok((out, entries))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fnv1a64() {
        assert_eq!(fnv1a64(b""), 0xcbf29ce484222325);
        assert_eq!(fnv1a64(b"a"), 0xaf63dc4c8601ec8c);
        assert_eq!(fnv1a64(b"foobar"), 0x85944171f73967e8);
    }

    #[test]
    fn test_build_manifest() {
        let input = ManifestInput {
            build_id: vec![0xAA; 20],
            symbols: vec![
                // Public + module record for the same symbol: flags merge, LOCAL clears.
                ManifestSymbol { name: "foo".into(), rva: 0x1000, flags: FLAG_CODE },
                ManifestSymbol { name: "foo".into(), rva: 0x1000, flags: FLAG_CODE | FLAG_LOCAL },
                ManifestSymbol { name: "bar".into(), rva: 0x2000, flags: FLAG_DATA },
                // Same name at two RVAs: both kept, flagged DUP_NAME.
                ManifestSymbol { name: "dup".into(), rva: 0x3000, flags: FLAG_CODE | FLAG_LOCAL },
                ManifestSymbol { name: "dup".into(), rva: 0x4000, flags: FLAG_CODE | FLAG_LOCAL },
                // Second name at bar's RVA: both flagged MULTI_NAME.
                ManifestSymbol { name: "bar_alias".into(), rva: 0x2000, flags: FLAG_DATA },
                // Display alias for foo: resolvable, no MULTI_NAME on either entry.
                ManifestSymbol {
                    name: "Foo::foo".into(),
                    rva: 0x1000,
                    flags: FLAG_CODE | FLAG_DISPLAY,
                },
                // Display alias colliding with the real name "bar" elsewhere: dropped.
                ManifestSymbol { name: "bar".into(), rva: 0x5000, flags: FLAG_CODE | FLAG_DISPLAY },
                // Two display aliases at distinct RVAs (overload set): kept, DUP_NAME.
                ManifestSymbol {
                    name: "Foo::over".into(),
                    rva: 0x6000,
                    flags: FLAG_CODE | FLAG_DISPLAY,
                },
                ManifestSymbol {
                    name: "Foo::over".into(),
                    rva: 0x7000,
                    flags: FLAG_CODE | FLAG_DISPLAY,
                },
            ],
        };
        let (data, count) = build_manifest_payload(&input).unwrap();
        assert_eq!(count, 8);

        let strings_off = count * size_of::<ManifestEntry>();
        assert!(strings_off <= data.len());
        let mut entries = Vec::new();
        let mut rest = &data[..strings_off];
        while !rest.is_empty() {
            let (entry, r) = ManifestEntry::read_from_prefix(rest).unwrap();
            entries.push(entry);
            rest = r;
        }
        assert_eq!(entries.len(), 8);
        assert!(entries.is_sorted_by_key(|e| (e.hash.get(), e.name_off.get(), e.rva.get())));

        let strings = &data[strings_off..];
        let find = |name: &str| -> Vec<&ManifestEntry> {
            entries
                .iter()
                .filter(|e| {
                    e.hash.get() == fnv1a64(name.as_bytes())
                        && strings[e.name_off.get() as usize..].starts_with(name.as_bytes())
                        && strings[e.name_off.get() as usize + name.len()] == 0
                })
                .collect()
        };

        let foo = find("foo");
        assert_eq!(foo.len(), 1);
        assert_eq!(foo[0].rva.get(), 0x1000);
        assert_eq!(foo[0].flags.get(), FLAG_CODE);

        let dup = find("dup");
        assert_eq!(dup.len(), 2);
        assert!(dup.iter().all(|e| e.flags.get() == FLAG_CODE | FLAG_LOCAL | FLAG_DUP_NAME));

        let bar = find("bar");
        assert_eq!(bar.len(), 1);
        assert_eq!(bar[0].rva.get(), 0x2000, "display alias must not displace the real 'bar'");
        assert_eq!(bar[0].flags.get(), FLAG_DATA | FLAG_MULTI_NAME);

        // foo's display alias resolves, and doesn't drag MULTI_NAME onto foo.
        let foo_display = find("Foo::foo");
        assert_eq!(foo_display.len(), 1);
        assert_eq!(foo_display[0].rva.get(), 0x1000);
        assert_eq!(foo_display[0].flags.get(), FLAG_CODE | FLAG_DISPLAY);
        assert_eq!(find("foo")[0].flags.get(), FLAG_CODE);

        // Overload set: both display entries kept and marked ambiguous.
        let over = find("Foo::over");
        assert_eq!(over.len(), 2);
        assert!(over.iter().all(|e| e.flags.get() == FLAG_CODE | FLAG_DISPLAY | FLAG_DUP_NAME));
    }

    #[test]
    fn test_build_manifest_v2_zstd() {
        let input = ManifestInput {
            build_id: vec![0xBB; 16],
            symbols: vec![
                ManifestSymbol { name: "_ZN3Foo3barEv".into(), rva: 0x1000, flags: FLAG_CODE },
                ManifestSymbol {
                    name: "Foo::bar".into(),
                    rva: 0x1000,
                    flags: FLAG_CODE | FLAG_DISPLAY,
                },
            ],
        };

        let (data, count) = build_manifest(&input).unwrap();
        assert_eq!(count, 2);

        let (header, compressed) = ManifestHeader::read_from_prefix(&data).unwrap();
        assert_eq!(header.magic, MAGIC);
        assert_eq!(header.version.get(), VERSION);
        assert_eq!(header.compression.get(), ManifestCompression::Zstd.code());
        assert_eq!(header.build_id_len.get(), 16);
        assert_eq!(header.build_id[..16], [0xBB; 16]);
        assert_eq!(header.entry_count.get(), 2);
        assert_eq!(header.compressed_len.get() as usize, compressed.len());

        let payload = zstd::stream::decode_all(compressed).unwrap();
        assert_eq!(header.uncompressed_len.get() as usize, payload.len());
        let strings_off = header.entry_count.get() as usize * size_of::<ManifestEntry>();
        assert!(strings_off <= payload.len());
    }

    #[test]
    fn test_build_manifest_v2_uncompressed() {
        let input = ManifestInput {
            build_id: vec![0xCC; 16],
            symbols: vec![
                ManifestSymbol { name: "foo".into(), rva: 0x1000, flags: FLAG_CODE },
                ManifestSymbol { name: "bar".into(), rva: 0x2000, flags: FLAG_DATA },
            ],
        };

        let (expected_payload, expected_count) = build_manifest_payload(&input).unwrap();
        let (data, count) = build_manifest_with_options(&input, ManifestOptions {
            compression: ManifestCompression::None,
        })
        .unwrap();
        assert_eq!(count, expected_count);

        let (header, payload) = ManifestHeader::read_from_prefix(&data).unwrap();
        assert_eq!(header.magic, MAGIC);
        assert_eq!(header.version.get(), VERSION);
        assert_eq!(header.compression.get(), ManifestCompression::None.code());
        assert_eq!(header.uncompressed_len.get() as usize, expected_payload.len());
        assert_eq!(header.compressed_len.get() as usize, expected_payload.len());
        assert_eq!(header.entry_count.get(), count as u32);
        assert_eq!(payload, expected_payload.as_slice());
    }
}
