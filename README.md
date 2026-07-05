# symgen [![Build Status]][actions]

[Build Status]: https://github.com/encounter/symgen/actions/workflows/build.yml/badge.svg
[actions]: https://github.com/encounter/symgen/actions

Symbol pipeline tool for moddable game binaries. Built for [Dusklight](https://github.com/TwilitRealm/dusklight).

- `symgen def` scans built COFF objects and archives and writes a curated Windows `.def`,
  defining the linkable ABI surface for mods on Windows.
- `symgen manifest` scans the fully linked executable and exports a manifest mapping
  the hookable symbol surface (including statics) to RVAs, keyed to the exact build.

## Commands

### def

Scans the objects listed in a linker response file and writes a `.def` of exportable symbols.
Compiler and runtime symbols (RTTI descriptors, string literals, initializer thunks, EH data, etc.)
and selectany COMDAT symbols (duplicated inline functions, templates, vtables) are filtered out
automatically.

```shell
symgen def --rsp objects.rsp -o game.def
```

- `--sdk-lib <lib>`: also scan a static library, keeping only unmangled (`extern "C"`) symbols.
  Repeatable.
- `--include <substr>` / `--exclude <substr>`: filter scanned objects by path substring.
  Repeatable.
- `--exclude-sym <prefix>`: exclude symbols with the given name prefix. Repeatable.
- `--max-exports <n>`: fail if the export count exceeds `n` (default 60000; the PE
  hard limit is 65535). `0` to disable.

### manifest

Maps every hookable symbol in a linked executable to its RVA and writes a symbol manifest.
Symbol sources: on Windows, the PDB provides publics plus per-module procedure/data records.
Elsewhere, the linked executable's own symbol table.

```shell
symgen manifest --pdb game.pdb -o game.symdb
symgen manifest --binary game.elf -o game.symdb
```

## Manifest format

Little-endian, designed to be memory-mapped by a mod loader:

```text
Header  { magic "SYMGEN\0\0", version u32, entry_count u32,
          build_id_len u32, build_id [u8; 32], reserved u32,
          strings_off u64, strings_len u64 } (72 bytes; entries 8-aligned)
Entry   { hash u64, rva u64, name_off u32, flags u32 } * entry_count,
          sorted by (hash, name_off) for binary search
Strings NUL-terminated names, referenced by name_off
```

`hash` is FNV-1a 64 of the name. The build id keys the manifest to the exact binary
(PDB GUID+age on Windows, `LC_UUID` on Mach-O, GNU build-id on ELF), so a stale manifest
is not loaded accidentally. RVAs are relative to the image base; the loader adds the module's
runtime base.

Entry flags:

| Flag           | Bit | Meaning                                                                       |
|----------------|-----|-------------------------------------------------------------------------------|
| `CODE`         | 0   | Function                                                                      |
| `DATA`         | 1   | Data                                                                          |
| `LOCAL`        | 2   | Not externally visible in the image: hookable, never linkable                 |
| `MULTI_NAME`   | 3   | Multiple names resolve to this RVA (ICF fold or alias)                        |
| `DUP_NAME`     | 4   | This name maps to multiple RVAs; by-name lookup must treat it as ambiguous    |
| `INLINE_SITES` | 5   | Inlined into at least one caller; an entry hook misses the inlined calls      |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
