# symgen [![Build Status]][actions]

[Build Status]: https://github.com/encounter/symgen/actions/workflows/build.yml/badge.svg
[actions]: https://github.com/encounter/symgen/actions

Symbol pipeline tool for moddable game binaries. Built for [Dusklight](https://github.com/TwilitRealm/dusklight).

- `symgen def` scans COFF objects (and archives) and writes a curated Windows `.def`, defining the linkable exports for
  mods on Windows.
- `symgen exports` scans Mach-O/ELF objects (and archives) and writes curated exports that can be used as an input to
  the linker.
- `symgen stub` converts exports into a link stub (COFF import library, Mach-O executable, or ELF shared object)
  for mods to link without the main binary.
- `symgen manifest` scans the fully linked executable and exports a manifest containing all hookable symbols (including
  statics), written to a file or embedded into the executable itself.
- `symgen modmeta` dumps static mod metadata records embedded in native libraries.

## Commands

### def

Scans COFF objects and archives and writes a `.def` of exportable symbols. Inputs can be
listed directly or read from a response file by prefixing its path with `@`.
Compiler and runtime symbols (RTTI descriptors, string literals, initializer thunks, EH data, etc.)
and selectany COMDAT symbols (duplicated inline functions, templates, vtables) are filtered out
automatically.

```shell
symgen def @objects.rsp -o game.def
```

Positional inputs are repeatable. Response files may separate paths with newlines or semicolons.

- `--sdk-lib <lib>`: also scan a static library, keeping only unmangled (`extern "C"`) symbols.
  Repeatable.
- `--forward-dll <dll>`: read a PE DLL's named exports and emit forwarded exports through the
  generated module (for example, `wgpuFoo=webgpu_dawn.wgpuFoo`). Repeatable.
- `--forward-sym-prefix <prefix>`: only forward symbols matching one of the supplied prefixes.
  Repeatable; all named exports are forwarded when omitted.
- `--include <substr>` / `--exclude <substr>`: filter scanned objects by path substring.
  Repeatable.
- `--exclude-sym <prefix>`: exclude symbols with the given name prefix. Repeatable.
- `--max-exports <n>`: fail if the export count exceeds `n` (default 60000; the PE
  hard limit is 65535). `0` to disable.

### exports

The Mach-O/ELF counterpart of `def`: scans objects and archives and writes curated exports for the executable link step.
Like `def`, prefix response files with `@`.

```shell
symgen exports @objects.rsp -o game.exp
symgen exports @objects.rsp -o game.ver --format version-script \
    --extra-sym JNI_OnLoad --extra-sym 'Java_*'
```

- `--format <fmt>`: `list` (default) writes one symbol per line for ld64's
  `-exported_symbols_list`; `version-script` writes an anonymous ELF version script.
- `--extra-sym <name>`: add a name (or glob) to the output verbatim, bypassing the scan.
  For symbols that live outside the scanned objects but must stay exported. Repeatable.
- `--sdk-lib`, `--include`/`--exclude`, `--exclude-sym`: same as `def`

Semantics differ by format: every `-exported_symbols_list` entry becomes an initial undefined
at link time, so it must exist in the final image and forces extraction of listed archive
members (matching `.def`). A version script is a filter — names that don't exist are silently
ignored and force nothing, so unreferenced archive members stay out of the image.

### stub

Converts exports into a link stub that mods can link against instead of the main executable.

```shell
symgen stub -f implib game.def -o game.lib --dll-name game.exe
symgen stub -f macho game.exp -o game-stub --min-os 11.0
symgen stub -f elf libmain.so -o stub.so --soname libmain.so --arch arm64
```

- `-f implib`: COFF short import library from a `.def`. Imports bind to `--dll-name` (or an explicit `LIBRARY` line);
  `name=target` forwards import as `name`. `--arch x86_64|arm64`.
- `-f macho`: stub `MH_EXECUTE` from a symbol list, for linking bundles with `-bundle_loader`. `--arch arm64|x86_64` (
  repeatable), `--platform macos|ios|tvos`, `--min-os <ver>`.
- `-f elf`: stub shared object from a symbol list, or directly from a built ELF shared object to mirror its dynamic
  symbols. `--soname <exe>`, `--arch x86_64|arm64`.

### manifest

Maps every hookable symbol in a linked executable to its RVA and writes a symbol manifest.
Symbol sources: on Windows, the PDB provides publics plus per-module procedure/data records.
Elsewhere, the linked executable's own symbol table.

```shell
symgen manifest --pdb game.pdb -o game.symdb
symgen manifest --binary game.elf -o game.symdb --no-compress
# or, embed directly in an executable:
symgen manifest --pdb game.pdb --embed game.exe
symgen manifest --binary libmain.so --embed libmain.so
```

- `-o <file>`: write the manifest to a file
- `--embed <image>`: embed the manifest into an executable (see below)
- `--no-compress`: disables zstd compression

At least one of `-o` and `--embed` is required.

#### Embedding

A manifest is a post-link artifact, so it cannot be compiled in. Instead, a program may
reserve a 24-byte descriptor `{ magic "SYMDBHDR" u64, rva u64, size u64 }` in a dedicated
section (`.symdbh` on PE, `__DATA,__symdbh` on Mach-O, `symdbh` on ELF), and `--embed` appends
the manifest to the image as a new section and patches the descriptor with its location. No
relocations are involved: the descriptor's `rva` uses the same convention as manifest RVAs
(see below), and the runtime reads the manifest at `image base + rva`. The descriptor's
fields should be declared `volatile` so the compiler cannot fold reads to the zero
initializer.

### modmeta

Dumps static mod metadata records (manifest, service imports/exports, hook declarations) from built mod libraries as
JSON and resolves hook target symbols.

```shell
symgen modmeta mod.dll mod.so
symgen modmeta --check mod.dll mod.so
symgen modmeta --check --update-json mod.json mod.dll mod.so
```

- `--check`: verify well-formedness and that the ABI version and service imports/exports match across a mod's
  native libraries
- `--out <file>`: write the JSON dump to a file instead of stdout
- `--update-json <file>`: verify agreement (as `--check`), then merge the package-level keys (`abi`, `imports`,
  `exports`) into an existing JSON file such as a mod's `mod.json`, preserving its other keys

## Manifest format

Layout (little-endian):

```text
Header  { magic "SYMGEN\0\0", version 2 (u32), compression u32,
           uncompressed_len u64, compressed_len u64,
           build_id_len u32, build_id [u8; 32], entry_count u32 } (72 bytes)
Payload  compressed_len bytes, optionally zstd-compressed
```

`compression` is an enum: `0 = none`, `1 = zstd`.

The decompressed payload contains the entries and string table:

```text
Entry   { hash u64, rva u64, name_off u32, flags u32 } * entry_count,
          sorted by (hash, name_off) for binary search
Strings NUL-terminated names, referenced by name_off
```

`hash` is FNV-1a 64 of the name. The build id keys the manifest to the exact binary
(PDB GUID+age on Windows, `LC_UUID` on Mach-O, GNU build-id on ELF), so a stale manifest
is not loaded accidentally. RVAs are relative to the image base; the loader adds the module's
runtime base.

Entry flags:

| Flag           | Bit | Meaning                                                                    |
|----------------|-----|----------------------------------------------------------------------------|
| `CODE`         | 0   | Function                                                                   |
| `DATA`         | 1   | Data                                                                       |
| `LOCAL`        | 2   | Not externally visible in the image: hookable, never linkable              |
| `MULTI_NAME`   | 3   | Multiple names resolve to this RVA (ICF fold or alias)                     |
| `DUP_NAME`     | 4   | This name maps to multiple RVAs; by-name lookup must treat it as ambiguous |
| `INLINE_SITES` | 5   | Inlined into at least one caller; an entry hook misses the inlined calls   |
| `DISPLAY`      | 6   | Demangled display-name alias generated beside the real symbol name         |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
