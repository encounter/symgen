//! Package-time AArch64 hook gateway preparation for Apple platforms.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use argp::FromArgs;
use object::macho;
use serde::Serialize;

use crate::util::{
    arm64,
    file::atomic_replace,
    macho::{MachOImage, SectionSpec, SegmentSpec, insert_segments},
    manifest::{EmbeddedManifest, FLAG_CODE, LookupError},
    modmeta::{self, HookTarget},
};

const ARENA_MAGIC: [u8; 4] = *b"PA01";
const SITE_MAGIC: [u8; 4] = *b"PS01";
const CODE_SEGMENT_PREFIX: &[u8; 8] = b"__PPATCH";
const DATA_SEGMENT_PREFIX: &[u8; 8] = b"__PPDATA";
// magic[4], capacity[4], record_size[4], reserved[4]
const ARENA_HEADER_SIZE: u64 = 16;
const SITE_HEADER_SIZE: u64 = 12;
const GATEWAY_SIZE: u64 = 28;
const RECORD_SIZE: u64 = SITE_HEADER_SIZE + GATEWAY_SIZE + 4;
const PAGE_SIZE: u64 = 0x4000;
const DEFAULT_ARENA_CAPACITY: u32 = ((PAGE_SIZE - ARENA_HEADER_SIZE) / RECORD_SIZE) as u32;

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Prepare package-time hook gateways in a thin arm64 Apple executable.
#[argp(subcommand, name = "prepatch")]
pub struct Args {
    #[argp(option)]
    /// thin arm64 Mach-O game executable
    binary: PathBuf,
    #[argp(option)]
    /// write a deterministic JSON audit report
    report: Option<PathBuf>,
    #[argp(switch)]
    /// validate and report without replacing the executable
    check: bool,
    #[argp(positional)]
    /// staged bundled native mod libraries
    mods: Vec<PathBuf>,
}

#[derive(Serialize)]
struct Report {
    binary: PathBuf,
    mode: &'static str,
    build_uuid: Option<String>,
    declarations: Vec<DeclarationReport>,
    failures: Vec<String>,
}

#[derive(Serialize)]
struct DeclarationReport {
    mod_id: String,
    mod_path: PathBuf,
    record_kind: &'static str,
    name: String,
    resolved_target_vmaddr: Option<String>,
    alias_group: Vec<String>,
    entry_bytes: Option<String>,
    patch_status: Option<&'static str>,
    gateway_vmaddr: Option<String>,
    orig_stub_vmaddr: Option<String>,
    slot_vmaddr: Option<String>,
    target_to_gateway_distance: Option<i64>,
    stub_to_original_distance: Option<i64>,
    failure: Option<String>,
}

impl DeclarationReport {
    fn new(mod_path: &Path, record_kind: &'static str, name: String) -> Self {
        let stem = mod_path.file_stem().and_then(|name| name.to_str()).unwrap_or("<unknown>");
        let mod_id = if stem == "mod" {
            mod_path
                .parent()
                .and_then(Path::parent)
                .and_then(Path::parent)
                .and_then(Path::file_name)
                .and_then(|name| name.to_str())
                .unwrap_or(stem)
        } else {
            stem
        };
        Self {
            mod_id: mod_id.to_string(),
            mod_path: mod_path.to_path_buf(),
            record_kind,
            name,
            resolved_target_vmaddr: None,
            alias_group: Vec::new(),
            entry_bytes: None,
            patch_status: None,
            gateway_vmaddr: None,
            orig_stub_vmaddr: None,
            slot_vmaddr: None,
            target_to_gateway_distance: None,
            stub_to_original_distance: None,
            failure: None,
        }
    }
}

fn parse_image(data: &[u8]) -> Result<MachOImage<'_>> {
    let image = MachOImage::parse(data)?;
    if image.cpu_type() != macho::CPU_TYPE_ARM64 {
        bail!("prepatch requires arm64 (Mach-O cputype is {:#x})", image.cpu_type());
    }
    let subtype = image.cpu_subtype();
    let base_subtype = subtype & !macho::CPU_SUBTYPE_MASK;
    if base_subtype == macho::CPU_SUBTYPE_ARM64E
        || subtype & macho::CPU_SUBTYPE_ARM64_PTR_AUTH_MASK != 0
    {
        bail!("arm64e/pointer-authenticated Mach-O images are unsupported");
    }
    if !image.platforms()?.into_iter().any(|platform| {
        matches!(platform, macho::PLATFORM_MACOS | macho::PLATFORM_IOS | macho::PLATFORM_TVOS)
    }) {
        bail!("prepatch supports only macOS, iOS, and tvOS Mach-O executables");
    }
    Ok(image)
}

#[derive(Clone, Debug)]
struct ResolvedDecl {
    report_index: usize,
    target: u64,
    alias: String,
}

#[derive(Debug)]
struct Placement {
    record: u64,
    gateway: u64,
    stub: u64,
    slot: u64,
    instructions: [u32; 7],
}

#[derive(Debug)]
struct ExistingArena {
    code_vmaddr: u64,
    data_vmaddr: u64,
    free_indices: Vec<u32>,
}

#[derive(Debug)]
struct NewArena {
    generation: u32,
    code_vmaddr: u64,
    data_vmaddr: u64,
    capacity: u32,
}

struct PrepatchPlan {
    targets: Vec<u64>,
    placements: BTreeMap<u64, Placement>,
    new_arena: Option<NewArena>,
}

fn lookup_code(manifest: &EmbeddedManifest, name: &str) -> Result<u64> {
    let result = manifest.lookup(name).map_err(|error| match error {
        LookupError::NotFound => anyhow::anyhow!("symbol '{name}' is not in the embedded manifest"),
        LookupError::Ambiguous => anyhow::anyhow!(
            "symbol '{name}' maps to multiple addresses; use an unambiguous mangled name"
        ),
    })?;
    if result.flags & FLAG_CODE == 0 {
        bail!("symbol '{name}' is not a code symbol");
    }
    Ok(result.vmaddr)
}

fn resolve_target(
    image: &MachOImage<'_>,
    manifest: &EmbeddedManifest,
    target: &HookTarget,
) -> Result<u64> {
    match target {
        HookTarget::Fn { symbol } => {
            let symbol =
                symbol.as_deref().context("function record has no recoverable bind symbol")?;
            lookup_code(manifest, symbol)
        }
        HookTarget::Name { name } => lookup_code(manifest, name),
        HookTarget::Mem { symbol: Some(symbol), .. } => lookup_code(manifest, symbol),
        HookTarget::Mem { vtable, display, symbol: None, virtual_slot } => {
            let display_error = match lookup_code(manifest, display) {
                Ok(target) => return Ok(target),
                Err(error) => error,
            };
            let Some(slot) = virtual_slot else {
                bail!(
                    "member display name did not resolve ({display_error:#}) and the record has no primary-vtable slot"
                );
            };
            (|| -> Result<u64> {
                let vtable = manifest.lookup(vtable).map_err(|error| match error {
                    LookupError::NotFound => {
                        anyhow::anyhow!("vtable symbol '{vtable}' is not in the embedded manifest")
                    }
                    LookupError::Ambiguous => {
                        anyhow::anyhow!("vtable symbol '{vtable}' is ambiguous")
                    }
                })?;
                let location = vtable
                    .vmaddr
                    .checked_add(16)
                    .and_then(|value| value.checked_add(*slot))
                    .context("vtable slot address overflows")?;
                image.rebased_pointer(location)
            })()
            .with_context(|| {
                format!("display-name lookup failed before vtable fallback: {display_error:#}")
            })
        }
    }
}

fn target_label(target: &HookTarget) -> (&'static str, String) {
    match target {
        HookTarget::Fn { symbol } => ("fn", symbol.clone().unwrap_or_else(|| "<fn>".into())),
        HookTarget::Name { name } => ("name", name.clone()),
        HookTarget::Mem { display, symbol, virtual_slot, .. } => {
            let suffix = symbol
                .as_ref()
                .map(|symbol| format!(" [{symbol}]"))
                .or_else(|| virtual_slot.map(|slot| format!(" [virtual+{slot:#x}]")))
                .unwrap_or_default();
            ("member", format!("{display}{suffix}"))
        }
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join("")
}

fn hex_addr(value: u64) -> String { format!("{value:#018x}") }

fn align_up(value: u64, alignment: u64) -> Result<u64> {
    let remainder = value % alignment;
    if remainder == 0 {
        Ok(value)
    } else {
        value.checked_add(alignment - remainder).context("Prepatch segment size overflows")
    }
}

fn arena_capacity(required: u32) -> Result<u32> {
    let required = required.max(DEFAULT_ARENA_CAPACITY);
    let required_size = ARENA_HEADER_SIZE
        .checked_add(u64::from(required) * RECORD_SIZE)
        .context("Arena size overflows")?;
    let allocated_size = align_up(required_size, PAGE_SIZE)?;
    u32::try_from((allocated_size - ARENA_HEADER_SIZE) / RECORD_SIZE)
        .context("Arena capacity exceeds u32")
}

fn signed_delta(from: u64, to: u64, description: &str) -> Result<i32> {
    i32::try_from(i128::from(to) - i128::from(from))
        .with_context(|| format!("{description} offset is outside signed 32-bit range"))
}

fn add_delta(address: u64, delta: i32, description: &str) -> Result<u64> {
    address.checked_add_signed(i64::from(delta)).with_context(|| format!("{description} overflows"))
}

fn segment_name(prefix: &[u8; 8], generation: u32) -> String {
    format!("{}{:08X}", std::str::from_utf8(prefix).unwrap(), generation)
}

fn segment_generation(name: &[u8; 16], prefix: &[u8; 8]) -> Option<u32> {
    if &name[..8] != prefix {
        return None;
    }
    let suffix = std::str::from_utf8(&name[8..]).ok()?;
    u32::from_str_radix(suffix, 16).ok()
}

fn make_placement(target: u64, record: u64, slot: u64) -> Result<Placement> {
    let gateway = record.checked_add(SITE_HEADER_SIZE).context("Gateway address overflows")?;
    let stub = gateway.checked_add(20).context("Original stub address overflows")?;
    let original = target.checked_add(4).context("Original entry address overflows")?;
    arm64::b(target, gateway)?;
    signed_delta(gateway, target, "Gateway target")?;
    signed_delta(gateway, slot, "Gateway slot")?;
    let instructions = [
        arm64::adrp_x16(gateway, slot)?,
        arm64::add_x16_pageoff(slot),
        arm64::ldar_x16_x16(),
        arm64::cbz_x16(
            gateway.checked_add(12).context("Gateway instruction address overflows")?,
            stub,
        )?,
        arm64::br_x16(),
        arm64::bti_c(),
        arm64::b(stub.checked_add(4).context("Original stub address overflows")?, original)?,
    ];
    Ok(Placement { record, gateway, stub, slot, instructions })
}

fn encode_record(target: u64, placement: &Placement) -> Result<[u8; RECORD_SIZE as usize]> {
    let mut record = [0u8; RECORD_SIZE as usize];
    record[..4].copy_from_slice(&SITE_MAGIC);
    record[4..8]
        .copy_from_slice(&signed_delta(placement.gateway, target, "Gateway target")?.to_le_bytes());
    record[8..12].copy_from_slice(
        &signed_delta(placement.gateway, placement.slot, "Gateway slot")?.to_le_bytes(),
    );
    for (index, instruction) in placement.instructions.iter().enumerate() {
        let offset = SITE_HEADER_SIZE as usize + index * 4;
        record[offset..offset + 4].copy_from_slice(&instruction.to_le_bytes());
    }
    Ok(record)
}

fn has_protection(image: &MachOImage<'_>, address: u64, size: u64, protection: u32) -> bool {
    let Some(end) = address.checked_add(size) else { return false };
    image.segments().iter().any(|segment| {
        let Some(segment_end) = segment.vmaddr.checked_add(segment.vmsize) else { return false };
        address >= segment.vmaddr
            && end <= segment_end
            && segment.max_prot == protection
            && segment.init_prot == protection
    })
}

fn scan_arenas(
    image: &MachOImage<'_>,
) -> Result<(Vec<ExistingArena>, BTreeMap<u64, Placement>, u32)> {
    let mut code_segments = BTreeMap::new();
    let mut data_segments = BTreeMap::new();
    for segment in image.segments() {
        let destination =
            if let Some(generation) = segment_generation(&segment.name, CODE_SEGMENT_PREFIX) {
                Some((&mut code_segments, generation))
            } else {
                segment_generation(&segment.name, DATA_SEGMENT_PREFIX)
                    .map(|generation| (&mut data_segments, generation))
            };
        if let Some((segments, generation)) = destination
            && segments.insert(generation, segment).is_some()
        {
            bail!("Duplicate prepatch arena generation {generation}");
        }
    }
    if code_segments.keys().ne(data_segments.keys()) {
        bail!("Prepatch code/data arena generations do not match");
    }

    let rx = macho::VM_PROT_READ | macho::VM_PROT_EXECUTE;
    let rw = macho::VM_PROT_READ | macho::VM_PROT_WRITE;
    let mut arenas = Vec::new();
    let mut sites = BTreeMap::new();
    for (&generation, code) in &code_segments {
        let data = data_segments[&generation];
        if code.max_prot != rx || code.init_prot != rx {
            bail!("Prepatch code arena {generation} does not have exact r-x protections");
        }
        if data.max_prot != rw || data.init_prot != rw {
            bail!("Prepatch data arena {generation} does not have exact rw- protections");
        }
        let header = image.bytes_at(code.vmaddr, ARENA_HEADER_SIZE as usize)?;
        if header[..4] != ARENA_MAGIC {
            bail!("Prepatch arena {generation} has an unsupported header");
        }
        let capacity = u32::from_le_bytes(header[4..8].try_into().unwrap());
        let record_size = u32::from_le_bytes(header[8..12].try_into().unwrap());
        if capacity == 0 || u64::from(record_size) != RECORD_SIZE {
            bail!("Prepatch arena {generation} has an invalid capacity or record size");
        }
        let code_size = ARENA_HEADER_SIZE
            .checked_add(
                u64::from(capacity).checked_mul(RECORD_SIZE).context("Arena size overflows")?,
            )
            .context("Arena size overflows")?;
        let data_size = u64::from(capacity).checked_mul(8).context("Slot arena size overflows")?;
        if code_size > code.filesize || data_size > data.filesize {
            bail!("Prepatch arena {generation} exceeds its file-backed segments");
        }

        let mut free_indices = Vec::new();
        for index in 0..capacity {
            let record = code
                .vmaddr
                .checked_add(ARENA_HEADER_SIZE)
                .and_then(|value| value.checked_add(u64::from(index) * RECORD_SIZE))
                .context("Arena record address overflows")?;
            let slot = data
                .vmaddr
                .checked_add(u64::from(index) * 8)
                .context("Arena slot address overflows")?;
            let bytes = image.bytes_at(record, RECORD_SIZE as usize)?;
            let slot_bytes = image.bytes_at(slot, 8)?;
            if bytes.iter().all(|&byte| byte == 0) {
                if !slot_bytes.iter().all(|&byte| byte == 0) {
                    bail!("Free prepatch record {generation}:{index} has a nonzero slot");
                }
                free_indices.push(index);
                continue;
            }
            if bytes[..4] != SITE_MAGIC {
                bail!("Prepatch record {generation}:{index} has an unsupported header");
            }
            if !slot_bytes.iter().all(|&byte| byte == 0) {
                bail!("Prepatch record {generation}:{index} has a nonzero file slot");
            }
            let gateway =
                record.checked_add(SITE_HEADER_SIZE).context("Gateway address overflows")?;
            let target_delta = i32::from_le_bytes(bytes[4..8].try_into().unwrap());
            let slot_delta = i32::from_le_bytes(bytes[8..12].try_into().unwrap());
            let target = add_delta(gateway, target_delta, "Gateway target address")?;
            let recorded_slot = add_delta(gateway, slot_delta, "Gateway slot address")?;
            if recorded_slot != slot {
                bail!("Prepatch record {generation}:{index} points at the wrong slot");
            }
            if !has_protection(image, target, 4, rx) {
                bail!("Prepatch record {generation}:{index} target is not executable");
            }
            let placement = make_placement(target, record, slot)?;
            if bytes != encode_record(target, &placement)? {
                bail!("Prepatch record {generation}:{index} gateway bytes are inconsistent");
            }
            if image.bytes_at(target, 4)? != arm64::b(target, gateway)?.to_le_bytes() {
                bail!("Prepatch record {generation}:{index} is not installed at its target");
            }
            if sites.insert(target, placement).is_some() {
                bail!("Target {target:#x} appears in more than one prepatch arena");
            }
        }
        arenas.push(ExistingArena {
            code_vmaddr: code.vmaddr,
            data_vmaddr: data.vmaddr,
            free_indices,
        });
    }
    let next_generation = code_segments
        .last_key_value()
        .map(|(&generation, _)| generation.checked_add(1).context("Arena generation overflows"))
        .transpose()?
        .unwrap_or(0);
    Ok((arenas, sites, next_generation))
}

fn write_report(path: Option<&Path>, report: &Report) -> Result<()> {
    let Some(path) = path else { return Ok(()) };
    let text = serde_json::to_string_pretty(report)? + "\n";
    fs::write(path, text).with_context(|| format!("Failed to write report '{}'", path.display()))
}

fn resolve_hooks(
    mod_paths: &[PathBuf],
    image: &MachOImage<'_>,
    manifest: &EmbeddedManifest,
    report: &mut Report,
) -> Result<Vec<ResolvedDecl>> {
    let mut resolved = Vec::new();
    for mod_path in mod_paths {
        let mod_data = match fs::read(mod_path) {
            Ok(data) => data,
            Err(error) => {
                let mut entry = DeclarationReport::new(mod_path, "library", "<metadata>".into());
                entry.failure = Some(format!("failed to read mod library: {error}"));
                report.declarations.push(entry);
                continue;
            }
        };
        let meta = match modmeta::parse_library(&mod_data) {
            Ok(meta) => meta,
            Err(error) => {
                let mut entry = DeclarationReport::new(mod_path, "library", "<metadata>".into());
                entry.failure = Some(format!("failed to parse mod metadata: {error:#}"));
                report.declarations.push(entry);
                continue;
            }
        };
        for target in &meta.hooks {
            let (kind, label) = target_label(target);
            let report_index = report.declarations.len();
            report.declarations.push(DeclarationReport::new(mod_path, kind, label.clone()));
            match resolve_target(image, manifest, target) {
                Ok(target) => {
                    report.declarations[report_index].resolved_target_vmaddr =
                        Some(hex_addr(target));
                    resolved.push(ResolvedDecl { report_index, target, alias: label });
                }
                Err(error) => {
                    report.declarations[report_index].failure = Some(format!("{error:#}"))
                }
            }
        }
    }
    if report.declarations.iter().any(|entry| entry.failure.is_some()) {
        bail!("one or more hook declarations could not be resolved");
    }
    Ok(resolved)
}

fn plan_prepatch(
    image: &MachOImage<'_>,
    resolved: &[ResolvedDecl],
    report: &mut Report,
) -> Result<Option<PrepatchPlan>> {
    let (arenas, existing_sites, next_generation) = scan_arenas(image)?;

    let mut aliases: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    for declaration in resolved {
        aliases.entry(declaration.target).or_default().insert(declaration.alias.clone());
    }
    for declaration in resolved {
        report.declarations[declaration.report_index].alias_group =
            aliases[&declaration.target].iter().cloned().collect();
    }

    let entry_nop = arm64::nop().to_le_bytes();
    let mut missing = Vec::new();
    for &target in aliases.keys() {
        if existing_sites.contains_key(&target) {
            continue;
        }
        match image.bytes_at(target, 4) {
            Ok(bytes) if bytes == entry_nop => missing.push(target),
            Ok(bytes) => {
                for declaration in
                    resolved.iter().filter(|declaration| declaration.target == target)
                {
                    report.declarations[declaration.report_index].failure = Some(format!(
                        "target {} begins with {}, expected canonical arm64 nop {} or a valid prepatch branch",
                        hex_addr(target),
                        hex_bytes(bytes),
                        hex_bytes(&entry_nop)
                    ));
                }
            }
            Err(error) => {
                for declaration in
                    resolved.iter().filter(|declaration| declaration.target == target)
                {
                    report.declarations[declaration.report_index].failure =
                        Some(format!("target is not patchable: {error:#}"));
                }
            }
        }
    }
    if report.declarations.iter().any(|entry| entry.failure.is_some()) {
        bail!("one or more hook targets do not satisfy the patchable-entry contract");
    }

    let mut placements = BTreeMap::new();
    let mut missing_index = 0usize;
    for arena in &arenas {
        for &index in &arena.free_indices {
            let Some(&target) = missing.get(missing_index) else { break };
            let record = arena
                .code_vmaddr
                .checked_add(ARENA_HEADER_SIZE)
                .and_then(|value| value.checked_add(u64::from(index) * RECORD_SIZE))
                .context("Arena record address overflows")?;
            let slot = arena
                .data_vmaddr
                .checked_add(u64::from(index) * 8)
                .context("Arena slot address overflows")?;
            match make_placement(target, record, slot) {
                Ok(placement) => {
                    placements.insert(target, placement);
                    missing_index += 1;
                }
                Err(error) => {
                    for declaration in
                        resolved.iter().filter(|declaration| declaration.target == target)
                    {
                        report.declarations[declaration.report_index].failure =
                            Some(format!("gateway cannot be encoded: {error:#}"));
                    }
                }
            }
        }
    }

    let remaining = &missing[missing_index..];
    let new_arena = if remaining.is_empty() {
        None
    } else {
        let remaining_count =
            u32::try_from(remaining.len()).context("Hook site count exceeds u32")?;
        let capacity = arena_capacity(remaining_count)?;
        let code_vmaddr = image.linkedit_vmaddr()?;
        let code_size = ARENA_HEADER_SIZE
            .checked_add(u64::from(capacity) * RECORD_SIZE)
            .context("Arena size overflows")?;
        let data_vmaddr = code_vmaddr
            .checked_add(align_up(code_size, PAGE_SIZE)?)
            .context("Arena data address overflows")?;
        for (index, &target) in remaining.iter().enumerate() {
            let index = u64::try_from(index).context("Arena record index overflows")?;
            let record = code_vmaddr
                .checked_add(ARENA_HEADER_SIZE)
                .and_then(|value| value.checked_add(index * RECORD_SIZE))
                .context("Arena record address overflows")?;
            let slot =
                data_vmaddr.checked_add(index * 8).context("Arena slot address overflows")?;
            match make_placement(target, record, slot) {
                Ok(placement) => {
                    placements.insert(target, placement);
                }
                Err(error) => {
                    for declaration in
                        resolved.iter().filter(|declaration| declaration.target == target)
                    {
                        report.declarations[declaration.report_index].failure =
                            Some(format!("gateway cannot be encoded: {error:#}"));
                    }
                }
            }
        }
        Some(NewArena { generation: next_generation, code_vmaddr, data_vmaddr, capacity })
    };
    if report.declarations.iter().any(|entry| entry.failure.is_some()) {
        bail!("one or more hook targets are not branch-reachable");
    }

    for declaration in resolved {
        let (placement, status) = match placements.get(&declaration.target) {
            Some(placement) => (placement, "added"),
            None => (&existing_sites[&declaration.target], "existing"),
        };
        let item = &mut report.declarations[declaration.report_index];
        item.entry_bytes = Some(hex_bytes(image.bytes_at(declaration.target, 4)?));
        item.patch_status = Some(status);
        item.gateway_vmaddr = Some(hex_addr(placement.gateway));
        item.orig_stub_vmaddr = Some(hex_addr(placement.stub));
        item.slot_vmaddr = Some(hex_addr(placement.slot));
        item.target_to_gateway_distance = Some(
            i64::try_from(i128::from(placement.gateway) - i128::from(declaration.target))
                .expect("entry branch displacement was validated"),
        );
        item.stub_to_original_distance = Some(
            i64::try_from(i128::from(declaration.target) - i128::from(placement.stub))
                .expect("original-stub branch displacement was validated"),
        );
    }

    if placements.is_empty() {
        Ok(None)
    } else {
        Ok(Some(PrepatchPlan { targets: missing, placements, new_arena }))
    }
}

fn apply_prepatch(original: &[u8], image: &MachOImage<'_>, plan: &PrepatchPlan) -> Result<Vec<u8>> {
    let mut output = original.to_vec();
    for &target in &plan.targets {
        let placement = &plan.placements[&target];
        let in_new_arena = plan.new_arena.as_ref().is_some_and(|arena| {
            placement.record >= arena.code_vmaddr && placement.record < arena.data_vmaddr
        });
        if !in_new_arena {
            let offset = image.vm_to_file(placement.record, RECORD_SIZE)?;
            output[offset..offset + RECORD_SIZE as usize]
                .copy_from_slice(&encode_record(target, placement)?);
        }
    }

    if let Some(arena) = &plan.new_arena {
        let code_size = ARENA_HEADER_SIZE
            .checked_add(u64::from(arena.capacity) * RECORD_SIZE)
            .context("Arena size overflows")?;
        let slots_size = u64::from(arena.capacity) * 8;
        let mut code = vec![0u8; usize::try_from(code_size).context("Arena exceeds host space")?];
        code[..4].copy_from_slice(&ARENA_MAGIC);
        code[4..8].copy_from_slice(&arena.capacity.to_le_bytes());
        code[8..12].copy_from_slice(&(RECORD_SIZE as u32).to_le_bytes());
        for &target in &plan.targets {
            let placement = &plan.placements[&target];
            if placement.record < arena.code_vmaddr || placement.record >= arena.data_vmaddr {
                continue;
            }
            let offset = usize::try_from(placement.record - arena.code_vmaddr)
                .context("Arena record offset exceeds host space")?;
            code[offset..offset + RECORD_SIZE as usize]
                .copy_from_slice(&encode_record(target, placement)?);
        }
        let inserted = insert_segments(output, &[
            SegmentSpec {
                name: segment_name(CODE_SEGMENT_PREFIX, arena.generation),
                data: code,
                max_prot: macho::VM_PROT_READ | macho::VM_PROT_EXECUTE,
                init_prot: macho::VM_PROT_READ | macho::VM_PROT_EXECUTE,
                sections: vec![SectionSpec {
                    name: "__arena",
                    offset: 0,
                    size: code_size,
                    align: 3,
                    flags: macho::S_REGULAR,
                }],
            },
            SegmentSpec {
                name: segment_name(DATA_SEGMENT_PREFIX, arena.generation),
                data: vec![0u8; usize::try_from(slots_size).context("Slots exceed host space")?],
                max_prot: macho::VM_PROT_READ | macho::VM_PROT_WRITE,
                init_prot: macho::VM_PROT_READ | macho::VM_PROT_WRITE,
                sections: vec![SectionSpec {
                    name: "__slots",
                    offset: 0,
                    size: slots_size,
                    align: 3,
                    flags: macho::S_REGULAR,
                }],
            },
        ])?;
        if inserted.segments[0].vmaddr != arena.code_vmaddr
            || inserted.segments[1].vmaddr != arena.data_vmaddr
        {
            bail!("Mach-O inserter placement disagrees with prevalidated arena addresses");
        }
        output = inserted.data;
    }

    for &target in &plan.targets {
        let offset = image.vm_to_file(target, 4)?;
        output[offset..offset + 4]
            .copy_from_slice(&arm64::b(target, plan.placements[&target].gateway)?.to_le_bytes());
    }

    let reparsed = parse_image(&output).context("Transformed Mach-O failed structural reparse")?;
    scan_arenas(&reparsed).context("Transformed Mach-O has invalid prepatch arenas")?;
    EmbeddedManifest::parse_macho(&output)
        .context("Transformed Mach-O lost its symbol manifest")?;
    Ok(output)
}

fn execute(args: &Args, report: &mut Report) -> Result<Option<Vec<u8>>> {
    let original = fs::read(&args.binary)
        .with_context(|| format!("Failed to read '{}'", args.binary.display()))?;
    let image = parse_image(&original)?;
    let manifest = EmbeddedManifest::parse_macho(&original)?;
    report.build_uuid = Some(hex_bytes(&manifest.build_uuid));

    let resolved = resolve_hooks(&args.mods, &image, &manifest, report)?;

    let Some(plan) = plan_prepatch(&image, &resolved, report)? else {
        return Ok(None);
    };

    Ok(Some(apply_prepatch(&original, &image, &plan)?))
}

pub fn run(args: Args) -> Result<()> {
    let mut report = Report {
        binary: args.binary.clone(),
        mode: if args.check { "check" } else { "rewrite" },
        build_uuid: None,
        declarations: Vec::new(),
        failures: Vec::new(),
    };
    let result = execute(&args, &mut report);
    if let Err(error) = &result {
        report.failures.push(format!("{error:#}"));
    }
    write_report(args.report.as_deref(), &report)?;
    let output = result?;
    let added_count = report
        .declarations
        .iter()
        .filter(|entry| entry.patch_status == Some("added"))
        .filter_map(|entry| entry.resolved_target_vmaddr.as_deref())
        .collect::<BTreeSet<_>>()
        .len();
    let existing_count = report
        .declarations
        .iter()
        .filter(|entry| entry.patch_status == Some("existing"))
        .filter_map(|entry| entry.resolved_target_vmaddr.as_deref())
        .collect::<BTreeSet<_>>()
        .len();
    match output {
        Some(output) if !args.check => {
            atomic_replace(&args.binary, &output)?;
            log::info!(
                "Added {added_count} prepatch hook site(s); reused {existing_count} existing site(s) in '{}'",
                args.binary.display()
            );
        }
        Some(_) => {
            log::info!(
                "Prepatch check passed for {} hook declaration(s)",
                report.declarations.len()
            );
        }
        None if existing_count != 0 => {
            log::info!("All {existing_count} requested hook site(s) are already prepatched")
        }
        None => log::info!("No hook declarations found; image left unchanged"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use object::{LittleEndian as LE, U32 as ObjectU32, U64 as ObjectU64, pod::bytes_of};

    use super::*;
    use crate::util::manifest::{ManifestInput, ManifestSymbol, build_manifest};

    const BASE: u64 = 0x1_0000_0000;
    const TARGET: u64 = BASE + 0x1000;
    const TARGET_2: u64 = BASE + 0x1100;
    const UUID: [u8; 16] = *b"prepatch-fixture";

    fn segment(
        name: &[u8],
        vmaddr: u64,
        vmsize: u64,
        fileoff: u64,
        filesize: u64,
        protection: u32,
    ) -> macho::SegmentCommand64<LE> {
        let mut segment_name = [0u8; 16];
        segment_name[..name.len()].copy_from_slice(name);
        macho::SegmentCommand64 {
            cmd: ObjectU32::new(LE, macho::LC_SEGMENT_64),
            cmdsize: ObjectU32::new(LE, size_of::<macho::SegmentCommand64<LE>>() as u32),
            segname: segment_name,
            vmaddr: ObjectU64::new(LE, vmaddr),
            vmsize: ObjectU64::new(LE, vmsize),
            fileoff: ObjectU64::new(LE, fileoff),
            filesize: ObjectU64::new(LE, filesize),
            maxprot: ObjectU32::new(LE, protection),
            initprot: ObjectU32::new(LE, protection),
            nsects: ObjectU32::new(LE, 0),
            flags: ObjectU32::new(LE, 0),
        }
    }

    fn base_image() -> Vec<u8> {
        let command_size = 2 * size_of::<macho::SegmentCommand64<LE>>()
            + size_of::<macho::BuildVersionCommand<LE>>()
            + size_of::<macho::UuidCommand<LE>>();
        let header = macho::MachHeader64::<LE> {
            magic: ObjectU32::new(object::BigEndian, macho::MH_CIGAM_64),
            cputype: ObjectU32::new(LE, macho::CPU_TYPE_ARM64),
            cpusubtype: ObjectU32::new(LE, macho::CPU_SUBTYPE_ARM64_ALL),
            filetype: ObjectU32::new(LE, macho::MH_EXECUTE),
            ncmds: ObjectU32::new(LE, 4),
            sizeofcmds: ObjectU32::new(LE, command_size as u32),
            flags: ObjectU32::new(LE, macho::MH_NOUNDEFS | macho::MH_DYLDLINK | macho::MH_PIE),
            reserved: ObjectU32::new(LE, 0),
        };
        let text = segment(
            b"__TEXT",
            BASE,
            PAGE_SIZE,
            0,
            PAGE_SIZE,
            macho::VM_PROT_READ | macho::VM_PROT_EXECUTE,
        );
        let linkedit =
            segment(b"__LINKEDIT", BASE + PAGE_SIZE, PAGE_SIZE, PAGE_SIZE, 16, macho::VM_PROT_READ);
        let build_version = macho::BuildVersionCommand::<LE> {
            cmd: ObjectU32::new(LE, macho::LC_BUILD_VERSION),
            cmdsize: ObjectU32::new(LE, size_of::<macho::BuildVersionCommand<LE>>() as u32),
            platform: ObjectU32::new(LE, macho::PLATFORM_MACOS),
            minos: ObjectU32::new(LE, 0x000B_0000),
            sdk: ObjectU32::new(LE, 0x000B_0000),
            ntools: ObjectU32::new(LE, 0),
        };
        let uuid = macho::UuidCommand::<LE> {
            cmd: ObjectU32::new(LE, macho::LC_UUID),
            cmdsize: ObjectU32::new(LE, size_of::<macho::UuidCommand<LE>>() as u32),
            uuid: UUID,
        };

        let mut data = Vec::new();
        data.extend_from_slice(bytes_of(&header));
        data.extend_from_slice(bytes_of(&text));
        data.extend_from_slice(bytes_of(&linkedit));
        data.extend_from_slice(bytes_of(&build_version));
        data.extend_from_slice(bytes_of(&uuid));
        data.resize(PAGE_SIZE as usize + 16, 0);
        data[TARGET as usize - BASE as usize..TARGET as usize - BASE as usize + 4]
            .copy_from_slice(&arm64::nop().to_le_bytes());
        data[TARGET_2 as usize - BASE as usize..TARGET_2 as usize - BASE as usize + 4]
            .copy_from_slice(&arm64::nop().to_le_bytes());
        data
    }

    fn fixture() -> Vec<u8> {
        let (manifest, _) = build_manifest(&ManifestInput {
            build_id: UUID.to_vec(),
            symbols: vec![
                ManifestSymbol { name: "game_func".to_string(), rva: TARGET, flags: FLAG_CODE },
                ManifestSymbol { name: "game_func_2".to_string(), rva: TARGET_2, flags: FLAG_CODE },
            ],
        })
        .unwrap();
        insert_segments(base_image(), &[SegmentSpec {
            name: "__SYMDB".into(),
            data: manifest.clone(),
            max_prot: macho::VM_PROT_READ,
            init_prot: macho::VM_PROT_READ,
            sections: vec![SectionSpec {
                name: "__symdb",
                offset: 0,
                size: manifest.len() as u64,
                align: 3,
                flags: macho::S_REGULAR,
            }],
        }])
        .unwrap()
        .data
    }

    fn report(name: &str) -> Report {
        Report {
            binary: PathBuf::from("fixture"),
            mode: "check",
            build_uuid: Some(hex_bytes(&UUID)),
            declarations: vec![DeclarationReport::new(
                Path::new("mods/example/lib/apple-arm64/mod.dylib"),
                "name",
                name.to_string(),
            )],
            failures: Vec::new(),
        }
    }

    fn many_targets(count: usize) -> (Vec<u8>, Vec<ResolvedDecl>, Report) {
        let mut original = fixture();
        let mut declarations = Vec::with_capacity(count);
        let mut resolved = Vec::with_capacity(count);
        for index in 0..count {
            let target = BASE + 0x2000 + u64::try_from(index).unwrap() * 4;
            let offset = usize::try_from(target - BASE).unwrap();
            original[offset..offset + 4].copy_from_slice(&arm64::nop().to_le_bytes());
            let name = format!("many_{index}");
            declarations.push(DeclarationReport::new(
                Path::new("mods/example/lib/apple-arm64/mod.dylib"),
                "name",
                name.clone(),
            ));
            resolved.push(ResolvedDecl { report_index: index, target, alias: name });
        }
        let report = Report {
            binary: PathBuf::from("fixture"),
            mode: "check",
            build_uuid: Some(hex_bytes(&UUID)),
            declarations,
            failures: Vec::new(),
        };
        (original, resolved, report)
    }

    #[test]
    fn arenas_are_additive_and_idempotent() {
        let original = fixture();
        let image = parse_image(&original).unwrap();
        let mut first_report = report("game_func");
        let first_resolved =
            [ResolvedDecl { report_index: 0, target: TARGET, alias: "game_func".to_string() }];

        let plan = plan_prepatch(&image, &first_resolved, &mut first_report).unwrap().unwrap();
        assert_eq!(plan.targets, [TARGET]);
        assert_eq!(plan.new_arena.as_ref().unwrap().capacity, DEFAULT_ARENA_CAPACITY);
        assert_eq!(first_report.declarations[0].patch_status, Some("added"));
        let first_output = apply_prepatch(&original, &image, &plan).unwrap();

        let first_image = parse_image(&first_output).unwrap();
        let (arenas, sites, _) = scan_arenas(&first_image).unwrap();
        assert_eq!(arenas.len(), 1);
        assert_eq!(sites.len(), 1);
        assert_eq!(arenas[0].free_indices.len(), DEFAULT_ARENA_CAPACITY as usize - 1);
        assert_ne!(first_image.bytes_at(TARGET, 4).unwrap(), arm64::nop().to_le_bytes());
        EmbeddedManifest::parse_macho(&first_output).unwrap();

        let mut repeat_report = report("game_func");
        assert!(
            plan_prepatch(&first_image, &first_resolved, &mut repeat_report).unwrap().is_none()
        );
        assert_eq!(repeat_report.declarations[0].patch_status, Some("existing"));

        let mut second_report = report("game_func_2");
        let second_resolved =
            [ResolvedDecl { report_index: 0, target: TARGET_2, alias: "game_func_2".to_string() }];
        let second_plan =
            plan_prepatch(&first_image, &second_resolved, &mut second_report).unwrap().unwrap();
        assert!(second_plan.new_arena.is_none());
        let second_output = apply_prepatch(&first_output, &first_image, &second_plan).unwrap();
        assert_eq!(second_output.len(), first_output.len());

        let second_image = parse_image(&second_output).unwrap();
        let (arenas, sites, _) = scan_arenas(&second_image).unwrap();
        assert_eq!(arenas.len(), 1);
        assert_eq!(sites.len(), 2);
        assert_eq!(arenas[0].free_indices.len(), DEFAULT_ARENA_CAPACITY as usize - 2);
        assert_ne!(second_image.bytes_at(TARGET_2, 4).unwrap(), arm64::nop().to_le_bytes());
    }

    #[test]
    fn default_arena_fills_one_arm64_page() {
        assert_eq!(ARENA_HEADER_SIZE + u64::from(DEFAULT_ARENA_CAPACITY) * RECORD_SIZE, PAGE_SIZE);
        assert_eq!(DEFAULT_ARENA_CAPACITY, 372);
    }

    #[test]
    fn oversized_request_fills_its_allocated_pages() {
        let count = DEFAULT_ARENA_CAPACITY as usize + 1;
        let (original, resolved, mut report) = many_targets(count);
        let image = parse_image(&original).unwrap();
        let plan = plan_prepatch(&image, &resolved, &mut report).unwrap().unwrap();
        assert_eq!(plan.new_arena.as_ref().unwrap().capacity, 744);
    }

    #[test]
    fn a_full_arena_adds_another_generation() {
        let count = DEFAULT_ARENA_CAPACITY as usize + 1;
        let (original, resolved, mut report) = many_targets(count);
        let image = parse_image(&original).unwrap();
        let first_plan =
            plan_prepatch(&image, &resolved[..DEFAULT_ARENA_CAPACITY as usize], &mut report)
                .unwrap()
                .unwrap();
        let first_output = apply_prepatch(&original, &image, &first_plan).unwrap();
        let first_image = parse_image(&first_output).unwrap();

        let mut last_report = Report {
            binary: PathBuf::from("fixture"),
            mode: "check",
            build_uuid: Some(hex_bytes(&UUID)),
            declarations: vec![DeclarationReport::new(
                Path::new("mods/example/lib/apple-arm64/mod.dylib"),
                "name",
                "last".to_string(),
            )],
            failures: Vec::new(),
        };
        let last = [ResolvedDecl {
            report_index: 0,
            target: resolved.last().unwrap().target,
            alias: "last".to_string(),
        }];
        let second_plan = plan_prepatch(&first_image, &last, &mut last_report).unwrap().unwrap();
        assert_eq!(second_plan.new_arena.as_ref().unwrap().generation, 1);
        assert_eq!(second_plan.new_arena.as_ref().unwrap().capacity, DEFAULT_ARENA_CAPACITY);
        let second_output = apply_prepatch(&first_output, &first_image, &second_plan).unwrap();
        let second_image = parse_image(&second_output).unwrap();
        let (arenas, sites, next_generation) = scan_arenas(&second_image).unwrap();
        assert_eq!(arenas.len(), 2);
        assert_eq!(sites.len(), count);
        assert_eq!(next_generation, 2);
    }

    #[test]
    fn plan_reports_aliases() {
        let original = fixture();
        let image = parse_image(&original).unwrap();
        let mut report = report("game_func");
        let resolved =
            [ResolvedDecl { report_index: 0, target: TARGET, alias: "game_func".to_string() }];
        let plan = plan_prepatch(&image, &resolved, &mut report).unwrap().unwrap();
        assert_eq!(plan.targets, [TARGET]);
        assert_eq!(report.declarations[0].alias_group, ["game_func"]);
    }

    #[test]
    fn member_resolution_matches_runtime_ordering() {
        let original = fixture();
        let image = parse_image(&original).unwrap();
        let manifest = EmbeddedManifest::parse_macho(&original).unwrap();

        let secondary_virtual = HookTarget::Mem {
            vtable: "missing_vtable".to_string(),
            display: "game_func".to_string(),
            symbol: None,
            virtual_slot: None,
        };
        assert_eq!(resolve_target(&image, &manifest, &secondary_virtual).unwrap(), TARGET);

        let primary_virtual = HookTarget::Mem {
            vtable: "missing_vtable".to_string(),
            display: "game_func_2".to_string(),
            symbol: None,
            virtual_slot: Some(0),
        };
        assert_eq!(resolve_target(&image, &manifest, &primary_virtual).unwrap(), TARGET_2);

        let direct = HookTarget::Mem {
            vtable: "missing_vtable".to_string(),
            display: "game_func_2".to_string(),
            symbol: Some("game_func".to_string()),
            virtual_slot: None,
        };
        assert_eq!(resolve_target(&image, &manifest, &direct).unwrap(), TARGET);
    }
}
