// SPDX-License-Identifier: Apache-2.0

//! `bhf binary rehost`: fuzz an unmodified Cortex-M firmware image, with no
//! source and no instrumentation, in the rehosting emulator (`crates/rehost`),
//! and replay what it finds.
//!
//! Each input is written into a fixed buffer in the firmware's memory, the
//! core starts from the reset vector, and the basic blocks it enters fill an
//! edge map that steers the builtin engine's mutator and power schedule. A
//! run that faults (an invalid memory access, a bad PC, or a HardFault) is a
//! finding; `bhf replay` runs its testcase through the same machine again and
//! matches the fault signature.

use anyhow::{anyhow, Context};
use fuzz_engine_builtin::{
    Dictionary, MutationInput, MutationRng, MutatorConfig, MutatorSuite, PowerScheduler,
    ScheduleFeedback,
};
use rehost::{
    CoverageMap, Execution, Fault, Image, InputBuffer, Machine, MachineConfig, MemoryRange, Stop,
    DEFAULT_MAX_INSTRUCTIONS,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// `kind` of a rehosted-firmware finding; `bhf replay` dispatches on it.
pub(crate) const FINDING_KIND: &str = "rehost_fault";
const REHOST_SCHEMA: &str = "bhf.rehost.v1";
const RUN_SCHEMA: &str = "bhf.binary_rehost.run.v1";
/// The binary-only crash rule: a replayable abnormal termination.
const RULE_ID: &str = "BHF-501";
/// The longest input the mutator makes when the buffer is larger.
const MAX_INPUT_LEN: u32 = 4096;

#[derive(Debug, clap::Args)]
pub struct BinaryRehostArgs {
    /// Firmware image: a 32-bit ARM ELF, or a raw image (a flash dump,
    /// `objcopy -O binary` output) with `--base`.
    pub image: PathBuf,

    /// BHF work directory where findings are written.
    #[arg(long, default_value = "bhf_work")]
    pub work_dir: PathBuf,

    /// Load a raw image at this address (hex, `0x` optional, e.g.
    /// 0x08000000). An ELF says where it loads, so it takes none.
    #[arg(long, value_name = "ADDR", value_parser = parse_address)]
    pub base: Option<u32>,

    /// Where the vector table is (hex, `0x` optional). Default: the ELF's
    /// `.isr_vector`
    /// (or `.vectors`, `.vector_table`) section, else the lowest loaded
    /// address; for a raw image, its base.
    #[arg(long = "vector-table", value_name = "ADDR", value_parser = parse_address)]
    pub vector_table: Option<u32>,

    /// RAM as `BASE:SIZE` (hex), e.g. 0x20000000:0x20000. Repeatable.
    /// Default: 0x20000000:0x100000. An ELF's `.data` and `.bss` RAM is
    /// mapped as well. A load or store outside the image, its RAM, the
    /// peripheral window (0x40000000-0x5fffffff) and the system space is an
    /// invalid access.
    #[arg(long = "ram", value_name = "BASE:SIZE", value_parser = parse_ram)]
    pub ram: Vec<MemoryRange>,

    /// Where each input is written: an address (hex, `0x` optional, as `nm`
    /// prints it) or an ELF symbol, such as the buffer the firmware's receive
    /// routine fills. A name the symbol table holds is that symbol.
    #[arg(long = "input-buffer", value_name = "ADDR|SYMBOL")]
    pub input_buffer: String,

    /// Bytes the input buffer holds; a longer input is cut to this.
    /// Default: the symbol's size.
    #[arg(long = "input-size", value_name = "BYTES")]
    pub input_size: Option<u32>,

    /// Where the input's length is written, as a little-endian 32-bit word:
    /// an address (hex) or an ELF symbol.
    #[arg(long = "input-length", value_name = "ADDR|SYMBOL")]
    pub input_length: Option<String>,

    /// Write the input when the core first reaches this address (hex) or
    /// function, e.g. `main`, so the start-up code's `.bss` clearing does not
    /// wipe it. Default: at reset. The run JSON's `input_not_delivered`
    /// counts the runs that never reached it.
    #[arg(long = "inject-at", value_name = "ADDR|SYMBOL")]
    pub inject_at: Option<String>,

    /// End a run cleanly when the core reaches this address (hex) or
    /// function. Repeatable. A run also ends when the core goes idle (WFI,
    /// WFE, a branch to itself) or uses `--max-instructions`.
    #[arg(long = "exit-at", value_name = "ADDR|SYMBOL")]
    pub exit_at: Vec<String>,

    /// The most instructions one run executes.
    #[arg(long = "max-instructions", default_value_t = DEFAULT_MAX_INSTRUCTIONS)]
    pub max_instructions: u64,

    /// Runs in the campaign: the seeds, then mutations of the inputs that
    /// reached new edges.
    #[arg(long, default_value_t = 10_000)]
    pub iterations: usize,

    /// Wall-clock budget (e.g. 30s, 5m); the campaign stops at it or at
    /// `--iterations`, whichever comes first.
    #[arg(long = "time", value_parser = crate::fuzz::parse_duration)]
    pub time: Option<Duration>,

    /// Literal seed input bytes. Repeatable.
    #[arg(long = "seed-input")]
    pub seed_inputs: Vec<String>,

    /// File containing seed input bytes. Repeatable.
    #[arg(long = "seed-file")]
    pub seed_files: Vec<PathBuf>,

    /// Seed of the mutation, so a campaign repeats exactly.
    #[arg(long = "rng-seed", default_value_t = 0)]
    pub rng_seed: u64,
}

fn parse_address(value: &str) -> Result<u32, String> {
    hex_number(value)
        .ok_or_else(|| format!("{value:?} is not a 32-bit hex address (e.g. 0x08000000)"))
}

/// A 32-bit hex number, `0x` optional: `nm` and `objdump` print addresses
/// as bare hex digits.
fn hex_number(value: &str) -> Option<u32> {
    let value = value.trim();
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(digits, 16).ok()
}

fn parse_ram(value: &str) -> Result<MemoryRange, String> {
    let (base, size) = value
        .split_once(':')
        .ok_or_else(|| format!("RAM {value:?} is not BASE:SIZE (e.g. 0x20000000:0x20000)"))?;
    let base = parse_address(base)?;
    let size = hex_number(size).ok_or_else(|| format!("RAM size {size:?} is not a hex number"))?;
    if size == 0 {
        return Err(format!("RAM {value:?} has no bytes"));
    }
    if u64::from(base) + u64::from(size) > 1 << 32 {
        return Err(format!(
            "RAM {value:?} runs past the end of the address space"
        ));
    }
    Ok(MemoryRange { base, size })
}

fn hex(value: u32) -> String {
    format!("{value:#010x}")
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Read and load an image: ELF unless `base` makes it raw.
fn load_image(path: &Path, base: Option<u32>) -> anyhow::Result<(Image, Vec<u8>)> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let elf = Image::is_elf(&bytes);
    if elf && base.is_some() {
        return Err(anyhow!(
            "{} is an ELF, which says where it loads: drop --base",
            path.display()
        ));
    }
    if !elf && base.is_none() {
        return Err(anyhow!(
            "{} is not an ELF: give a raw image's load address with --base",
            path.display()
        ));
    }
    let image =
        Image::load(&bytes, base).map_err(|error| anyhow!("load {}: {error}", path.display()))?;
    Ok((image, bytes))
}

/// An address given as an ELF symbol or a hex number, with the symbol's
/// size. A name the image's symbol table holds is that symbol; anything else
/// is hex digits, `0x` optional.
fn resolve(image: &Image, what: &str, value: &str) -> anyhow::Result<(u32, Option<u32>)> {
    let name = value.trim();
    if let Some(symbol) = image.symbol(name) {
        return Ok((symbol.address, Some(symbol.size).filter(|&size| size > 0)));
    }
    if let Some(address) = hex_number(name) {
        return Ok((address, None));
    }
    if image.symbols().is_empty() {
        Err(anyhow!(
            "{what} {value:?} is not an address, and the image has no symbol table to look it up in"
        ))
    } else {
        Err(anyhow!("{what}: the image has no symbol {value:?}"))
    }
}

/// How an image is mapped and run: everything a replay needs to run a
/// finding's testcase the way the campaign did.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Setup {
    image: PathBuf,
    base: Option<u32>,
    vector_table: Option<u32>,
    ram: Vec<MemoryRange>,
    input: InputBuffer,
    exit_at: Vec<u32>,
    max_instructions: u64,
}

impl Setup {
    fn from_args(args: &BinaryRehostArgs, image: &Image) -> anyhow::Result<Self> {
        let (address, symbol_size) = resolve(image, "--input-buffer", &args.input_buffer)?;
        let capacity = match (args.input_size, symbol_size) {
            (Some(size), _) | (None, Some(size)) => size,
            (None, None) => {
                return Err(anyhow!(
                    "--input-size is needed: --input-buffer {:?} names no sized symbol",
                    args.input_buffer
                ))
            }
        };
        let length_word = args
            .input_length
            .as_deref()
            .map(|value| resolve(image, "--input-length", value).map(|(address, _)| address))
            .transpose()?;
        // A code address may carry the Thumb bit, as a vector-table entry
        // or a function pointer does; the instruction is at the even address.
        let code = |what: &str, value: &str| resolve(image, what, value).map(|(at, _)| at & !1);
        let inject_at = args
            .inject_at
            .as_deref()
            .map(|value| code("--inject-at", value))
            .transpose()?;
        let exit_at = args
            .exit_at
            .iter()
            .map(|value| code("--exit-at", value))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let image_path = fs::canonicalize(&args.image).unwrap_or_else(|_| args.image.clone());
        Ok(Self {
            image: image_path,
            base: args.base,
            vector_table: args.vector_table,
            ram: if args.ram.is_empty() {
                vec![MemoryRange::default_ram()]
            } else {
                args.ram.clone()
            },
            input: InputBuffer {
                address,
                capacity,
                length_word,
                inject_at,
            },
            exit_at,
            max_instructions: args.max_instructions,
        })
    }

    fn machine(&self, image: &Image) -> anyhow::Result<Machine> {
        Machine::new(
            image,
            MachineConfig {
                ram: self.ram.clone(),
                vector_table: self.vector_table,
                input: Some(self.input),
                exit_at: self.exit_at.clone(),
                max_instructions: self.max_instructions,
            },
        )
        .map_err(|error| anyhow!("{}: {error}", self.image.display()))
    }

    fn to_json(&self) -> Value {
        json!({
            "image": self.image,
            "base": self.base.map(hex),
            "vector_table": self.vector_table.map(hex),
            "ram": self.ram.iter().map(|range| json!({
                "base": hex(range.base),
                "size": hex(range.size),
            })).collect::<Vec<_>>(),
            "input": {
                "address": hex(self.input.address),
                "capacity": self.input.capacity,
                "length_word": self.input.length_word.map(hex),
                "inject_at": self.input.inject_at.map(hex),
            },
            "exit_at": self.exit_at.iter().copied().map(hex).collect::<Vec<_>>(),
            "max_instructions": self.max_instructions,
        })
    }

    fn from_json(value: &Value) -> Result<Self, String> {
        let address = |value: &Value, field: &str| -> Result<Option<u32>, String> {
            match value {
                Value::Null => Ok(None),
                Value::String(text) => hex_number(text)
                    .map(Some)
                    .ok_or_else(|| format!("rehost.setup.{field} {text:?} is not an address")),
                other => Err(format!("rehost.setup.{field} is {other}, not an address")),
            }
        };
        let required = |value: &Value, field: &str| -> Result<u32, String> {
            address(value, field)?.ok_or_else(|| format!("rehost.setup.{field} is missing"))
        };
        let image = value
            .get("image")
            .and_then(Value::as_str)
            .ok_or("rehost.setup.image is missing")?;
        let ram = value
            .get("ram")
            .and_then(Value::as_array)
            .ok_or("rehost.setup.ram is missing")?
            .iter()
            .map(|range| {
                Ok(MemoryRange {
                    base: required(&range["base"], "ram.base")?,
                    size: required(&range["size"], "ram.size")?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let input = &value["input"];
        let capacity = input["capacity"]
            .as_u64()
            .and_then(|capacity| u32::try_from(capacity).ok())
            .ok_or("rehost.setup.input.capacity is missing")?;
        let exit_at = value
            .get("exit_at")
            .and_then(Value::as_array)
            .map(|addresses| {
                addresses
                    .iter()
                    .map(|address| required(address, "exit_at"))
                    .collect::<Result<Vec<_>, String>>()
            })
            .transpose()?
            .unwrap_or_default();
        Ok(Self {
            image: PathBuf::from(image),
            base: address(&value["base"], "base")?,
            vector_table: address(&value["vector_table"], "vector_table")?,
            ram,
            input: InputBuffer {
                address: required(&input["address"], "input.address")?,
                capacity,
                length_word: address(&input["length_word"], "input.length_word")?,
                inject_at: address(&input["inject_at"], "input.inject_at")?,
            },
            exit_at,
            max_instructions: value["max_instructions"]
                .as_u64()
                .ok_or("rehost.setup.max_instructions is missing")?,
        })
    }
}

/// What a rehosted run does and does not model, recorded with every run and
/// finding so a result is never read as more than it is.
fn fidelity() -> Value {
    json!({
        "execution": "rehosted",
        "cpu": "ARMv7-M Thumb-2 integer core (Cortex-M3/M4), interpreted",
        "peripherals": "not modelled: peripheral registers read as zero and drop writes",
        "interrupts": "not modelled",
        "floating_point": "not modelled",
    })
}

fn fault_json(fault: &Fault) -> Value {
    let names = [
        "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp",
        "lr", "pc",
    ];
    let registers: serde_json::Map<String, Value> = names
        .iter()
        .zip(fault.registers)
        .map(|(name, value)| ((*name).to_owned(), Value::String(hex(value))))
        .collect();
    json!({
        "class": fault.class().as_str(),
        "kind": fault.kind.as_str(),
        "description": fault.message(),
        "pc": hex(fault.pc),
        "address": fault.address.map(hex),
        "from": fault.from.map(hex),
        "site": hex(fault.site()),
        "registers": registers,
        "xpsr": hex(fault.xpsr),
    })
}

/// How a run that did not fault ended, as a phrase.
fn describe_stop(stop: &Stop) -> String {
    match stop {
        Stop::Exit { address } => format!("reached the exit address {}", hex(*address)),
        Stop::Idle { pc, reason } => format!("went idle ({}) at pc {}", reason.as_str(), hex(*pc)),
        Stop::SemihostingExit { code } => format!("exited through semihosting with code {code}"),
        Stop::SystemReset { pc } => format!("requested a system reset at pc {}", hex(*pc)),
        Stop::InstructionLimit => "used its instruction budget".to_owned(),
        Stop::Unsupported { pc, encoding, what } => format!(
            "met an instruction the emulator does not implement ({what}, {encoding:#x}) at pc {}",
            hex(*pc)
        ),
        Stop::Fault(fault) => format!("faulted: {}", fault.message()),
    }
}

/// The image and how it was run, for the findings a campaign writes.
struct Target<'a> {
    setup: &'a Setup,
    sha256: String,
    format: &'static str,
}

fn render_finding(
    id: &str,
    dir: &Path,
    target: &Target<'_>,
    input: &[u8],
    run: &Execution,
    fault: &Fault,
) -> Value {
    json!({
        "id": id,
        "kind": FINDING_KIND,
        "rule_id": RULE_ID,
        "classification": fault.class().as_str(),
        "severity": "high",
        "confidence": "high",
        "message": format!("Rehosted firmware fault: {}", fault.message()),
        "binary": {
            "path": target.setup.image,
            "sha256": target.sha256,
            "format": target.format,
        },
        "input": {
            "mode": "rehost-buffer",
            "bytes": input.len(),
            "delivered": run.input_delivered,
            "testcase": "testcase.bin",
        },
        "crash": {
            "exit_code": Value::Null,
            "timeout": false,
            "signature": fault.signature(),
        },
        "rehost": {
            "schema": REHOST_SCHEMA,
            "setup": target.setup.to_json(),
            "fault": fault_json(fault),
            "instructions": run.instructions,
            "blocks": run.blocks,
            "fidelity": fidelity(),
        },
        "paths": {
            "testcase": "testcase.bin",
        },
        "triage": {
            "replay": format!("bhf replay {}", dir.display()),
        },
    })
}

/// The fault signatures the findings already in `findings_dir` record for
/// the image whose digest is `sha256`, so a campaign rerun into the same work
/// dir does not write a fault twice. Another image's faults are its own.
fn recorded_signatures(findings_dir: &Path, sha256: &str) -> HashSet<String> {
    let Ok(entries) = fs::read_dir(findings_dir) else {
        return HashSet::new();
    };
    entries
        .flatten()
        .filter_map(|entry| fs::read(entry.path().join("finding.json")).ok())
        .filter_map(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .filter(|finding| finding["kind"] == FINDING_KIND && finding["binary"]["sha256"] == sha256)
        .filter_map(|finding| finding["crash"]["signature"].as_str().map(str::to_owned))
        .collect()
}

/// The state of a campaign.
struct Campaign<'a> {
    machine: Machine,
    target: Target<'a>,
    coverage: CoverageMap,
    scheduler: PowerScheduler,
    allocator: corpus::layout::FamilyAllocator,
    seen: HashSet<String>,
    executions: usize,
    corpus_new: usize,
    stops: BTreeMap<&'static str, usize>,
    unsupported: Option<Value>,
    findings: Vec<String>,
    repeated_faults: usize,
    /// Runs that never reached `--inject-at`, so ran without their input.
    input_not_delivered: usize,
    /// How the first of them ended.
    first_undelivered: Option<String>,
}

impl Campaign<'_> {
    /// Run one input: fold its edges in, keep it when it is a seed or a clean
    /// run that reached new edges, and write a new fault as a finding.
    fn execute(&mut self, input: &[u8], seed: bool) -> anyhow::Result<()> {
        let run = self.machine.run(input);
        self.executions += 1;
        *self.stops.entry(run.stop.as_str()).or_default() += 1;
        if run.input_delivered.is_none() {
            self.input_not_delivered += 1;
            self.first_undelivered
                .get_or_insert_with(|| describe_stop(&run.stop));
        }
        let new_edges = self.coverage.merge(self.machine.edge_map());
        match &run.stop {
            Stop::Fault(fault) => {
                if self.seen.insert(fault.signature()) {
                    self.write_finding(input, &run, fault)?;
                } else {
                    self.repeated_faults += 1;
                }
            }
            Stop::Unsupported { pc, encoding, what } => {
                let entry = self.unsupported.get_or_insert_with(|| {
                    json!({
                        "runs": 0,
                        "first": {"pc": hex(*pc), "encoding": format!("{encoding:#x}"), "what": what},
                    })
                });
                entry["runs"] = json!(entry["runs"].as_u64().unwrap_or(0) + 1);
            }
            _ => {}
        }
        let clean = !matches!(run.stop, Stop::Fault(_) | Stop::Unsupported { .. });
        if seed || (clean && new_edges > 0) {
            self.scheduler.insert_with_feedback(
                input,
                ScheduleFeedback {
                    new_exception_signatures: 0,
                    new_breadcrumb_bits: u32::try_from(new_edges).unwrap_or(u32::MAX),
                },
            );
            if !seed {
                self.corpus_new += 1;
            }
        }
        Ok(())
    }

    fn write_finding(
        &mut self,
        input: &[u8],
        run: &Execution,
        fault: &Fault,
    ) -> anyhow::Result<()> {
        let (id, dir) = self
            .allocator
            .create()
            .context("create a finding directory")?;
        fs::write(dir.join("testcase.bin"), input)
            .with_context(|| format!("write {}", dir.join("testcase.bin").display()))?;
        let mut finding = render_finding(&id, &dir, &self.target, input, run, fault);
        corpus::finding::stamp_v1(&mut finding, corpus::finding::finding_kind::BINARY);
        fs::write(
            dir.join("finding.json"),
            serde_json::to_vec_pretty(&finding)?,
        )
        .with_context(|| format!("write {}", dir.join("finding.json").display()))?;
        self.findings.push(id);
        Ok(())
    }
}

pub fn run(args: BinaryRehostArgs) -> i32 {
    match run_inner(&args) {
        Ok(summary) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&summary).unwrap_or_default()
            );
            0
        }
        Err(error) => {
            bhfeprintln!("bhf binary rehost: {error:#}");
            1
        }
    }
}

fn run_inner(args: &BinaryRehostArgs) -> anyhow::Result<Value> {
    if args.iterations == 0 {
        return Err(anyhow!("--iterations must be greater than zero"));
    }
    let (image, bytes) = load_image(&args.image, args.base)?;
    let setup = Setup::from_args(args, &image)?;
    let machine = setup.machine(&image)?;
    let mut seeds = args
        .seed_inputs
        .iter()
        .map(|seed| seed.as_bytes().to_vec())
        .collect::<Vec<_>>();
    for file in &args.seed_files {
        seeds.push(fs::read(file).with_context(|| format!("read {}", file.display()))?);
    }
    if seeds.is_empty() {
        seeds.push(Vec::new());
    }
    let findings_dir = corpus::layout::findings_dir(&args.work_dir);
    fs::create_dir_all(&findings_dir)
        .with_context(|| format!("create {}", findings_dir.display()))?;
    let allocator = corpus::layout::FamilyAllocator::new(&findings_dir, "BF-")
        .with_context(|| format!("read {}", findings_dir.display()))?;
    let sha256 = sha256_hex(&bytes);
    let seen = recorded_signatures(&findings_dir, &sha256);
    let mut campaign = Campaign {
        machine,
        target: Target {
            setup: &setup,
            sha256,
            format: image.format().as_str(),
        },
        coverage: CoverageMap::new(),
        scheduler: PowerScheduler::default(),
        allocator,
        seen,
        executions: 0,
        corpus_new: 0,
        stops: BTreeMap::new(),
        unsupported: None,
        findings: Vec::new(),
        repeated_faults: 0,
        input_not_delivered: 0,
        first_undelivered: None,
    };
    let started = Instant::now();
    let done = |campaign: &Campaign<'_>| {
        campaign.executions >= args.iterations
            || args.time.is_some_and(|budget| started.elapsed() >= budget)
    };
    let mut seeds_run = 0;
    for seed in &seeds {
        if done(&campaign) {
            break;
        }
        campaign.execute(seed, true)?;
        seeds_run += 1;
    }
    // A run is the same for every input until the input is written, so when
    // no seed reaches `--inject-at`, no run will.
    if seeds_run > 0 && campaign.input_not_delivered == seeds_run {
        if let Some(address) = setup.input.inject_at {
            bhfeprintln!(
                "bhf binary rehost: warning: no seed run reached --inject-at {}, so no input was \
                 written into the firmware and every run ignores its input (the first run {}); \
                 check the address, and what the start-up code waits on before it",
                hex(address),
                campaign.first_undelivered.as_deref().unwrap_or("stopped")
            );
        }
    }
    let mutator = MutatorSuite::new(MutatorConfig {
        max_len: setup.input.capacity.clamp(1, MAX_INPUT_LEN) as usize,
        ..MutatorConfig::default()
    });
    let dictionary = Dictionary::from_tokens(Vec::<Vec<u8>>::new());
    let mut rng = MutationRng::new(args.rng_seed);
    'campaign: while !done(&campaign) {
        let Some(scheduled) = campaign.scheduler.select_next() else {
            break;
        };
        for _ in 0..scheduled.energy.max(1) {
            if done(&campaign) {
                break 'campaign;
            }
            let child = mutator
                .mutate(&MutationInput::new(&scheduled.bytes, &dictionary), &mut rng)
                .map(|result| result.bytes)
                .unwrap_or_else(|| scheduled.bytes.clone());
            campaign.execute(&child, false)?;
        }
    }
    Ok(json!({
        "schema_version": RUN_SCHEMA,
        "image": setup.image,
        "format": image.format().as_str(),
        "sha256": campaign.target.sha256,
        "engine": "rehost",
        "setup": setup.to_json(),
        "fidelity": fidelity(),
        "seeds_run": seeds_run,
        "executions": campaign.executions,
        "corpus_new": campaign.corpus_new,
        "coverage_edges": campaign.coverage.edges(),
        "stops": campaign.stops,
        "unsupported": campaign.unsupported,
        "findings": campaign.findings,
        "repeated_faults": campaign.repeated_faults,
        "input_not_delivered": campaign.input_not_delivered,
        "elapsed_ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    }))
}

/// Whether the finding at `finding_dir` is a rehosted-firmware fault.
pub(crate) fn is_rehost_finding(finding_dir: &Path) -> bool {
    fs::read(finding_dir.join("finding.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .is_some_and(|finding| finding["kind"] == FINDING_KIND)
}

/// `bhf replay` of a rehosted-firmware finding: run its testcase through the
/// machine the finding records (the image at `image`, when given, in place of
/// the recorded one) and match the fault signature.
pub(crate) fn replay_rehost_outcome(
    finding_dir: &Path,
    image: Option<&Path>,
) -> Result<crate::replay::LaneReplay, String> {
    let path = finding_dir.join("finding.json");
    let finding: Value = fs::read(&path)
        .map_err(|error| format!("read {}: {error}", path.display()))
        .and_then(|bytes| {
            serde_json::from_slice(&bytes)
                .map_err(|error| format!("parse {}: {error}", path.display()))
        })?;
    let recorded = finding["crash"]["signature"]
        .as_str()
        .ok_or_else(|| format!("{} records no crash.signature", path.display()))?
        .to_owned();
    let setup = Setup::from_json(&finding["rehost"]["setup"])?;
    let image_path = image.map_or_else(|| setup.image.clone(), Path::to_path_buf);
    let (loaded, _) = load_image(&image_path, setup.base).map_err(|error| format!("{error:#}"))?;
    let testcase = finding_dir.join("testcase.bin");
    let input =
        fs::read(&testcase).map_err(|error| format!("read {}: {error}", testcase.display()))?;
    let mut machine = Setup {
        image: image_path.clone(),
        ..setup
    }
    .machine(&loaded)
    .map_err(|error| format!("{error:#}"))?;
    let started = Instant::now();
    let run = machine.run(&input);
    let duration = started.elapsed();
    let replayed = match &run.stop {
        Stop::Fault(fault) => Some(fault.signature()),
        _ => None,
    };
    let matched = replayed.as_deref() == Some(recorded.as_str());
    let mut differences = Vec::new();
    if !matched {
        differences.push(match &replayed {
            Some(signature) => {
                format!("fault signature: recorded {recorded}, replayed {signature}")
            }
            None => format!(
                "fault signature: recorded {recorded}, the replayed run {} instead",
                describe_stop(&run.stop)
            ),
        });
    }
    let outcome = describe_stop(&run.stop);
    Ok(crate::replay::LaneReplay {
        lane: "rehost",
        matched,
        unverified: false,
        status_line: if matched {
            "MATCH".to_owned()
        } else {
            "MISMATCH rehosted fault changed".to_owned()
        },
        compared: format!("fault {recorded}"),
        differences,
        details: vec![
            crate::replay::Detail::new("outcome", outcome.clone()),
            crate::replay::Detail::new(
                "executed",
                format!("{} instructions, {} blocks", run.instructions, run.blocks),
            ),
        ],
        exit: Some(crate::replay::ExitSummary::described(
            None,
            None,
            matches!(run.stop, Stop::InstructionLimit),
            duration,
            outcome,
        )),
        output: Some((run.output, Vec::new())),
        binary: Some((image_path, "rehosted".to_owned())),
        history: "replay",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDir;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../rehost/tests/fixtures")
            .join(name)
    }

    fn args(image: PathBuf, work: &Path) -> BinaryRehostArgs {
        BinaryRehostArgs {
            image,
            work_dir: work.to_path_buf(),
            base: None,
            vector_table: None,
            ram: Vec::new(),
            input_buffer: "rx_buf".to_owned(),
            input_size: None,
            input_length: Some("rx_len".to_owned()),
            inject_at: Some("main".to_owned()),
            exit_at: Vec::new(),
            max_instructions: DEFAULT_MAX_INSTRUCTIONS,
            iterations: 1,
            time: None,
            seed_inputs: Vec::new(),
            seed_files: Vec::new(),
            rng_seed: 0,
        }
    }

    fn write_record(dir: &Path, command: u8, operand: u32) -> PathBuf {
        let mut record = b"FUZZ".to_vec();
        record.push(command);
        record.extend_from_slice(&operand.to_le_bytes());
        let path = dir.join(format!("seed-{}", command as char));
        fs::write(&path, record).unwrap();
        path
    }

    #[test]
    fn addresses_and_ram_ranges_parse_and_bad_ones_are_refused() {
        // Hex with or without `0x`: `nm` and `objdump` print bare digits.
        assert_eq!(parse_address("0x08000000"), Ok(0x0800_0000));
        assert_eq!(parse_address("08000184"), Ok(0x0800_0184));
        assert_eq!(parse_address("4096"), Ok(0x4096));
        assert_eq!(parse_address("E000ED08"), Ok(0xe000_ed08));
        for bad in ["", "0x", "+10", "0x1_0000_0000", "100000000", "main"] {
            assert!(parse_address(bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            parse_ram("0x20000000:0x20000"),
            Ok(MemoryRange {
                base: 0x2000_0000,
                size: 0x20000
            })
        );
        assert_eq!(
            parse_ram("20000000:4000"),
            Ok(MemoryRange {
                base: 0x2000_0000,
                size: 0x4000
            })
        );
        assert!(parse_ram("0x20000000").is_err());
        assert!(parse_ram("0x20000000:0").is_err());
        assert!(parse_ram("0xffff0000:0x20000").is_err());
    }

    #[test]
    fn symbols_resolve_and_a_missing_one_is_named() {
        let (image, _) = load_image(&fixture("faults.elf"), None).unwrap();
        let (buffer, size) = resolve(&image, "--input-buffer", "rx_buf").unwrap();
        assert_eq!(size, Some(64));
        assert_eq!(image.symbol("rx_buf").unwrap().address, buffer);
        assert_eq!(
            resolve(&image, "--exit-at", "0x08000010").unwrap(),
            (0x0800_0010, None)
        );
        // An address as `arm-none-eabi-nm` prints it.
        assert_eq!(
            resolve(&image, "--inject-at", "08000184").unwrap(),
            (image.symbol("main").unwrap().address, None)
        );
        let error = resolve(&image, "--exit-at", "no_such_function").unwrap_err();
        assert!(
            error.to_string().contains("no symbol \"no_such_function\""),
            "{error}"
        );
        let (raw, _) = load_image(&fixture("faults.bin"), Some(0x0800_0000)).unwrap();
        let error = resolve(&raw, "--input-buffer", "rx_buf").unwrap_err();
        assert!(error.to_string().contains("no symbol table"), "{error}");
    }

    #[test]
    fn an_elf_refuses_a_base_and_a_raw_image_needs_one() {
        let error = load_image(&fixture("faults.elf"), Some(0)).unwrap_err();
        assert!(error.to_string().contains("drop --base"), "{error}");
        let error = load_image(&fixture("faults.bin"), None).unwrap_err();
        assert!(error.to_string().contains("--base"), "{error}");
    }

    #[test]
    fn a_buffer_without_a_size_needs_input_size() {
        let work = TestDir::new("rehost-size");
        let (image, _) = load_image(&fixture("faults.elf"), None).unwrap();
        let mut args = args(fixture("faults.elf"), &work);
        args.input_buffer = "0x20000000".to_owned();
        let error = Setup::from_args(&args, &image).unwrap_err();
        assert!(error.to_string().contains("--input-size"), "{error}");
        args.input_size = Some(16);
        assert_eq!(Setup::from_args(&args, &image).unwrap().input.capacity, 16);
    }

    #[test]
    fn a_code_address_with_the_thumb_bit_names_the_instruction() {
        let work = TestDir::new("rehost-thumb-bit");
        let (image, _) = load_image(&fixture("faults.elf"), None).unwrap();
        let main = image.symbol("main").unwrap().address;
        let mut args = args(fixture("faults.elf"), &work);
        args.inject_at = Some(format!("{:#x}", main | 1));
        args.exit_at = vec![format!("{:#x}", main | 1)];
        let setup = Setup::from_args(&args, &image).unwrap();
        assert_eq!(setup.input.inject_at, Some(main));
        assert_eq!(setup.exit_at, vec![main]);
        assert!(setup.machine(&image).is_ok());
    }

    #[test]
    fn the_setup_round_trips_through_its_json() {
        let work = TestDir::new("rehost-setup");
        let (image, _) = load_image(&fixture("faults.elf"), None).unwrap();
        let mut args = args(fixture("faults.elf"), &work);
        args.exit_at = vec!["0x08000010".to_owned()];
        args.vector_table = Some(0x0800_0000);
        args.ram = vec![MemoryRange {
            base: 0x2000_0000,
            size: 0x4000,
        }];
        let setup = Setup::from_args(&args, &image).unwrap();
        assert_eq!(Setup::from_json(&setup.to_json()), Ok(setup.clone()));
        let mut broken = setup.to_json();
        broken["input"]["address"] = json!("rx_buf");
        assert!(Setup::from_json(&broken).is_err());
    }

    #[test]
    fn a_faulting_seed_is_a_finding_that_replays_as_a_match() {
        let work = TestDir::new("rehost-campaign");
        let mut args = args(fixture("faults.elf"), &work);
        args.seed_files = vec![write_record(&work, b'W', 0x6000_0000)];
        let summary = run_inner(&args).unwrap();
        assert_eq!(summary["schema_version"], RUN_SCHEMA);
        assert_eq!(summary["executions"], 1);
        assert_eq!(summary["stops"]["fault"], 1);
        assert_eq!(summary["input_not_delivered"], 0);
        let id = summary["findings"][0].as_str().unwrap().to_owned();
        let dir = corpus::layout::findings_dir(&work).join(&id);
        let finding: Value =
            serde_json::from_slice(&fs::read(dir.join("finding.json")).unwrap()).unwrap();
        assert_eq!(finding["kind"], FINDING_KIND);
        assert_eq!(finding["finding_kind"], "binary");
        assert_eq!(finding["classification"], "invalid_access");
        assert_eq!(finding["rehost"]["fault"]["kind"], "write_unmapped");
        assert_eq!(finding["rehost"]["fault"]["address"], "0x60000000");
        assert!(is_rehost_finding(&dir));
        let replay = replay_rehost_outcome(&dir, None).unwrap();
        assert!(replay.matched, "{:?}", replay.differences);
        assert_eq!(replay.status_line, "MATCH");
        // A rerun into the same work dir does not write the fault again.
        let again = run_inner(&args).unwrap();
        assert_eq!(again["findings"], json!([]));
        assert_eq!(again["repeated_faults"], 1);
    }

    #[test]
    fn another_image_in_the_same_work_dir_keeps_its_own_findings() {
        let work = TestDir::new("rehost-two-images");
        let mut args = args(fixture("faults.elf"), &work);
        args.seed_files = vec![write_record(&work, b'W', 0x6000_0000)];
        assert_eq!(
            run_inner(&args).unwrap()["findings"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        // A different build of the firmware faulting at the same instruction is
        // its own finding: one byte past the code changes its digest.
        let mut bytes = fs::read(fixture("faults.elf")).unwrap();
        bytes.push(0);
        let other = work.join("other.elf");
        fs::write(&other, bytes).unwrap();
        args.image = other;
        let summary = run_inner(&args).unwrap();
        assert_eq!(
            summary["findings"].as_array().unwrap().len(),
            1,
            "{summary:#}"
        );
        assert_eq!(summary["repeated_faults"], 0);
    }

    #[test]
    fn a_testcase_that_no_longer_faults_replays_as_a_mismatch() {
        let work = TestDir::new("rehost-mismatch");
        let mut args = args(fixture("faults.elf"), &work);
        args.seed_files = vec![write_record(&work, b'J', 0x4000_0001)];
        let summary = run_inner(&args).unwrap();
        let id = summary["findings"][0].as_str().unwrap();
        let dir = corpus::layout::findings_dir(&work).join(id);
        let finding: Value =
            serde_json::from_slice(&fs::read(dir.join("finding.json")).unwrap()).unwrap();
        assert_eq!(finding["classification"], "bad_pc");
        fs::write(dir.join("testcase.bin"), b"FUZZQ").unwrap();
        let replay = replay_rehost_outcome(&dir, None).unwrap();
        assert!(!replay.matched);
        assert!(
            replay.differences[0].contains("went idle"),
            "{:?}",
            replay.differences
        );
    }

    #[test]
    fn a_replay_reads_the_image_it_is_given_in_place_of_the_recorded_one() {
        let work = TestDir::new("rehost-override");
        let copy = work.join("moved.elf");
        fs::copy(fixture("faults.elf"), &copy).unwrap();
        let mut args = args(copy.clone(), &work);
        args.seed_files = vec![write_record(&work, b'R', 0x7000_0000)];
        let summary = run_inner(&args).unwrap();
        let id = summary["findings"][0].as_str().unwrap();
        let dir = corpus::layout::findings_dir(&work).join(id);
        fs::remove_file(&copy).unwrap();
        let error = replay_rehost_outcome(&dir, None).unwrap_err();
        assert!(error.contains("moved.elf"), "{error}");
        let replay = replay_rehost_outcome(&dir, Some(&fixture("faults.elf"))).unwrap();
        assert!(replay.matched, "{:?}", replay.differences);
    }

    #[test]
    fn runs_that_never_reach_the_injection_address_are_counted() {
        let work = TestDir::new("rehost-undelivered");
        let mut args = args(fixture("faults.elf"), &work);
        // Nothing raises an exception, so the core never runs the default
        // handler: no input is ever written.
        args.inject_at = Some("Default_Handler".to_owned());
        args.seed_files = vec![write_record(&work, b'W', 0x6000_0000)];
        args.iterations = 5;
        let summary = run_inner(&args).unwrap();
        assert_eq!(summary["executions"], 5);
        assert_eq!(summary["input_not_delivered"], 5, "{summary:#}");
        assert_eq!(summary["findings"], json!([]));
    }

    #[test]
    fn mutation_finds_a_fault_a_clean_seed_is_one_byte_from() {
        let work = TestDir::new("rehost-mutate");
        let mut args = args(fixture("faults.elf"), &work);
        // A store into RAM: clean. Most values of its top byte are unmapped.
        args.seed_files = vec![write_record(&work, b'W', 0x2000_0100)];
        args.iterations = 2000;
        let summary = run_inner(&args).unwrap();
        assert_eq!(summary["seeds_run"], 1);
        let findings = summary["findings"].as_array().unwrap();
        assert!(!findings.is_empty(), "{summary:#}");
        assert!(summary["coverage_edges"].as_u64().unwrap() > 0);
    }
}
