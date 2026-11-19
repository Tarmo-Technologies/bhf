// SPDX-License-Identifier: Apache-2.0

//! `bhf binary rehost`: fuzz an unmodified Cortex-M firmware image, with no
//! source and no instrumentation, in the rehosting emulator (`crates/rehost`),
//! and replay what it finds.
//!
//! Each input is written into a fixed buffer in the firmware's memory, or
//! read by its peripheral reads through MMIO models (passthrough, which takes
//! the read's bytes from the input, and constant), or both; the core starts
//! from the reset vector, and the basic blocks it enters fill an edge map
//! that steers the builtin engine's mutator and power schedule. A run that
//! faults (an invalid memory access, a bad PC, or a HardFault) is a finding
//! that records the machine setup, its MMIO models included; `bhf replay`
//! runs its testcase through the same machine again and matches the fault
//! signature.

use anyhow::{anyhow, Context};
use fuzz_engine_builtin::{
    Dictionary, MutationInput, MutationRng, MutatorConfig, MutatorSuite, PowerScheduler,
    ScheduleFeedback,
};
use rehost::{
    CoverageMap, Execution, Fault, Image, InputBuffer, Machine, MachineConfig, MemoryRange,
    MmioConfig, MmioDefault, MmioModel, MmioModelKind, Stop, DEFAULT_MAX_INSTRUCTIONS,
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
    /// routine fills. A name the symbol table holds is that symbol. Without
    /// it, the input reaches the firmware through its peripheral reads
    /// (see `--mmio`).
    #[arg(long = "input-buffer", value_name = "ADDR|SYMBOL")]
    pub input_buffer: Option<String>,

    /// Bytes the input buffer holds; a longer input is cut to this, and
    /// peripheral reads that take input take the bytes after it (the buffer
    /// then takes at most the input's first 4096 bytes). Default: the
    /// symbol's size.
    #[arg(long = "input-size", value_name = "BYTES", requires = "input_buffer")]
    pub input_size: Option<u32>,

    /// Where the input's length is written, as a little-endian 32-bit word:
    /// an address (hex) or an ELF symbol.
    #[arg(
        long = "input-length",
        value_name = "ADDR|SYMBOL",
        requires = "input_buffer"
    )]
    pub input_length: Option<String>,

    /// Write the input when the core first reaches this address (hex) or
    /// function, e.g. `main`, so the start-up code's `.bss` clearing does not
    /// wipe it. Default: at reset. The run JSON's `input_not_delivered`
    /// counts the runs that never reached it.
    #[arg(
        long = "inject-at",
        value_name = "ADDR|SYMBOL",
        requires = "input_buffer"
    )]
    pub inject_at: Option<String>,

    /// End a run cleanly when the core reaches this address (hex) or
    /// function. Repeatable. A run also ends when the core goes idle (WFI,
    /// WFE, a branch to itself) or uses `--max-instructions`.
    #[arg(long = "exit-at", value_name = "ADDR|SYMBOL")]
    pub exit_at: Vec<String>,

    /// The most instructions one run executes.
    #[arg(long = "max-instructions", default_value_t = DEFAULT_MAX_INSTRUCTIONS)]
    pub max_instructions: u64,

    /// A model for a peripheral register's reads: `ADDR[@PC]=MODEL`, where
    /// ADDR is the register (hex or an ELF symbol), PC limits the model to
    /// the instruction there (hex or a function), and MODEL is `passthrough`
    /// (each read takes its bytes from the input) or `constant:VALUE` (hex).
    /// A model for one instruction wins over one for the register.
    /// Repeatable. Peripheral reads take the input in order (after the
    /// bytes `--input-buffer` holds), and a run whose reads want more input
    /// than it has stops as `input_exhausted`.
    #[arg(long = "mmio", value_name = "ADDR[@PC]=MODEL")]
    pub mmio: Vec<String>,

    /// Peripheral models from a JSON file: the `mmio` object a run JSON's
    /// `setup` or a finding's `rehost.setup` records, or either whole
    /// document. `--mmio` models are added to them. A file with no
    /// `default` leaves the default to `--mmio-default`'s rule.
    #[arg(long = "mmio-models", value_name = "FILE")]
    pub mmio_models: Option<PathBuf>,

    /// What a peripheral register no model names reads as: `zero`, or
    /// `passthrough` (its bytes from the input). Default: `passthrough`
    /// without `--input-buffer`, `zero` with it (or what `--mmio-models`
    /// records).
    #[arg(long = "mmio-default", value_enum, value_name = "MODEL")]
    pub mmio_default: Option<MmioDefaultArg>,

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

/// `--mmio-default`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum MmioDefaultArg {
    Zero,
    Passthrough,
}

impl From<MmioDefaultArg> for MmioDefault {
    fn from(value: MmioDefaultArg) -> Self {
        match value {
            MmioDefaultArg::Zero => Self::Zero,
            MmioDefaultArg::Passthrough => Self::Passthrough,
        }
    }
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

/// A code address may carry the Thumb bit, as a vector-table entry or a
/// function pointer does; the instruction is at the even address.
fn resolve_code(image: &Image, what: &str, value: &str) -> anyhow::Result<u32> {
    resolve(image, what, value).map(|(address, _)| address & !1)
}

/// A `--mmio` model: `ADDR[@PC]=MODEL`.
fn parse_mmio_model(image: &Image, spec: &str) -> anyhow::Result<MmioModel> {
    let shape = || anyhow!("--mmio {spec:?} is not ADDR[@PC]=MODEL (e.g. 0x40011004=passthrough)");
    let (site, model) = spec.split_once('=').ok_or_else(shape)?;
    let (register, pc) = match site.split_once('@') {
        Some((register, pc)) => (register, Some(pc)),
        None => (site, None),
    };
    if register.trim().is_empty() {
        return Err(shape());
    }
    let (address, _) = resolve(image, "--mmio", register)?;
    let pc = pc.map(|pc| resolve_code(image, "--mmio", pc)).transpose()?;
    let model = model.trim();
    let kind = match model.split_once(':') {
        None if model == "passthrough" => MmioModelKind::Passthrough,
        Some(("constant", value)) => MmioModelKind::Constant {
            value: hex_number(value)
                .ok_or_else(|| anyhow!("--mmio {spec:?}: {value:?} is not a hex value"))?,
        },
        None if model == "constant" => {
            return Err(anyhow!(
                "--mmio {spec:?}: a constant model is constant:VALUE"
            ))
        }
        _ => {
            return Err(anyhow!(
                "--mmio {spec:?}: {model:?} is not a model (passthrough or constant:VALUE)"
            ))
        }
    };
    Ok(MmioModel { address, pc, kind })
}

fn mmio_to_json(mmio: &MmioConfig) -> Value {
    json!({
        "default": mmio.default.as_str(),
        "models": mmio.models.iter().map(|model| {
            let mut entry = json!({
                "address": hex(model.address),
                "pc": model.pc.map(hex),
                "model": model.kind.as_str(),
            });
            if let MmioModelKind::Constant { value } = model.kind {
                entry["value"] = json!(hex(value));
            }
            entry
        }).collect::<Vec<_>>(),
    })
}

/// The peripheral default an `mmio` object records, or `None` when it
/// records none.
fn mmio_default_from_json(value: &Value, field: &str) -> Result<Option<MmioDefault>, String> {
    match value.get("default").unwrap_or(&Value::Null) {
        Value::Null => Ok(None),
        Value::String(name) if name == "zero" => Ok(Some(MmioDefault::Zero)),
        Value::String(name) if name == "passthrough" => Ok(Some(MmioDefault::Passthrough)),
        other => Err(format!(
            "{field}.default {other} is not zero or passthrough"
        )),
    }
}

/// The MMIO models a setup records under `field`; a setup recorded before
/// they existed has none, and reads every peripheral register as zero.
fn mmio_from_json(value: &Value, field: &str) -> Result<MmioConfig, String> {
    let Some(mmio) = value.as_object() else {
        return match value {
            Value::Null => Ok(MmioConfig::default()),
            other => Err(format!("{field} is {other}, not an object")),
        };
    };
    let hex_field = |entry: &Value, name: &str| -> Result<Option<u32>, String> {
        match &entry[name] {
            Value::Null => Ok(None),
            Value::String(text) => hex_number(text)
                .map(Some)
                .ok_or_else(|| format!("{field}.models[].{name} {text:?} is not hex")),
            other => Err(format!("{field}.models[].{name} is {other}, not hex")),
        }
    };
    let default = mmio_default_from_json(value, field)?.unwrap_or(MmioDefault::Zero);
    let models = mmio
        .get("models")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|entry| {
            let address = hex_field(entry, "address")?
                .ok_or_else(|| format!("{field}.models[].address is missing"))?;
            let kind = match entry["model"].as_str() {
                Some("passthrough") => MmioModelKind::Passthrough,
                Some("constant") => MmioModelKind::Constant {
                    value: hex_field(entry, "value")?
                        .ok_or_else(|| format!("{field}.models[].value is missing"))?,
                },
                other => {
                    return Err(format!(
                        "{field}.models[].model {} is not passthrough or constant",
                        other
                            .map_or_else(|| entry["model"].to_string(), |name| format!("{name:?}"))
                    ))
                }
            };
            Ok(MmioModel {
                address,
                pc: hex_field(entry, "pc")?,
                kind,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(MmioConfig { models, default })
}

/// What a `--mmio-models` file gives.
struct ModelsFile {
    models: Vec<MmioModel>,
    /// The default it records; a file that names none leaves the default to
    /// the usual rule (`passthrough` without an input buffer).
    default: Option<MmioDefault>,
}

/// The MMIO models of a `--mmio-models` file: the `mmio` object itself, or
/// a run JSON or finding that records one in its setup.
fn load_mmio_models(path: &Path) -> anyhow::Result<ModelsFile> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let document: Value =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
    let mmio = if document.get("models").is_some() {
        &document
    } else if document["rehost"]["setup"]["mmio"].is_object() {
        &document["rehost"]["setup"]["mmio"]
    } else if document["setup"]["mmio"].is_object() {
        &document["setup"]["mmio"]
    } else {
        return Err(anyhow!(
            "{} holds no MMIO models: give the mmio object a run JSON's setup or a finding's \
             rehost.setup records, or either document",
            path.display()
        ));
    };
    let named = |error: String| anyhow!("{}: {error}", path.display());
    Ok(ModelsFile {
        models: mmio_from_json(mmio, "mmio").map_err(named)?.models,
        default: mmio_default_from_json(mmio, "mmio").map_err(named)?,
    })
}

/// How an image is mapped and run: everything a replay needs to run a
/// finding's testcase the way the campaign did.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Setup {
    image: PathBuf,
    base: Option<u32>,
    vector_table: Option<u32>,
    ram: Vec<MemoryRange>,
    input: Option<InputBuffer>,
    exit_at: Vec<u32>,
    max_instructions: u64,
    mmio: MmioConfig,
}

impl Setup {
    fn from_args(args: &BinaryRehostArgs, image: &Image) -> anyhow::Result<Self> {
        let input = args
            .input_buffer
            .as_deref()
            .map(|buffer| input_buffer(args, image, buffer))
            .transpose()?;
        let exit_at = args
            .exit_at
            .iter()
            .map(|value| resolve_code(image, "--exit-at", value))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let file = args
            .mmio_models
            .as_deref()
            .map(load_mmio_models)
            .transpose()?;
        let recorded_default = file.as_ref().and_then(|file| file.default);
        let mut mmio = MmioConfig {
            models: file.map(|file| file.models).unwrap_or_default(),
            default: MmioDefault::Zero,
        };
        for spec in &args.mmio {
            mmio.models.push(parse_mmio_model(image, spec)?);
        }
        // Without a buffer, peripheral reads are how the input arrives.
        mmio.default = match (args.mmio_default, recorded_default) {
            (Some(named), _) => named.into(),
            (None, Some(recorded)) => recorded,
            (None, None) if input.is_none() => MmioDefault::Passthrough,
            (None, None) => MmioDefault::Zero,
        };
        if input.is_none() && !mmio.takes_input() {
            return Err(anyhow!(
                "no input reaches the firmware: give --input-buffer, or let peripheral reads take \
                 the input (--mmio-default passthrough, or an --mmio ADDR=passthrough model)"
            ));
        }
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
            input,
            exit_at,
            max_instructions: args.max_instructions,
            mmio,
        })
    }

    fn config(&self) -> MachineConfig {
        MachineConfig {
            ram: self.ram.clone(),
            vector_table: self.vector_table,
            input: self.input.map(|input| InputBuffer {
                capacity: self.buffer_share(),
                ..input
            }),
            exit_at: self.exit_at.clone(),
            max_instructions: self.max_instructions,
            mmio: self.mmio.clone(),
        }
    }

    fn machine(&self, image: &Image) -> anyhow::Result<Machine> {
        Machine::new(image, self.config())
            .map_err(|error| anyhow!("{}: {error}", self.image.display()))
    }

    /// The bytes of each input the buffer takes: its capacity, or, when
    /// peripheral reads take input as well, at most [`MAX_INPUT_LEN`], so
    /// that the bytes after it reach the peripheral reads in an input the
    /// mutator can make.
    fn buffer_share(&self) -> u32 {
        self.input.map_or(0, |input| {
            if self.mmio.takes_input() {
                input.capacity.min(MAX_INPUT_LEN)
            } else {
                input.capacity
            }
        })
    }

    /// The longest input a run can use: the buffer's bytes, then what the
    /// peripheral reads take.
    fn max_input_len(&self) -> usize {
        let buffer = self.buffer_share().min(MAX_INPUT_LEN);
        let peripherals = if self.mmio.takes_input() {
            MAX_INPUT_LEN
        } else {
            0
        };
        (buffer + peripherals).max(1) as usize
    }

    /// How the input reaches the firmware, as a finding's `input.mode`.
    fn input_mode(&self) -> &'static str {
        match (self.input.is_some(), self.mmio.takes_input()) {
            (true, false) => "rehost-buffer",
            (false, _) => "rehost-mmio",
            (true, true) => "rehost-buffer+mmio",
        }
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
            "input": self.input.map(|input| json!({
                "address": hex(input.address),
                "capacity": input.capacity,
                "length_word": input.length_word.map(hex),
                "inject_at": input.inject_at.map(hex),
            })),
            "exit_at": self.exit_at.iter().copied().map(hex).collect::<Vec<_>>(),
            "max_instructions": self.max_instructions,
            "mmio": mmio_to_json(&self.mmio),
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
        let input = match &value["input"] {
            Value::Null => None,
            input => Some(InputBuffer {
                address: required(&input["address"], "input.address")?,
                capacity: input["capacity"]
                    .as_u64()
                    .and_then(|capacity| u32::try_from(capacity).ok())
                    .ok_or("rehost.setup.input.capacity is missing")?,
                length_word: address(&input["length_word"], "input.length_word")?,
                inject_at: address(&input["inject_at"], "input.inject_at")?,
            }),
        };
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
            input,
            exit_at,
            max_instructions: value["max_instructions"]
                .as_u64()
                .ok_or("rehost.setup.max_instructions is missing")?,
            mmio: mmio_from_json(&value["mmio"], "rehost.setup.mmio")?,
        })
    }
}

/// The input buffer `--input-buffer` names, with its size, length word and
/// injection address.
fn input_buffer(
    args: &BinaryRehostArgs,
    image: &Image,
    buffer: &str,
) -> anyhow::Result<InputBuffer> {
    let (address, symbol_size) = resolve(image, "--input-buffer", buffer)?;
    let capacity = match (args.input_size, symbol_size) {
        (Some(size), _) | (None, Some(size)) => size,
        (None, None) => {
            return Err(anyhow!(
                "--input-size is needed: --input-buffer {buffer:?} names no sized symbol"
            ))
        }
    };
    let length_word = args
        .input_length
        .as_deref()
        .map(|value| resolve(image, "--input-length", value).map(|(address, _)| address))
        .transpose()?;
    let inject_at = args
        .inject_at
        .as_deref()
        .map(|value| resolve_code(image, "--inject-at", value))
        .transpose()?;
    Ok(InputBuffer {
        address,
        capacity,
        length_word,
        inject_at,
    })
}

/// What a rehosted run does and does not model, recorded with every run and
/// finding so a result is never read as more than it is.
fn fidelity(mmio: &MmioConfig) -> Value {
    json!({
        "execution": "rehosted",
        "cpu": "ARMv7-M Thumb-2 integer core (Cortex-M3/M4), interpreted",
        "peripherals": describe_peripherals(mmio),
        "interrupts": "not modelled",
        "floating_point": "not modelled",
    })
}

fn describe_peripherals(mmio: &MmioConfig) -> String {
    if mmio.models.is_empty() && mmio.default == MmioDefault::Zero {
        return "not modelled: peripheral registers read as zero and drop writes".to_owned();
    }
    let mut kinds: Vec<&str> = mmio
        .models
        .iter()
        .map(|model| model.kind.as_str())
        .collect();
    kinds.sort_unstable();
    kinds.dedup();
    let models = match mmio.models.len() {
        0 => "no register models".to_owned(),
        1 => format!("1 register model ({})", kinds.join(", ")),
        count => format!("{count} register models ({})", kinds.join(", ")),
    };
    let others = match mmio.default {
        MmioDefault::Zero => "read as zero",
        MmioDefault::Passthrough => "take their bytes from the input",
    };
    format!(
        "modelled reads: {models}; other peripheral registers {others}; writes are dropped; no \
         peripheral behaviour beyond what its reads return"
    )
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
        Stop::InputExhausted { pc, address } => format!(
            "ran out of input at a read of the peripheral register {} at pc {}",
            hex(*address),
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
            "mode": target.setup.input_mode(),
            "bytes": input.len(),
            "delivered": run.input_delivered,
            "mmio_reads": run.mmio_reads,
            "mmio_bytes": run.mmio_input,
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
            "fidelity": fidelity(&target.setup.mmio),
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
    /// Peripheral registers the runs read.
    mmio_reads: u64,
    /// How the first of them ended.
    first_undelivered: Option<String>,
}

impl Campaign<'_> {
    /// Run one input: fold its edges in, keep it when it is a seed or a clean
    /// run that reached new edges, and write a new fault as a finding.
    fn execute(&mut self, input: &[u8], seed: bool) -> anyhow::Result<()> {
        let run = self.machine.run(input);
        self.executions += 1;
        self.mmio_reads += run.mmio_reads;
        *self.stops.entry(run.stop.as_str()).or_default() += 1;
        if self.target.setup.input.is_some() && run.input_delivered.is_none() {
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
        mmio_reads: 0,
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
        if let Some(address) = setup.input.and_then(|input| input.inject_at) {
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
        max_len: setup.max_input_len(),
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
        "fidelity": fidelity(&setup.mmio),
        "seeds_run": seeds_run,
        "executions": campaign.executions,
        "corpus_new": campaign.corpus_new,
        "coverage_edges": campaign.coverage.edges(),
        "stops": campaign.stops,
        "unsupported": campaign.unsupported,
        "findings": campaign.findings,
        "repeated_faults": campaign.repeated_faults,
        "input_not_delivered": campaign.input_not_delivered,
        "mmio_reads": campaign.mmio_reads,
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
        ..setup.clone()
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
    let mut details = vec![
        crate::replay::Detail::new("outcome", outcome.clone()),
        crate::replay::Detail::new(
            "executed",
            format!("{} instructions, {} blocks", run.instructions, run.blocks),
        ),
    ];
    if run.mmio_reads > 0 {
        details.push(crate::replay::Detail::new(
            "peripheral reads",
            format!(
                "{} reads, {} input bytes ({} register models; others {})",
                run.mmio_reads,
                run.mmio_input,
                setup.mmio.models.len(),
                match setup.mmio.default {
                    MmioDefault::Zero => "read as zero",
                    MmioDefault::Passthrough => "take the input",
                }
            ),
        ));
    }
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
        details,
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
            input_buffer: Some("rx_buf".to_owned()),
            input_size: None,
            input_length: Some("rx_len".to_owned()),
            inject_at: Some("main".to_owned()),
            exit_at: Vec::new(),
            max_instructions: DEFAULT_MAX_INSTRUCTIONS,
            mmio: Vec::new(),
            mmio_models: None,
            mmio_default: None,
            iterations: 1,
            time: None,
            seed_inputs: Vec::new(),
            seed_files: Vec::new(),
            rng_seed: 0,
        }
    }

    /// The peripheral fixture (`mmio.c`): its ID register at 0x40013000
    /// must read 0x4c31a5c3, and its data register at 0x40013004 gives the
    /// record's length and then the record.
    const PERIPH_ID: u32 = 0x4001_3000;
    const PERIPH_DATA: u32 = 0x4001_3004;

    /// `mmio.elf` with no input buffer: its data register takes the input.
    fn mmio_args(work: &Path) -> BinaryRehostArgs {
        let mut args = args(fixture("mmio.elf"), work);
        args.input_buffer = None;
        args.input_length = None;
        args.inject_at = None;
        args.mmio = vec!["0x40013000=constant:0x4c31a5c3".to_owned()];
        args
    }

    /// The length byte, then a "FUZZW" record that stores `value` at
    /// `offset` in the fixture's table.
    fn store_record(dir: &Path, offset: u32, value: u8) -> PathBuf {
        let mut record = b"FUZZW".to_vec();
        record.extend_from_slice(&offset.to_le_bytes());
        record.push(value);
        let mut bytes = vec![record.len() as u8];
        bytes.extend_from_slice(&record);
        let path = dir.join(format!("seed-store-{offset:08x}"));
        fs::write(&path, bytes).unwrap();
        path
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
        args.input_buffer = Some("0x20000000".to_owned());
        let error = Setup::from_args(&args, &image).unwrap_err();
        assert!(error.to_string().contains("--input-size"), "{error}");
        args.input_size = Some(16);
        assert_eq!(
            Setup::from_args(&args, &image)
                .unwrap()
                .input
                .unwrap()
                .capacity,
            16
        );
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
        assert_eq!(setup.input.unwrap().inject_at, Some(main));
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
        args.mmio = vec![
            "0x40011000=constant:0x20".to_owned(),
            "0x40011004@main=passthrough".to_owned(),
        ];
        let setup = Setup::from_args(&args, &image).unwrap();
        assert_eq!(setup.mmio.models.len(), 2);
        assert_eq!(Setup::from_json(&setup.to_json()), Ok(setup.clone()));
        let mut broken = setup.to_json();
        broken["input"]["address"] = json!("rx_buf");
        assert!(Setup::from_json(&broken).is_err());
        let mut broken = setup.to_json();
        broken["mmio"]["models"][0]["model"] = json!("mystery");
        let error = Setup::from_json(&broken).unwrap_err();
        assert!(error.contains("mystery"), "{error}");
        let mut broken = setup.to_json();
        broken["mmio"]["default"] = json!(1);
        let error = Setup::from_json(&broken).unwrap_err();
        assert!(error.contains("rehost.setup.mmio.default 1"), "{error}");
        // A setup with no input buffer, whose peripheral reads take the input.
        let (image, _) = load_image(&fixture("mmio.elf"), None).unwrap();
        let setup = Setup::from_args(&mmio_args(&work), &image).unwrap();
        assert_eq!(setup.input, None);
        assert_eq!(setup.to_json()["input"], Value::Null);
        assert_eq!(setup.to_json()["mmio"]["default"], "passthrough");
        assert_eq!(Setup::from_json(&setup.to_json()), Ok(setup));
    }

    #[test]
    fn a_setup_recorded_before_mmio_models_reads_peripherals_as_zero() {
        let work = TestDir::new("rehost-setup-old");
        let (image, _) = load_image(&fixture("faults.elf"), None).unwrap();
        let setup = Setup::from_args(&args(fixture("faults.elf"), &work), &image).unwrap();
        let mut old = setup.to_json();
        old.as_object_mut().unwrap().remove("mmio");
        let read = Setup::from_json(&old).unwrap();
        assert_eq!(read.mmio, MmioConfig::default());
        assert_eq!(read, setup);
    }

    #[test]
    fn mmio_models_parse_from_their_flags_and_bad_ones_are_named() {
        let (image, _) = load_image(&fixture("mmio.elf"), None).unwrap();
        let main = image.symbol("main").unwrap().address;
        let model = |spec: &str| parse_mmio_model(&image, spec);
        assert_eq!(
            model("0x40013000=constant:0x4c31a5c3").unwrap(),
            MmioModel {
                address: PERIPH_ID,
                pc: None,
                kind: MmioModelKind::Constant { value: 0x4c31_a5c3 },
            }
        );
        // Hex, `0x` optional, as for every address; the instruction may be
        // a symbol and may carry the Thumb bit.
        assert_eq!(
            model("40013004@08000113=passthrough").unwrap(),
            MmioModel {
                address: PERIPH_DATA,
                pc: Some(0x0800_0112),
                kind: MmioModelKind::Passthrough,
            }
        );
        assert_eq!(model("0x40013004@main=constant:10").unwrap().pc, Some(main));
        assert_eq!(
            model("0x40013004=constant:10").unwrap().kind,
            MmioModelKind::Constant { value: 0x10 }
        );
        for (bad, says) in [
            ("0x40013000", "ADDR[@PC]=MODEL"),
            ("0x40013000=", "passthrough"),
            ("=passthrough", "ADDR[@PC]=MODEL"),
            ("0x40013000=constant", "constant:VALUE"),
            ("0x40013000=constant:zz", "\"zz\""),
            ("0x40013000=mystery", "\"mystery\""),
            (
                "0x40013000@no_such_function=passthrough",
                "no_such_function",
            ),
        ] {
            let error = model(bad).unwrap_err().to_string();
            assert!(error.contains(says), "{bad:?}: {error}");
        }
    }

    #[test]
    fn the_peripheral_default_follows_the_input_buffer_unless_named() {
        let work = TestDir::new("rehost-mmio-default");
        let (image, _) = load_image(&fixture("mmio.elf"), None).unwrap();
        let mut args = mmio_args(&work);
        assert_eq!(
            Setup::from_args(&args, &image).unwrap().mmio.default,
            MmioDefault::Passthrough,
            "with no buffer, peripheral reads are how the input arrives"
        );
        args.input_buffer = Some("record".to_owned());
        assert_eq!(
            Setup::from_args(&args, &image).unwrap().mmio.default,
            MmioDefault::Zero,
            "with a buffer, unmodelled registers read as zero as before"
        );
        args.mmio_default = Some(MmioDefaultArg::Passthrough);
        assert_eq!(
            Setup::from_args(&args, &image).unwrap().mmio.default,
            MmioDefault::Passthrough
        );
    }

    #[test]
    fn a_setup_no_input_reaches_is_refused() {
        let work = TestDir::new("rehost-no-input");
        let (image, _) = load_image(&fixture("mmio.elf"), None).unwrap();
        let mut args = mmio_args(&work);
        args.mmio_default = Some(MmioDefaultArg::Zero);
        let error = Setup::from_args(&args, &image).unwrap_err().to_string();
        assert!(error.contains("no input reaches the firmware"), "{error}");
        // An input-fed model for the data register is enough.
        args.mmio.push(format!("{PERIPH_DATA:#x}=passthrough"));
        assert!(Setup::from_args(&args, &image).is_ok());
    }

    #[test]
    fn mmio_models_load_from_a_file_or_a_recorded_setup() {
        let work = TestDir::new("rehost-mmio-file");
        let (image, _) = load_image(&fixture("mmio.elf"), None).unwrap();
        let mut given = mmio_args(&work);
        given.mmio.push("0x40013004@main=constant:3".to_owned());
        let setup = Setup::from_args(&given, &image).unwrap();
        let mut args = mmio_args(&work);
        args.mmio.clear();
        // The models alone, a run JSON's setup and a finding's all load.
        let documents = [
            setup.to_json()["mmio"].clone(),
            json!({"schema_version": RUN_SCHEMA, "setup": setup.to_json()}),
            json!({"kind": FINDING_KIND, "rehost": {"setup": setup.to_json()}}),
        ];
        for (index, document) in documents.iter().enumerate() {
            let path = work.join(format!("models-{index}.json"));
            fs::write(&path, document.to_string()).unwrap();
            args.mmio_models = Some(path);
            assert_eq!(
                Setup::from_args(&args, &image).unwrap().mmio,
                setup.mmio,
                "{document:#}"
            );
        }
        // A flag adds to the file's models.
        args.mmio = vec![format!("{PERIPH_DATA:#x}@0x08000128=passthrough")];
        assert_eq!(
            Setup::from_args(&args, &image).unwrap().mmio.models.len(),
            3
        );
        let path = work.join("not-models.json");
        fs::write(&path, "{\"schema_version\": 1}").unwrap();
        args.mmio_models = Some(path);
        let error = Setup::from_args(&args, &image).unwrap_err().to_string();
        assert!(error.contains("not-models.json"), "{error}");
    }

    #[test]
    fn a_models_file_with_no_default_leaves_it_to_the_input_buffer_rule() {
        let work = TestDir::new("rehost-mmio-file-default");
        let (image, _) = load_image(&fixture("mmio.elf"), None).unwrap();
        let id = json!({"address": "0x40013000", "model": "constant", "value": "0x4c31a5c3"});
        let path = work.join("models.json");
        fs::write(&path, json!({"models": [id]}).to_string()).unwrap();
        let mut args = mmio_args(&work);
        args.mmio.clear();
        args.mmio_models = Some(path.clone());
        let setup = Setup::from_args(&args, &image).unwrap();
        assert_eq!(setup.mmio.default, MmioDefault::Passthrough, "no buffer");
        assert_eq!(setup.mmio.models.len(), 1);
        args.input_buffer = Some("record".to_owned());
        assert_eq!(
            Setup::from_args(&args, &image).unwrap().mmio.default,
            MmioDefault::Zero,
            "a buffer"
        );
        // A default the file does record is kept.
        args.input_buffer = None;
        fs::write(
            &path,
            json!({"default": "zero", "models": [id]}).to_string(),
        )
        .unwrap();
        let error = Setup::from_args(&args, &image).unwrap_err().to_string();
        assert!(error.contains("no input reaches the firmware"), "{error}");
    }

    #[test]
    fn a_large_buffer_leaves_peripheral_reads_the_rest_of_an_input_the_mutator_makes() {
        let work = TestDir::new("rehost-large-buffer");
        let (image, _) = load_image(&fixture("mmio.elf"), None).unwrap();
        let mut args = mmio_args(&work);
        args.input_buffer = Some("0x20008000".to_owned());
        args.input_size = Some(8192);
        args.mmio_default = Some(MmioDefaultArg::Passthrough);
        let setup = Setup::from_args(&args, &image).unwrap();
        assert_eq!(setup.max_input_len(), 8192);
        assert_eq!(setup.config().input.unwrap().capacity, 4096);
        // The buffer's share, then a record with a wild offset for the data
        // register: no longer than the mutator's inputs.
        let mut input = vec![0x55; 4096];
        input.extend_from_slice(&fs::read(store_record(&work, 0x4000_0000, 0x5a)).unwrap());
        assert!(input.len() <= setup.max_input_len());
        let run = setup.machine(&image).unwrap().run(&input);
        assert_eq!(run.input_delivered, Some(4096));
        assert!(matches!(run.stop, Stop::Fault(_)), "{:?}", run.stop);
        assert_eq!(run.mmio_input, 11, "the whole record");
        // The campaign and the replay of its finding split it the same way.
        let seed = work.join("seed-large");
        fs::write(&seed, &input).unwrap();
        args.seed_files = vec![seed];
        let summary = run_inner(&args).unwrap();
        assert_eq!(summary["stops"]["fault"], 1, "{summary:#}");
        assert_eq!(summary["setup"]["input"]["capacity"], 8192);
        let id = summary["findings"][0].as_str().unwrap().to_owned();
        let dir = corpus::layout::findings_dir(&work).join(&id);
        let replay = replay_rehost_outcome(&dir, None).unwrap();
        assert!(replay.matched, "{:?}", replay.differences);
        // With no peripheral input the buffer keeps its whole capacity.
        args.mmio_default = Some(MmioDefaultArg::Zero);
        let setup = Setup::from_args(&args, &image).unwrap();
        assert_eq!(setup.config().input.unwrap().capacity, 8192);
        assert_eq!(setup.max_input_len(), 4096);
    }

    #[test]
    fn a_fault_behind_a_peripheral_is_a_finding_that_replays_with_its_models() {
        let work = TestDir::new("rehost-mmio-campaign");
        let mut args = mmio_args(&work);
        args.seed_files = vec![store_record(&work, 0x4000_0000, 0x5a)];
        let summary = run_inner(&args).unwrap();
        assert_eq!(summary["stops"]["fault"], 1, "{summary:#}");
        assert_eq!(
            summary["input_not_delivered"], 0,
            "no buffer, nothing to miss"
        );
        assert!(summary["mmio_reads"].as_u64().unwrap() > 10, "{summary:#}");
        let id = summary["findings"][0].as_str().unwrap().to_owned();
        let dir = corpus::layout::findings_dir(&work).join(&id);
        let finding: Value =
            serde_json::from_slice(&fs::read(dir.join("finding.json")).unwrap()).unwrap();
        assert_eq!(finding["rehost"]["fault"]["kind"], "write_unmapped");
        assert_eq!(finding["input"]["mode"], "rehost-mmio");
        assert_eq!(finding["input"]["mmio_bytes"], 11);
        let mmio = &finding["rehost"]["setup"]["mmio"];
        assert_eq!(mmio["default"], "passthrough");
        assert_eq!(
            mmio["models"],
            json!([{"address": "0x40013000", "pc": null, "model": "constant", "value": "0x4c31a5c3"}])
        );
        let peripherals = finding["rehost"]["fidelity"]["peripherals"]
            .as_str()
            .unwrap();
        assert!(peripherals.contains("1 register model"), "{peripherals}");
        assert!(peripherals.contains("from the input"), "{peripherals}");
        let replay = replay_rehost_outcome(&dir, None).unwrap();
        assert!(replay.matched, "{:?}", replay.differences);
        // The recorded models are what the replay runs: without them the ID
        // register reads as the input's first bytes and the firmware sleeps.
        let mut stripped = finding.clone();
        stripped["rehost"]["setup"]["mmio"]["models"] = json!([]);
        fs::write(dir.join("finding.json"), stripped.to_string()).unwrap();
        let replay = replay_rehost_outcome(&dir, None).unwrap();
        assert!(!replay.matched);
        assert!(
            replay.differences[0].contains("went idle"),
            "{:?}",
            replay.differences
        );
    }

    #[test]
    fn a_run_that_reads_past_its_input_is_a_clean_stop() {
        let work = TestDir::new("rehost-mmio-exhausted");
        let mut args = mmio_args(&work);
        // A length of 10 and no record.
        args.seed_inputs = vec!["\n".to_owned()];
        let summary = run_inner(&args).unwrap();
        assert_eq!(summary["stops"]["input_exhausted"], 1, "{summary:#}");
        assert_eq!(summary["findings"], json!([]));
        assert_eq!(
            describe_stop(&Stop::InputExhausted {
                pc: 0x0800_0128,
                address: PERIPH_DATA
            }),
            "ran out of input at a read of the peripheral register 0x40013004 at pc 0x08000128"
        );
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
