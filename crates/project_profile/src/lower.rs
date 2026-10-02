// SPDX-License-Identifier: Apache-2.0

//! Lower a validated [`Target`] to an engine-neutral launch plan.
//!
//! "Engine-neutral" means this crate never names the CLI's `clap` argument
//! types — the dependency points the other way. Lowering carries the declared,
//! manifest-relative asset paths and the per-engine knobs into a plain data
//! structure that the CLI maps onto `FuzzArgs` / `BinaryFuzzArgs` field by
//! field. It also enforces engine / input-mode compatibility and rejects
//! fields that belong to engine features not available in this bhf
//! (fail-closed), and emits fidelity warnings where an asset cannot be honored
//! by the chosen engine.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::error::ProjectError;
use crate::interpolate::{self, InterpolatedValue};
use crate::schema::Target;
use crate::warning::{Warning, WarningKind};

/// Native source-harness engine (`bhf fuzz` lane).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeEngine {
    Builtin,
    AflPlusPlus,
}

/// AFL++ binary-only mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AflMode {
    Native,
    Qemu,
    Frida,
}

/// Binary (no-source) sub-engine (`bhf binary fuzz` lane).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryEngine {
    Builtin,
    AflQemu,
    Auto,
}

/// Input contract for the binary lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryInput {
    Stdin,
    File,
}

/// A classified env entry (name + literal/handle value), order-stable.
pub type EnvEntry = (String, InterpolatedValue);

/// The engine-neutral launch plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoweredLaunch {
    Native(NativeLaunch),
    Binary(BinaryLaunch),
}

/// Native source-harness launch (builtin / afl++).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeLaunch {
    pub engine: NativeEngine,
    pub afl_mode: AflMode,
    pub afl_inst_ranges: Option<String>,
    pub afl_path: Option<PathBuf>,
    /// Declared (manifest-relative) harness source/binary path.
    pub binary: PathBuf,
    /// Declared seed files/dirs, in order.
    pub seeds: Vec<PathBuf>,
    /// Declared dictionaries, in layering order.
    pub dictionaries: Vec<PathBuf>,
    /// Declared grammar descriptor.
    pub grammar: Option<PathBuf>,
    /// Classified env entries (handles not yet resolved).
    pub env: Vec<EnvEntry>,
    pub time: Option<String>,
    pub timeout: Option<String>,
    pub max_len: Option<String>,
    pub rss_limit_mb: Option<u64>,
    pub sandbox: bool,
}

/// Binary (no-source) launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryLaunch {
    pub engine: BinaryEngine,
    pub input_mode: BinaryInput,
    /// Declared (manifest-relative) target binary path.
    pub binary: PathBuf,
    pub seeds: Vec<PathBuf>,
    pub env: Vec<EnvEntry>,
    pub timeout_ms: Option<u64>,
    pub mem_mb: Option<u64>,
    pub time: Option<String>,
}

/// Which engine a target names.
pub(crate) enum Engine {
    Native(NativeEngine),
    Binary,
}

pub(crate) fn parse_engine(target: &Target) -> Result<Engine, ProjectError> {
    match target.engine.as_str() {
        "builtin" => Ok(Engine::Native(NativeEngine::Builtin)),
        "afl++" => Ok(Engine::Native(NativeEngine::AflPlusPlus)),
        "binary" => Ok(Engine::Binary),
        other => Err(ProjectError::UnknownEngine {
            target: target.id.clone(),
            engine: other.to_owned(),
        }),
    }
}

fn parse_afl_mode(target: &Target) -> Result<AflMode, ProjectError> {
    match target.afl_mode.as_deref() {
        None | Some("native") => Ok(AflMode::Native),
        Some("qemu") => Ok(AflMode::Qemu),
        Some("frida") => Ok(AflMode::Frida),
        Some(other) => Err(ProjectError::InputModeMismatch {
            target: target.id.clone(),
            detail: format!("unknown afl-mode '{other}' (expected native, qemu, or frida)"),
        }),
    }
}

/// Reject any field that belongs to an engine feature not yet available.
fn reject_gated_fields(target: &Target) -> Result<(), ProjectError> {
    let gated: [(bool, &'static str, &'static str); 6] = [
        (target.runner.is_some(), "runner", "#47"),
        (target.runner_args.is_some(), "runner-args", "#47"),
        (target.target_args.is_some(), "target-args", "#47"),
        (target.arguments.is_some(), "arguments", "#47"),
        (target.runtime_oracles.is_some(), "runtime-oracles", "#59"),
        (target.postcondition.is_some(), "postcondition", "#55"),
    ];
    for (present, field, issue) in gated {
        if present {
            return Err(ProjectError::GatedFeature {
                target: target.id.clone(),
                field,
                issue,
            });
        }
    }
    Ok(())
}

fn classify_env(target: &Target) -> Result<Vec<EnvEntry>, ProjectError> {
    // BTreeMap iteration is sorted, so the lowered env order is deterministic.
    let map: &BTreeMap<String, String> = &target.env;
    let mut out = Vec::with_capacity(map.len());
    for (k, v) in map {
        out.push((k.clone(), interpolate::classify(v)?));
    }
    Ok(out)
}

fn require_binary(target: &Target) -> Result<PathBuf, ProjectError> {
    target.binary.clone().ok_or(ProjectError::MissingField {
        target: target.id.clone(),
        field: "binary",
    })
}

/// Lower a single target. Returns the launch plan plus any fidelity warnings.
pub fn lower_target(target: &Target) -> Result<(LoweredLaunch, Vec<Warning>), ProjectError> {
    reject_gated_fields(target)?;
    let engine = parse_engine(target)?;
    let env = classify_env(target)?;
    let binary = require_binary(target)?;
    let mut warnings = Vec::new();

    match engine {
        Engine::Native(native_engine) => {
            // Native engines consume input over BHF's framed fork-server
            // protocol. `framed` is the only valid input-mode; stdin/file (and
            // any argv/runner) on a native engine is gated on #47.
            match target.input_mode.as_deref() {
                None | Some("framed") => {}
                Some(mode @ ("stdin" | "file")) => {
                    return Err(ProjectError::InputModeMismatch {
                        target: target.id.clone(),
                        detail: format!(
                            "input-mode '{mode}' is not valid for a native engine (its harness \
                             uses BHF's framed fork-server protocol); per-input argv/stdin/file \
                             delivery requires feature #47 (not available in this bhf)"
                        ),
                    });
                }
                Some(other) => {
                    return Err(ProjectError::InputModeMismatch {
                        target: target.id.clone(),
                        detail: format!("unknown input-mode '{other}' (expected 'framed')"),
                    });
                }
            }

            if target.grammar.is_some() && native_engine == NativeEngine::AflPlusPlus {
                warnings.push(Warning::new(
                    WarningKind::GrammarUnsupportedByEngine,
                    format!(
                        "target '{}': a grammar is declared but engine 'afl++' drives an external \
                         afl-fuzz that cannot consume BHF's JSON grammar mutator; the grammar will \
                         not shape mutation",
                        target.id
                    ),
                ));
            }

            let launch = NativeLaunch {
                engine: native_engine,
                afl_mode: parse_afl_mode(target)?,
                afl_inst_ranges: target.afl_inst_ranges.clone(),
                afl_path: target.afl_path.clone(),
                binary,
                seeds: target.seeds.clone(),
                dictionaries: target.dictionaries.clone(),
                grammar: target.grammar.clone(),
                env,
                time: target.time.clone(),
                timeout: target.timeout.clone(),
                max_len: target.max_len.clone(),
                rss_limit_mb: target.rss_limit_mb,
                sandbox: target.sandbox.unwrap_or(false),
            };
            Ok((LoweredLaunch::Native(launch), warnings))
        }
        Engine::Binary => {
            let input_mode = match target.input_mode.as_deref() {
                // Binary lane default is stdin, matching `bhf binary fuzz`.
                None | Some("stdin") => BinaryInput::Stdin,
                Some("file") => BinaryInput::File,
                Some("framed") => {
                    return Err(ProjectError::InputModeMismatch {
                        target: target.id.clone(),
                        detail: "input-mode 'framed' is not valid for the binary engine (framed \
                                 is the native fork-server protocol); use 'stdin' or 'file'"
                            .to_owned(),
                    });
                }
                Some(other) => {
                    return Err(ProjectError::InputModeMismatch {
                        target: target.id.clone(),
                        detail: format!(
                            "unknown input-mode '{other}' (expected 'stdin' or 'file')"
                        ),
                    });
                }
            };

            if target.grammar.is_some() {
                warnings.push(Warning::new(
                    WarningKind::GrammarUnsupportedByEngine,
                    format!(
                        "target '{}': a grammar is declared but the binary engine has no \
                         structured-input mutator; the grammar will be ignored",
                        target.id
                    ),
                ));
            }

            let launch = BinaryLaunch {
                engine: BinaryEngine::Auto,
                input_mode,
                binary,
                seeds: target.seeds.clone(),
                env,
                timeout_ms: target.timeout_ms,
                mem_mb: target.mem_mb,
                time: target.time.clone(),
            };
            Ok((LoweredLaunch::Binary(launch), warnings))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_target(id: &str, engine: &str) -> Target {
        Target {
            id: id.to_owned(),
            engine: engine.to_owned(),
            binary: Some(PathBuf::from("prebuilt/harness")),
            input_mode: None,
            build_command: None,
            seeds: vec![],
            dictionaries: vec![],
            grammar: None,
            afl_mode: None,
            afl_inst_ranges: None,
            afl_path: None,
            time: None,
            timeout: None,
            timeout_ms: None,
            max_len: None,
            rss_limit_mb: None,
            mem_mb: None,
            sandbox: None,
            env: BTreeMap::new(),
            runner: None,
            runner_args: None,
            target_args: None,
            arguments: None,
            runtime_oracles: None,
            postcondition: None,
        }
    }

    #[test]
    fn lowers_native_aflpp_target() {
        let mut t = base_target("alpha", "afl++");
        t.afl_mode = Some("frida".to_owned());
        t.afl_inst_ranges = Some("libfoo.so".to_owned());
        let (launch, warnings) = lower_target(&t).unwrap();
        assert!(warnings.is_empty());
        match launch {
            LoweredLaunch::Native(n) => {
                assert_eq!(n.engine, NativeEngine::AflPlusPlus);
                assert_eq!(n.afl_mode, AflMode::Frida);
                assert_eq!(n.afl_inst_ranges.as_deref(), Some("libfoo.so"));
            }
            other => panic!("expected native launch, got {other:?}"),
        }
    }

    #[test]
    fn lowers_binary_file_target() {
        let mut t = base_target("beta", "binary");
        t.input_mode = Some("file".to_owned());
        t.timeout_ms = Some(5000);
        let (launch, _) = lower_target(&t).unwrap();
        match launch {
            LoweredLaunch::Binary(b) => {
                assert_eq!(b.input_mode, BinaryInput::File);
                assert_eq!(b.timeout_ms, Some(5000));
                assert_eq!(b.engine, BinaryEngine::Auto);
            }
            other => panic!("expected binary launch, got {other:?}"),
        }
    }

    #[test]
    fn native_defaults_to_framed_input() {
        let t = base_target("g", "builtin");
        let (launch, _) = lower_target(&t).unwrap();
        // framed has no explicit variant on the native side — it is simply the
        // only accepted mode. Reaching here (no error) is the assertion.
        assert!(matches!(launch, LoweredLaunch::Native(_)));
    }

    #[test]
    fn binary_engine_rejects_framed_input_mode() {
        let mut t = base_target("b", "binary");
        t.input_mode = Some("framed".to_owned());
        let err = lower_target(&t).unwrap_err();
        assert!(
            matches!(err, ProjectError::InputModeMismatch { ref detail, .. } if detail.contains("framed")),
            "{err:?}"
        );
    }

    #[test]
    fn native_engine_rejects_stdin_input_mode() {
        let mut t = base_target("n", "builtin");
        t.input_mode = Some("stdin".to_owned());
        let err = lower_target(&t).unwrap_err();
        match err {
            ProjectError::InputModeMismatch { detail, .. } => {
                assert!(detail.contains("#47"), "should reference #47: {detail}");
            }
            other => panic!("expected input-mode mismatch, got {other:?}"),
        }
    }

    #[test]
    fn runner_field_is_unsupported_error() {
        let mut t = base_target("r", "binary");
        t.runner = Some("wine".to_owned());
        let err = lower_target(&t).unwrap_err();
        match err {
            ProjectError::GatedFeature { field, issue, .. } => {
                assert_eq!(field, "runner");
                assert_eq!(issue, "#47");
            }
            other => panic!("expected gated feature, got {other:?}"),
        }
    }

    #[test]
    fn postcondition_field_is_unsupported_error() {
        let mut t = base_target("p", "builtin");
        t.postcondition = Some(toml::Value::Boolean(true));
        let err = lower_target(&t).unwrap_err();
        match err {
            ProjectError::GatedFeature { field, issue, .. } => {
                assert_eq!(field, "postcondition");
                assert_eq!(issue, "#55");
            }
            other => panic!("expected gated feature, got {other:?}"),
        }
    }

    #[test]
    fn runtime_oracles_field_is_unsupported_error() {
        let mut t = base_target("o", "builtin");
        t.runtime_oracles = Some(vec!["asan".to_owned()]);
        let err = lower_target(&t).unwrap_err();
        match err {
            ProjectError::GatedFeature { field, issue, .. } => {
                assert_eq!(field, "runtime-oracles");
                assert_eq!(issue, "#59");
            }
            other => panic!("expected gated feature, got {other:?}"),
        }
    }

    #[test]
    fn grammar_with_aflpp_emits_fidelity_warning() {
        let mut t = base_target("gr", "afl++");
        t.grammar = Some(PathBuf::from("grammar/a.json"));
        let (launch, warnings) = lower_target(&t).unwrap();
        // The target still lowers.
        assert!(matches!(launch, LoweredLaunch::Native(_)));
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].kind, WarningKind::GrammarUnsupportedByEngine);
    }

    #[test]
    fn missing_binary_is_missing_field_error() {
        let mut t = base_target("m", "builtin");
        t.binary = None;
        let err = lower_target(&t).unwrap_err();
        assert!(
            matches!(
                err,
                ProjectError::MissingField {
                    field: "binary",
                    ..
                }
            ),
            "{err:?}"
        );
    }
}
