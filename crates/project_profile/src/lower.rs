// SPDX-License-Identifier: Apache-2.0

//! Lower a validated [`Target`] to an engine-neutral launch plan.
//!
//! "Engine-neutral" means this crate never names the CLI's `clap` argument
//! types — the dependency points the other way. Lowering carries the declared,
//! manifest-relative asset paths and the per-engine knobs into a plain data
//! structure that the CLI maps onto `FuzzArgs` / `BinaryFuzzArgs` field by
//! field. It also enforces engine / input-mode compatibility and the
//! well-formedness of the composition fields (#47 runner/argv, #59
//! runtime-oracles, #55 postcondition) — rejecting a binary-lane launch wrapper
//! on a native engine, a `runner-args` without `runner`, a `target-args` /
//! `arguments` conflict, a postcondition with no oracle, or an invalid
//! `runtime-oracles` mode — and emits fidelity warnings where an asset cannot be
//! honored by the chosen engine.

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

/// Runtime sink-oracle mode (#59) — the engine-neutral mirror of the CLI's
/// `--runtime-oracles` flag. The CLI maps this onto its own `RuntimeOracleMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuntimeOraclesMode {
    /// Load the sink oracles when the shim + platform support it, else skip.
    Auto,
    /// Require them; the run errors if the shim or platform is unavailable.
    On,
    /// Never load them (crash-only). The default — runtime oracles are opt-in.
    #[default]
    Off,
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
    /// Runtime sink-oracle mode (#59). The only composition field valid on the
    /// native lane — runner/argv/postcondition are binary-only.
    pub runtime_oracles: RuntimeOraclesMode,
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
    /// Runner / argv wrapper the target launches under (#47), e.g. `wine`.
    pub runner: Option<String>,
    /// Arguments for the `runner` prefix, before the target binary (#47).
    pub runner_args: Vec<String>,
    /// Fixed target argv before the fuzz input; `@@` marks the input position
    /// (#47). Lowered from `target-args` or its `arguments` alias.
    pub target_args: Vec<String>,
    /// Runtime sink-oracle mode (#59).
    pub runtime_oracles: RuntimeOraclesMode,
    /// Postcondition hook run BEFORE each testcase (#55).
    pub setup_command: Option<String>,
    /// Postcondition oracle run AFTER each testcase (#55).
    pub oracle_command: Option<String>,
    /// Postcondition hook run AFTER the oracle to reset state (#55).
    pub reset_command: Option<String>,
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

/// Parse the `runtime-oracles` mode string (#59), valid on both lanes.
fn parse_runtime_oracles(target: &Target) -> Result<RuntimeOraclesMode, ProjectError> {
    match target.runtime_oracles.as_deref() {
        None | Some("off") => Ok(RuntimeOraclesMode::Off),
        Some("auto") => Ok(RuntimeOraclesMode::Auto),
        Some("on") => Ok(RuntimeOraclesMode::On),
        Some(other) => Err(ProjectError::InvalidFieldValue {
            target: target.id.clone(),
            field: "runtime-oracles",
            value: other.to_owned(),
            detail: "expected 'auto', 'on', or 'off'",
        }),
    }
}

/// Resolve the fixed target argv (#47) from `target-args`, accepting `arguments`
/// as an alias. Setting both at once is rejected rather than silently picking one.
fn resolve_target_args(target: &Target) -> Result<Vec<String>, ProjectError> {
    match (&target.target_args, &target.arguments) {
        (Some(_), Some(_)) => Err(ProjectError::InvalidComposition {
            target: target.id.clone(),
            detail: "'target-args' and 'arguments' are aliases — set only one".to_owned(),
        }),
        (Some(args), None) | (None, Some(args)) => Ok(args.clone()),
        (None, None) => Ok(Vec::new()),
    }
}

/// Reject the binary-lane launch wrappers (#47 runner/argv, #55 postcondition) on
/// a native engine: its harness consumes input over BHF's framed fork-server
/// protocol, which has no per-launch argv, runner, or lifecycle hooks.
fn reject_native_launch_wrappers(target: &Target) -> Result<(), ProjectError> {
    let offending = [
        (target.runner.is_some(), "runner"),
        (target.runner_args.is_some(), "runner-args"),
        (target.target_args.is_some(), "target-args"),
        (target.arguments.is_some(), "arguments"),
        (target.postcondition.is_some(), "postcondition"),
    ]
    .into_iter()
    .find_map(|(present, field)| present.then_some(field));
    if let Some(field) = offending {
        return Err(ProjectError::InvalidComposition {
            target: target.id.clone(),
            detail: format!(
                "field '{field}' is not valid for engine '{}' (a native harness uses BHF's \
                 framed fork-server protocol, with no per-launch runner/argv/postcondition); \
                 use engine 'binary' for a runner-wrapped or postcondition-checked target",
                target.engine
            ),
        });
    }
    Ok(())
}

/// Resolve the binary-lane launch wrappers (#47) and postcondition hooks (#55),
/// enforcing their well-formedness: `runner-args` requires `runner`, the
/// `target-args`/`arguments` alias is single-valued, and a declared
/// `[target.postcondition]` must carry an `oracle-command`.
struct BinaryComposition {
    runner: Option<String>,
    runner_args: Vec<String>,
    target_args: Vec<String>,
    setup_command: Option<String>,
    oracle_command: Option<String>,
    reset_command: Option<String>,
}

fn resolve_binary_composition(target: &Target) -> Result<BinaryComposition, ProjectError> {
    let runner = target.runner.clone();
    let runner_args = target.runner_args.clone().unwrap_or_default();
    if runner.is_none() && !runner_args.is_empty() {
        return Err(ProjectError::InvalidComposition {
            target: target.id.clone(),
            detail: "'runner-args' requires 'runner' (the program to pass the args to)".to_owned(),
        });
    }
    let target_args = resolve_target_args(target)?;

    let (setup_command, oracle_command, reset_command) = match &target.postcondition {
        None => (None, None, None),
        Some(pc) => {
            // A postcondition with no oracle asserts nothing — fail closed with a
            // target-attributed diagnostic rather than a silent no-op.
            if pc.oracle_command.is_none() {
                return Err(ProjectError::MissingField {
                    target: target.id.clone(),
                    field: "postcondition.oracle-command",
                });
            }
            (
                pc.setup_command.clone(),
                pc.oracle_command.clone(),
                pc.reset_command.clone(),
            )
        }
    };

    Ok(BinaryComposition {
        runner,
        runner_args,
        target_args,
        setup_command,
        oracle_command,
        reset_command,
    })
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
    let engine = parse_engine(target)?;
    let env = classify_env(target)?;
    let binary = require_binary(target)?;
    // `runtime-oracles` (#59) is valid on both lanes; parse it up front so an
    // invalid mode is caught regardless of engine.
    let runtime_oracles = parse_runtime_oracles(target)?;
    let mut warnings = Vec::new();

    match engine {
        Engine::Native(native_engine) => {
            // The native harness consumes input over BHF's framed fork-server
            // protocol, which has no per-launch runner/argv/postcondition — reject
            // those binary-lane wrappers here (runtime-oracles are still honored).
            reject_native_launch_wrappers(target)?;
            // `framed` is the only valid input-mode; stdin/file are binary-lane.
            match target.input_mode.as_deref() {
                None | Some("framed") => {}
                Some(mode @ ("stdin" | "file")) => {
                    return Err(ProjectError::InputModeMismatch {
                        target: target.id.clone(),
                        detail: format!(
                            "input-mode '{mode}' is not valid for a native engine (its harness \
                             uses BHF's framed fork-server protocol); use engine 'binary' for \
                             stdin/file input delivery"
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
                runtime_oracles,
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

            let composition = resolve_binary_composition(target)?;

            // runner (#47) and the postcondition hooks (#55) are builtin-engine
            // capabilities — `afl-qemu` rejects a custom runner and user
            // postconditions. The manifest has no engine selector, so a target
            // that declares either is pinned to the binary builtin engine;
            // otherwise `auto` keeps coverage-guided afl-qemu when available.
            let engine = if composition.runner.is_some() || composition.oracle_command.is_some() {
                BinaryEngine::Builtin
            } else {
                BinaryEngine::Auto
            };

            let launch = BinaryLaunch {
                engine,
                input_mode,
                binary,
                seeds: target.seeds.clone(),
                env,
                timeout_ms: target.timeout_ms,
                mem_mb: target.mem_mb,
                time: target.time.clone(),
                runner: composition.runner,
                runner_args: composition.runner_args,
                target_args: composition.target_args,
                runtime_oracles,
                setup_command: composition.setup_command,
                oracle_command: composition.oracle_command,
                reset_command: composition.reset_command,
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
                // No builtin-only composition fields → engine stays `auto`
                // (coverage-guided afl-qemu when its toolchain is present).
                assert_eq!(b.engine, BinaryEngine::Auto);
                assert!(b.runner.is_none());
                assert!(b.target_args.is_empty());
                assert_eq!(b.runtime_oracles, RuntimeOraclesMode::Off);
                assert!(b.oracle_command.is_none());
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
                assert!(
                    detail.contains("binary"),
                    "should point to the binary engine: {detail}"
                );
            }
            other => panic!("expected input-mode mismatch, got {other:?}"),
        }
    }

    fn postcondition(oracle: Option<&str>) -> crate::schema::Postcondition {
        crate::schema::Postcondition {
            setup_command: Some("./prepare-case".to_owned()),
            oracle_command: oracle.map(str::to_owned),
            reset_command: Some("./reset-case".to_owned()),
        }
    }

    #[test]
    fn lowers_binary_target_with_runner_and_postcondition() {
        // A fully-composed binary target: runner + args, fixed target argv,
        // runtime oracles, and a postcondition. All lower into usable values and
        // the builtin-only features pin the engine to builtin.
        let mut t = base_target("acme", "binary");
        t.input_mode = Some("file".to_owned());
        t.runner = Some("wine".to_owned());
        t.runner_args = Some(vec!["--mode".to_owned(), "fuzz".to_owned()]);
        t.target_args = Some(vec!["@@".to_owned()]);
        t.runtime_oracles = Some("auto".to_owned());
        t.postcondition = Some(postcondition(Some("./check-postcondition")));

        let (launch, _) = lower_target(&t).unwrap();
        match launch {
            LoweredLaunch::Binary(b) => {
                assert_eq!(b.runner.as_deref(), Some("wine"));
                assert_eq!(b.runner_args, vec!["--mode".to_owned(), "fuzz".to_owned()]);
                assert_eq!(b.target_args, vec!["@@".to_owned()]);
                assert_eq!(b.runtime_oracles, RuntimeOraclesMode::Auto);
                assert_eq!(b.setup_command.as_deref(), Some("./prepare-case"));
                assert_eq!(b.oracle_command.as_deref(), Some("./check-postcondition"));
                assert_eq!(b.reset_command.as_deref(), Some("./reset-case"));
                // runner + postcondition are builtin-only → engine pinned.
                assert_eq!(b.engine, BinaryEngine::Builtin);
            }
            other => panic!("expected binary launch, got {other:?}"),
        }
    }

    #[test]
    fn arguments_is_accepted_alias_for_target_args() {
        let mut t = base_target("alias", "binary");
        t.arguments = Some(vec!["--flag".to_owned()]);
        let (launch, _) = lower_target(&t).unwrap();
        match launch {
            LoweredLaunch::Binary(b) => assert_eq!(b.target_args, vec!["--flag".to_owned()]),
            other => panic!("expected binary launch, got {other:?}"),
        }
    }

    #[test]
    fn target_args_and_arguments_conflict_is_rejected() {
        let mut t = base_target("conflict", "binary");
        t.target_args = Some(vec!["a".to_owned()]);
        t.arguments = Some(vec!["b".to_owned()]);
        let err = lower_target(&t).unwrap_err();
        assert!(
            matches!(err, ProjectError::InvalidComposition { ref detail, .. } if detail.contains("alias")),
            "{err:?}"
        );
    }

    #[test]
    fn runner_args_without_runner_is_rejected() {
        let mut t = base_target("ra", "binary");
        t.runner_args = Some(vec!["--mode".to_owned()]);
        let err = lower_target(&t).unwrap_err();
        assert!(
            matches!(err, ProjectError::InvalidComposition { ref detail, .. } if detail.contains("runner")),
            "{err:?}"
        );
    }

    #[test]
    fn postcondition_without_oracle_command_is_missing_field() {
        let mut t = base_target("pc", "binary");
        t.postcondition = Some(postcondition(None));
        let err = lower_target(&t).unwrap_err();
        assert!(
            matches!(
                err,
                ProjectError::MissingField {
                    field: "postcondition.oracle-command",
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn native_engine_rejects_binary_launch_wrappers() {
        for (field, apply) in [
            (
                "runner",
                (|t: &mut Target| t.runner = Some("wine".to_owned())) as fn(&mut Target),
            ),
            ("target-args", |t: &mut Target| {
                t.target_args = Some(vec!["@@".to_owned()])
            }),
            ("postcondition", |t: &mut Target| {
                t.postcondition = Some(postcondition(Some("./o")))
            }),
        ] {
            let mut t = base_target("n", "builtin");
            apply(&mut t);
            let err = lower_target(&t).unwrap_err();
            assert!(
                matches!(err, ProjectError::InvalidComposition { ref detail, .. } if detail.contains(field)),
                "field {field}: {err:?}"
            );
        }
    }

    #[test]
    fn native_engine_lowers_runtime_oracles() {
        // runtime-oracles is the one composition field valid on the native lane.
        let mut t = base_target("rt", "builtin");
        t.runtime_oracles = Some("on".to_owned());
        let (launch, _) = lower_target(&t).unwrap();
        match launch {
            LoweredLaunch::Native(n) => assert_eq!(n.runtime_oracles, RuntimeOraclesMode::On),
            other => panic!("expected native launch, got {other:?}"),
        }
    }

    #[test]
    fn invalid_runtime_oracles_mode_is_rejected() {
        let mut t = base_target("bad", "binary");
        t.runtime_oracles = Some("asan".to_owned());
        let err = lower_target(&t).unwrap_err();
        assert!(
            matches!(
                err,
                ProjectError::InvalidFieldValue {
                    field: "runtime-oracles",
                    ref value,
                    ..
                } if value == "asan"
            ),
            "{err:?}"
        );
    }

    #[test]
    fn runtime_oracles_defaults_to_off() {
        let (launch, _) = lower_target(&base_target("d", "builtin")).unwrap();
        match launch {
            LoweredLaunch::Native(n) => assert_eq!(n.runtime_oracles, RuntimeOraclesMode::Off),
            other => panic!("expected native launch, got {other:?}"),
        }
    }

    #[test]
    fn target_args_alone_keeps_auto_engine() {
        // `target-args` works on both binary engines, so it must NOT pin builtin.
        let mut t = base_target("ta", "binary");
        t.target_args = Some(vec!["--flag".to_owned()]);
        let (launch, _) = lower_target(&t).unwrap();
        match launch {
            LoweredLaunch::Binary(b) => {
                assert_eq!(b.engine, BinaryEngine::Auto);
                assert_eq!(b.target_args, vec!["--flag".to_owned()]);
            }
            other => panic!("expected binary launch, got {other:?}"),
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
