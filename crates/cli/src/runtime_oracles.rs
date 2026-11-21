// SPDX-License-Identifier: Apache-2.0
//! Runtime sink-oracle integration for manual fuzzing (#59).
//!
//! `bhf auto` runs each harness under the `LD_PRELOAD` runtrace shim and feeds
//! the captured events through the shared bug-oracle registry, so a clean-exit
//! semantic violation — a fuzz-controlled command execution, path escape,
//! `dlopen`, network egress, or SQL query — becomes a finding even though the
//! process exits 0. This module makes the SAME capability available to the manual
//! `bhf fuzz` and `bhf binary fuzz` commands, which previously keyed only on
//! crash signals.
//!
//! The shim is Linux-only (`LD_PRELOAD`); QEMU/Wine/cross targets are out of
//! scope for this layer (a different collector covers those). `on` errors when
//! the shim or platform is unavailable rather than silently presenting
//! crash-only coverage as equivalent; `auto` falls back to inactive.

use crate::auto::shim_path;
use anyhow::anyhow;
use finding_rules::oracle_sdk::OracleHit;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Whether the manual fuzz paths load the runtime sink oracles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum RuntimeOracleMode {
    /// Load them when the shim and the platform support it; otherwise run
    /// without them.
    Auto,
    /// Require them: an error when the shim or the platform does not support
    /// them.
    On,
    /// Do not load them, so the findings are crashes. The default.
    #[default]
    Off,
}

/// A resolved, active runtime-oracle session: the shim is present and the
/// platform supports `LD_PRELOAD`. Built once per command and applied to each
/// target execution.
#[derive(Debug, Clone)]
pub struct RuntimeOracles {
    ld_preload: String,
    shim_sha256: String,
    mode_label: String,
}

impl RuntimeOracles {
    /// Resolve the session for `mode`. `on` returns an actionable error when the
    /// shim or platform is unavailable; `auto` returns `Ok(None)` (inactive);
    /// `off` always returns `Ok(None)`. `mode_label` is the `BHF_RUNTRACE_MODE`
    /// value (`reporting`/`attacking`), matching the command's `--mode`.
    pub fn resolve(mode: RuntimeOracleMode, mode_label: &str) -> anyhow::Result<Option<Self>> {
        match mode {
            RuntimeOracleMode::Off => Ok(None),
            RuntimeOracleMode::On => {
                if !cfg!(target_os = "linux") {
                    return Err(anyhow!(
                        "--runtime-oracles on: the runtrace shim is Linux-only (LD_PRELOAD); \
                         it is unavailable on this platform"
                    ));
                }
                let shim = shim_path::locate().ok_or_else(|| {
                    anyhow!("--runtime-oracles on: {}", shim_path::unavailable_reason())
                })?;
                Self::for_shim(shim, mode_label).map(Some)
            }
            RuntimeOracleMode::Auto => {
                if !cfg!(target_os = "linux") {
                    return Ok(None);
                }
                match shim_path::locate() {
                    Some(shim) => Self::for_shim(shim, mode_label).map(Some),
                    None => Ok(None),
                }
            }
        }
    }

    fn for_shim(shim: PathBuf, mode_label: &str) -> anyhow::Result<Self> {
        let bytes = std::fs::read(&shim)
            .map_err(|e| anyhow!("read runtrace shim {}: {e}", shim.display()))?;
        Ok(Self {
            ld_preload: shim_path::ld_preload_value(&shim),
            shim_sha256: corpus::hex_lower(&Sha256::digest(&bytes)),
            mode_label: mode_label.to_owned(),
        })
    }

    /// Route one target execution's runtrace events to `log`: set `LD_PRELOAD`,
    /// `BHF_RUNTRACE_LOG`, and `BHF_RUNTRACE_MODE` on `cmd`. The caller truncates
    /// `log` beforehand (per-exec) and reads it afterwards with [`hits_from_log`].
    ///
    /// `ASAN_OPTIONS` keeps a crashing input from wedging the run: the oracle pass
    /// still records what ran before a fault, and `symbolize=0` avoids the ASan
    /// symbolizer hang seen on coverage-instrumented binaries.
    ///
    /// [`hits_from_log`]: Self::hits_from_log
    pub fn apply(&self, cmd: &mut Command, log: &Path) {
        cmd.env("LD_PRELOAD", &self.ld_preload)
            .env("BHF_RUNTRACE_LOG", log)
            .env("BHF_RUNTRACE_MODE", &self.mode_label);
        if std::env::var_os("ASAN_OPTIONS").is_none() {
            cmd.env("ASAN_OPTIONS", "abort_on_error=0:exitcode=0:symbolize=0");
        }
    }

    /// Env pairs to splice into a command's environment set (the `bhf fuzz`
    /// `extra_env` channel, which the builtin loop threads to every child and
    /// already reads back for oracle evaluation): `LD_PRELOAD`,
    /// `BHF_RUNTRACE_LOG`, and `BHF_RUNTRACE_MODE`. Unlike [`apply`], this does not
    /// touch `ASAN_OPTIONS` — the live fuzz loop keeps its abort-on-crash policy so
    /// a real crash still surfaces.
    ///
    /// [`apply`]: Self::apply
    pub fn env_pairs(&self, log: &Path) -> Vec<(String, String)> {
        vec![
            ("LD_PRELOAD".to_owned(), self.ld_preload.clone()),
            ("BHF_RUNTRACE_LOG".to_owned(), log.display().to_string()),
            ("BHF_RUNTRACE_MODE".to_owned(), self.mode_label.clone()),
        ]
    }

    /// The shim's SHA-256, recorded in finding provenance.
    pub fn shim_sha256(&self) -> &str {
        &self.shim_sha256
    }
}

/// The runtrace shim's mode gates that change what a target does, so a
/// replay must set them again: a desocketed server (#312) and the virtual
/// clock (#342).
pub const SHIM_MODE_GATES: &[&str] = &["BHF_DESOCKET", "BHF_FAKE_CLOCK"];

/// The shim mode gates a child given `extra_env` on top of this process's
/// environment runs with: each one set to `1`, when the shim is preloaded
/// (without it a gate does nothing). A finding records them.
pub fn shim_mode_gates(extra_env: &[(String, String)]) -> Vec<(String, String)> {
    shim_mode_gates_with(extra_env, |key| std::env::var(key).ok())
}

fn shim_mode_gates_with(
    extra_env: &[(String, String)],
    inherited: impl Fn(&str) -> Option<String>,
) -> Vec<(String, String)> {
    let value = |key: &str| {
        extra_env
            .iter()
            .rev()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.clone())
            .or_else(|| inherited(key))
    };
    let preloaded = value("LD_PRELOAD").is_some_and(|preload| {
        preload.contains("bhf_runtrace")
            || inherited("BHF_RUNTRACE_SHIM")
                .is_some_and(|shim| !shim.is_empty() && preload.contains(&shim))
    });
    if !preloaded {
        return Vec::new();
    }
    SHIM_MODE_GATES
        .iter()
        .filter(|gate| value(gate).as_deref() == Some("1"))
        .map(|gate| ((*gate).to_owned(), "1".to_owned()))
        .collect()
}

/// A stable dedup/replay signature for an oracle finding: the oracle rule, the
/// dangerous API, and the subject value (the tainted path/command/address) it
/// fired on. Replay re-runs the target under the oracles and matches this, rather
/// than a crash signature.
pub fn oracle_signature(hit: &OracleHit) -> String {
    // `subject` evidence keys vary by oracle (path/command/address/library/query);
    // fold whichever is present so the signature is specific to the violation.
    let subject = [
        "path",
        "command",
        "address",
        "library",
        "query",
        "operation",
    ]
    .iter()
    .find_map(|key| hit.evidence_value(key))
    .unwrap_or("");
    format!("oracle:{}:{}:{}", hit.rule_id, hit.api, subject)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #312: the gates a campaign's children ran with, whether bhf's own
    /// environment or the run's set them; nothing without the shim, and a
    /// later `0` (the libFuzzer engine's real clock) wins.
    #[test]
    fn the_shim_mode_gates_a_child_runs_with_are_found() {
        let pair = |key: &str, value: &str| (key.to_owned(), value.to_owned());
        let env = |vars: &'static [(&'static str, &'static str)]| {
            move |key: &str| {
                vars.iter()
                    .find(|(name, _)| *name == key)
                    .map(|(_, value)| (*value).to_owned())
            }
        };
        let shim = pair("LD_PRELOAD", "/opt/bhf/libbhf_runtrace_shim.so");
        assert_eq!(
            shim_mode_gates_with(
                std::slice::from_ref(&shim),
                env(&[("BHF_DESOCKET", "1"), ("BHF_FAKE_CLOCK", "0")])
            ),
            [pair("BHF_DESOCKET", "1")]
        );
        assert_eq!(
            shim_mode_gates_with(
                &[shim.clone(), pair("BHF_FAKE_CLOCK", "1")],
                env(&[("BHF_DESOCKET", "1")])
            ),
            [pair("BHF_DESOCKET", "1"), pair("BHF_FAKE_CLOCK", "1")]
        );
        assert!(shim_mode_gates_with(
            &[shim.clone(), pair("BHF_FAKE_CLOCK", "0")],
            env(&[("BHF_FAKE_CLOCK", "1")])
        )
        .is_empty());
        // Without the shim a gate does nothing, so none is recorded.
        assert!(shim_mode_gates_with(&[], env(&[("BHF_DESOCKET", "1")])).is_empty());
        // A shim named by BHF_RUNTRACE_SHIM counts under any file name.
        assert_eq!(
            shim_mode_gates_with(
                &[pair("LD_PRELOAD", "/x/shim.so")],
                env(&[("BHF_RUNTRACE_SHIM", "/x/shim.so"), ("BHF_DESOCKET", "1")])
            ),
            [pair("BHF_DESOCKET", "1")]
        );
    }

    #[test]
    fn off_mode_is_always_inactive() {
        assert!(RuntimeOracles::resolve(RuntimeOracleMode::Off, "reporting")
            .unwrap()
            .is_none());
    }

    #[test]
    fn default_mode_is_off() {
        // Runtime oracles are opt-in; a plain `bhf fuzz` stays crash-only.
        assert_eq!(RuntimeOracleMode::default(), RuntimeOracleMode::Off);
    }

    #[test]
    fn env_pairs_set_ld_preload_log_and_mode() {
        // Gated: needs the shim + Linux; skips otherwise.
        if let Ok(Some(oracles)) = RuntimeOracles::resolve(RuntimeOracleMode::On, "attacking") {
            let pairs = oracles.env_pairs(Path::new("/tmp/bhf/rt.jsonl"));
            let map: std::collections::BTreeMap<_, _> = pairs.into_iter().collect();
            assert!(map
                .get("LD_PRELOAD")
                .is_some_and(|v| v.contains("runtrace")));
            assert_eq!(
                map.get("BHF_RUNTRACE_LOG").map(String::as_str),
                Some("/tmp/bhf/rt.jsonl")
            );
            assert_eq!(
                map.get("BHF_RUNTRACE_MODE").map(String::as_str),
                Some("attacking")
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn on_mode_errors_off_linux() {
        assert!(RuntimeOracles::resolve(RuntimeOracleMode::On, "reporting").is_err());
    }

    #[test]
    fn oracle_signature_folds_rule_api_and_subject() {
        use finding_rules::oracle_sdk::{OracleEvidence, OracleHit};
        let hit = OracleHit {
            oracle_name: "command-exec".to_owned(),
            rule_id: "BHF-431".to_owned(),
            category: "process-execution".to_owned(),
            api: "system".to_owned(),
            message: "fuzz-controlled command".to_owned(),
            evidence: vec![OracleEvidence::new("command", "echo pwned")],
        };
        assert_eq!(oracle_signature(&hit), "oracle:BHF-431:system:echo pwned");
    }
}
