// SPDX-License-Identifier: Apache-2.0

//! `${env:NAME}` / `${secret:NAME}` interpolation for manifest env values.
//!
//! A manifest env value is one of exactly three things:
//!   * a plain literal with no `${` anywhere (e.g. `"release"`),
//!   * a single `${env:NAME}` handle, or
//!   * a single `${secret:NAME}` handle.
//!
//! Anything else — a bare `${PATH}`, a nested `${env:${X}}`, or a handle spliced
//! inline with literal text like `Bearer ${secret:TOKEN}` — is rejected as
//! *unsafe interpolation*. This fail-closed rule keeps secrets from leaking into
//! logs through partially-interpolated strings and makes the provenance record
//! exact: a resolved value is either public literal text or a named handle whose
//! *value is never recorded*.
//!
//! Resolution reads `env:` names from the process (or an injected) environment
//! and `secret:` names from `BHF_SECRET_<NAME>`. The resolved value is returned
//! for the launch; provenance keeps only the handle form (see
//! [`ResolvedValue::redacted_display`]).

use crate::error::ProjectError;

/// A classified, not-yet-resolved manifest env value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterpolatedValue {
    /// Public literal text, recorded verbatim in provenance.
    Literal(String),
    /// `${env:NAME}` — resolved from the environment; provenance keeps the
    /// handle, not the value.
    Env(String),
    /// `${secret:NAME}` — resolved from `BHF_SECRET_<NAME>`; provenance keeps
    /// the handle and the value is redacted everywhere.
    Secret(String),
}

/// A value after resolution: the real text for the launch plus the handle form
/// for provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedValue {
    /// The concrete value to hand to the process. Never serialized into
    /// provenance for a secret.
    pub value: String,
    /// The source classification, used for redaction decisions.
    pub source: InterpolatedValue,
}

impl ResolvedValue {
    /// The form that is safe to record in provenance / print in logs: literals
    /// pass through, handles are shown as `${env:NAME}` / `${secret:NAME}` with
    /// the resolved value omitted.
    pub fn redacted_display(&self) -> String {
        match &self.source {
            InterpolatedValue::Literal(s) => s.clone(),
            InterpolatedValue::Env(name) => format!("${{env:{name}}}"),
            InterpolatedValue::Secret(name) => format!("${{secret:{name}}}"),
        }
    }

    /// Whether the resolved value must never be serialized (a secret).
    pub fn is_secret(&self) -> bool {
        matches!(self.source, InterpolatedValue::Secret(_))
    }
}

/// A source of environment / secret values, injectable for hermetic tests.
pub trait EnvSource {
    /// Return the value of an environment variable, or `None` if unset.
    fn get(&self, key: &str) -> Option<String>;
}

/// The real process environment.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessEnv;

impl EnvSource for ProcessEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !name.chars().next().unwrap().is_ascii_digit()
}

/// Classify a raw manifest env value without touching the environment.
pub fn classify(raw: &str) -> Result<InterpolatedValue, ProjectError> {
    if !raw.contains("${") {
        return Ok(InterpolatedValue::Literal(raw.to_owned()));
    }
    // There is a `${` — the entire value must be exactly one well-formed handle.
    let unsafe_err = |detail: &str| ProjectError::UnsafeInterpolation {
        value: raw.to_owned(),
        detail: detail.to_owned(),
    };
    let inner = raw
        .strip_prefix("${")
        .and_then(|s| s.strip_suffix('}'))
        .ok_or_else(|| {
            unsafe_err("value must be exactly one ${env:NAME} or ${secret:NAME} handle")
        })?;
    // Reject nesting / a second handle spliced in.
    if inner.contains("${") || inner.contains('}') {
        return Err(unsafe_err("nested or malformed interpolation handle"));
    }
    let (kind, name) = inner.split_once(':').ok_or_else(|| {
        unsafe_err("handle must be '${env:NAME}' or '${secret:NAME}' (missing ':')")
    })?;
    if !valid_name(name) {
        return Err(unsafe_err(
            "handle name must be a non-empty [A-Za-z_][A-Za-z0-9_]* identifier",
        ));
    }
    match kind {
        "env" => Ok(InterpolatedValue::Env(name.to_owned())),
        "secret" => Ok(InterpolatedValue::Secret(name.to_owned())),
        other => Err(unsafe_err(&format!(
            "unknown handle kind '{other}' (expected 'env' or 'secret')"
        ))),
    }
}

/// Resolve an already-classified value against an environment source.
pub fn resolve_classified(
    source: &InterpolatedValue,
    env: &dyn EnvSource,
) -> Result<ResolvedValue, ProjectError> {
    let value = match source {
        InterpolatedValue::Literal(s) => s.clone(),
        InterpolatedValue::Env(name) => env
            .get(name)
            .ok_or_else(|| ProjectError::UndefinedEnvHandle(name.clone()))?,
        InterpolatedValue::Secret(name) => {
            let env_var = format!("BHF_SECRET_{name}");
            env.get(&env_var)
                .ok_or_else(|| ProjectError::UndefinedSecret {
                    name: name.clone(),
                    env_var,
                })?
        }
    };
    Ok(ResolvedValue {
        value,
        source: source.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct MapEnv(HashMap<String, String>);
    impl EnvSource for MapEnv {
        fn get(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
    }

    fn env(pairs: &[(&str, &str)]) -> MapEnv {
        MapEnv(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    /// Classify + resolve in one step (the full path a caller takes per value).
    fn resolve(raw: &str, env: &dyn EnvSource) -> Result<ResolvedValue, ProjectError> {
        resolve_classified(&classify(raw)?, env)
    }

    #[test]
    fn env_handle_resolves_and_records_handle_not_value() {
        let e = env(&[("BUILD_PROFILE", "release")]);
        let r = resolve("${env:BUILD_PROFILE}", &e).unwrap();
        assert_eq!(r.value, "release");
        // Provenance keeps the handle, never the resolved value.
        assert_eq!(r.redacted_display(), "${env:BUILD_PROFILE}");
        assert!(!r.redacted_display().contains("release"));
    }

    #[test]
    fn secret_handle_redacted_in_provenance() {
        let e = env(&[("BHF_SECRET_API_TOKEN", "s3cr3t-value")]);
        let r = resolve("${secret:API_TOKEN}", &e).unwrap();
        assert_eq!(r.value, "s3cr3t-value");
        assert!(r.is_secret());
        assert_eq!(r.redacted_display(), "${secret:API_TOKEN}");
        assert!(!r.redacted_display().contains("s3cr3t-value"));
    }

    #[test]
    fn literal_passes_through() {
        let e = env(&[]);
        let r = resolve("plain-value", &e).unwrap();
        assert_eq!(r.value, "plain-value");
        assert_eq!(r.redacted_display(), "plain-value");
        assert!(!r.is_secret());
    }

    #[test]
    fn unsafe_interpolation_rejected() {
        let e = env(&[("PATH", "/usr/bin"), ("BHF_SECRET_T", "x")]);
        for bad in [
            "${PATH}",            // bare, no env:/secret: prefix
            "${env:${X}}",        // nested
            "Bearer ${secret:T}", // inline-spliced literal + handle
            "${secret:T}-suffix", // trailing literal after handle
            "${env:A}${env:B}",   // two handles
            "${env:}",            // empty name
            "${weird:NAME}",      // unknown handle kind
            "${env:bad-name}",    // invalid identifier
        ] {
            let err = resolve(bad, &e).unwrap_err();
            assert!(
                matches!(err, ProjectError::UnsafeInterpolation { .. }),
                "expected '{bad}' to be unsafe, got {err:?}"
            );
        }
    }

    #[test]
    fn undefined_env_handle_errors() {
        let e = env(&[]);
        let err = resolve("${env:NOT_SET}", &e).unwrap_err();
        assert!(
            matches!(err, ProjectError::UndefinedEnvHandle(_)),
            "{err:?}"
        );
    }

    #[test]
    fn undefined_secret_errors() {
        let e = env(&[]);
        let err = resolve("${secret:MISSING}", &e).unwrap_err();
        assert!(
            matches!(err, ProjectError::UndefinedSecret { .. }),
            "{err:?}"
        );
    }
}
