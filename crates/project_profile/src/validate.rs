// SPDX-License-Identifier: Apache-2.0

//! Structural validation of a parsed manifest.
//!
//! This is the type-check `bhf project validate` performs without running a
//! campaign or executing any build command: duplicate target ids, the
//! `requires-bhf` version gate, and every per-target check that lowering
//! enforces (unknown engine, missing required field, engine/input-mode
//! compatibility, gated-feature rejection, unsafe secret interpolation). It
//! returns the accumulated fidelity warnings on success.

use std::collections::BTreeSet;

use crate::error::ProjectError;
use crate::lower;
use crate::schema::Manifest;
use crate::version_req;
use crate::warning::Warning;

/// Validate the whole manifest against the running bhf version.
///
/// `current_bhf` is supplied by the caller (the `bhf` package's own
/// `CARGO_PKG_VERSION`) — this crate never reads it from `env!`. On success,
/// returns the warnings collected while lowering every target.
pub fn validate(manifest: &Manifest, current_bhf: &str) -> Result<Vec<Warning>, ProjectError> {
    check_bhf_version(manifest, current_bhf)?;
    check_duplicate_ids(manifest)?;

    let mut warnings = Vec::new();
    for target in &manifest.targets {
        // Lowering performs the per-target structural checks (engine, required
        // fields, input-mode compatibility, gated-feature rejection, unsafe
        // interpolation) and yields fidelity warnings.
        let (_launch, mut target_warnings) = lower::lower_target(target)?;
        warnings.append(&mut target_warnings);
    }
    // Every declared `[[extension]]` is structurally checked (non-empty
    // executable, supported wire format) without resolving or spawning it.
    for extension in &manifest.extensions {
        crate::validate_extension(extension)?;
    }
    Ok(warnings)
}

/// Enforce the `requires-bhf` floor, failing closed on an unmet or malformed
/// requirement.
pub fn check_bhf_version(manifest: &Manifest, current_bhf: &str) -> Result<(), ProjectError> {
    let Some(req) = manifest.project.requires_bhf.as_deref() else {
        return Ok(());
    };
    if !version_req::satisfied_by(req, current_bhf)? {
        return Err(ProjectError::UnsupportedBhfVersion {
            requires: req.to_owned(),
            current: current_bhf.to_owned(),
        });
    }
    Ok(())
}

fn check_duplicate_ids(manifest: &Manifest) -> Result<(), ProjectError> {
    let mut seen = BTreeSet::new();
    for target in &manifest.targets {
        if !seen.insert(target.id.as_str()) {
            return Err(ProjectError::DuplicateTargetId(target.id.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::load;

    use super::*;

    const CURRENT: &str = "0.2.34";

    fn manifest(body: &str) -> Manifest {
        let text = format!(
            "schema = \"bhf.project.v1\"\n\n[project]\nid = \"demo\"\nversion = \"1.0.0\"\n\n{body}"
        );
        load(&text).unwrap()
    }

    #[test]
    fn valid_manifest_passes() {
        let m = manifest(
            "[[target]]\nid = \"alpha\"\nengine = \"builtin\"\nbinary = \"prebuilt/harness\"\n",
        );
        assert!(validate(&m, CURRENT).is_ok());
    }

    #[test]
    fn duplicate_target_ids_error() {
        let m = manifest(
            "[[target]]\nid = \"dup\"\nengine = \"builtin\"\nbinary = \"a\"\n\n\
             [[target]]\nid = \"dup\"\nengine = \"binary\"\nbinary = \"b\"\n",
        );
        let err = validate(&m, CURRENT).unwrap_err();
        assert!(
            matches!(err, ProjectError::DuplicateTargetId(ref id) if id == "dup"),
            "{err:?}"
        );
    }

    #[test]
    fn unknown_engine_error() {
        let m = manifest("[[target]]\nid = \"x\"\nengine = \"magic\"\nbinary = \"a\"\n");
        let err = validate(&m, CURRENT).unwrap_err();
        assert!(
            matches!(err, ProjectError::UnknownEngine { ref engine, .. } if engine == "magic"),
            "{err:?}"
        );
    }

    #[test]
    fn missing_required_field_error() {
        let m = manifest("[[target]]\nid = \"x\"\nengine = \"builtin\"\n");
        let err = validate(&m, CURRENT).unwrap_err();
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

    #[test]
    fn requires_bhf_future_version_fails_closed() {
        let text = "schema = \"bhf.project.v1\"\n\n[project]\nid = \"demo\"\nversion = \"1.0.0\"\n\
                    requires-bhf = \">=9.9.9\"\n";
        let m = load(text).unwrap();
        let err = validate(&m, CURRENT).unwrap_err();
        assert!(
            matches!(err, ProjectError::UnsupportedBhfVersion { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn requires_bhf_satisfied_passes() {
        let text = "schema = \"bhf.project.v1\"\n\n[project]\nid = \"demo\"\nversion = \"1.0.0\"\n\
                    requires-bhf = \">=0.2.0\"\n";
        let m = load(text).unwrap();
        assert!(validate(&m, CURRENT).is_ok());
    }

    #[test]
    fn malformed_requires_bhf_errors() {
        let text = "schema = \"bhf.project.v1\"\n\n[project]\nid = \"demo\"\nversion = \"1.0.0\"\n\
                    requires-bhf = \"=>1.0\"\n";
        let m = load(text).unwrap();
        let err = validate(&m, CURRENT).unwrap_err();
        assert!(
            matches!(err, ProjectError::MalformedVersionReq { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn unsafe_secret_interpolation_rejected() {
        let m = manifest(
            "[[target]]\nid = \"x\"\nengine = \"builtin\"\nbinary = \"a\"\n\
             [target.env]\nTOKEN = \"Bearer ${secret:API}\"\n",
        );
        let err = validate(&m, CURRENT).unwrap_err();
        assert!(
            matches!(err, ProjectError::UnsafeInterpolation { .. }),
            "{err:?}"
        );
    }
}
