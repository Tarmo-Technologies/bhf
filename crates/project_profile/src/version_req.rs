// SPDX-License-Identifier: Apache-2.0

//! A tiny, internal `requires-bhf` version comparator.
//!
//! bhf has no `semver` dependency and the cross/MSVC/RHEL build matrices stay
//! C-toolchain-free, so this crate ships a minimal comparator rather than
//! pulling a new dep. It supports the operators `>=`, `>`, `<=`, `<`, `=`, `^`
//! and a bare `X.Y.Z` (treated as caret), over three-component versions.
//!
//! [`satisfied_by`] takes the *current* version as a parameter — it never reads
//! `env!("CARGO_PKG_VERSION")`. That keeps the gate deterministic and
//! independent of whatever version this crate happens to be built at; the CLI
//! supplies the `bhf` package's own version at the call site.

use crate::error::ProjectError;

/// A parsed three-component version (`major.minor.patch`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Version {
    major: u64,
    minor: u64,
    patch: u64,
}

fn parse_version(s: &str) -> Result<Version, ProjectError> {
    let mut parts = s.split('.');
    let mut next = |field: &'static str| -> Result<u64, ProjectError> {
        let raw = parts.next().ok_or_else(|| ProjectError::MalformedVersion {
            value: s.to_owned(),
            detail: format!("missing {field} component (expected major.minor.patch)"),
        })?;
        raw.parse::<u64>()
            .map_err(|_| ProjectError::MalformedVersion {
                value: s.to_owned(),
                detail: format!("{field} component '{raw}' is not a non-negative integer"),
            })
    };
    let major = next("major")?;
    let minor = next("minor")?;
    let patch = next("patch")?;
    if parts.next().is_some() {
        return Err(ProjectError::MalformedVersion {
            value: s.to_owned(),
            detail: "too many components (expected exactly major.minor.patch)".to_owned(),
        });
    }
    Ok(Version {
        major,
        minor,
        patch,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Gte,
    Gt,
    Lte,
    Lt,
    Eq,
    Caret,
}

/// Split a requirement into its operator and version text. A bare version
/// (no operator) is treated as caret, the Cargo convention for "compatible
/// with".
fn split_req(req: &str) -> Result<(Op, &str), ProjectError> {
    let req = req.trim();
    if req.is_empty() {
        return Err(ProjectError::MalformedVersionReq {
            value: req.to_owned(),
            detail: "empty requirement".to_owned(),
        });
    }
    // Two-character operators must be checked before single-character ones so
    // that a malformed `=>1.0` is not misread as `=` + `>1.0` (it still fails,
    // in version parsing, which is the desired outcome).
    for (prefix, op) in [(">=", Op::Gte), ("<=", Op::Lte)] {
        if let Some(rest) = req.strip_prefix(prefix) {
            return Ok((op, rest.trim()));
        }
    }
    for (prefix, op) in [
        (">", Op::Gt),
        ("<", Op::Lt),
        ("=", Op::Eq),
        ("^", Op::Caret),
    ] {
        if let Some(rest) = req.strip_prefix(prefix) {
            return Ok((op, rest.trim()));
        }
    }
    // No operator: bare version, caret semantics.
    Ok((Op::Caret, req))
}

/// The exclusive upper bound of a caret requirement: the next incompatible
/// version. For `^0.2.34` that is `0.3.0`; for `^0.0.3`, `0.0.4`; for `^1.2.3`,
/// `2.0.0`. The left-most non-zero component is the one that may not change.
fn caret_upper_bound(v: Version) -> Version {
    if v.major != 0 {
        Version {
            major: v.major + 1,
            minor: 0,
            patch: 0,
        }
    } else if v.minor != 0 {
        Version {
            major: 0,
            minor: v.minor + 1,
            patch: 0,
        }
    } else {
        Version {
            major: 0,
            minor: 0,
            patch: v.patch + 1,
        }
    }
}

/// Does `current` satisfy the requirement `req`?
///
/// `req` is a single comparator like `">=0.2.0"`, `"^0.2.34"`, `"<0.3.0"`, or a
/// bare `"0.2.34"` (caret). A malformed requirement or version is an error, not
/// a silent `false` — the caller fails closed.
pub fn satisfied_by(req: &str, current: &str) -> Result<bool, ProjectError> {
    let (op, version_text) = split_req(req)?;
    let want = parse_version(version_text).map_err(|e| ProjectError::MalformedVersionReq {
        value: req.trim().to_owned(),
        detail: match e {
            ProjectError::MalformedVersion { detail, .. } => detail,
            other => other.to_string(),
        },
    })?;
    let have = parse_version(current)?;
    Ok(match op {
        Op::Gte => have >= want,
        Op::Gt => have > want,
        Op::Lte => have <= want,
        Op::Lt => have < want,
        Op::Eq => have == want,
        Op::Caret => have >= want && have < caret_upper_bound(want),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_bhf_future_version_fails_closed() {
        assert!(!satisfied_by(">=9.9.9", "0.2.34").unwrap());
    }

    #[test]
    fn requires_bhf_satisfied() {
        assert!(satisfied_by(">=0.2.0", "0.2.34").unwrap());
    }

    #[test]
    fn malformed_requires_bhf_errors() {
        for bad in ["=>1.0", "1", "abc", "", ">=", "^1.2.3.4", "1.2", "1.x.0"] {
            assert!(
                satisfied_by(bad, "0.2.34").is_err(),
                "expected '{bad}' to be rejected"
            );
        }
    }

    #[test]
    fn malformed_current_version_errors() {
        assert!(satisfied_by(">=0.2.0", "0.2").is_err());
    }

    #[test]
    fn operator_coverage_both_directions() {
        // caret on a 0.x floor: in-range and out-of-range.
        assert!(satisfied_by("^0.2.34", "0.2.34").unwrap());
        assert!(satisfied_by("^0.2.34", "0.2.99").unwrap());
        assert!(!satisfied_by("^0.2.34", "0.3.0").unwrap());
        assert!(!satisfied_by("^0.2.34", "0.2.33").unwrap());
        // caret on a 1.x floor crosses the minor but not the major.
        assert!(satisfied_by("^1.2.3", "1.9.9").unwrap());
        assert!(!satisfied_by("^1.2.3", "2.0.0").unwrap());
        // strict comparisons.
        assert!(satisfied_by(">0.2.33", "0.2.34").unwrap());
        assert!(!satisfied_by(">0.2.34", "0.2.34").unwrap());
        assert!(satisfied_by("<=0.2.34", "0.2.34").unwrap());
        assert!(!satisfied_by("<=0.2.34", "0.2.35").unwrap());
        assert!(satisfied_by("=0.2.34", "0.2.34").unwrap());
        assert!(!satisfied_by("=0.2.34", "0.2.35").unwrap());
        assert!(satisfied_by("<0.3.0", "0.2.34").unwrap());
        assert!(!satisfied_by("<0.3.0", "0.3.0").unwrap());
    }

    #[test]
    fn bare_version_is_caret() {
        assert!(satisfied_by("0.2.0", "0.2.34").unwrap());
        assert!(!satisfied_by("0.2.0", "0.3.0").unwrap());
    }
}
