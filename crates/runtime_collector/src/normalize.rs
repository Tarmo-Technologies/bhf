// SPDX-License-Identifier: Apache-2.0

//! Pure, lexical path normalization.
//!
//! The collector runs on a Linux CI host but must reason about Windows paths
//! (`C:\sandbox\..\escaped`) as readily as POSIX ones. Resolution is therefore
//! **lexical only** — it never calls `fs::canonicalize` or touches the disk — so
//! the exact same logic that runs under a live Windows provider also runs in a
//! Linux unit test against a non-existent root. `escapes_root` answers the one
//! question the oracle layer cares about: did the resolved path leave the
//! allowed root?

/// The outcome of normalizing a path against an allowed root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedPath {
    /// The lexically resolved path (`.`/`..` removed), in the input's separator
    /// style.
    pub normalized: String,
    /// True when the resolved path is not under `root`.
    pub escapes_root: bool,
}

fn has_drive(p: &str) -> bool {
    let b = p.as_bytes();
    b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic()
}

fn is_windows_style(root: &str, path: &str) -> bool {
    root.contains('\\') || path.contains('\\') || has_drive(root) || has_drive(path)
}

fn is_absolute(p: &str, windows: bool) -> bool {
    if windows {
        p.starts_with('\\') || p.starts_with('/') || has_drive(p)
    } else {
        p.starts_with('/')
    }
}

fn split_components(p: &str) -> Vec<&str> {
    p.split(['/', '\\'])
        .filter(|s| !s.is_empty() && *s != ".")
        .collect()
}

/// Resolve `.`/`..` lexically. `..` pops the stack but is clamped at the
/// top (it can never escape above the first component), so the result is always
/// a well-formed component list.
fn resolve(parts: &[&str]) -> Vec<String> {
    let mut stack: Vec<String> = Vec::new();
    for c in parts {
        if *c == ".." {
            stack.pop();
        } else {
            stack.push((*c).to_owned());
        }
    }
    stack
}

fn starts_with(target: &[String], prefix: &[String]) -> bool {
    target.len() >= prefix.len() && target.iter().zip(prefix).all(|(a, b)| a == b)
}

fn join(parts: &[String], windows: bool) -> String {
    let sep = if windows { '\\' } else { '/' };
    let body = parts.join(&sep.to_string());
    if windows {
        // A leading drive component ("C:") already carries its own anchor; a
        // rooted Windows path without a drive gets a leading backslash.
        if parts.first().map(|p| has_drive(p)).unwrap_or(false) {
            body
        } else {
            format!("\\{body}")
        }
    } else {
        format!("/{body}")
    }
}

/// Normalize `path` against the allowed `root`, flagging whether the resolved
/// path escapes the root. Relative paths are resolved as if joined onto `root`.
pub fn normalize_path(root: &str, path: &str) -> NormalizedPath {
    let windows = is_windows_style(root, path);
    let root_parts = resolve(&split_components(root));

    let target_parts = if is_absolute(path, windows) {
        resolve(&split_components(path))
    } else {
        let mut combined = split_components(root);
        combined.extend(split_components(path));
        resolve(&combined)
    };

    let escapes_root = !starts_with(&target_parts, &root_parts);
    NormalizedPath {
        normalized: join(&target_parts, windows),
        escapes_root,
    }
}

/// Convenience predicate: does `path`, resolved against `root`, leave `root`?
pub fn escapes_root(root: &str, path: &str) -> bool {
    normalize_path(root, path).escapes_root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_dotdot_escape_posix() {
        let n = normalize_path("/srv/sandbox", "../escaped");
        assert_eq!(n.normalized, "/srv/escaped");
        assert!(n.escapes_root, "../ out of root must flag an escape");
    }

    #[test]
    fn normalizes_dotdot_escape_windows() {
        let n = normalize_path("C:\\sandbox", "..\\escaped");
        assert_eq!(n.normalized, "C:\\escaped");
        assert!(n.escapes_root);
    }

    #[test]
    fn absolute_path_outside_root_escapes() {
        let n = normalize_path("/srv/sandbox", "/etc/passwd");
        assert_eq!(n.normalized, "/etc/passwd");
        assert!(n.escapes_root);
    }

    #[test]
    fn repeated_dotdot_clamps_and_escapes() {
        let n = normalize_path("/srv/sandbox", "../../../etc/shadow");
        assert!(n.escapes_root);
        assert_eq!(n.normalized, "/etc/shadow");
    }

    #[test]
    fn in_root_path_not_flagged() {
        let n = normalize_path("/srv/sandbox", "inner/./file.txt");
        assert_eq!(n.normalized, "/srv/sandbox/inner/file.txt");
        assert!(!n.escapes_root);
    }

    #[test]
    fn in_root_dotdot_that_stays_inside_not_flagged() {
        let n = normalize_path("/srv/sandbox", "a/b/../c");
        assert_eq!(n.normalized, "/srv/sandbox/a/c");
        assert!(!n.escapes_root);
    }

    #[test]
    fn normalization_is_pure() {
        // A non-existent root must still resolve lexically with no FS access.
        let n = normalize_path("/does/not/exist/anywhere-xyzzy", "sub/../leaf");
        assert_eq!(n.normalized, "/does/not/exist/anywhere-xyzzy/leaf");
        assert!(!n.escapes_root);
    }
}
