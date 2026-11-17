// SPDX-License-Identifier: Apache-2.0

//! `bhf-daemon --security-config FILE` (#273): the workspace-scoped security a
//! shared deployment runs the JSON-RPC daemon with, read from a JSON file.
//!
//! ```json
//! {
//!   "mode": "multi_tenant",
//!   "tenants": [
//!     { "tenant": "alpha", "token_file": "alpha.token",
//!       "workspace_root": "/srv/alpha", "role": "operator" }
//!   ]
//! }
//! ```
//!
//! `mode` is `workspace_shared` (exactly one tenant) or `multi_tenant`. A
//! tenant's token is read from its `token_file`, never from the config, and a
//! token file its group or others can read or write is refused, as is a token
//! shorter than [`MIN_TOKEN_CHARS`]. Relative paths are relative to the
//! config file's dir.

use crate::{DaemonRole, DaemonSecurityConfig, TenantConfig};
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// The shortest token accepted.
pub const MIN_TOKEN_CHARS: usize = 16;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecurityConfigFile {
    mode: Mode,
    tenants: Vec<TenantEntry>,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Mode {
    WorkspaceShared,
    MultiTenant,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantEntry {
    tenant: String,
    token_file: PathBuf,
    workspace_root: PathBuf,
    role: DaemonRole,
}

/// Read the security config at `path`. The error says what is wrong with it.
pub fn load_security_config(path: &Path) -> Result<DaemonSecurityConfig, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    let file: SecurityConfigFile =
        serde_json::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?;
    let base = path.parent().unwrap_or(Path::new("."));
    if file.tenants.is_empty() {
        return Err(format!("{} names no tenant", path.display()));
    }
    if file.mode == Mode::WorkspaceShared && file.tenants.len() != 1 {
        return Err(format!(
            "{}: workspace_shared serves one tenant, and it names {}; use multi_tenant",
            path.display(),
            file.tenants.len()
        ));
    }
    let mut names = HashSet::new();
    let mut tokens = HashSet::new();
    let mut tenants = Vec::new();
    for entry in file.tenants {
        if entry.tenant.trim().is_empty() {
            return Err(format!("{}: a tenant has an empty name", path.display()));
        }
        if !names.insert(entry.tenant.clone()) {
            return Err(format!(
                "{}: tenant {:?} is named twice",
                path.display(),
                entry.tenant
            ));
        }
        let token = read_token(&base.join(&entry.token_file))?;
        if !tokens.insert(token.clone()) {
            return Err(format!(
                "{}: tenant {:?} has another tenant's token",
                path.display(),
                entry.tenant
            ));
        }
        let root = base.join(&entry.workspace_root);
        let workspace_root = root
            .canonicalize()
            .ok()
            .filter(|root| root.is_dir())
            .ok_or_else(|| {
                format!(
                    "tenant {:?}: workspace_root {} is not a directory",
                    entry.tenant,
                    root.display()
                )
            })?;
        tenants.push(TenantConfig {
            tenant: entry.tenant,
            token,
            workspace_root,
            role: entry.role,
        });
    }
    Ok(match file.mode {
        Mode::WorkspaceShared => DaemonSecurityConfig::workspace_shared(tenants.remove(0)),
        Mode::MultiTenant => DaemonSecurityConfig::multi_tenant(tenants),
    })
}

/// A tenant's token from `path`: refused when its group or others can read
/// or write the file, or when it is shorter than [`MIN_TOKEN_CHARS`].
fn read_token(path: &Path) -> Result<String, String> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("token file {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "token file {} is open to its group or others (mode {mode:03o}); \
                 make it private with `chmod 600`",
                path.display()
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = metadata;
    let token = std::fs::read_to_string(path)
        .map_err(|error| format!("token file {}: {error}", path.display()))?
        .trim_end_matches(['\r', '\n'])
        .to_owned();
    if token.chars().count() < MIN_TOKEN_CHARS || token.chars().any(char::is_whitespace) {
        return Err(format!(
            "token file {} holds no token of at least {MIN_TOKEN_CHARS} characters without \
             whitespace",
            path.display()
        ));
    }
    Ok(token)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn token_file(dir: &Path, name: &str, token: &str, mode: u32) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, format!("{token}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn config(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("security.json");
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn a_multi_tenant_config_reads_tokens_and_resolves_roots_beside_it() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("alpha")).unwrap();
        token_file(dir.path(), "alpha.token", "alpha-token-0123456789", 0o600);
        token_file(dir.path(), "beta.token", "beta-token-0123456789", 0o400);
        let path = config(
            dir.path(),
            r#"{ "mode": "multi_tenant", "tenants": [
                { "tenant": "alpha", "token_file": "alpha.token", "workspace_root": "alpha", "role": "operator" },
                { "tenant": "beta", "token_file": "beta.token", "workspace_root": ".", "role": "viewer" }
            ] }"#,
        );
        let DaemonSecurityConfig::MultiTenant(tenants) = load_security_config(&path).unwrap()
        else {
            panic!("multi_tenant");
        };
        assert_eq!(tenants[0].token, "alpha-token-0123456789");
        assert_eq!(tenants[0].role, DaemonRole::Operator);
        assert_eq!(
            tenants[0].workspace_root,
            dir.path().join("alpha").canonicalize().unwrap()
        );
        assert_eq!(tenants[1].role, DaemonRole::Viewer);
    }

    #[test]
    fn an_open_short_or_shared_token_and_a_bad_mode_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let entry = |file: &str| {
            format!(
                r#"{{ "tenant": "{file}", "token_file": "{file}", "workspace_root": ".", "role": "viewer" }}"#
            )
        };
        token_file(dir.path(), "open", "open-token-0123456789", 0o644);
        let error = load_security_config(&config(
            dir.path(),
            &format!(
                r#"{{ "mode": "multi_tenant", "tenants": [{}] }}"#,
                entry("open")
            ),
        ))
        .unwrap_err();
        assert!(
            error.contains("mode 644") && error.contains("chmod 600"),
            "{error}"
        );

        token_file(dir.path(), "short", "short", 0o600);
        let error = load_security_config(&config(
            dir.path(),
            &format!(
                r#"{{ "mode": "multi_tenant", "tenants": [{}] }}"#,
                entry("short")
            ),
        ))
        .unwrap_err();
        assert!(error.contains("at least 16"), "{error}");

        token_file(dir.path(), "a", "same-token-0123456789", 0o600);
        token_file(dir.path(), "b", "same-token-0123456789", 0o600);
        let error = load_security_config(&config(
            dir.path(),
            &format!(
                r#"{{ "mode": "multi_tenant", "tenants": [{}, {}] }}"#,
                entry("a"),
                entry("b")
            ),
        ))
        .unwrap_err();
        assert!(error.contains("another tenant's token"), "{error}");

        let error = load_security_config(&config(
            dir.path(),
            &format!(
                r#"{{ "mode": "workspace_shared", "tenants": [{}, {}] }}"#,
                entry("a"),
                entry("b")
            ),
        ))
        .unwrap_err();
        assert!(error.contains("serves one tenant"), "{error}");

        let error = load_security_config(&config(
            dir.path(),
            r#"{ "mode": "multi_tenant", "tenants": [], "token": "inline" }"#,
        ))
        .unwrap_err();
        assert!(error.contains("unknown field"), "{error}");
    }
}
