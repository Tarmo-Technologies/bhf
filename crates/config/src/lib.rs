// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

pub mod toolchain;

pub use toolchain::{
    cross_config_from_file_text, AdaToolchainConfig, CrossConfig, CrossGuardConfig,
    ToolchainConfig, ToolchainConfigError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    StrictPermissive,
    ExternalTools,
    ResearchLab,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseProfileError {
    value: String,
}

impl ParseProfileError {
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl std::fmt::Display for ParseProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown profile '{}'", self.value)
    }
}

impl std::error::Error for ParseProfileError {}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StrictPermissive => "strict-permissive",
            Self::ExternalTools => "external-tools",
            Self::ResearchLab => "research-lab",
        }
    }

    pub fn allowed_probes(self) -> &'static [&'static str] {
        match self {
            Self::StrictPermissive => &[],
            Self::ExternalTools => &["gnat_actions"],
            Self::ResearchLab => &[
                "gnat_actions",
                "libadalang",
                "gnatfuzz",
                "gnatcoverage",
                "polyorb",
            ],
        }
    }

    pub fn allowed_subprocesses(self) -> &'static [&'static str] {
        match self {
            Self::StrictPermissive => &[],
            Self::ExternalTools => &[
                "fsf_gnat",
                "gprbuild",
                "afl++",
                "rizin",
                "ghidra",
                "angr",
                // M23 Phase 3 external static-analysis adapters (subprocess-only).
                "gosec",
                "bandit",
                "semgrep",
                "gnatcheck",
                // #324: SymCC (GPL-3.0), the concolic lane of `auto --symcc`.
                "symcc",
                // #347: bhf's dirty-page plugin, run inside QEMU (GPL-2.0) by
                // the qemu-system lane's `reset=fast`.
                "qemu_plugin",
            ],
            Self::ResearchLab => &["*"],
        }
    }

    pub fn allowed_link_licenses(self) -> &'static [&'static str] {
        match self {
            Self::StrictPermissive | Self::ExternalTools | Self::ResearchLab => {
                &["Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause"]
            }
        }
    }
}

impl FromStr for Profile {
    type Err = ParseProfileError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "strict-permissive" => Ok(Self::StrictPermissive),
            "external-tools" => Ok(Self::ExternalTools),
            "research-lab" => Ok(Self::ResearchLab),
            _ => Err(ParseProfileError {
                value: value.to_owned(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Profile;
    use std::str::FromStr;

    #[test]
    fn strict_permissive_allows_no_probes() {
        assert!(Profile::StrictPermissive.allowed_probes().is_empty());
    }

    /// #324: SymCC (GPL-3.0) runs as a subprocess under external-tools and
    /// research-lab only.
    #[test]
    fn only_the_external_tool_profiles_allow_symcc() {
        assert!(!Profile::StrictPermissive
            .allowed_subprocesses()
            .contains(&"symcc"));
        assert!(Profile::ExternalTools
            .allowed_subprocesses()
            .contains(&"symcc"));
        assert_eq!(Profile::ResearchLab.allowed_subprocesses(), &["*"]);
    }

    /// #347: bhf's dirty-page plugin runs inside QEMU (GPL-2.0), under
    /// external-tools and research-lab only.
    #[test]
    fn only_the_external_tool_profiles_allow_the_qemu_plugin() {
        assert!(!Profile::StrictPermissive
            .allowed_subprocesses()
            .contains(&"qemu_plugin"));
        assert!(Profile::ExternalTools
            .allowed_subprocesses()
            .contains(&"qemu_plugin"));
    }

    #[test]
    fn parses_kebab_case_profile_names() {
        assert_eq!(
            Profile::from_str("external-tools"),
            Ok(Profile::ExternalTools)
        );
    }
}
