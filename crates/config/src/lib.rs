// SPDX-License-Identifier: Apache-2.0

use std::cell::RefCell;
use std::rc::Rc;
use std::str::FromStr;

pub mod toolchain;

pub use toolchain::{
    cross_config_from_file_text, AdaToolchainConfig, CrossConfig, CrossGuardConfig,
    ToolchainConfig, ToolchainConfigError,
};

/// The environment variable that names the license profile of a run whose
/// command line gives no `--profile`, for the tools a run asks for by flag
/// (`--external-tools`, `--symcc`, `reset=fast`). A value that names no
/// profile is ignored: `BHF_PROFILE=1` turns on bhf's stage timings instead.
pub const PROFILE_ENV: &str = "BHF_PROFILE";

thread_local! {
    static GIVEN_PROFILES: RefCell<Vec<Rc<Profile>>> = const { RefCell::new(Vec::new()) };
}

/// A run's `--profile`, which [`Profile::for_requested_tools`] reads ahead of
/// `BHF_PROFILE` while this value lives. It lives as long as the run, so a
/// later run starts from `BHF_PROFILE` again. The value is local to this
/// thread. Workers enter it with the profile copied from their caller.
#[must_use = "the profile holds only while the value lives"]
#[derive(Debug)]
pub struct GivenProfile {
    profile: Option<Rc<Profile>>,
}

impl GivenProfile {
    /// Hold `profile`, the run's `--profile`, until this value drops. `None`,
    /// a run that gives no `--profile`, holds nothing: a run inside another
    /// keeps the outer run's.
    pub fn enter(profile: Option<Profile>) -> Self {
        let profile = profile.map(|profile| {
            let profile = Rc::new(profile);
            GIVEN_PROFILES.with(|profiles| profiles.borrow_mut().push(Rc::clone(&profile)));
            profile
        });
        Self { profile }
    }
}

impl Drop for GivenProfile {
    fn drop(&mut self) {
        if let Some(profile) = &self.profile {
            GIVEN_PROFILES.with(|profiles| {
                profiles
                    .borrow_mut()
                    .retain(|held| !Rc::ptr_eq(held, profile));
            });
        }
    }
}

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
    /// The profile a tool's gate uses: `flag`, the command line's
    /// `--profile`, when there is one; else the profile `env` (the value of
    /// `BHF_PROFILE`) names; else `default`.
    pub fn resolve(flag: Option<Profile>, env: Option<&str>, default: Profile) -> Profile {
        flag.or_else(|| env.and_then(|value| value.trim().parse().ok()))
            .unwrap_or(default)
    }

    /// The profile of a tool this run asked for by flag (`--external-tools`,
    /// `--symcc`, `reset=fast`): the run's `--profile` ([`Profile::given`]),
    /// else `BHF_PROFILE`, else `external-tools`, which asking for the tool
    /// opts into.
    pub fn for_requested_tools() -> Profile {
        let env = std::env::var(PROFILE_ENV).ok();
        Self::resolve(Self::given(), env.as_deref(), Profile::ExternalTools)
    }

    /// The `--profile` of the run in progress on this thread, when its
    /// command line gave one: the [`GivenProfile`] entered last of those not
    /// yet ended.
    pub fn given() -> Option<Profile> {
        GIVEN_PROFILES.with(|profiles| profiles.borrow().last().map(|profile| **profile))
    }

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
            // Each id is checked where its tool runs. GNAT, GPRbuild and AFL++
            // run under every profile, so they have none.
            Self::ExternalTools => &[
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
    use super::{GivenProfile, Profile};
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

    /// `--profile` wins over `BHF_PROFILE`; without it `BHF_PROFILE` names the
    /// profile, and a value that names none (`BHF_PROFILE=1` turns on stage
    /// timings) leaves the gate's default.
    #[test]
    fn the_command_line_profile_wins_over_bhf_profile() {
        use Profile::{ExternalTools, ResearchLab, StrictPermissive};
        assert_eq!(
            Profile::resolve(Some(StrictPermissive), Some("research-lab"), ExternalTools),
            StrictPermissive
        );
        assert_eq!(
            Profile::resolve(Some(ResearchLab), Some("strict-permissive"), ExternalTools),
            ResearchLab
        );
        assert_eq!(
            Profile::resolve(None, Some(" research-lab "), ExternalTools),
            ResearchLab
        );
        assert_eq!(
            Profile::resolve(None, Some("1"), ExternalTools),
            ExternalTools
        );
        assert_eq!(
            Profile::resolve(None, None, StrictPermissive),
            StrictPermissive
        );
    }

    /// A run's `--profile` holds from the time the run enters it until the
    /// run ends, ahead of `BHF_PROFILE`; a run inside it that gives none
    /// keeps it. However the runs end, the last to end leaves none.
    #[test]
    fn a_given_profile_holds_until_its_run_ends() {
        use Profile::{ResearchLab, StrictPermissive};
        assert_eq!(Profile::given(), None);
        let outer = GivenProfile::enter(Some(StrictPermissive));
        assert_eq!(Profile::given(), Some(StrictPermissive));
        assert_eq!(Profile::for_requested_tools(), StrictPermissive);
        std::thread::spawn(|| {
            assert_eq!(Profile::given(), None);
            let _profile = GivenProfile::enter(Some(ResearchLab));
            assert_eq!(Profile::for_requested_tools(), ResearchLab);
        })
        .join()
        .unwrap();
        assert_eq!(Profile::given(), Some(StrictPermissive));
        let without = GivenProfile::enter(None);
        assert_eq!(Profile::given(), Some(StrictPermissive));
        let inner = GivenProfile::enter(Some(ResearchLab));
        assert_eq!(Profile::given(), Some(ResearchLab));
        drop(outer);
        assert_eq!(Profile::given(), Some(ResearchLab));
        drop(inner);
        assert_eq!(Profile::given(), None);
        drop(without);
        assert_eq!(Profile::given(), None);
    }

    #[test]
    fn parses_kebab_case_profile_names() {
        assert_eq!(
            Profile::from_str("external-tools"),
            Ok(Profile::ExternalTools)
        );
    }
}
