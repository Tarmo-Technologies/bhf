// SPDX-License-Identifier: Apache-2.0

//! Project config file for `bhf auto` (`--config <PATH>`, or an auto-loaded
//! `.bhf.toml` in the scanned tree root): persist common flags so a project's runs
//! are reproducible without re-typing them.
//!
//! Merge rule: the CLI always overrides the config — the config only fills a field left
//! at its default/unset value. Relative paths in the file resolve against the file's
//! own directory, so a config means the same thing whatever directory bhf runs from.
//! SECURITY: an AUTO-loaded `.bhf.toml` comes from the scanned, possibly-untrusted
//! tree, so it honors ONLY safe knobs; the fields that make bhf EXECUTE something the
//! file names (`build-command`, `unsafe-search-and-run…`, `run-untrusted`,
//! `probe-build`, and the whole `[toolchain]` and `[cross.<guard>]` tables, whose
//! compilers, flags and runners bhf would run) are ignored unless the config was passed
//! EXPLICITLY with `--config`, so a hostile tree can't auto-run code.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::cli::AutoArgs;

/// The default file name auto-loaded from the scanned tree root.
pub const CONFIG_FILE_NAME: &str = ".bhf.toml";

// Mirror the clap defaults so "still at default" can be detected for the merge.
const DEFAULT_PER_TARGET_TIME: u64 = 60;
const DEFAULT_JOBS: usize = 1;
const DEFAULT_MAX_LEN: &str = "auto";
const DEFAULT_MAX_CORPUS_MIB: usize = 64;
const DEFAULT_ENGINE: &str = "builtin";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct AutoConfig {
    // Safe knobs (honored from any config source).
    pub per_target_time: Option<u64>,
    pub max_targets: Option<usize>,
    pub jobs: Option<usize>,
    pub rss_limit_mb: Option<usize>,
    pub max_work_dir_mb: Option<u64>,
    pub max_corpus_mb: Option<usize>,
    pub cxx_std: Option<String>,
    pub max_len: Option<String>,
    pub timeout: Option<String>,
    pub grammar: Option<PathBuf>,
    pub extra_include: Option<Vec<PathBuf>>,
    pub extra_source: Option<Vec<PathBuf>>,
    pub exclude_path: Option<Vec<String>>,
    pub seed_file: Option<Vec<PathBuf>>,
    pub seed_dir: Option<Vec<PathBuf>>,
    pub sanitizers: Option<Vec<String>>,
    pub engine: Option<String>,
    pub languages: Option<Vec<String>>,
    pub project: Option<PathBuf>,
    pub ada_deps: Option<Vec<PathBuf>>,
    pub passes: Option<String>,
    pub force: Option<bool>,
    /// `false` turns off seeding from the tree's own test data (`--no-seed-mining`).
    pub seed_mining: Option<bool>,

    // Execute-y knobs: honored ONLY from an explicit --config (they run the tree's build
    // or a program the file names).
    pub build_command: Option<String>,
    pub run_untrusted: Option<bool>,
    pub unsafe_search_and_run_build_commands: Option<bool>,
    pub probe_build: Option<bool>,
    /// The `[toolchain]` table shared with `bhf build --config`.
    pub toolchain: Option<config::ToolchainConfig>,
    /// `[cross.<guard>]` tables: the toolchain and emulator of each
    /// guard-driven cross lane (`aarch64`, `armhf`, `mingw`, `ppc`, ...).
    pub cross: Option<config::CrossConfig>,
}

/// Every `bhf auto` flag that has a config key, as `(flag, key)`. A flag that
/// is not listed here is in [`FLAGS_WITHOUT_CONFIG_KEYS`]; a unit test holds the
/// two lists to the real flag set, so a new flag cannot silently go missing
/// from both. The `--help` text and `docs/site/auto.md` list these keys.
#[cfg(test)]
pub(crate) const FLAG_CONFIG_KEYS: &[(&str, &str)] = &[
    ("per-target-time", "per-target-time"),
    ("max-targets", "max-targets"),
    ("jobs", "jobs"),
    ("rss-limit-mb", "rss-limit-mb"),
    ("max-work-dir-mb", "max-work-dir-mb"),
    ("max-corpus-mb", "max-corpus-mb"),
    ("cxx-std", "cxx-std"),
    ("max-len", "max-len"),
    ("timeout", "timeout"),
    ("grammar", "grammar"),
    ("extra-include", "extra-include"),
    ("extra-source", "extra-source"),
    ("exclude-path", "exclude-path"),
    ("seed-file", "seed-file"),
    ("seed-dir", "seed-dir"),
    ("sanitizers", "sanitizers"),
    ("engine", "engine"),
    ("languages", "languages"),
    ("project", "project"),
    ("ada-deps", "ada-deps"),
    ("passes", "passes"),
    ("force", "force"),
    ("no-seed-mining", "seed-mining"),
    ("build-command", "build-command"),
    ("run-untrusted", "run-untrusted"),
    (
        "unsafe-search-and-run-build-commands",
        "unsafe-search-and-run-build-commands",
    ),
    ("probe-build", "probe-build"),
    ("cc", "toolchain.cc"),
    ("cxx", "toolchain.cxx"),
    ("cflags", "toolchain.cflags"),
    ("cxxflags", "toolchain.cxxflags"),
    ("ldflags", "toolchain.ldflags"),
    ("define", "toolchain.defines"),
    ("toolchain-include", "toolchain.include-dirs"),
    ("sysroot", "toolchain.sysroot"),
    ("target-triple", "toolchain.target"),
    ("runner", "toolchain.runner"),
    ("runner-arg", "toolchain.runner-args"),
    ("ada-prefix", "toolchain.ada.prefix"),
    ("ada-target", "toolchain.ada.target"),
    ("ada-runtime", "toolchain.ada.runtime"),
    ("ada-gprbuild", "toolchain.ada.gprbuild"),
    ("ada-gnat", "toolchain.ada.gnat"),
    ("ada-switch", "toolchain.ada.switches"),
    ("probe-backend", "toolchain.ada.probe-backend"),
];

/// The `bhf auto` flags that deliberately have no config key: per-run actions
/// and selections (`--target`, `--resume`, `--dry-run`, ...), output and
/// diagnostics switches, and the config file itself.
#[cfg(test)]
pub(crate) const FLAGS_WITHOUT_CONFIG_KEYS: &[&str] = &[
    "work-dir",
    "discovery-cache",
    "config",
    "total-time",
    "per-target-finding-count",
    "campaign-time",
    "min-target-time",
    "max-attempts",
    "max-repair-rounds",
    "single-pass",
    "reuse-discovery",
    "no-discovery-cache",
    "fresh-discovery",
    "resume",
    "iterations",
    "no-stubs",
    "list-fakes",
    "target",
    "harness-id",
    "target-file",
    "exclude",
    "reuse-legacy-corpus",
    "mode",
    "verbose",
    "deps-only",
    "list-targets",
    "dry-run",
    "exclude-dir",
    "include-dir",
    "preprocess",
    "install-deps",
    "comparison-progress",
    "sbom",
    "static",
    "external-tools",
    "differential",
    "sloc",
    "static-dynamic",
    "no-minimize",
    // C/C++ decoder synthesis caps (shared with `bhf generate-harness`).
    "array-max-size",
    "bitset-max-size",
    "container-size-max",
    "max-array-elems",
    "max-decl-bytes",
    "max-decode-depth",
];

/// Where the effective config came from, which gates the execute-y knobs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Trust {
    /// Passed with `--config <PATH>` — the operator trusts it; honor everything.
    Explicit,
    /// Auto-loaded `.bhf.toml` from the scanned tree — honor only safe knobs.
    TreeAutoloaded,
}

/// A parsed config, where it came from, and the directory its relative paths
/// resolve against.
struct LoadedConfig {
    config: AutoConfig,
    trust: Trust,
    path: PathBuf,
    base_dir: PathBuf,
}

/// Load the config for a run: `--config <PATH>` if given (explicit trust), else an
/// auto-loaded `.bhf.toml` from the tree root (safe knobs only). Returns `Ok(None)`
/// when there is no config. A malformed config is a hard error.
fn load(config_flag: Option<&Path>, tree_root: &Path) -> Result<Option<LoadedConfig>, String> {
    let (path, trust) = match config_flag {
        Some(p) => (p.to_path_buf(), Trust::Explicit),
        None => {
            let candidate = tree_root.join(CONFIG_FILE_NAME);
            if !candidate.is_file() {
                return Ok(None);
            }
            (candidate, Trust::TreeAutoloaded)
        }
    };
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("read config {}: {e}", path.display()))?;
    let config: AutoConfig =
        toml::from_str(&text).map_err(|e| format!("parse config {}: {e}", path.display()))?;
    let base_dir = crate::toolchain::config_base_dir(&path);
    Ok(Some(LoadedConfig {
        config,
        trust,
        path,
        base_dir,
    }))
}

fn resolved(base: &Path, path: PathBuf) -> PathBuf {
    if path.is_relative() {
        base.join(path)
    } else {
        path
    }
}

fn resolved_all(base: &Path, paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths.into_iter().map(|path| resolved(base, path)).collect()
}

/// Load + apply the project config to `args` in place (CLI values already parsed win).
/// Returns human-readable notes to print (what was applied / ignored), or an error for
/// a malformed config / bad value. A `[toolchain]` table is stored in
/// `args.config_toolchain` for the caller to merge with the toolchain flags.
pub fn apply(args: &mut AutoArgs, tree_root: &Path) -> Result<Vec<String>, String> {
    let Some(LoadedConfig {
        config,
        trust,
        path,
        base_dir,
    }) = load(args.config.as_deref(), tree_root)?
    else {
        return Ok(Vec::new());
    };
    let base = base_dir.as_path();
    let mut notes = Vec::new();

    // --- Safe knobs: apply only where the arg is still at its default/unset. ---
    if let Some(v) = config.per_target_time {
        if args.per_target_time == DEFAULT_PER_TARGET_TIME {
            args.per_target_time = v;
        }
    }
    if let Some(v) = config.max_targets {
        if args.max_targets.is_none() {
            args.max_targets = Some(v);
        }
    }
    if let Some(v) = config.jobs {
        if args.jobs == DEFAULT_JOBS {
            args.jobs = v;
        }
    }
    if let Some(v) = config.rss_limit_mb {
        if args.rss_limit_mb == super::cli::default_auto_rss_limit_mb() {
            args.rss_limit_mb = v;
        }
    }
    if let Some(v) = config.max_work_dir_mb {
        if args.max_work_dir_mb == super::storage::DEFAULT_MAX_WORK_DIR_MIB {
            args.max_work_dir_mb = v;
        }
    }
    if let Some(v) = config.max_corpus_mb {
        if v == 0 {
            return Err("max-corpus-mb must be at least 1".to_owned());
        }
        if args.max_corpus_mb == DEFAULT_MAX_CORPUS_MIB {
            args.max_corpus_mb = v;
        }
    }
    if let Some(v) = config.cxx_std {
        if args.cxx_std.is_none() {
            args.cxx_std = Some(v);
        }
    }
    if let Some(v) = config.max_len {
        if args.max_len == DEFAULT_MAX_LEN {
            args.max_len = v;
        }
    }
    if let Some(v) = &config.timeout {
        if args.timeout.is_none() {
            args.timeout = Some(crate::fuzz::parse_duration(v)?);
        }
    }
    if let Some(v) = config.grammar {
        if args.grammar_file.is_none() {
            args.grammar_file = Some(resolved(base, v));
        }
    }
    if let Some(v) = config.extra_include {
        if args.extra_includes.is_empty() {
            args.extra_includes = resolved_all(base, v);
        }
    }
    if let Some(v) = config.extra_source {
        if args.extra_sources.is_empty() {
            args.extra_sources = resolved_all(base, v);
        }
    }
    if let Some(v) = config.exclude_path {
        if args.exclude_paths.is_empty() {
            args.exclude_paths = v;
        }
    }
    if let Some(v) = config.seed_file {
        if args.seed_files.is_empty() {
            args.seed_files = resolved_all(base, v);
        }
    }
    if let Some(v) = config.seed_dir {
        if args.seed_dirs.is_empty() {
            args.seed_dirs = resolved_all(base, v);
        }
    }
    if let Some(v) = config.sanitizers {
        if args.sanitizers.is_empty() {
            args.sanitizers = v;
        }
    }
    if let Some(v) = config.engine {
        if args.engine == DEFAULT_ENGINE {
            args.engine = v;
        }
    }
    if let Some(v) = config.languages {
        if args.languages.is_empty() {
            args.languages = v
                .iter()
                .map(|name| {
                    <crate::auto::candidate::LangSelector as clap::ValueEnum>::from_str(name, true)
                        .map_err(|_| format!("languages: unknown language {name:?}"))
                })
                .collect::<Result<_, _>>()?;
        }
    }
    if let Some(v) = config.project {
        if args.project.is_none() {
            args.project = Some(resolved(base, v));
        }
    }
    if let Some(v) = config.ada_deps {
        if args.ada_deps.is_empty() {
            args.ada_deps = resolved_all(base, v);
        }
    }
    if let Some(v) = config.passes {
        if args.passes.is_none() && !args.single_pass {
            args.passes = Some(v);
        }
    }
    if let Some(true) = config.force {
        args.force = true; // union: config or CLI enables it
    }
    if let Some(false) = config.seed_mining {
        // Union with `--no-seed-mining`: either one turns mining off. Turning it
        // off only narrows what the run reads, so the tree's own config may too.
        args.no_seed_mining = true;
    }

    // --- Execute-y knobs: only from an EXPLICIT --config. ---
    let execute_y_requested = config.build_command.is_some()
        || config.run_untrusted == Some(true)
        || config.unsafe_search_and_run_build_commands == Some(true)
        || config.probe_build == Some(true)
        || config.toolchain.as_ref().is_some_and(|t| !t.is_empty())
        || config
            .cross
            .as_ref()
            .is_some_and(|cross| cross.values().any(|table| !table.is_empty()));
    match trust {
        Trust::Explicit => {
            if let Some(v) = config.build_command {
                if args.build_command.is_none() {
                    args.build_command = Some(v);
                }
            }
            if config.run_untrusted == Some(true) {
                args.run_untrusted = true;
            }
            if config.unsafe_search_and_run_build_commands == Some(true) {
                args.unsafe_search_and_run_build_commands = true;
            }
            if config.probe_build == Some(true) {
                args.probe_build = true;
            }
            if let Some(mut toolchain) = config.toolchain {
                toolchain.resolve_relative_to(base);
                args.config_toolchain = Some(toolchain);
            }
            if let Some(mut cross) = config.cross {
                for table in cross.values_mut() {
                    table.resolve_relative_to(base);
                }
                args.config_cross = Some(cross);
            }
        }
        Trust::TreeAutoloaded if execute_y_requested => {
            notes.push(format!(
                "ignoring build-executing keys in the auto-loaded {CONFIG_FILE_NAME} \
                 (build-command / run-untrusted / unsafe-search-and-run-build-commands / \
                 probe-build / [toolchain] / [cross.*]) — pass it explicitly with --config to \
                 honor them, \
                 since they run code or programs named by the scanned tree"
            ));
        }
        Trust::TreeAutoloaded => {}
    }

    notes.insert(0, format!("loaded config from {}", path.display()));
    Ok(notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_kebab_case_and_rejects_unknown_keys() {
        let cfg: AutoConfig = toml::from_str(
            "per-target-time = 30\ncxx-std = \"gnu++14\"\nextra-include = [\"deps/include\"]\n",
        )
        .unwrap();
        assert_eq!(cfg.per_target_time, Some(30));
        assert_eq!(cfg.cxx_std.as_deref(), Some("gnu++14"));
        assert_eq!(
            cfg.extra_include.unwrap(),
            vec![PathBuf::from("deps/include")]
        );
        assert!(toml::from_str::<AutoConfig>("bogus-key = 1\n").is_err());
    }

    /// A sample TOML value for each config key, so every listed key is proved
    /// to deserialize.
    fn sample_value(key: &str) -> &'static str {
        match key {
            "per-target-time" | "max-targets" | "jobs" | "rss-limit-mb" | "max-work-dir-mb"
            | "max-corpus-mb" => "2",
            "force"
            | "seed-mining"
            | "run-untrusted"
            | "unsafe-search-and-run-build-commands"
            | "probe-build" => "true",
            "extra-include" | "extra-source" | "exclude-path" | "seed-file" | "seed-dir"
            | "sanitizers" | "languages" | "ada-deps" | "cflags" | "cxxflags" | "ldflags"
            | "defines" | "include-dirs" | "runner-args" | "switches" => "[\"c\"]",
            _ => "\"x\"",
        }
    }

    #[test]
    fn every_auto_flag_is_either_a_config_key_or_listed_as_flag_only() {
        use clap::Args;
        let command = AutoArgs::augment_args(clap::Command::new("auto"));
        let mut flags: Vec<String> = command
            .get_arguments()
            .filter_map(|arg| arg.get_long().map(str::to_owned))
            .filter(|long| long != "help")
            .collect();
        flags.sort();
        let mut listed: Vec<String> = FLAG_CONFIG_KEYS
            .iter()
            .map(|(flag, _)| (*flag).to_owned())
            .chain(
                FLAGS_WITHOUT_CONFIG_KEYS
                    .iter()
                    .map(|flag| (*flag).to_owned()),
            )
            .collect();
        listed.sort();
        let missing: Vec<_> = flags.iter().filter(|f| !listed.contains(f)).collect();
        let stale: Vec<_> = listed.iter().filter(|f| !flags.contains(f)).collect();
        assert!(
            missing.is_empty() && stale.is_empty(),
            "auto flags not classified as config key or flag-only: {missing:?}; \
             listed but no such flag: {stale:?}"
        );
        let mut deduped = listed.clone();
        deduped.dedup();
        assert_eq!(deduped, listed, "a flag is listed twice");
    }

    #[test]
    fn every_listed_config_key_is_accepted() {
        let mut top = String::new();
        let mut toolchain = String::from("[toolchain]\n");
        let mut ada = String::from("[toolchain.ada]\n");
        for (_, key) in FLAG_CONFIG_KEYS {
            if let Some(rest) = key.strip_prefix("toolchain.ada.") {
                ada.push_str(&format!("{rest} = {}\n", sample_value(rest)));
            } else if let Some(rest) = key.strip_prefix("toolchain.") {
                toolchain.push_str(&format!("{rest} = {}\n", sample_value(rest)));
            } else {
                top.push_str(&format!("{key} = {}\n", sample_value(key)));
            }
        }
        let text = format!("{top}{toolchain}{ada}");
        let parsed: Result<AutoConfig, _> = toml::from_str(&text);
        assert!(parsed.is_ok(), "{:?}\n{text}", parsed.err());
    }

    #[test]
    fn the_docs_list_every_config_key() {
        let docs = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/site/auto.md"),
        )
        .unwrap();
        for (_, key) in FLAG_CONFIG_KEYS {
            let leaf = key.rsplit('.').next().unwrap();
            // `key`, or `key = value`.
            let documented = |name: &str| {
                docs.contains(&format!("`{name}`")) || docs.contains(&format!("`{name} ="))
            };
            assert!(
                documented(key) || documented(leaf),
                "docs/site/auto.md does not document config key {key}"
            );
        }
        assert!(
            !docs.contains("Keys are the flag names in kebab-case"),
            "the docs must not claim every flag is a config key"
        );
    }

    #[test]
    fn relative_paths_resolve_against_the_config_files_directory() {
        let tree = tempfile::tempdir().unwrap();
        std::fs::write(
            tree.path().join(CONFIG_FILE_NAME),
            "extra-include = [\"include\", \"/abs/inc\"]\ngrammar = \"fmt.json\"\n\
             seed-dir = [\"seeds\"]\nextra-source = [\"lib/aux.c\"]\n",
        )
        .unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let mut args = parse_auto_args(&["bhf", "tree"]);
        // An auto-loaded config: relative to the tree root it sits in.
        apply(&mut args, tree.path()).unwrap();
        let base = crate::toolchain::config_base_dir(&tree.path().join(CONFIG_FILE_NAME));
        assert_eq!(
            args.extra_includes,
            [base.join("include"), PathBuf::from("/abs/inc")]
        );
        assert_eq!(args.grammar_file, Some(base.join("fmt.json")));
        assert_eq!(args.seed_dirs, [base.join("seeds")]);
        assert_eq!(args.extra_sources, [base.join("lib/aux.c")]);

        // An explicit --config elsewhere: relative to that file, not the CWD.
        let config = elsewhere.path().join("ci.toml");
        std::fs::write(
            &config,
            "extra-include = [\"deps/inc\"]\nproject = \"p.gpr\"\n",
        )
        .unwrap();
        let mut args = parse_auto_args(&["bhf", "tree", "--config", config.to_str().unwrap()]);
        apply(&mut args, tree.path()).unwrap();
        let base = crate::toolchain::config_base_dir(&config);
        assert_eq!(args.extra_includes, [base.join("deps/inc")]);
        assert_eq!(args.project, Some(base.join("p.gpr")));
    }

    #[test]
    fn the_toolchain_table_is_honored_only_from_an_explicit_config() {
        let tree = tempfile::tempdir().unwrap();
        let text =
            "[toolchain]\ncc = \"tools/gcc\"\ninclude-dirs = [\"inc\"]\nprobe-build = true\n";
        // `probe-build` inside [toolchain] is not a toolchain key.
        std::fs::write(tree.path().join(CONFIG_FILE_NAME), text).unwrap();
        let mut args = parse_auto_args(&["bhf", "tree"]);
        let error = apply(&mut args, tree.path()).unwrap_err();
        assert!(error.contains("probe-build"), "{error}");

        let text =
            "probe-build = true\n[toolchain]\ncc = \"tools/gcc\"\ninclude-dirs = [\"inc\"]\n";
        std::fs::write(tree.path().join(CONFIG_FILE_NAME), text).unwrap();
        let mut args = parse_auto_args(&["bhf", "tree"]);
        let notes = apply(&mut args, tree.path()).unwrap();
        assert!(args.config_toolchain.is_none());
        assert!(!args.probe_build);
        assert!(
            notes.iter().any(|note| note.contains("[toolchain]")),
            "{notes:?}"
        );

        let explicit = tree.path().join(CONFIG_FILE_NAME);
        let mut args = parse_auto_args(&["bhf", "tree", "--config", explicit.to_str().unwrap()]);
        apply(&mut args, tree.path()).unwrap();
        assert!(args.probe_build);
        let toolchain = args
            .config_toolchain
            .expect("explicit config keeps the table");
        let base = crate::toolchain::config_base_dir(&explicit);
        assert_eq!(
            toolchain.cc.as_deref(),
            Some(base.join("tools/gcc").to_str().unwrap())
        );
        assert_eq!(toolchain.include_dirs, [base.join("inc")]);
    }

    #[test]
    fn cross_tables_are_honored_only_from_an_explicit_config() {
        let tree = tempfile::tempdir().unwrap();
        let text = "[cross.aarch64]\ncc = \"tools/aarch64-linux-gnu-gcc\"\n\
                    sysroot = \"sysroot\"\nrunner = \"qemu-aarch64\"\n";
        std::fs::write(tree.path().join(CONFIG_FILE_NAME), text).unwrap();
        let mut args = parse_auto_args(&["bhf", "tree"]);
        let notes = apply(&mut args, tree.path()).unwrap();
        assert!(args.config_cross.is_none());
        assert!(
            notes.iter().any(|note| note.contains("[cross.*]")),
            "{notes:?}"
        );

        let explicit = tree.path().join(CONFIG_FILE_NAME);
        let mut args = parse_auto_args(&["bhf", "tree", "--config", explicit.to_str().unwrap()]);
        apply(&mut args, tree.path()).unwrap();
        let cross = args.config_cross.expect("explicit config keeps the tables");
        let base = crate::toolchain::config_base_dir(&explicit);
        let aarch64 = &cross["aarch64"];
        assert_eq!(
            aarch64.cc.as_deref(),
            Some(base.join("tools/aarch64-linux-gnu-gcc").to_str().unwrap())
        );
        assert_eq!(
            aarch64.sysroot.as_deref(),
            Some(base.join("sysroot").as_path())
        );
        assert_eq!(aarch64.runner.as_deref(), Some("qemu-aarch64"));

        std::fs::write(&explicit, "[cross.aarch64]\nrunner-arg = [\"-L\"]\n").unwrap();
        let mut args = parse_auto_args(&["bhf", "tree", "--config", explicit.to_str().unwrap()]);
        let error = apply(&mut args, tree.path()).unwrap_err();
        assert!(error.contains("runner-arg"), "{error}");
    }

    #[test]
    fn the_help_and_docs_list_every_cross_lane() {
        use clap::Args;
        let command = AutoArgs::augment_args(clap::Command::new("auto"));
        let help = command
            .get_arguments()
            .find(|arg| arg.get_long() == Some("config"))
            .and_then(|arg| arg.get_long_help().or(arg.get_help()))
            .map(|help| help.to_string())
            .unwrap_or_default();
        let docs = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/site/cross-compilation.md"),
        )
        .unwrap();
        for lane in crate::auto::cross_target::cross_lane_names() {
            assert!(
                help.contains(lane),
                "--config help does not list lane {lane}"
            );
            assert!(
                docs.contains(&format!("`{lane}`")),
                "cross-compilation.md does not list lane {lane}"
            );
        }
    }

    #[test]
    fn list_and_selection_keys_fill_only_unset_flags() {
        let tree = tempfile::tempdir().unwrap();
        std::fs::write(
            tree.path().join(CONFIG_FILE_NAME),
            "sanitizers = [\"asan\"]\nengine = \"builtin,afl++\"\nlanguages = [\"c\", \"cpp\"]\n\
             passes = \"fuzz_driven\"\n",
        )
        .unwrap();
        let mut args = parse_auto_args(&["bhf", "tree"]);
        apply(&mut args, tree.path()).unwrap();
        assert_eq!(args.sanitizers, ["asan"]);
        assert_eq!(args.engine, "builtin,afl++");
        assert_eq!(args.languages.len(), 2);
        assert_eq!(args.passes.as_deref(), Some("fuzz_driven"));

        let mut args = parse_auto_args(&["bhf", "tree", "--languages", "ada", "--single-pass"]);
        apply(&mut args, tree.path()).unwrap();
        assert_eq!(args.languages.len(), 1, "the CLI wins");
        assert_eq!(args.passes, None, "--single-pass is not overridden");

        std::fs::write(
            tree.path().join(CONFIG_FILE_NAME),
            "languages = [\"cobolx\"]\n",
        )
        .unwrap();
        let mut args = parse_auto_args(&["bhf", "tree"]);
        assert!(apply(&mut args, tree.path())
            .unwrap_err()
            .contains("cobolx"));
    }

    fn parse_auto_args(argv: &[&str]) -> AutoArgs {
        use clap::Parser;
        #[derive(Parser)]
        struct TestCli {
            #[command(flatten)]
            auto: AutoArgs,
        }
        TestCli::try_parse_from(argv).unwrap().auto
    }

    #[test]
    fn seed_mining_false_turns_tree_seed_mining_off() {
        let tree = tempfile::tempdir().unwrap();
        std::fs::write(tree.path().join(CONFIG_FILE_NAME), "seed-mining = false\n").unwrap();
        let mut args = parse_auto_args(&["bhf", "tree"]);
        assert!(!args.no_seed_mining);
        apply(&mut args, tree.path()).unwrap();
        assert!(
            args.no_seed_mining,
            "an auto-loaded config may disable mining"
        );

        // `seed-mining = true` never re-enables what the CLI turned off.
        std::fs::write(tree.path().join(CONFIG_FILE_NAME), "seed-mining = true\n").unwrap();
        let mut args = parse_auto_args(&["bhf", "tree", "--no-seed-mining"]);
        apply(&mut args, tree.path()).unwrap();
        assert!(args.no_seed_mining);
        let mut args = parse_auto_args(&["bhf", "tree"]);
        apply(&mut args, tree.path()).unwrap();
        assert!(!args.no_seed_mining);
    }
}
