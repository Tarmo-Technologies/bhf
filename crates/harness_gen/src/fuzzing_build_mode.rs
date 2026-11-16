// SPDX-License-Identifier: Apache-2.0

//! OSS-Fuzz's `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`: a project tests it
//! to skip checksum and signature checks and to make randomness repeatable in
//! a fuzz build, and AFL++'s compiler wrappers define it. bhf's C and C++
//! harness builds define it for every lane unless [`ENV`] is `0`.

/// The environment variable that turns the define off (`0`, `off`, `false`
/// or `no`). `--no-fuzzing-build-mode` sets it for the process.
pub const ENV: &str = "BHF_FUZZING_BUILD_MODE";

/// The harness Makefile variable holding the define, empty when it is off.
pub const MAKE_VAR: &str = "BHF_FUZZING_BUILD_MODE_FLAGS";

/// The macro itself.
pub const MACRO: &str = "FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION";

/// Whether this process builds with the define.
pub fn enabled() -> bool {
    enabled_for(std::env::var(ENV).ok().as_deref())
}

/// [`enabled`] for a value of [`ENV`] (`None` when it is unset).
pub fn enabled_for(value: Option<&str>) -> bool {
    !value.is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "off" | "false" | "no"
        )
    })
}

/// Turn the define off for this process and every build it runs. Called once
/// at startup, before any thread is spawned.
pub fn disable() {
    std::env::set_var(ENV, "0");
}

/// Assert that `makefile` defines the macro and that every recipe compiling
/// `target_source` takes it.
#[cfg(test)]
pub(crate) fn assert_every_target_compile_defines_it(makefile: &str, target_source: &str) {
    let definition = makefile
        .lines()
        .find(|line| line.starts_with(MAKE_VAR))
        .unwrap_or_else(|| panic!("no {MAKE_VAR} line:\n{makefile}"));
    assert!(definition.contains(&format!("-D{MACRO}=1")), "{definition}");
    let recipes: Vec<&str> = makefile
        .lines()
        .filter(|line| line.starts_with('\t'))
        .filter(|line| line.split_whitespace().any(|word| word == target_source))
        .collect();
    assert!(recipes.len() >= 5, "too few target compiles:\n{makefile}");
    for recipe in recipes {
        assert!(
            recipe.contains(&format!("$({MAKE_VAR})")),
            "a lane compiles the target without the fuzz-build define:\n{recipe}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::enabled_for;

    #[test]
    fn only_an_explicit_off_value_turns_the_define_off() {
        for on in [None, Some("1"), Some(""), Some("on"), Some("yes")] {
            assert!(enabled_for(on), "{on:?}");
        }
        for off in ["0", "off", "OFF", " false ", "no"] {
            assert!(!enabled_for(Some(off)), "{off}");
        }
    }
}
