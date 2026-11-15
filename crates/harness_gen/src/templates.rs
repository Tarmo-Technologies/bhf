// SPDX-License-Identifier: Apache-2.0

pub const DIRECT_HARNESS_TEMPLATE: &str = include_str!("templates/direct_harness.adb.tera");
pub const SEQUENCE_HARNESS_TEMPLATE: &str = include_str!("templates/sequence_harness.adb.tera");
pub const SERVANT_DIRECT_HARNESS_TEMPLATE: &str =
    include_str!("templates/servant_direct_harness.adb.tera");
pub const GPR_TEMPLATE: &str = include_str!("templates/harness.gpr.tera");
pub const DIRECT_HARNESS_C_TEMPLATE: &str = include_str!("templates/direct_harness.c.tera");
pub const SEQUENCE_HARNESS_C_TEMPLATE: &str = include_str!("templates/sequence_harness.c.tera");
pub const HARNESS_MAKEFILE_TEMPLATE: &str = include_str!("templates/harness.makefile.tera");
pub const DIRECT_HARNESS_CPP_TEMPLATE: &str = include_str!("templates/direct_harness.cpp.tera");
pub const HARNESS_MAKEFILE_CPP_TEMPLATE: &str = include_str!("templates/harness.makefile.cpp.tera");

pub fn build_tera() -> Result<tera::Tera, tera::Error> {
    let mut tera = tera::Tera::default();
    tera.add_raw_template("direct_harness", DIRECT_HARNESS_TEMPLATE)?;
    tera.add_raw_template("sequence_harness", SEQUENCE_HARNESS_TEMPLATE)?;
    tera.add_raw_template("servant_direct_harness", SERVANT_DIRECT_HARNESS_TEMPLATE)?;
    tera.add_raw_template("harness_gpr", GPR_TEMPLATE)?;
    tera.add_raw_template("direct_harness_c", DIRECT_HARNESS_C_TEMPLATE)?;
    tera.add_raw_template("sequence_harness_c", SEQUENCE_HARNESS_C_TEMPLATE)?;
    tera.add_raw_template("harness_makefile", HARNESS_MAKEFILE_TEMPLATE)?;
    tera.add_raw_template("direct_harness_cpp", DIRECT_HARNESS_CPP_TEMPLATE)?;
    tera.add_raw_template("harness_makefile_cpp", HARNESS_MAKEFILE_CPP_TEMPLATE)?;
    Ok(tera)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Windows crash handler of every C/C++ driver — the generated harness
    /// templates and the shared `c_runtime/bhf_driver.c` — must be the chained
    /// unhandled-exception filter. A first-chance vectored handler sees the
    /// exceptions AddressSanitizer raises and handles itself (its shadow memory
    /// is committed on demand through access violations), so it turns every
    /// valid sanitized input into a crash.
    #[test]
    fn every_windows_crash_handler_is_the_chained_unhandled_exception_filter() {
        let driver = include_str!("../../../c_runtime/bhf_driver.c");
        for (name, source) in [
            ("direct_harness.c.tera", DIRECT_HARNESS_C_TEMPLATE),
            ("direct_harness.cpp.tera", DIRECT_HARNESS_CPP_TEMPLATE),
            ("sequence_harness.c.tera", SEQUENCE_HARNESS_C_TEMPLATE),
            ("c_runtime/bhf_driver.c", driver),
        ] {
            assert!(
                !source.contains("AddVectoredExceptionHandler"),
                "{name} installs a first-chance vectored exception handler"
            );
            assert!(
                source.contains(
                    "bhf_win_previous_filter = SetUnhandledExceptionFilter(bhf_win_unhandled)"
                ),
                "{name} does not install the chained unhandled-exception filter"
            );
            assert!(
                source.contains("LONG handled = bhf_win_previous_filter(info);"),
                "{name} does not give the previous filter (the sanitizer's) the first look"
            );
        }
    }
    /// Both Makefiles turn fortification off with the words every other
    /// sanitized compile bhf runs ends with (the gcc probe build, capsule
    /// `build.sh`).
    #[test]
    fn both_makefiles_turn_fortify_off_with_the_shared_override() {
        let expected = format!(
            "BHF_NO_FORTIFY = {}\n",
            crate::compiler_family::SANITIZED_NO_FORTIFY.join(" ")
        );
        for (name, makefile) in [
            ("harness.makefile.tera", HARNESS_MAKEFILE_TEMPLATE),
            ("harness.makefile.cpp.tera", HARNESS_MAKEFILE_CPP_TEMPLATE),
        ] {
            assert!(
                makefile.contains(&expected),
                "{name}: {:?}",
                makefile
                    .lines()
                    .find(|line| line.starts_with("BHF_NO_FORTIFY"))
            );
        }
    }
}
