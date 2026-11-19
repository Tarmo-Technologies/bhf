// SPDX-License-Identifier: Apache-2.0

//! The Ada half of `bhf export regression` (#339): each Ada harness's
//! `main.adb` with a project, `regress.gpr`, that builds it against the
//! scanned tree's own sources (not bhf's instrumented copies) and a copy of
//! bhf's Ada runtime, and its corpus and finding inputs. `run.sh` feeds each
//! input on stdin with `BHF_CRASH_ON_FINDING=1`, so an exception that escapes
//! the target aborts the harness and fails the suite.

use crate::export_regression::{
    copy_corpus, copy_finding_inputs, harness_dirs, Exported, RegressionArgs,
};
use std::path::Path;

pub(crate) fn export(args: &RegressionArgs, source_root: &Path) -> Result<Exported, String> {
    let harnesses = harness_dirs(&args.work_dir, &["main.adb"]);
    let mut exported = Exported::default();
    if harnesses.is_empty() {
        return Ok(exported);
    }
    let runtime = crate::runtime_assets::locate("ada_runtime", "adafuzz.gpr")
        .ok_or_else(|| "could not locate bhf's ada_runtime".to_owned())?;
    copy_ada(&runtime, &args.out.join("ada_runtime"), false)?;
    for (id, dir) in &harnesses {
        let dest = args.out.join("harnesses").join(id);
        copy_ada(dir, &dest, true)?;
        let project = format!(
            "--  bhf regression suite: the harness built against the scanned tree's\n\
             --  sources. SOURCE_ROOT names another checkout of it.\n\
             with \"../../ada_runtime/adafuzz.gpr\";\n\
             project Regress is\n\
             \x20  Source_Root := external (\"SOURCE_ROOT\", \"{root}\");\n\
             \x20  for Source_Dirs use (\".\", \"repairs/**\", Source_Root & \"/**\");\n\
             \x20  for Object_Dir use \"obj\";\n\
             \x20  for Main use (\"main.adb\");\n\
             \x20  package Compiler is\n\
             \x20     for Default_Switches (\"Ada\") use (\"-g\", \"-gnata\");\n\
             \x20  end Compiler;\n\
             end Regress;\n",
            root = source_root.display(),
        );
        std::fs::write(dest.join("regress.gpr"), project)
            .map_err(|error| format!("write {}: {error}", dest.join("regress.gpr").display()))?;
        exported.findings +=
            copy_finding_inputs(&args.work_dir, id, &dest.join("inputs").join("findings"));
        exported.corpus += copy_corpus(
            &args.work_dir,
            id,
            &dest.join("inputs").join("corpus"),
            args.max_corpus,
        );
        exported.harnesses += 1;
    }
    let script = format!(
        "#!/bin/sh\n\
         # SPDX-License-Identifier: Apache-2.0\n\
         # bhf regression suite (Ada): build each harness against the scanned tree\n\
         # and feed it every input. An exception that escapes the target aborts the\n\
         # harness (BHF_CRASH_ON_FINDING=1) and fails the suite.\n\
         #\n\
         #   SOURCE_ROOT=<checkout> ./run.sh\n\
         set -u\n\
         SUITE_DIR=$(cd \"$(dirname \"$0\")\" && pwd)\n\
         SOURCE_ROOT=${{SOURCE_ROOT:-'{root}'}}\n\
         export SOURCE_ROOT\n\
         BHF_CRASH_ON_FINDING=1\n\
         export BHF_CRASH_ON_FINDING\n\
         failed=0\n\
         ran=0\n\
         for harness in \"$SUITE_DIR\"/harnesses/*/; do\n\
         \x20 id=$(basename \"$harness\")\n\
         \x20 gprbuild -q -P \"$harness/regress.gpr\" -XSOURCE_ROOT=\"$SOURCE_ROOT\" \\\n\
         \x20   >\"$harness/build.log\" 2>&1 \\\n\
         \x20   || {{ echo \"BUILD FAILED $id (see $harness/build.log)\"; failed=1; continue; }}\n\
         \x20 for input in \"$harness\"inputs/findings/* \"$harness\"inputs/corpus/*; do\n\
         \x20   [ -f \"$input\" ] || continue\n\
         \x20   ran=$((ran + 1))\n\
         \x20   kind=$(basename \"$(dirname \"$input\")\")\n\
         \x20   if \"$harness/obj/main\" <\"$input\" >/dev/null 2>\"$harness/last.log\"; then\n\
         \x20     echo \"pass $id $kind/$(basename \"$input\")\"\n\
         \x20   else\n\
         \x20     echo \"FAIL $id $kind/$(basename \"$input\") (exit $?)\"\n\
         \x20     failed=1\n\
         \x20   fi\n\
         \x20 done\n\
         done\n\
         echo \"$ran input(s) run\"\n\
         exit $failed\n",
        root = source_root.display().to_string().replace('\'', "'\\''"),
    );
    let path = args.out.join("run.sh");
    std::fs::write(&path, script).map_err(|error| format!("write {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755));
    }
    Ok(exported)
}

/// Copy the Ada and C sources and projects of `from` into `to` (its
/// `repairs/` stubs too, for a harness).
fn copy_ada(from: &Path, to: &Path, harness: bool) -> Result<(), String> {
    std::fs::create_dir_all(to).map_err(|error| format!("create {}: {error}", to.display()))?;
    for entry in std::fs::read_dir(from)
        .map_err(|error| format!("read {}: {error}", from.display()))?
        .flatten()
    {
        let path = entry.path();
        let dest = to.join(entry.file_name());
        if path.is_dir() {
            if harness && (entry.file_name() == "repairs" || from.ends_with("repairs")) {
                copy_ada(&path, &dest, true)?;
            }
            continue;
        }
        let keep = path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| matches!(extension, "adb" | "ads" | "gpr" | "c" | "h"));
        if keep {
            std::fs::copy(&path, &dest)
                .map_err(|error| format!("copy {}: {error}", path.display()))?;
        }
    }
    Ok(())
}
