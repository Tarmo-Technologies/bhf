// SPDX-License-Identifier: Apache-2.0
use cli::auto::{
    attempt::{attempt, AttemptOptions, Outcome},
    candidate::{Candidate, Lang},
    decl_index::DeclarationIndex,
};

#[test]
fn project_builds_are_denied_before_generating_or_executing_without_consent() {
    let root = tempfile::tempdir().unwrap();
    let index = DeclarationIndex::build(root.path()).unwrap();
    for (lang, extension) in [(Lang::Rust, "rs"), (Lang::CSharp, "cs")] {
        let candidate = Candidate {
            harness_id: format!("consent-{extension}"),
            lang,
            source_path: root.path().join(format!("absent.{extension}")),
            line: 1,
            name: "checksum".into(),
            score: 60,
            is_static: false,
            foreign_guard: None,
            input_reachability: None,
            dialect: None,
        };
        let result = attempt(&candidate, root.path(), &index, AttemptOptions::default()).unwrap();
        match result.outcome {
            Outcome::UnsupportedParams { reason } => assert!(reason.contains("--run-untrusted")),
            other => panic!("expected denied project execution, got {other:?}"),
        }
        assert!(
            !result.harness_dir.exists(),
            "denied build must not generate a project"
        );
    }
}
