// SPDX-License-Identifier: Apache-2.0

//! `bhf fuzz --help` called `--grammar` "a Nautilus-style grammar mutator"
//! when the engine only generated fresh derivations from it (#329). The engine
//! now keeps each grammar input's derivation tree and mutates the tree, and
//! `bhf fuzz --help` and docs/site/cli.md describe generation plus tree
//! mutation in the same words.

use std::path::Path;
use std::process::Command;

/// What `--grammar` does, as the help and the docs say it.
const GRAMMAR: &str = "for structure-aware generation plus tree mutation: the builtin engine \
                       generates inputs from the grammar, keeps each one's derivation tree, and \
                       mutates a kept input on its tree (a subtree derived afresh, a recursion \
                       repeated, or a subtree spliced in from another input's tree of the same \
                       rule), so those mutants stay sentences of the grammar.";

fn words(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn fuzz_help_describes_grammar_generation_plus_tree_mutation() {
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["fuzz", "--help"])
        .env("COLUMNS", "100")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let help = words(&String::from_utf8_lossy(&out.stdout));
    let start = help
        .find("--grammar <PATH>")
        .expect("--grammar in the help");
    let entry = &help[start..];
    assert!(entry.contains(GRAMMAR), "{entry}");
    assert!(!help.contains("Nautilus-style grammar mutator"), "{help}");

    let docs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/site/cli.md");
    let docs = words(&std::fs::read_to_string(docs).unwrap());
    assert!(
        docs.contains(&format!(
            "`--grammar <PATH>` — a JSON grammar describing the target's input format, {GRAMMAR}"
        )),
        "docs/site/cli.md"
    );
}
