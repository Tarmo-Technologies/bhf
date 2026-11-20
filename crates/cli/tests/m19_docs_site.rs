// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The Python interpreter: Windows' installer provides `python`, not `python3`.
const PYTHON: &str = if cfg!(windows) { "python" } else { "python3" };

#[test]
fn docs_site_workflow_builds_and_deploys_github_pages() {
    let workflow = read(repo_root().join(".github/workflows/docs-site.yml"));

    assert!(workflow.contains("name: Docs Site"));
    assert!(workflow.contains("pull_request:"));
    assert!(workflow.contains("push:"));
    assert!(workflow.contains("branches: [main]"));
    assert!(workflow.contains("python3 scripts/docs/build-site.py --out target/docs-site"));
    // Actions are pinned to a commit SHA (supply-chain hardening); Dependabot
    // bumps the pin + version comment, so assert the action is referenced rather
    // than a specific tag/SHA.
    assert!(workflow.contains("uses: actions/configure-pages@"));
    assert!(workflow.contains("uses: actions/upload-pages-artifact@"));
    assert!(workflow.contains("uses: actions/deploy-pages@"));
    assert!(workflow.contains("vars.BHF_PAGES_ENABLED == 'true'"));
    assert!(workflow.contains("contents: read"));
    assert!(workflow.contains("pages: write"));
    assert!(workflow.contains("id-token: write"));
    assert!(workflow.contains(
        "github.event_name == 'push' && github.ref == 'refs/heads/main' && vars.BHF_PAGES_ENABLED == 'true'"
    ));
}

#[test]
fn docs_site_sources_cover_m19_topics() {
    let root = repo_root();
    let required_pages = [
        ("index", "no public host serves it yet"),
        ("architecture", "docs site"),
        ("instrumentation", "instrumentation"),
        ("fake-corba", "fake-CORBA"),
        ("licensing", "license audit"),
        ("cli", "# CLI"),
        ("c-cpp", "C and C++ Fuzzing"),
        ("cross-compilation", "cross-compil"),
        ("daemon", "JSON-RPC"),
        ("custom-harness", "Custom C and C++ Harnesses"),
    ];

    for (slug, required_text) in required_pages {
        let source = read(root.join(format!("docs/site/{slug}.md"))).to_lowercase();
        assert!(
            source.contains(&required_text.to_lowercase()),
            "docs/site/{slug}.md should mention {required_text:?}"
        );
    }
}

#[test]
fn primary_product_surfaces_do_not_use_ada_first_positioning() {
    let root = repo_root();
    let checked = [
        "README.md",
        "ROADMAP.md",
        "docs/fuzzing-landscape-2026-05-20.md",
        "docs/site/index.md",
        "docs/site/architecture.md",
        "docs/site/auto.md",
        "docs/site/c-cpp.md",
        "crates/cli/src/lib.rs",
    ];

    for rel in checked {
        let source = read(root.join(rel));
        assert!(
            !source.contains("Ada-first") && !source.contains("Ada first."),
            "{rel} should position BHF as a government legacy Ada/C/C++ fuzzer, not Ada-first"
        );
    }
}

#[test]
fn docs_site_generator_emits_html_pages_and_metadata() {
    let root = repo_root();
    let output_dir = root.join("target/m19-docs-site-test");
    if output_dir.exists() {
        fs::remove_dir_all(&output_dir).unwrap_or_else(|error| {
            panic!(
                "failed to remove old docs output {}: {error}",
                output_dir.display()
            );
        });
    }

    let status = Command::new(PYTHON)
        .arg("scripts/docs/build-site.py")
        .arg("--out")
        .arg(&output_dir)
        .current_dir(&root)
        .status()
        .expect("failed to run docs site generator");

    assert!(status.success(), "docs site generator failed: {status}");

    let index = read(output_dir.join("index.html"));
    assert!(index.contains("BHF Documentation"));
    assert!(index.contains("href=\"architecture/\""));
    assert!(index.contains("href=\"instrumentation/\""));
    assert!(index.contains("href=\"fake-corba/\""));
    assert!(index.contains("href=\"licensing/\""));
    assert!(index.contains("href=\"cli/\""));
    assert!(index.contains("href=\"c-cpp/\""));
    assert!(index.contains("href=\"custom-harness/\""));
    assert!(index.contains("href=\"cross-compilation/\""));
    assert!(index.contains("href=\"daemon/\""));

    let cross_compilation = read(output_dir.join("cross-compilation/index.html"));
    assert!(cross_compilation.contains("&lt;prefix&gt;-gnat"));

    let c_cpp = read(output_dir.join("c-cpp/index.html"));
    assert!(c_cpp.contains("Supported C++ Parameter Shapes"));
    assert!(c_cpp.contains("href=\"../custom-harness/\""));

    let custom = read(output_dir.join("custom-harness/index.html"));
    for expected in [
        "LLVMFuzzerTestOneInput",
        "--output bhf_work/harnesses",
        "AUTO_EXTRA_SOURCES",
        "AUTO_EXTRA_INCLUDES",
        "CXX_STD",
        "--seed-file",
        "bhf_run_one",
        "bhf binary fuzz",
    ] {
        assert!(
            custom.contains(expected),
            "custom-harness page should cover {expected:?}"
        );
    }

    // The extension protocol page is published and cli.md links it (#228).
    assert!(output_dir.join("extension-protocol/index.html").is_file());
    let cli = read(output_dir.join("cli/index.html"));
    assert!(
        cli.contains("href=\"../extension-protocol/\""),
        "cli links the page"
    );
    assert!(
        !cli.contains("](../extension-protocol.md)"),
        "no literal Markdown link"
    );

    // No public host serves the site: no CNAME, no canonical links, no
    // sitemap, and robots.txt names none.
    assert!(!output_dir.join("CNAME").exists());
    assert!(!index.contains("rel=\"canonical\""));
    assert!(!output_dir.join("sitemap.xml").exists());
    assert!(!read(output_dir.join("robots.txt")).contains("Sitemap:"));
}

/// A relative link to a Markdown file that does not exist fails the build
/// (#228): it reached the page as literal Markdown.
#[test]
fn the_docs_build_fails_on_a_broken_relative_link() {
    let root = repo_root();
    let scratch = root.join("target/m19-docs-broken-link");
    let _ = fs::remove_dir_all(&scratch);
    let source = scratch.join("site");
    fs::create_dir_all(&source).unwrap();
    for entry in fs::read_dir(root.join("docs/site")).unwrap().flatten() {
        let path = entry.path();
        if path.is_file() {
            fs::copy(&path, source.join(entry.file_name())).unwrap();
        } else if entry.file_name() == "img" {
            fs::create_dir_all(source.join("img")).unwrap();
            for image in fs::read_dir(&path).unwrap().flatten() {
                fs::copy(image.path(), source.join("img").join(image.file_name())).unwrap();
            }
        }
    }
    let cli = source.join("cli.md");
    let mut text = read(&cli);
    text.push_str("\nSee [the missing page](no-such-page.md).\n");
    fs::write(&cli, text).unwrap();
    let output = Command::new(PYTHON)
        .arg("scripts/docs/build-site.py")
        .arg("--source")
        .arg(&source)
        .arg("--out")
        .arg(scratch.join("out"))
        .current_dir(&root)
        .output()
        .expect("run the docs site generator");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("cli.md -> no-such-page.md"), "{stderr}");
    let _ = fs::remove_dir_all(&scratch);
}

/// index.md and the site builder's DEFAULT_BASE_URL name the same public
/// host, or both name none (#228): index.md named a domain with no DNS record.
#[test]
fn index_and_the_default_base_url_agree() {
    let root = repo_root();
    let builder = read(root.join("scripts/docs/build-site.py"));
    let base = builder
        .lines()
        .find_map(|line| line.strip_prefix("DEFAULT_BASE_URL = "))
        .expect("DEFAULT_BASE_URL")
        .trim()
        .trim_matches('"')
        .to_owned();
    let index = read(root.join("docs/site/index.md"));
    let host = base
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    if host.is_empty() {
        assert!(index.contains("no public host serves it"), "{index}");
        assert!(
            !index.contains("is the public documentation site"),
            "{index}"
        );
        assert!(!root.join("docs/site/CNAME").exists());
    } else {
        assert!(index.contains(host), "index.md must name {host}");
    }
}

fn read(path: impl AsRef<Path>) -> String {
    let path = path.as_ref();
    fs::read_to_string(path).unwrap_or_else(|error| {
        panic!("failed to read {}: {error}", path.display());
    })
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
