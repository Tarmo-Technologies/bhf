// SPDX-License-Identifier: Apache-2.0

//! The reference target-side agent (`c_runtime/bhf_agent.c`, #289) over a
//! loopback socket: its POSIX example, linked with a SanitizerCoverage-built
//! target, is driven by the host's `AgentTransport` as `--target-transport
//! agent:tcp` drives it. Coverage grows as an input reaches new code, a
//! fault is reported for the input that caused it and the agent serves the
//! next input, and an input longer than its buffer is refused, not run. The
//! Zephyr glue (`c_runtime/zephyr/`, #291) runs the same way against a host
//! stand-in for the Zephyr API it uses. It needs clang; `BHF_REQUIRE_TOOLS=1`
//! makes a missing one a failure.
#![cfg(unix)]

use std::io::BufRead;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use target_transport::agent::AgentTransport;
use target_transport::{ExitKind, FaultKind, TargetTransport};

mod common;

/// The input buffer the agent is built with.
const INPUT_CAP: usize = 64;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Build the POSIX agent with the test target into `dir`; `None` without
/// clang.
fn build_agent(dir: &Path) -> Option<PathBuf> {
    let clang = common::tool_on_path("clang");
    if !clang {
        assert!(
            std::env::var_os("BHF_REQUIRE_TOOLS").is_none_or(|value| value != "1"),
            "BHF_REQUIRE_TOOLS=1 and clang is not on PATH"
        );
        return None;
    }
    let runtime = repo().join("c_runtime");
    let compile = |args: &[&std::ffi::OsStr]| {
        let status = Command::new("clang").args(args).status().unwrap();
        assert!(status.success(), "clang {args:?}");
    };
    let obj = |name: &str| dir.join(name);
    // The agent is not code under test: no coverage there.
    compile(&[
        "-std=c99".as_ref(),
        "-Wall".as_ref(),
        "-Werror".as_ref(),
        "-c".as_ref(),
        runtime.join("bhf_agent.c").as_os_str(),
        "-o".as_ref(),
        obj("bhf_agent.o").as_os_str(),
    ]);
    compile(&[
        "-Wall".as_ref(),
        "-Werror".as_ref(),
        format!("-DAGENT_INPUT_CAP={INPUT_CAP}").as_ref(),
        "-I".as_ref(),
        runtime.as_os_str(),
        "-c".as_ref(),
        runtime.join("examples/agent_posix.c").as_os_str(),
        "-o".as_ref(),
        obj("agent_posix.o").as_os_str(),
    ]);
    compile(&[
        "-fsanitize-coverage=trace-pc-guard".as_ref(),
        "-O0".as_ref(),
        "-c".as_ref(),
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/agent/target.c")
            .as_os_str(),
        "-o".as_ref(),
        obj("target.o").as_os_str(),
    ]);
    let agent = dir.join("agent");
    compile(&[
        obj("agent_posix.o").as_os_str(),
        obj("bhf_agent.o").as_os_str(),
        obj("target.o").as_os_str(),
        "-o".as_ref(),
        agent.as_os_str(),
    ]);
    Some(agent)
}

/// The agent, listening on the port it printed.
struct Agent {
    child: Child,
    port: u16,
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(agent: &Path) -> Agent {
    let mut child = Command::new(agent)
        .arg("0")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    std::io::BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let port = line
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("port: {line:?}"));
    Agent { child, port }
}

#[test]
fn the_reference_agent_reports_coverage_faults_and_refusals_over_tcp() {
    let dir = tempfile::tempdir().unwrap();
    let Some(binary) = build_agent(dir.path()) else {
        eprintln!("skipping: clang not on PATH");
        return;
    };
    let agent = start(&binary);
    let port = agent.port;
    let transport =
        AgentTransport::new(move || TcpStream::connect(("127.0.0.1", port)).map_err(Into::into));
    let mut session = transport.arm().unwrap();

    // Each matched byte of "BUG" reaches new code: the campaign's coverage
    // grows with each input.
    let edges = |input: &[u8], session: &mut Box<dyn target_transport::TargetSession>| {
        let outcome = session.run_input(input).unwrap();
        assert_eq!(outcome.exit, ExitKind::Ok, "{input:?}: {outcome:?}");
        assert!(outcome.fault.is_none() && outcome.inconclusive.is_none());
        let mut edges = outcome.coverage_edges;
        let all = edges.len();
        edges.sort_unstable();
        edges.dedup();
        assert_eq!(edges.len(), all, "an edge is reported once per input");
        edges
    };
    let none = edges(b"", &mut session);
    assert!(!none.is_empty(), "the entry's own edges");
    let mut seen: std::collections::BTreeSet<u32> = none.iter().copied().collect();
    let b = edges(b"B", &mut session);
    let bu = edges(b"BU", &mut session);
    for (input, reached) in [("B", &b), ("BU", &bu)] {
        let before = seen.len();
        seen.extend(reached.iter().copied());
        assert!(seen.len() > before, "{input} reaches new code: {reached:?}");
    }
    assert_eq!(
        edges(b"B", &mut session),
        b,
        "the same input, the same edges"
    );

    // The fault, for the input that caused it; the next input runs.
    let fault = session.run_input(b"BUG").unwrap();
    assert_eq!(fault.exit, ExitKind::Crash, "{fault:?}");
    let detail = fault.fault.expect("a fault");
    assert_eq!(detail.kind, FaultKind::MemoryProtection);
    assert_eq!(detail.address, Some(0));
    assert_eq!(detail.detail, "SIGSEGV");
    assert_eq!(
        edges(b"BU", &mut session),
        bu,
        "the agent goes on after a fault"
    );

    // An input longer than the agent's buffer is refused, not run, and the
    // link stays in step.
    let refused = session.run_input(&[b'B'; INPUT_CAP + 1]).unwrap();
    assert_eq!(refused.exit, ExitKind::Ok);
    assert!(refused.coverage_edges.is_empty() && refused.fault.is_none());
    assert!(
        refused
            .inconclusive
            .as_deref()
            .is_some_and(|reason| reason.contains("refused")),
        "{refused:?}"
    );
    assert_eq!(edges(b"B", &mut session), b);
    let at_cap = session.run_input(&[b'x'; INPUT_CAP]).unwrap();
    assert!(
        at_cap.inconclusive.is_none(),
        "an input of the capacity runs"
    );

    // A new session once this one closes (the agent serves one link at a
    // time, as a board's does).
    drop(session);
    let mut again = transport.arm().unwrap();
    assert_eq!(edges(b"B", &mut again), b);
}

/// Build the Zephyr glue against the host stand-in of `tests/agent/zephyr_host`
/// (#291), with the test target, into `dir`; `None` without clang.
fn build_zephyr_host_agent(dir: &Path) -> Option<PathBuf> {
    if !common::tool_on_path("clang") {
        assert!(
            std::env::var_os("BHF_REQUIRE_TOOLS").is_none_or(|value| value != "1"),
            "BHF_REQUIRE_TOOLS=1 and clang is not on PATH"
        );
        return None;
    }
    let runtime = repo().join("c_runtime");
    let host = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/agent/zephyr_host");
    let include = |args: &mut Vec<std::ffi::OsString>| {
        for dir in [&host, &runtime, &runtime.join("zephyr")] {
            args.push("-I".into());
            args.push(dir.into());
        }
    };
    let compile = |source: PathBuf, extra: &[&str], object: &str| {
        let mut args: Vec<std::ffi::OsString> = vec!["-Wall".into(), "-Werror".into()];
        include(&mut args);
        args.extend(extra.iter().map(Into::into));
        args.extend([
            "-c".into(),
            source.into(),
            "-o".into(),
            dir.join(object).into(),
        ]);
        let status = Command::new("clang").args(&args).status().unwrap();
        assert!(status.success(), "clang {args:?}");
    };
    compile(
        runtime.join("bhf_agent.c"),
        &["-std=c99", "-DBHF_AGENT_NO_SETJMP"],
        "bhf_agent.o",
    );
    compile(
        runtime.join("zephyr/bhf_agent_zephyr.c"),
        &[
            &format!("-DCONFIG_BHF_AGENT_INPUT_SIZE={INPUT_CAP}"),
            "-DCONFIG_BHF_AGENT_EDGE_CAP=1024",
            "-DCONFIG_BHF_AGENT_STACK_SIZE=65536",
            "-DCONFIG_BHF_AGENT_PRIORITY=5",
        ],
        "bhf_agent_zephyr.o",
    );
    compile(host.join("zephyr_host.c"), &[], "zephyr_host.o");
    compile(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/agent/target.c"),
        &["-fsanitize-coverage=trace-pc-guard", "-O0"],
        "target.o",
    );
    let agent = dir.join("zephyr_agent");
    let status = Command::new("clang")
        .args([
            "zephyr_host.o",
            "bhf_agent_zephyr.o",
            "bhf_agent.o",
            "target.o",
        ])
        .args(["-pthread", "-o"])
        .arg(&agent)
        .current_dir(dir)
        .status()
        .unwrap();
    assert!(status.success(), "link the Zephyr host agent");
    Some(agent)
}

/// #291: the Zephyr glue serves the agent protocol; a fault ends the agent
/// thread, the thread that started it reports the fault for the input, and
/// a new agent thread serves the next input.
#[test]
fn the_zephyr_glue_reports_a_fault_and_serves_on_in_a_new_thread() {
    let dir = tempfile::tempdir().unwrap();
    let Some(binary) = build_zephyr_host_agent(dir.path()) else {
        eprintln!("skipping: clang not on PATH");
        return;
    };
    let agent = start(&binary);
    let port = agent.port;
    let transport =
        AgentTransport::new(move || TcpStream::connect(("127.0.0.1", port)).map_err(Into::into));
    let mut session = transport.arm().unwrap();
    let clean = |input: &[u8], session: &mut Box<dyn target_transport::TargetSession>| {
        let outcome = session.run_input(input).unwrap();
        assert_eq!(outcome.exit, ExitKind::Ok, "{input:?}: {outcome:?}");
        assert!(outcome.fault.is_none() && outcome.inconclusive.is_none());
        let mut edges = outcome.coverage_edges;
        edges.sort_unstable();
        edges
    };
    let b = clean(b"B", &mut session);
    let bu = clean(b"BU", &mut session);
    assert!(
        bu.iter().any(|edge| !b.contains(edge)),
        "BU reaches new code: {b:?} {bu:?}"
    );

    for _ in 0..3 {
        let fault = session.run_input(b"BUG").unwrap();
        assert_eq!(fault.exit, ExitKind::Crash, "{fault:?}");
        let detail = fault.fault.clone().expect("a fault");
        assert_eq!(detail.kind, FaultKind::CpuException);
        assert_eq!(detail.detail, "Zephyr fatal error");
        assert!(
            fault
                .coverage_edges
                .iter()
                .any(|edge| !b.contains(edge) && !bu.contains(edge)),
            "the faulting input's edges are reported: {fault:?}"
        );
        assert_eq!(
            clean(b"BU", &mut session),
            bu,
            "a new agent thread serves on"
        );
    }

    let refused = session.run_input(&[b'B'; INPUT_CAP + 1]).unwrap();
    assert!(
        refused
            .inconclusive
            .as_deref()
            .is_some_and(|reason| reason.contains("refused")),
        "{refused:?}"
    );
    drop(session);
    let mut again = transport.arm().unwrap();
    assert_eq!(clean(b"B", &mut again), b);
}
