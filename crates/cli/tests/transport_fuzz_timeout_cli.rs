// SPDX-License-Identifier: Apache-2.0

//! CLI-level regression for the transport lane's bounded run control (#70),
//! exercised through the shipped `bhf fuzz --target-transport agent:tcp:...`
//! dispatch (not a library factory with its own timeouts). A peer that accepts
//! the connection but never answers must be terminated by the per-input
//! `--timeout` bound and reported as a distinct, non-clean outcome — it must not
//! run to the much larger `--time` budget, and must not report a clean run.

#![cfg(unix)]

use std::io::Read;
use std::net::TcpListener;
use std::process::Command;
use std::time::{Duration, Instant};

#[test]
fn cli_agent_tcp_bounds_a_nonresponsive_peer() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let port = listener.local_addr().unwrap().port();

    // Accept one connection and hold it open: drain whatever bhf sends but never
    // write a reply, so bhf's bounded read (not a missing connection) is what
    // fires. The thread ends when bhf drops the socket after its timeout.
    let accepter = std::thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let _ = sock.set_read_timeout(Some(Duration::from_secs(20)));
            let mut buf = [0u8; 64];
            loop {
                match sock.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => continue,
                }
            }
        }
    });

    let tmp = tempfile::tempdir().unwrap();
    let work = tmp.path().join("work");

    let started = Instant::now();
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args([
            "fuzz",
            "--target-transport",
            &format!("agent:tcp:127.0.0.1:{port}"),
        ])
        .args(["--harness", "nonresponsive"])
        // 1s per-input/connect bound, with a 30s campaign budget it must NOT reach.
        .args(["--timeout", "1s", "--time", "30s", "--iterations", "4"])
        .arg(&work)
        .output()
        .expect("run bhf fuzz");
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(15),
        "a non-responsive peer must be bounded by --timeout (1s), not run to the \
         30s --time budget; took {elapsed:?}"
    );
    assert!(
        !out.status.success(),
        "a non-responsive peer is a non-clean outcome, not a clean exit (code {:?})\n\
         stdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let _ = accepter.join();
}
