// SPDX-License-Identifier: Apache-2.0
//! The desocket mode (#312).
//!
//! With `BHF_DESOCKET=1` a TCP server's listening socket is faked: `bind` and
//! `listen` succeed without touching the network, the listener reads as
//! ready to `poll`, and the first `accept` returns a pseudo-connection whose
//! reads deliver the fuzz input (the one the harness published, else stdin)
//! and then end of file. A later `accept` ends the process with status 0 once
//! the server has closed that connection, so a server's main loop handles
//! exactly one connection per run, whether it handles it in line, in a
//! thread of its own, or from an event loop that drains its accept queue.

#![cfg(target_os = "linux")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn target_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("CARGO_TARGET_DIR") {
        return PathBuf::from(dir);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root above crates/bhf_runtrace_shim")
        .join("target")
}

fn shim_so() -> Option<PathBuf> {
    let shim = ["debug", "release"]
        .into_iter()
        .map(|profile| target_dir().join(profile).join("libbhf_runtrace_shim.so"))
        .find(|p| p.is_file());
    assert!(
        shim.is_some() || std::env::var_os("BHF_REQUIRE_TOOLS").is_none_or(|v| v != "1"),
        "BHF_REQUIRE_TOOLS=1 and the shim cdylib is not built (cargo build --workspace)"
    );
    shim
}

fn cc() -> Option<&'static str> {
    ["cc", "gcc", "clang"].into_iter().find(|c| {
        Command::new(c)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
}

/// A blocking accept loop: binds a port, prints what each connection sent,
/// the peer's address, and a reply's result, then accepts again. `PUBLISH`
/// makes it publish its input to the shim the way a harness does.
const BLOCKING_SERVER: &str = r#"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
extern void bhf_shim_set_fuzz_input(const uint8_t *data, size_t size) __attribute__((weak));
int main(void) {
#ifdef PUBLISH
    static const uint8_t input[] = "R:published";
    if (bhf_shim_set_fuzz_input) bhf_shim_set_fuzz_input(input, sizeof input - 1);
#endif
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(5);  /* a real accept would wait for a client forever */
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0) return 10;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1);  /* a privileged port: a real bind fails */
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)&addr, sizeof addr) != 0) { printf("bind failed\n"); return 11; }
    if (listen(s, 4) != 0) return 12;
    for (int round = 0; round < 3; round++) {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof peer;
        int c = accept(s, (struct sockaddr *)&peer, &peer_len);
        if (c < 0) { printf("accept failed\n"); return 13; }
        if (setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one) != 0) return 14;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof ip);
        char buf[256];
        size_t total = 0;
        ssize_t n;
        while ((n = recv(c, buf + total, sizeof buf - 1 - total, 0)) > 0) total += (size_t)n;
        buf[total] = 0;
        ssize_t sent = send(c, "OK\n", 3, 0);
        printf("round %d peer %s len %zu data [%s] sent %zd\n", round, ip, total, buf, sent);
        close(c);
    }
    printf("served three\n");
    return 0;
}
"#;

/// A `poll`-driven server: it waits for the listener to be readable before
/// it accepts, as event-loop servers do.
const POLL_SERVER: &str = r#"
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(5);
    int s = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof addr);
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(8443);
    if (bind(s, (struct sockaddr *)&addr, sizeof addr) != 0) return 11;
    if (listen(s, 4) != 0) return 12;
    struct sockaddr_in6 bound;
    socklen_t bound_len = sizeof bound;
    if (getsockname(s, (struct sockaddr *)&bound, &bound_len) != 0) return 15;
    printf("listening on %d\n", ntohs(bound.sin6_port));
    for (;;) {
        struct pollfd fds = { .fd = s, .events = POLLIN };
        if (poll(&fds, 1, 2000) != 1) { printf("listener never ready\n"); return 16; }
        int c = accept(s, NULL, NULL);
        char buf[64];
        ssize_t n = read(c, buf, sizeof buf - 1);
        buf[n > 0 ? n : 0] = 0;
        printf("read [%s]\n", buf);
        close(c);
    }
}
"#;

/// A thread-per-connection server: the accept loop hands each connection to
/// a new thread and accepts again at once; the handler reads the request to
/// end of file, prints it after a pause (so the main thread is back in
/// `accept` first) and closes the connection.
const THREAD_SERVER: &str = r#"
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
static void *handle(void *arg) {
    int c = (int)(intptr_t)arg;
    char buf[256];
    size_t total = 0;
    ssize_t n;
    usleep(200000);
    while ((n = recv(c, buf + total, sizeof buf - 1 - total, 0)) > 0) total += (size_t)n;
    buf[total] = 0;
    printf("handled [%s]\n", buf);
    send(c, "OK\n", 3, 0);
    close(c);
    return NULL;
}
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(5);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    if (bind(s, (struct sockaddr *)&addr, sizeof addr) != 0) return 11;
    if (listen(s, 16) != 0) return 12;
    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) { printf("accept failed\n"); return 13; }
        pthread_t thread;
        pthread_create(&thread, NULL, handle, (void *)(intptr_t)c);
        pthread_detach(thread);
    }
}
"#;

/// An edge-triggered epoll server with a non-blocking listener: each time
/// the listener is reported it accepts until EAGAIN (as libevent's listener
/// and most event loops do), and it reads each connection when epoll
/// reports it, closing it at end of file.
const EPOLL_SERVER: &str = r#"
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(5);
    int s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8081);
    if (bind(s, (struct sockaddr *)&addr, sizeof addr) != 0) return 11;
    if (listen(s, 16) != 0) return 12;
    int ep = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN | EPOLLET, .data.fd = s };
    epoll_ctl(ep, EPOLL_CTL_ADD, s, &ev);
    char request[256];
    size_t total = 0;
    for (;;) {
        struct epoll_event ready[8];
        int n = epoll_wait(ep, ready, 8, 2000);
        if (n <= 0) { printf("stalled\n"); return 14; }
        for (int i = 0; i < n; i++) {
            if (ready[i].data.fd == s) {
                for (;;) {
                    int c = accept4(s, NULL, NULL, SOCK_NONBLOCK);
                    if (c < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        printf("accept failed %d\n", errno);
                        return 13;
                    }
                    printf("accepted\n");
                    struct epoll_event cev = { .events = EPOLLIN | EPOLLET, .data.fd = c };
                    epoll_ctl(ep, EPOLL_CTL_ADD, c, &cev);
                }
                continue;
            }
            int c = ready[i].data.fd;
            for (;;) {
                ssize_t got = read(c, request + total, sizeof request - 1 - total);
                if (got > 0) { total += (size_t)got; continue; }
                if (got == 0) {
                    request[total] = 0;
                    printf("read [%s]\n", request);
                    close(c);
                }
                break;
            }
        }
    }
}
"#;

fn build(dir: &Path, name: &str, source: &str, defines: &[&str]) -> Option<PathBuf> {
    let cc = cc()?;
    let src = dir.join(format!("{name}.c"));
    let bin = dir.join(name);
    std::fs::write(&src, source).unwrap();
    let built = Command::new(cc)
        .args(defines)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .arg("-pthread")
        .status()
        .is_ok_and(|s| s.success());
    assert!(built, "{name} must compile");
    Some(bin)
}

fn run(bin: &Path, shim: &Path, desocket: bool, stdin: &[u8]) -> Output {
    let mut cmd = Command::new(bin);
    cmd.env("LD_PRELOAD", shim)
        .env_remove("BHF_DESOCKET")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if desocket {
        cmd.env("BHF_DESOCKET", "1");
    }
    let mut child = cmd.spawn().expect("spawn server");
    // A server that exits before reading stdin (a failed real bind) closes
    // the pipe first: that is its outcome, not the test's error.
    let _ = child.stdin.take().unwrap().write_all(stdin);
    child.wait_with_output().expect("wait for server")
}

#[test]
fn the_first_accept_serves_stdin_and_the_next_ends_the_run() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let dir = tempfile::Builder::new()
        .prefix("bhf-desock-")
        .tempdir()
        .unwrap();
    let Some(bin) = build(dir.path(), "blocking", BLOCKING_SERVER, &[]) else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let out = run(&bin, &shim, true, b"R:hello");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{:?} {stdout}", out.status);
    assert_eq!(
        stdout, "round 0 peer 127.0.0.1 len 7 data [R:hello] sent 3\n",
        "one connection with the input, then the run ends"
    );

    // Without the gate the network is real: an unprivileged bind to port 1
    // fails, and a privileged one waits in a real accept until the alarm.
    let real = run(&bin, &shim, false, b"R:hello");
    let real_stdout = String::from_utf8_lossy(&real.stdout);
    assert!(
        !real.status.success() && !real_stdout.contains("round 0"),
        "{:?} {real_stdout}",
        real.status
    );
}

#[test]
fn a_published_input_takes_the_place_of_stdin() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let dir = tempfile::Builder::new()
        .prefix("bhf-desock-")
        .tempdir()
        .unwrap();
    let Some(bin) = build(dir.path(), "published", BLOCKING_SERVER, &["-DPUBLISH"]) else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let out = run(&bin, &shim, true, b"ignored");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{:?} {stdout}", out.status);
    assert!(stdout.contains("len 11 data [R:published]"), "{stdout}");
}

#[test]
fn a_poll_driven_server_sees_its_listener_ready() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let dir = tempfile::Builder::new()
        .prefix("bhf-desock-")
        .tempdir()
        .unwrap();
    let Some(bin) = build(dir.path(), "poll", POLL_SERVER, &[]) else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let out = run(&bin, &shim, true, b"GET / HTTP/1.0\r\n\r\n");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{:?} {stdout}", out.status);
    assert_eq!(
        stdout, "listening on 8443\nread [GET / HTTP/1.0\r\n\r\n]\n",
        "the bound port is reported, the input is read once, the run ends"
    );
}

/// #312: a thread-per-connection server is back in `accept` before its
/// handler has read the request. The run ends only once the handler has
/// closed the connection, so the request is handled.
#[test]
fn a_thread_per_connection_server_handles_its_connection() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let dir = tempfile::Builder::new()
        .prefix("bhf-desock-")
        .tempdir()
        .unwrap();
    let Some(bin) = build(dir.path(), "threads", THREAD_SERVER, &[]) else {
        eprintln!("skipping: no C compiler");
        return;
    };
    for _ in 0..5 {
        let out = run(&bin, &shim, true, b"R:payload");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{:?} {stdout}", out.status);
        assert_eq!(stdout, "handled [R:payload]\n");
    }
}

/// #312: an event loop drains its non-blocking listener until EAGAIN before
/// it reads the connections it accepted. The later `accept` reports EAGAIN
/// while the connection is open; once the server has read and closed it, the
/// listener is reported again (it is edge-triggered here) and its `accept`
/// ends the run.
#[test]
fn an_event_loop_that_accepts_until_eagain_reads_its_connection() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let dir = tempfile::Builder::new()
        .prefix("bhf-desock-")
        .tempdir()
        .unwrap();
    let Some(bin) = build(dir.path(), "epoll", EPOLL_SERVER, &[]) else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let out = run(&bin, &shim, true, b"GET /x HTTP/1.0\r\n\r\n");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{:?} {stdout}", out.status);
    assert_eq!(stdout, "accepted\nread [GET /x HTTP/1.0\r\n\r\n]\n");
}
