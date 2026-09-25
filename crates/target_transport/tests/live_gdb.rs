// SPDX-License-Identifier: Apache-2.0

//! RV-2 — live gdb-remote validation against a REAL QEMU gdbstub.
//!
//! This drives the real [`target_transport::GdbClient`] /
//! [`target_transport::GdbRemoteTransport`] (the RSP client, NOT the in-crate
//! mock) against a real `qemu-arm` user-mode gdbstub. A tiny statically-linked
//! ARM Linux guest is cross-compiled at test time; it exports a fixed 16-byte
//! `known_region`. The test attaches over RSP, reads that region out of the live
//! target, asserts the bytes match, and exercises continue-to-exit and the reset
//! packet — proving the RSP client works end-to-end against a genuine stub.
//!
//! It self-skips (loudly) ONLY when `qemu-arm` or the ARM cross gcc is absent.
//! Under `scripts/hil-emu.sh` (`BHF_HIL_REQUIRE=1`) a missing tool is a hard
//! failure, so the live path cannot be silently skipped in CI.

mod common;

use common::{connect_tcp_retry, gate, ChildGuard, TempDir};
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;
use target_transport::{
    ExitKind, GdbClient, GdbMemoryMap, GdbRemoteTransport, StopReply, TargetTransport,
    TransportError,
};

/// The fixed region we read back over RSP. Sixteen distinct-ish bytes with no run
/// of four identical bytes, so QEMU's gdbstub does not run-length-compress the
/// reply (the client expands RLE, but a clean read keeps the assertion obvious).
const KNOWN_REGION: [u8; 16] = [
    0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x10, 0x20, 0x30, 0x40, 0xCA, 0xFE, 0xBA, 0xBE,
];

const GUEST_C: &str = r#"#include <stdint.h>
/* A fixed, distinct 16-byte region the host reads back over the gdb remote
   serial protocol. No run of >=4 identical bytes, so the stub will not
   run-length-compress the m-packet reply. */
volatile const uint8_t known_region[16] = {
    0xDE,0xAD,0xBE,0xEF, 0x01,0x02,0x03,0x04,
    0x10,0x20,0x30,0x40, 0xCA,0xFE,0xBA,0xBE
};
int main(void) {
    volatile uint8_t sink = 0;
    for (int i = 0; i < 16; i++) sink ^= known_region[i];
    return (int)sink & 1;
}
"#;

const CC: &str = "arm-linux-gnueabihf-gcc";
const QEMU: &str = "qemu-arm";

/// Launch `qemu-arm -g <port> <guest>` (user-mode gdbstub, halted until the
/// debugger continues) and connect a timed-out RSP channel to it.
fn launch_and_connect(guest: &std::path::Path) -> (ChildGuard, TcpStream) {
    let port = common::free_tcp_port();
    let child = Command::new(QEMU)
        .arg("-g")
        .arg(port.to_string())
        .arg(guest)
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn {QEMU}: {e}"));
    let guard = ChildGuard::new(child, format!("{QEMU} -g {port}"));
    let stream = connect_tcp_retry(port, Duration::from_secs(10))
        .unwrap_or_else(|e| panic!("could not connect to qemu gdbstub on :{port}: {e}"));
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .expect("set read timeout");
    eprintln!("live_gdb: launched `{QEMU} -g {port} {}`", guest.display());
    (guard, stream)
}

#[test]
fn live_gdb_remote_reads_known_memory_from_real_qemu() {
    if let Err(reason) = gate(
        "live_gdb_remote_reads_known_memory_from_real_qemu",
        &[CC, QEMU],
    ) {
        eprintln!("{reason}");
        return;
    }

    let dir = TempDir::new("bhf-live-gdb").expect("temp dir");
    let src = dir.join("guest.c");
    let guest = dir.join("guest");
    std::fs::write(&src, GUEST_C).expect("write guest source");

    // Cross-compile a static, non-PIE ARM Linux binary so `known_region` sits at
    // a FIXED, discoverable address (no load-time relocation to chase).
    let built = Command::new(CC)
        .args(["-O0", "-static", "-no-pie", "-o"])
        .arg(&guest)
        .arg(&src)
        .status()
        .unwrap_or_else(|e| panic!("failed to run {CC}: {e}"));
    assert!(
        built.success(),
        "{CC} failed to build the ARM guest (tool is present, so this is a real failure)"
    );

    let known_addr = common::nm_symbol("nm", &guest, "known_region");
    eprintln!("live_gdb: known_region @ {known_addr:#x}");

    let mut checks = 0usize;

    // ---- Part 1: raw GdbClient — attach, read known memory, continue to exit. ----
    {
        let (_qemu, stream) = launch_and_connect(&guest);
        let mut client = GdbClient::new(stream);

        // Attach: `!` extended-mode + `?` stop query. QEMU answers `T05...`.
        let stop = client.attach().expect("attach to real qemu gdbstub");
        assert!(
            matches!(stop, StopReply::Signal(_)),
            "attach stop reply should be a signal stop, got {stop:?}"
        );
        checks += 1;

        // THE core assertion: the bytes read from the live target match the ones
        // baked into the guest binary.
        let read_back = client
            .read_memory(known_addr, KNOWN_REGION.len())
            .expect("read known_region from live qemu");
        assert_eq!(
            read_back, KNOWN_REGION,
            "live gdb memory read must return the planted bytes"
        );
        eprintln!("live_gdb: read_memory({known_addr:#x}, 16) = {read_back:02x?} (matches)");
        checks += 1;

        // A sub-slice read proves the address/length arithmetic, not just a lucky
        // full-region match.
        let mid = client
            .read_memory(known_addr + 4, 4)
            .expect("read known_region[4..8]");
        assert_eq!(mid, KNOWN_REGION[4..8], "sub-slice read must line up");
        checks += 1;

        // Continue to program exit; qemu-user reports a clean `W00`.
        let exit = client.cont().expect("continue live guest to exit");
        assert_eq!(
            exit,
            StopReply::Exited(0),
            "the guest returns 0 -> W00 exited-clean"
        );
        assert_eq!(exit.to_exit_kind(), ExitKind::Ok);
        eprintln!("live_gdb: continue -> {exit:?} (clean exit)");
        checks += 1;
    }

    // ---- Part 2: exercise the reset packet against the real stub. ----
    // qemu-user acks the `R` restart packet (RSP defines no reply for it); the
    // client only needs the framing ack, so reset() succeeds against real qemu.
    {
        let (_qemu, stream) = launch_and_connect(&guest);
        let mut client = GdbClient::new(stream);
        client.attach().expect("attach for reset");
        client
            .reset()
            .expect("reset packet round-trips against real qemu");
        eprintln!("live_gdb: reset() (R00) acked by real qemu");
        checks += 1;
    }

    // ---- Part 3: drive the GdbRemoteTransport seam's attach against real qemu. ----
    {
        let (_qemu, stream) = launch_and_connect(&guest);
        let slot = std::sync::Mutex::new(Some(stream));
        let map = GdbMemoryMap {
            input_address: known_addr, // unused by arm(); a real address regardless
            ring_address: known_addr,
            ring_write_address: known_addr,
            ring_wrapped_address: known_addr,
            ring_capacity: 16,
        };
        let transport = GdbRemoteTransport::new(
            move || {
                slot.lock()
                    .unwrap()
                    .take()
                    .ok_or_else(|| TransportError::Io(std::io::ErrorKind::NotConnected.into()))
            },
            map,
        );
        // arm() connects + attaches over the real stub and hands back a session.
        let _session = transport
            .arm()
            .expect("GdbRemoteTransport::arm attaches to real qemu");
        eprintln!("live_gdb: GdbRemoteTransport::arm() attached over the real stub");
        checks += 1;
    }

    // Guard against a silent no-op: if the tools are present we MUST have run the
    // real assertions above.
    assert!(
        checks >= 6,
        "live_gdb ran but performed only {checks} live checks — it must not no-op"
    );
    eprintln!("live_gdb: PASSED — {checks} live checks against real qemu-arm");
}
