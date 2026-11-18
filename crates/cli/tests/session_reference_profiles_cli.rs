// SPDX-License-Identifier: Apache-2.0

//! The reference protocol profiles shipped under `profiles/protocols/`, each
//! driven by `bhf fuzz --protocol-profile` against a fixture server in this
//! test.
//!
//! A session's state advances only when the reply to a message arrives and
//! the profile's captures are read from it, and each profile captures the
//! reply's type (a function code, a packet type) as an enum that names only
//! the reply that answers the request. The states a run's summary counts are
//! therefore states the server took the session to. Each fixture also counts
//! what only a session that carried a captured value back could have done, so
//! a test proves the profile's back-references reached the server too.
//!
//! The fixtures follow their protocol: they answer an error with the
//! protocol's error reply where it has one and close the connection where the
//! protocol says to, which the campaign may record as dropped sessions. These
//! tests look at the states, not at those.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn reference_profile(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../profiles/protocols")
        .join(name)
}

/// Run a session campaign with `profile` against `transport` and return its
/// summary.
fn campaign(work: &Path, profile: &Path, transport: &str) -> serde_json::Value {
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("fuzz")
        .arg(work)
        .args(["--harness", "H-reference-profile", "--protocol-profile"])
        .arg(profile)
        .args(["--session-transport", transport])
        .args(["--session-reply-timeout", "1s", "--iterations", "300"])
        .output()
        .expect("run bhf fuzz");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("summary ({e}):\n{stderr}"))
}

fn listen() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a fixture server");
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

// ---------------------------------------------------------------------------
// Modbus/TCP
// ---------------------------------------------------------------------------

const MODBUS_REGISTERS: usize = 64;

#[derive(Default)]
struct ModbusCounts {
    /// Write Single Register requests that wrote back the value the same
    /// connection had read from that register.
    write_backs: AtomicUsize,
    /// Write Multiple Registers requests served.
    block_writes: AtomicUsize,
}

/// A Modbus/TCP server with 64 holding registers whose values no profile
/// seed names. It serves Read Holding Registers (0x03), Write Single Register
/// (0x06) and Write Multiple Registers (0x10), answers anything else with an
/// exception response, and closes a connection whose MBAP header is not
/// Modbus's.
fn start_modbus_server(counts: Arc<ModbusCounts>) -> u16 {
    let (listener, port) = listen();
    let registers: [u16; MODBUS_REGISTERS] =
        std::array::from_fn(|i| 0xBE00 ^ (i as u16).wrapping_mul(0x0101));
    let registers = Arc::new(Mutex::new(registers));
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (registers, counts) = (registers.clone(), counts.clone());
            thread::spawn(move || serve_modbus(stream, &registers, &counts));
        }
    });
    port
}

fn serve_modbus(
    mut stream: TcpStream,
    registers: &Mutex<[u16; MODBUS_REGISTERS]>,
    counts: &ModbusCounts,
) {
    stream.set_nodelay(true).ok();
    // What this connection has read: register address -> value.
    let mut read: HashMap<u16, u16> = HashMap::new();
    loop {
        // MBAP: transaction id, protocol id, length, unit id.
        let mut mbap = [0u8; 7];
        if stream.read_exact(&mut mbap).is_err() {
            return;
        }
        let protocol = u16::from_be_bytes([mbap[2], mbap[3]]);
        let length = usize::from(u16::from_be_bytes([mbap[4], mbap[5]]));
        // The length counts the unit id and a PDU of 1..=253 bytes.
        if protocol != 0 || !(2..=254).contains(&length) {
            return;
        }
        let mut pdu = vec![0u8; length - 1];
        if stream.read_exact(&mut pdu).is_err() {
            return;
        }
        let reply = modbus_pdu(&pdu, registers, &mut read, counts);
        let mut frame = mbap[..4].to_vec();
        frame.extend_from_slice(&(reply.len() as u16 + 1).to_be_bytes());
        frame.push(mbap[6]);
        frame.extend_from_slice(&reply);
        if stream.write_all(&frame).is_err() {
            return;
        }
    }
}

/// The response PDU to `pdu`.
fn modbus_pdu(
    pdu: &[u8],
    registers: &Mutex<[u16; MODBUS_REGISTERS]>,
    read: &mut HashMap<u16, u16>,
    counts: &ModbusCounts,
) -> Vec<u8> {
    let function = pdu[0];
    let exception = |code: u8| vec![function | 0x80, code];
    let word = |at: usize| {
        pdu.get(at..at + 2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
    };
    let mut registers = registers.lock().unwrap();
    match function {
        0x03 => {
            let (Some(address), Some(quantity), 5) = (word(1), word(3), pdu.len()) else {
                return exception(3);
            };
            if !(1..=125).contains(&quantity) {
                return exception(3);
            }
            let start = usize::from(address);
            let end = start + usize::from(quantity);
            if end > MODBUS_REGISTERS {
                return exception(2);
            }
            let mut reply = vec![0x03, (2 * quantity) as u8];
            for (at, value) in (start..end).zip(&registers[start..end]) {
                reply.extend_from_slice(&value.to_be_bytes());
                read.insert(at as u16, *value);
            }
            reply
        }
        0x06 => {
            let (Some(address), Some(value), 5) = (word(1), word(3), pdu.len()) else {
                return exception(3);
            };
            if usize::from(address) >= MODBUS_REGISTERS {
                return exception(2);
            }
            if read.get(&address) == Some(&value) {
                counts.write_backs.fetch_add(1, Ordering::SeqCst);
            }
            registers[usize::from(address)] = value;
            pdu.to_vec()
        }
        0x10 => {
            let (Some(address), Some(quantity)) = (word(1), word(3)) else {
                return exception(3);
            };
            let quantity = usize::from(quantity);
            let count = pdu.get(5).map(|count| usize::from(*count));
            if !(1..=123).contains(&quantity)
                || count != Some(2 * quantity)
                || pdu.len() != 6 + 2 * quantity
            {
                return exception(3);
            }
            let start = usize::from(address);
            if start + quantity > MODBUS_REGISTERS {
                return exception(2);
            }
            for (i, value) in pdu[6..].chunks(2).enumerate() {
                registers[start + i] = u16::from_be_bytes([value[0], value[1]]);
            }
            counts.block_writes.fetch_add(1, Ordering::SeqCst);
            pdu[..5].to_vec()
        }
        // Illegal function.
        _ => exception(1),
    }
}

/// #311: the Modbus/TCP profile reads a holding register, writes the value it
/// read back to it, and writes a block of registers, each state reached only
/// on the function's normal response.
#[test]
fn the_modbus_tcp_profile_reaches_every_state_against_a_modbus_server() {
    let counts = Arc::new(ModbusCounts::default());
    let port = start_modbus_server(counts.clone());
    let work = TestDir::new("modbus-profile");
    let summary = campaign(
        work.path(),
        &reference_profile("modbus-tcp.toml"),
        &format!("tcp:127.0.0.1:{port}"),
    );
    assert_eq!(
        summary["framing"], "length_field(u16 big at 4)",
        "{summary:#}"
    );
    // start, read and written.
    assert_eq!(summary["states_covered"], 3, "{summary:#}");
    assert!(
        summary["transitions_covered"].as_u64().unwrap() >= 3,
        "{summary:#}"
    );
    assert!(
        counts.write_backs.load(Ordering::SeqCst) >= 1,
        "a write carried back the register value its session read"
    );
    assert!(counts.block_writes.load(Ordering::SeqCst) >= 1);
}

// ---------------------------------------------------------------------------
// MQTT 3.1.1
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MqttCounts {
    /// Topic filters subscribed to.
    subscriptions: AtomicUsize,
    /// QoS 2 publications released: a PUBREL naming the packet id of a
    /// PUBLISH the server had answered with PUBREC.
    released: AtomicUsize,
}

/// What an MQTT server does with a packet.
enum Answer {
    Send(Vec<u8>),
    /// Send, then close the connection (a refused CONNECT).
    Last(Vec<u8>),
    /// Nothing to send (a QoS 0 PUBLISH).
    Quiet,
    /// Close the connection, as MQTT-4.8.0-1 has a server do on a protocol
    /// violation.
    Close,
}

/// A packet: the fixed header's first byte and the Remaining Length.
fn mqtt_packet(header: u8, body: &[u8]) -> Vec<u8> {
    let mut packet = vec![header];
    let mut remaining = body.len();
    loop {
        let byte = (remaining % 128) as u8;
        remaining /= 128;
        if remaining == 0 {
            packet.push(byte);
            break;
        }
        packet.push(byte | 0x80);
    }
    packet.extend_from_slice(body);
    packet
}

fn read_mqtt_packet(stream: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
    let mut byte = [0u8; 1];
    stream.read_exact(&mut byte).ok()?;
    let header = byte[0];
    let mut remaining = 0usize;
    for i in 0..4 {
        stream.read_exact(&mut byte).ok()?;
        remaining |= usize::from(byte[0] & 0x7f) << (7 * i);
        if byte[0] & 0x80 == 0 {
            let mut body = vec![0u8; remaining];
            stream.read_exact(&mut body).ok()?;
            return Some((header, body));
        }
    }
    // A Remaining Length of more than four bytes is malformed.
    None
}

/// A UTF-8 string: a big-endian u16 length and that many bytes.
fn mqtt_string(body: &[u8], at: &mut usize) -> Option<String> {
    let len = usize::from(u16::from_be_bytes([*body.get(*at)?, *body.get(*at + 1)?]));
    let bytes = body.get(*at + 2..*at + 2 + len)?;
    *at += 2 + len;
    String::from_utf8(bytes.to_vec()).ok()
}

fn mqtt_connect(body: &[u8]) -> Answer {
    let mut at = 0;
    let (Some(name), Some(&level), Some(&flags)) =
        (mqtt_string(body, &mut at), body.get(at), body.get(at + 1))
    else {
        return Answer::Close;
    };
    at += 4; // the level, the flags and the keep alive
             // MQTT-3.1.2-3: the reserved flag is zero.
    if name != "MQTT" || flags & 0x01 != 0 || body.len() < at {
        return Answer::Close;
    }
    if level != 4 {
        // Unacceptable protocol level, then the server disconnects.
        return Answer::Last(vec![0x20, 0x02, 0x00, 0x01]);
    }
    let Some(client_id) = mqtt_string(body, &mut at) else {
        return Answer::Close;
    };
    let mut strings = 0;
    if flags & 0x04 != 0 {
        strings += 2; // will topic and will message
    }
    if flags & 0x80 != 0 {
        strings += 1; // user name
    }
    if flags & 0x40 != 0 {
        if flags & 0x80 == 0 {
            return Answer::Close; // MQTT-3.1.2-22
        }
        strings += 1; // password
    }
    for _ in 0..strings {
        if mqtt_string(body, &mut at).is_none() {
            return Answer::Close;
        }
    }
    if at != body.len() {
        return Answer::Close;
    }
    if client_id.is_empty() && flags & 0x02 == 0 {
        // Identifier rejected (MQTT-3.1.3-8).
        return Answer::Last(vec![0x20, 0x02, 0x00, 0x02]);
    }
    Answer::Send(vec![0x20, 0x02, 0x00, 0x00])
}

/// The server's answer to a packet on a connection that has sent CONNECT.
fn mqtt_session_answer(
    header: u8,
    body: &[u8],
    pending: &mut HashSet<u16>,
    counts: &MqttCounts,
) -> Answer {
    let packet_id = |at: usize| {
        body.get(at..at + 2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .filter(|id| *id != 0)
    };
    match header >> 4 {
        // SUBSCRIBE: its fixed-header flags are 0b0010 (MQTT-3.8.1-1).
        8 if header & 0x0f == 0x02 => {
            let Some(id) = packet_id(0) else {
                return Answer::Close;
            };
            let mut at = 2;
            let mut granted = id.to_be_bytes().to_vec();
            while at < body.len() {
                let (Some(filter), Some(&qos)) = (mqtt_string(body, &mut at), body.get(at)) else {
                    return Answer::Close;
                };
                at += 1;
                if filter.is_empty() || qos > 2 {
                    return Answer::Close;
                }
                granted.push(qos);
                counts.subscriptions.fetch_add(1, Ordering::SeqCst);
            }
            // At least one topic filter (MQTT-3.8.3-3).
            if granted.len() == 2 {
                return Answer::Close;
            }
            Answer::Send(mqtt_packet(0x90, &granted))
        }
        // PUBLISH
        3 => {
            let qos = (header >> 1) & 0x03;
            let mut at = 0;
            let Some(topic) = mqtt_string(body, &mut at) else {
                return Answer::Close;
            };
            // MQTT-3.3.1-4, -2 and 3.3.2-2: no QoS 3, no DUP at QoS 0, no
            // wildcard in a topic name.
            if qos == 3 || (qos == 0 && header & 0x08 != 0) || topic.is_empty() {
                return Answer::Close;
            }
            if topic.contains(['+', '#']) {
                return Answer::Close;
            }
            if qos == 0 {
                return Answer::Quiet;
            }
            let Some(id) = packet_id(at) else {
                return Answer::Close;
            };
            if qos == 1 {
                return Answer::Send(mqtt_packet(0x40, &id.to_be_bytes()));
            }
            pending.insert(id);
            Answer::Send(mqtt_packet(0x50, &id.to_be_bytes()))
        }
        // PUBREL: its flags are 0b0010 (MQTT-3.6.1-1).
        6 if header == 0x62 && body.len() == 2 => {
            let Some(id) = packet_id(0) else {
                return Answer::Close;
            };
            if pending.remove(&id) {
                counts.released.fetch_add(1, Ordering::SeqCst);
            }
            Answer::Send(mqtt_packet(0x70, &id.to_be_bytes()))
        }
        // PINGREQ
        12 if header == 0xc0 && body.is_empty() => Answer::Send(vec![0xd0, 0x00]),
        // DISCONNECT, a second CONNECT (MQTT-3.1.0-2), and anything else.
        _ => Answer::Close,
    }
}

/// An MQTT 3.1.1 server that acknowledges what a broker acknowledges and
/// routes nothing: CONNECT, SUBSCRIBE, PUBLISH at each QoS, PUBREL and
/// PINGREQ.
fn start_mqtt_server(counts: Arc<MqttCounts>) -> u16 {
    let (listener, port) = listen();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let counts = counts.clone();
            thread::spawn(move || serve_mqtt(stream, &counts));
        }
    });
    port
}

fn serve_mqtt(mut stream: TcpStream, counts: &MqttCounts) {
    stream.set_nodelay(true).ok();
    let mut connected = false;
    // The QoS 2 packet ids answered with PUBREC and not yet released.
    let mut pending: HashSet<u16> = HashSet::new();
    while let Some((header, body)) = read_mqtt_packet(&mut stream) {
        // The first packet is a CONNECT (MQTT-3.1.0-1).
        let answer = match (connected, header) {
            (false, 0x10) => mqtt_connect(&body),
            (false, _) => Answer::Close,
            (true, _) => mqtt_session_answer(header, &body, &mut pending, counts),
        };
        match answer {
            Answer::Send(reply) => {
                connected = true;
                if stream.write_all(&reply).is_err() {
                    return;
                }
            }
            Answer::Last(reply) => {
                let _ = stream.write_all(&reply);
                return;
            }
            Answer::Quiet => {}
            Answer::Close => return,
        }
    }
}

/// #311: the MQTT 3.1.1 profile connects, subscribes, publishes at QoS 2 and
/// releases the publication with the packet id the server's PUBREC named,
/// then pings, each state reached only on the packet that answers it.
#[test]
fn the_mqtt_profile_reaches_every_state_against_an_mqtt_server() {
    let counts = Arc::new(MqttCounts::default());
    let port = start_mqtt_server(counts.clone());
    let work = TestDir::new("mqtt-profile");
    let summary = campaign(
        work.path(),
        &reference_profile("mqtt-3.1.1.toml"),
        &format!("tcp:127.0.0.1:{port}"),
    );
    assert_eq!(
        summary["framing"], "length_field(varint at 1)",
        "{summary:#}"
    );
    // start, connected, subscribed and publish_received.
    assert_eq!(summary["states_covered"], 4, "{summary:#}");
    assert!(
        summary["transitions_covered"].as_u64().unwrap() >= 5,
        "{summary:#}"
    );
    assert!(counts.subscriptions.load(Ordering::SeqCst) >= 1);
    assert!(
        counts.released.load(Ordering::SeqCst) >= 1,
        "a PUBREL released the QoS 2 publication its session's PUBREC named"
    );
}
