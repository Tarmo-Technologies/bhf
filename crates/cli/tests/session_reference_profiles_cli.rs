// SPDX-License-Identifier: Apache-2.0

//! The reference protocol profiles shipped under `profiles/protocols/`, each
//! driven by `bhf fuzz --protocol-profile` against a fixture server in this
//! test.
//!
//! A session's state advances only when the reply to a message arrives and
//! the profile's captures are read from it, and each profile captures the
//! reply's type (a function code, a packet type, a response code, a
//! submessage id) as an enum that names only the reply that answers the
//! request. The states a run's summary counts are
//! therefore states the server took the session to. Each fixture also counts
//! what only a session that carried a captured value back could have done, so
//! a test proves the profile's back-references reached the server too.
//!
//! The fixtures follow their protocol: they answer an error with the
//! protocol's error reply where it has one and close the connection where the
//! protocol says to, which the campaign may record as dropped sessions. These
//! tests look at the states, not at those. The UDP fixtures answer every
//! datagram, where a server would ignore some, so a request the campaign
//! garbles costs it no reply deadline.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
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

/// A value that differs from run to run, so no profile seed can name it.
fn run_unique() -> u32 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.subsec_nanos());
    (nanos ^ std::process::id().rotate_left(16)) | 1
}

fn bind_udp() -> (UdpSocket, u16) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind a fixture server");
    let port = socket.local_addr().unwrap().port();
    (socket, port)
}

// ---------------------------------------------------------------------------
// CoAP (RFC 7252)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct CoapCounts {
    /// GETs of /.well-known/core.
    discoveries: AtomicUsize,
    /// PUTs of /limit whose If-Match carried the resource's current ETag.
    conditional_updates: AtomicUsize,
}

/// The /limit resource: a number and the ETag of its current value.
struct CoapLimit {
    value: u16,
    etag: u32,
}

/// A CoAP option's delta or length: a nibble, or 13 and 14 for one or two
/// more bytes (RFC 7252 §3.1); 15 is reserved.
fn coap_extended(nibble: u8, bytes: &[u8], at: &mut usize) -> Option<usize> {
    match nibble {
        0..=12 => Some(usize::from(nibble)),
        13 => {
            let value = usize::from(*bytes.get(*at)?) + 13;
            *at += 1;
            Some(value)
        }
        14 => {
            let value = usize::from(u16::from_be_bytes([*bytes.get(*at)?, *bytes.get(*at + 1)?]));
            *at += 2;
            Some(value + 269)
        }
        _ => None,
    }
}

/// A message's options (number, value) and payload, after its token.
type CoapContent = (Vec<(usize, Vec<u8>)>, Vec<u8>);

/// The options and the payload after a token, or `None` for a message
/// format error.
fn coap_options(bytes: &[u8]) -> Option<CoapContent> {
    let mut options = Vec::new();
    let (mut number, mut at) = (0usize, 0usize);
    while let Some(&byte) = bytes.get(at) {
        at += 1;
        if byte == 0xff {
            // A payload marker before an empty payload is a format error.
            let payload = bytes[at..].to_vec();
            return (!payload.is_empty()).then_some((options, payload));
        }
        number += coap_extended(byte >> 4, bytes, &mut at)?;
        let len = coap_extended(byte & 0x0f, bytes, &mut at)?;
        options.push((number, bytes.get(at..at + len)?.to_vec()));
        at += len;
    }
    Some((options, Vec::new()))
}

/// A message echoing `request`'s message id and token, with `options` in
/// ascending order, each delta and length below 13.
fn coap_message(
    first: u8,
    code: u8,
    request: &[u8],
    options: &[(usize, &[u8])],
    payload: &[u8],
) -> Vec<u8> {
    let mut message = vec![first, code];
    message.extend_from_slice(&request[2..]);
    let mut last = 0;
    for (number, value) in options {
        message.push((((number - last) as u8) << 4) | value.len() as u8);
        message.extend_from_slice(value);
        last = *number;
    }
    if !payload.is_empty() {
        message.push(0xff);
        message.extend_from_slice(payload);
    }
    message
}

/// The reply to one datagram.
fn coap_reply(datagram: &[u8], limit: &mut CoapLimit, counts: &CoapCounts) -> Vec<u8> {
    let Some(mid) = datagram.get(2..4) else {
        return vec![0x70, 0x00, 0x00, 0x00];
    };
    let reset = vec![0x70, 0x00, mid[0], mid[1]];
    let (version, kind, tkl) = (
        datagram[0] >> 6,
        (datagram[0] >> 4) & 0x03,
        datagram[0] & 0x0f,
    );
    let token_end = 4 + usize::from(tkl);
    // A server ignores another version, and an ACK or a Reset it is not
    // waiting for, and resets a CON it cannot parse (§4.2); a CON with code
    // 0.00 is a ping, answered with a Reset (§4.3).
    if version != 1 || kind > 1 || tkl > 8 || datagram.len() < token_end || datagram[1] == 0 {
        return reset;
    }
    let request = &datagram[..token_end];
    let Some((options, payload)) = coap_options(&datagram[token_end..]) else {
        return reset;
    };
    // A CON is answered on its ACK, a NON with a NON.
    let first = (if kind == 0 { 0x60 } else { 0x50 }) | tkl;
    let respond = |code: u8, options: &[(usize, &[u8])], payload: &[u8]| {
        coap_message(first, code, request, options, payload)
    };
    // If-Match, Uri-Host, Uri-Port, Uri-Path, Uri-Query, Accept: another odd
    // option is critical, and unrecognized (§5.4.1).
    if options
        .iter()
        .any(|(number, _)| number % 2 == 1 && ![1, 3, 7, 11, 15, 17].contains(number))
    {
        return respond(0x82, &[], b"");
    }
    let path: Vec<&[u8]> = options
        .iter()
        .filter(|(number, _)| *number == 11)
        .map(|(_, value)| value.as_slice())
        .collect();
    let if_match = options.iter().find(|(number, _)| *number == 1);
    match (path.as_slice(), datagram[1]) {
        ([b".well-known", b"core"], 0x01) => {
            counts.discoveries.fetch_add(1, Ordering::SeqCst);
            respond(0x45, &[(12, &[40])], b"</limit>;rt=\"threshold\";ct=0")
        }
        ([b"limit"], 0x01) => respond(
            0x45,
            &[(4, &limit.etag.to_be_bytes()), (12, &[])],
            limit.value.to_string().as_bytes(),
        ),
        ([b"limit"], 0x03) => {
            if if_match.is_some_and(|(_, etag)| etag.as_slice() != limit.etag.to_be_bytes()) {
                // 4.12 Precondition Failed.
                return respond(0x8c, &[], b"");
            }
            let Some(value) = std::str::from_utf8(&payload)
                .ok()
                .and_then(|text| text.parse::<u16>().ok())
                .filter(|value| *value <= 1000)
            else {
                return respond(0x80, &[], b"");
            };
            if if_match.is_some() {
                counts.conditional_updates.fetch_add(1, Ordering::SeqCst);
            }
            limit.value = value;
            limit.etag = limit.etag.wrapping_mul(0x9e37_79b1).wrapping_add(1);
            respond(0x44, &[(4, &limit.etag.to_be_bytes())], b"")
        }
        // 4.05 Method Not Allowed, 4.04 Not Found.
        ([b".well-known", b"core"] | [b"limit"], _) => respond(0x85, &[], b""),
        _ => respond(0x84, &[], b""),
    }
}

/// A CoAP server with /.well-known/core and a /limit resource that a GET
/// reads with an ETag and a PUT updates, conditionally on If-Match.
fn start_coap_server(counts: Arc<CoapCounts>) -> u16 {
    let (socket, port) = bind_udp();
    thread::spawn(move || {
        let mut limit = CoapLimit {
            value: 75,
            etag: run_unique(),
        };
        let mut buf = [0u8; 2048];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let reply = coap_reply(&buf[..n], &mut limit, &counts);
            let _ = socket.send_to(&reply, peer);
        }
    });
    port
}

/// #372: the CoAP profile discovers the server's resources, reads /limit and
/// updates it with an If-Match carrying the ETag the read returned, over UDP.
#[test]
fn the_coap_profile_reaches_every_state_against_a_coap_server_over_udp() {
    let counts = Arc::new(CoapCounts::default());
    let port = start_coap_server(counts.clone());
    let work = TestDir::new("coap-profile");
    let summary = campaign(
        work.path(),
        &reference_profile("coap.toml"),
        &format!("udp:127.0.0.1:{port}"),
    );
    assert_eq!(
        summary["reset_fidelity"], "udp;reset=reconnect",
        "{summary:#}"
    );
    // start, discovered, read and updated.
    assert_eq!(summary["states_covered"], 4, "{summary:#}");
    assert!(
        summary["transitions_covered"].as_u64().unwrap() >= 3,
        "{summary:#}"
    );
    assert!(counts.discoveries.load(Ordering::SeqCst) >= 1);
    assert!(
        counts.conditional_updates.load(Ordering::SeqCst) >= 1,
        "a PUT's If-Match carried the ETag its session's GET returned"
    );
}

// ---------------------------------------------------------------------------
// RTPS 2.3 (the DDS interoperability wire protocol)
// ---------------------------------------------------------------------------

const SPDP_WRITER: [u8; 4] = [0x00, 0x01, 0x00, 0xc2];
const SPDP_READER: [u8; 4] = [0x00, 0x01, 0x00, 0xc7];
const PUBLICATIONS_WRITER: [u8; 4] = [0x00, 0x00, 0x03, 0xc2];
const PUBLICATIONS_READER: [u8; 4] = [0x00, 0x00, 0x03, 0xc7];
const PID_SENTINEL: u16 = 0x0001;
const PID_TOPIC_NAME: u16 = 0x0005;
const PID_TYPE_NAME: u16 = 0x0007;
const PID_PARTICIPANT_GUID: u16 = 0x0050;
const PID_ENDPOINT_GUID: u16 = 0x005a;

#[derive(Default)]
struct RtpsCounts {
    /// Participants discovered from a well-formed SPDP announcement.
    participants: AtomicUsize,
    /// Publications received from a discovered participant's publications
    /// writer at the sequence number the reader had asked for.
    publications: AtomicUsize,
}

/// What the participant knows of the peer at one address.
#[derive(Default)]
struct RtpsPeer {
    prefix: Option<[u8; 12]>,
    /// The highest sequence number received in order from its publications
    /// writer.
    received: u32,
    acknacks: u32,
}

fn rtps_u16(bytes: &[u8], at: usize, little: bool) -> Option<u16> {
    let raw = [*bytes.get(at)?, *bytes.get(at + 1)?];
    Some(if little {
        u16::from_le_bytes(raw)
    } else {
        u16::from_be_bytes(raw)
    })
}

fn rtps_u32(bytes: &[u8], at: usize, little: bool) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(at..at + 4)?.try_into().ok()?;
    Some(if little {
        u32::from_le_bytes(raw)
    } else {
        u32::from_be_bytes(raw)
    })
}

/// The parameters of a serialized payload's ParameterList (PL_CDR_LE or
/// PL_CDR_BE) before its PID_SENTINEL; `None` when it is malformed.
fn rtps_parameters(payload: &[u8]) -> Option<Vec<(u16, &[u8])>> {
    let little = match payload.get(..2)? {
        [0x00, 0x03] => true,
        [0x00, 0x02] => false,
        _ => return None,
    };
    let mut at = 4;
    let mut parameters = Vec::new();
    loop {
        let pid = rtps_u16(payload, at, little)?;
        let len = usize::from(rtps_u16(payload, at + 2, little)?);
        if pid == PID_SENTINEL {
            return Some(parameters);
        }
        if len % 4 != 0 {
            return None;
        }
        parameters.push((pid, payload.get(at + 4..at + 4 + len)?));
        at += 4 + len;
    }
}

/// A CDR string parameter: a u32 length counting the NUL, then the bytes.
fn rtps_string(value: &[u8]) -> Option<&[u8]> {
    let len = rtps_u32(value, 0, true)? as usize;
    let bytes = value.get(4..4 + len)?;
    (len > 1 && bytes[len - 1] == 0).then(|| &bytes[..len - 1])
}

fn rtps_header(prefix: &[u8; 12]) -> Vec<u8> {
    let mut message = b"RTPS".to_vec();
    message.extend_from_slice(&[2, 3, 0x00, 0x00]);
    message.extend_from_slice(prefix);
    message
}

fn rtps_submessage(message: &mut Vec<u8>, id: u8, flags: u8, body: &[u8]) {
    message.extend_from_slice(&[id, flags]);
    message.extend_from_slice(&(body.len() as u16).to_le_bytes());
    message.extend_from_slice(body);
}

/// The participant's own SPDP announcement, little-endian.
fn rtps_announcement(prefix: &[u8; 12]) -> Vec<u8> {
    let mut data = vec![0, 0, 16, 0];
    data.extend_from_slice(&SPDP_READER);
    data.extend_from_slice(&SPDP_WRITER);
    data.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0]);
    data.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]);
    let mut guid = prefix.to_vec();
    guid.extend_from_slice(&[0x00, 0x00, 0x01, 0xc1]);
    for (pid, value) in [
        (0x0015, &[2, 3, 0, 0][..]),
        (0x0016, &[0, 0, 0, 0][..]),
        (PID_PARTICIPANT_GUID, &guid[..]),
        (0x0058, &[0x3f, 0, 0, 0][..]),
        (PID_SENTINEL, &[][..]),
    ] {
        data.extend_from_slice(&pid.to_le_bytes());
        data.extend_from_slice(&(value.len() as u16).to_le_bytes());
        data.extend_from_slice(value);
    }
    let mut message = rtps_header(prefix);
    rtps_submessage(&mut message, 0x15, 0x05, &data);
    message
}

/// The publications reader's ACKNACK to a heartbeat whose last sequence
/// number is `last`: the first one missing and a bitmap of those missing up
/// to `last`, addressed to `source`.
fn rtps_acknack(own: &[u8; 12], source: &[u8; 12], peer: &mut RtpsPeer, last: u32) -> Vec<u8> {
    let base = peer.received + 1;
    let missing = last.saturating_add(1).saturating_sub(base).min(256);
    let mut acknack = PUBLICATIONS_READER.to_vec();
    acknack.extend_from_slice(&PUBLICATIONS_WRITER);
    acknack.extend_from_slice(&0u32.to_le_bytes());
    acknack.extend_from_slice(&base.to_le_bytes());
    acknack.extend_from_slice(&missing.to_le_bytes());
    for word in 0..missing.div_ceil(32) {
        let bits = (missing - 32 * word).min(32);
        let mask = if bits == 32 {
            u32::MAX
        } else {
            !(u32::MAX >> bits)
        };
        acknack.extend_from_slice(&mask.to_le_bytes());
    }
    peer.acknacks += 1;
    acknack.extend_from_slice(&peer.acknacks.to_le_bytes());
    let mut message = rtps_header(own);
    rtps_submessage(&mut message, 0x0e, 0x01, source);
    // The final flag when nothing is missing: the writer need not answer.
    let flags = if missing == 0 { 0x03 } else { 0x01 };
    rtps_submessage(&mut message, 0x06, flags, &acknack);
    message
}

/// The reply to one datagram from `peer`: an ACKNACK to a heartbeat of its
/// publications writer, the participant's announcement to an announcement,
/// and otherwise a message with nothing in it (an INFO_TS).
fn rtps_reply(
    datagram: &[u8],
    own: &[u8; 12],
    peer: &mut RtpsPeer,
    counts: &RtpsCounts,
) -> Vec<u8> {
    let mut nothing = rtps_header(own);
    rtps_submessage(&mut nothing, 0x09, 0x03, &[]);
    if datagram.len() < 20 || &datagram[..4] != b"RTPS" || datagram[4] != 2 {
        return nothing;
    }
    let source: [u8; 12] = datagram[8..20].try_into().unwrap();
    let (mut at, mut for_us, mut announced) = (20, true, false);
    let mut heartbeat_last = None;
    while at + 4 <= datagram.len() {
        let (id, flags) = (datagram[at], datagram[at + 1]);
        let little = flags & 0x01 != 0;
        let len = usize::from(rtps_u16(datagram, at + 2, little).unwrap());
        let Some(body) = datagram.get(at + 4..at + 4 + len) else {
            return nothing;
        };
        at += 4 + len;
        let matched = peer.prefix == Some(source);
        match id {
            // INFO_DST: what follows is for that participant.
            0x0e => {
                let Some(destination) = body.get(..12) else {
                    return nothing;
                };
                for_us = destination == own || destination == [0; 12];
            }
            // DATA
            0x15 if for_us && body.len() >= 20 => {
                let (reader, writer) = (&body[4..8], &body[8..12]);
                let (Some(high), Some(low), Some(to_payload)) = (
                    rtps_u32(body, 12, little),
                    rtps_u32(body, 16, little),
                    rtps_u16(body, 2, little),
                ) else {
                    return nothing;
                };
                let Some(parameters) = body
                    .get(4 + usize::from(to_payload)..)
                    .and_then(rtps_parameters)
                else {
                    return nothing;
                };
                let parameter = |pid: u16| {
                    parameters
                        .iter()
                        .find(|(p, _)| *p == pid)
                        .map(|(_, value)| *value)
                };
                if writer == SPDP_WRITER && (reader == SPDP_READER || reader == [0; 4]) {
                    let guid = parameter(PID_PARTICIPANT_GUID);
                    if guid
                        .is_some_and(|guid| guid[..12] == source && guid[12..] == [0, 0, 1, 0xc1])
                    {
                        peer.prefix = Some(source);
                        counts.participants.fetch_add(1, Ordering::SeqCst);
                        announced = true;
                    }
                } else if writer == PUBLICATIONS_WRITER
                    && reader == PUBLICATIONS_READER
                    && matched
                    && (high, low) == (0, peer.received + 1)
                    && parameter(PID_ENDPOINT_GUID)
                        .is_some_and(|guid| guid.get(..12) == Some(&source))
                    && parameter(PID_TOPIC_NAME).and_then(rtps_string).is_some()
                    && parameter(PID_TYPE_NAME).and_then(rtps_string).is_some()
                {
                    peer.received += 1;
                    counts.publications.fetch_add(1, Ordering::SeqCst);
                }
            }
            // HEARTBEAT, not final: the reader must answer it.
            0x07 if for_us && flags & 0x02 == 0 && body.len() >= 28 => {
                let last = (rtps_u32(body, 16, little), rtps_u32(body, 20, little));
                if body[..4] == PUBLICATIONS_READER
                    && body[4..8] == PUBLICATIONS_WRITER
                    && matched
                    && last.0 == Some(0)
                {
                    heartbeat_last = last.1;
                }
            }
            _ => {}
        }
    }
    match (heartbeat_last, announced) {
        (Some(last), _) => rtps_acknack(own, &source, peer, last),
        (None, true) => rtps_announcement(own),
        (None, false) => nothing,
    }
}

/// An RTPS participant on a unicast port that answers to the datagram's
/// source: an SPDP announcement with its own, and a heartbeat of a
/// discovered participant's SEDP publications writer with its publications
/// reader's ACKNACK. Each source address is a peer of its own, so every
/// session starts undiscovered.
fn start_rtps_participant(counts: Arc<RtpsCounts>) -> u16 {
    let (socket, port) = bind_udp();
    thread::spawn(move || {
        let mut own = [0u8; 12];
        own[..4].copy_from_slice(&[0x01, 0x0f, 0xfe, 0xed]);
        own[4..8].copy_from_slice(&run_unique().to_be_bytes());
        own[8..].copy_from_slice(&std::process::id().to_be_bytes());
        let mut peers: HashMap<SocketAddr, RtpsPeer> = HashMap::new();
        let mut buf = [0u8; 65_536];
        while let Ok((n, source)) = socket.recv_from(&mut buf) {
            let peer = peers.entry(source).or_default();
            let reply = rtps_reply(&buf[..n], &own, peer, &counts);
            let _ = socket.send_to(&reply, source);
        }
    });
    port
}

/// #372: the RTPS profile announces a participant (SPDP), heartbeats its
/// SEDP publications writer to the participant it discovered, addressed with
/// the GUID prefix that participant announced, and sends the publication at
/// the sequence number the reader's ACKNACK asked for, over UDP.
#[test]
fn the_rtps_profile_reaches_every_state_against_an_rtps_participant_over_udp() {
    let counts = Arc::new(RtpsCounts::default());
    let port = start_rtps_participant(counts.clone());
    let work = TestDir::new("rtps-profile");
    let summary = campaign(
        work.path(),
        &reference_profile("rtps.toml"),
        &format!("udp:127.0.0.1:{port}"),
    );
    assert_eq!(
        summary["reset_fidelity"], "udp;reset=reconnect",
        "{summary:#}"
    );
    // start, discovered, nacked and acknowledged.
    assert_eq!(summary["states_covered"], 4, "{summary:#}");
    assert!(
        summary["transitions_covered"].as_u64().unwrap() >= 3,
        "{summary:#}"
    );
    assert!(counts.participants.load(Ordering::SeqCst) >= 1);
    assert!(
        counts.publications.load(Ordering::SeqCst) >= 1,
        "a publication reached the participant its session discovered, at the sequence \
         number its ACKNACK asked for"
    );
}
