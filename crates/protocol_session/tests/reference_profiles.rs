// SPDX-License-Identifier: Apache-2.0

//! The reference profiles under `profiles/protocols/` write their seed
//! messages as the protocols' specifications do and read the replies the
//! specifications define. Each test pins a profile's frames to the bytes of a
//! hand-checked exchange, and checks that a reply which does not answer the
//! request (an exception, a refusal, another packet) is not captured, so it
//! cannot advance a session.

use std::path::Path;

use protocol_session::{
    encode_message, extract, Bindings, BoundValue, MessageInstance, Profile, ProtocolModel,
    ReplyProgress, ResponseError,
};

fn model(name: &str) -> ProtocolModel {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../profiles/protocols")
        .join(name);
    let source =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let profile = Profile::from_toml(&source).unwrap_or_else(|e| panic!("{name}: {e}"));
    ProtocolModel::from_profile(&profile).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// The wire bytes of `message`'s seed instance.
fn seed(model: &ProtocolModel, message: &str, bindings: &Bindings) -> Vec<u8> {
    let instance = MessageInstance::from_seed(model.message(message).expect(message));
    encode_message(model, &instance, bindings)
        .unwrap_or_else(|e| panic!("{message}: {e}"))
        .into_bytes()
}

fn captures(
    model: &ProtocolModel,
    message: &str,
    reply: &[u8],
) -> Result<Vec<(String, BoundValue)>, ResponseError> {
    extract(message, &model.message(message).unwrap().response, reply)
}

fn captured(captures: &[(String, BoundValue)], source: &str) -> Option<u64> {
    captures
        .iter()
        .find(|(key, _)| key == source)
        .and_then(|(_, value)| value.as_u64())
}

fn bound(source: &str, value: u64) -> Bindings {
    let mut bindings = Bindings::new();
    bindings.bind(source, BoundValue::Int { value });
    bindings
}

#[test]
fn the_modbus_tcp_profile_writes_and_reads_mbap_frames() {
    let modbus = model("modbus-tcp.toml");
    let none = Bindings::new();

    // Read Holding Registers: transaction 1, protocol 0, length 6, unit 1,
    // function 3, address 0, quantity 1.
    assert_eq!(
        seed(&modbus, "READ_HOLDING_REGISTERS", &none),
        [0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 1]
    );
    let reply = [0, 1, 0, 0, 0, 5, 1, 3, 2, 0xbe, 0xef];
    assert_eq!(
        modbus.framing().take_reply(&reply, 260),
        ReplyProgress::Complete {
            reply: reply.to_vec(),
            consumed: reply.len()
        }
    );
    let read = captures(&modbus, "READ_HOLDING_REGISTERS", &reply).expect("a normal response");
    assert_eq!(
        captured(&read, "READ_HOLDING_REGISTERS.response.value"),
        Some(0xbeef)
    );
    // Exception 2 (illegal data address) answers the read but is not its
    // normal response.
    assert_eq!(
        captures(
            &modbus,
            "READ_HOLDING_REGISTERS",
            &[0, 1, 0, 0, 0, 3, 1, 0x83, 0x02]
        ),
        Err(ResponseError::OutOfRange {
            field: "function".to_owned(),
            value: 0x83
        })
    );

    // Write Single Register writes back the value the read returned.
    assert_eq!(
        seed(
            &modbus,
            "WRITE_SINGLE_REGISTER",
            &bound("READ_HOLDING_REGISTERS.response.value", 0xbeef)
        ),
        [0, 2, 0, 0, 0, 6, 1, 6, 0, 0, 0xbe, 0xef]
    );

    // Write Multiple Registers: 2 registers from address 1, byte count 4.
    assert_eq!(
        seed(&modbus, "WRITE_MULTIPLE_REGISTERS", &none),
        [0, 3, 0, 0, 0, 11, 1, 0x10, 0, 1, 0, 2, 4, 0, 0x2a, 1, 0]
    );
}

#[test]
fn the_mqtt_profile_writes_and_reads_mqtt_3_1_1_packets() {
    let mqtt = model("mqtt-3.1.1.toml");
    let none = Bindings::new();

    let mut connect = vec![0x10, 2 + 4 + 1 + 1 + 2 + 2 + 11, 0, 4];
    connect.extend_from_slice(b"MQTT");
    connect.extend_from_slice(&[4, 0x02, 0, 60, 0, 11]);
    connect.extend_from_slice(b"bhf-session");
    assert_eq!(seed(&mqtt, "CONNECT", &none), connect);
    let accepted = captures(&mqtt, "CONNECT", &[0x20, 0x02, 0x00, 0x00]).expect("CONNACK");
    assert_eq!(captured(&accepted, "CONNECT.response.return_code"), Some(0));
    // A CONNACK that refuses the connection (not authorized), and a packet
    // that is not a CONNACK, do not connect the session.
    assert_eq!(
        captures(&mqtt, "CONNECT", &[0x20, 0x02, 0x00, 0x05]),
        Err(ResponseError::OutOfRange {
            field: "return_code".to_owned(),
            value: 5
        })
    );
    assert!(captures(&mqtt, "CONNECT", &[0x90, 0x03, 0x00, 0x01, 0x01]).is_err());

    let filter = b"bhf/session/commands/#";
    let mut subscribe = vec![0x82, (2 + 2 + filter.len() + 1) as u8, 0, 1, 0];
    subscribe.push(filter.len() as u8);
    subscribe.extend_from_slice(filter);
    subscribe.push(1);
    assert_eq!(seed(&mqtt, "SUBSCRIBE", &none), subscribe);
    let suback = [0x90, 0x03, 0x00, 0x01, 0x01, 0xd0, 0x00];
    assert_eq!(
        mqtt.framing().take_reply(&suback, 128),
        ReplyProgress::Complete {
            reply: suback[..5].to_vec(),
            consumed: 5
        },
        "the Remaining Length ends the SUBACK"
    );
    let granted = captures(&mqtt, "SUBSCRIBE", &suback[..5]).expect("SUBACK");
    assert_eq!(captured(&granted, "SUBSCRIBE.response.packet_id"), Some(1));

    let topic = b"bhf/session/telemetry";
    let mut publish = vec![0x34, (2 + topic.len() + 2 + 4) as u8, 0];
    publish.push(topic.len() as u8);
    publish.extend_from_slice(topic);
    publish.extend_from_slice(&[0, 2]);
    publish.extend_from_slice(b"21.5");
    assert_eq!(seed(&mqtt, "PUBLISH", &none), publish);
    let pubrec = captures(&mqtt, "PUBLISH", &[0x50, 0x02, 0x12, 0x34]).expect("PUBREC");
    assert_eq!(
        captured(&pubrec, "PUBLISH.response.packet_id"),
        Some(0x1234)
    );

    // PUBREL carries the packet id the PUBREC named.
    assert_eq!(
        seed(
            &mqtt,
            "PUBREL",
            &bound("PUBLISH.response.packet_id", 0x1234)
        ),
        [0x62, 0x02, 0x12, 0x34]
    );
    assert_eq!(seed(&mqtt, "PINGREQ", &none), [0xc0, 0x00]);
    assert!(captures(&mqtt, "PINGREQ", &[0xd0, 0x00]).is_ok());
}

fn bytes_bound(source: &str, value: &[u8]) -> Bindings {
    let mut bindings = Bindings::new();
    bindings.bind(
        source,
        BoundValue::Bytes {
            value: value.to_vec(),
        },
    );
    bindings
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

#[test]
fn the_coap_profile_writes_and_reads_rfc_7252_messages() {
    let coap = model("coap.toml");
    let none = Bindings::new();

    // CON GET, message id 0x0101, token 1, Uri-Path ".well-known", "core".
    assert_eq!(
        seed(&coap, "GET_CORE", &none),
        concat(&[
            &[0x44, 0x01, 0x01, 0x01, 0, 0, 0, 1, 0xbb],
            b".well-known",
            &[0x04],
            b"core"
        ])
    );
    assert_eq!(
        seed(&coap, "GET_LIMIT", &none),
        concat(&[&[0x44, 0x01, 0x01, 0x02, 0, 0, 0, 2, 0xb5], b"limit"])
    );
    // ACK 2.05 Content: ETag (4 bytes), Content-Format 0, payload "75".
    let content = concat(&[
        &[
            0x64, 0x45, 0x01, 0x02, 0, 0, 0, 2, 0x44, 0xde, 0xad, 0xbe, 0xef,
        ],
        &[0x80, 0xff],
        b"75",
    ]);
    let read = captures(&coap, "GET_LIMIT", &content).expect("2.05 Content");
    assert_eq!(
        read.iter()
            .find(|(key, _)| key == "GET_LIMIT.response.etag")
            .and_then(|(_, value)| value.as_bytes()),
        Some(&[0xde, 0xad, 0xbe, 0xef][..])
    );
    // 4.04 Not Found and a Reset answer the request but do not read it.
    assert_eq!(
        captures(&coap, "GET_LIMIT", &[0x64, 0x84, 0x01, 0x02, 0, 0, 0, 2]),
        Err(ResponseError::OutOfRange {
            field: "code".to_owned(),
            value: 0x84
        })
    );
    assert!(captures(&coap, "GET_LIMIT", &[0x70, 0x00, 0x01, 0x02]).is_err());

    // CON PUT: If-Match (the ETag read), Uri-Path "limit", Content-Format 0,
    // the payload marker and "80".
    assert_eq!(
        seed(
            &coap,
            "PUT_LIMIT",
            &bytes_bound("GET_LIMIT.response.etag", &[0xde, 0xad, 0xbe, 0xef])
        ),
        concat(&[
            &[0x44, 0x03, 0x01, 0x03, 0, 0, 0, 3],
            &[0x14, 0xde, 0xad, 0xbe, 0xef, 0xa5],
            b"limit",
            &[0x10, 0xff],
            b"80"
        ])
    );
    assert!(captures(&coap, "PUT_LIMIT", &[0x64, 0x44, 0x01, 0x03, 0, 0, 0, 3]).is_ok());
    // 4.12 Precondition Failed: the ETag did not match.
    assert!(captures(&coap, "PUT_LIMIT", &[0x64, 0x8c, 0x01, 0x03, 0, 0, 0, 3]).is_err());
}

/// The submessages of an RTPS message: id and body, each found by the
/// previous one's octetsToNextHeader (little-endian), which must end the
/// message exactly.
fn rtps_submessages(message: &[u8]) -> Vec<(u8, Vec<u8>)> {
    assert_eq!(&message[..8], b"RTPS\x02\x03\x00\x00");
    let mut submessages = Vec::new();
    let mut at = 20;
    while at < message.len() {
        let len = usize::from(u16::from_le_bytes([message[at + 2], message[at + 3]]));
        assert_eq!(message[at + 1] & 0x01, 0x01, "little-endian");
        submessages.push((message[at], message[at + 4..at + 4 + len].to_vec()));
        at += 4 + len;
    }
    assert_eq!(at, message.len(), "the lengths end the message exactly");
    submessages
}

/// The parameter ids of a DATA body's PL_CDR_LE payload, which ends at
/// PID_SENTINEL.
fn rtps_parameter_ids(data: &[u8]) -> Vec<u16> {
    assert_eq!(&data[20..24], [0x00, 0x03, 0x00, 0x00], "PL_CDR_LE");
    let mut ids = Vec::new();
    let mut at = 24;
    loop {
        let pid = u16::from_le_bytes([data[at], data[at + 1]]);
        let len = usize::from(u16::from_le_bytes([data[at + 2], data[at + 3]]));
        assert_eq!(len % 4, 0, "parameter {pid:#06x} is 4-byte aligned");
        ids.push(pid);
        at += 4 + len;
        if pid == 0x0001 {
            assert_eq!(at, data.len());
            return ids;
        }
    }
}

#[test]
fn the_rtps_profile_writes_and_reads_ddsi_rtps_2_3_messages() {
    let rtps = model("rtps.toml");
    let none = Bindings::new();
    let prefix = b"bhf-session1";

    let announce = seed(&rtps, "SPDP_ANNOUNCE", &none);
    assert_eq!(&announce[8..20], prefix);
    let submessages = rtps_submessages(&announce);
    assert_eq!(submessages.len(), 1);
    let (id, data) = &submessages[0];
    assert_eq!(*id, 0x15, "DATA");
    // extraFlags, octetsToInlineQos 16, the SPDP reader and writer, SN 1.
    assert_eq!(
        &data[..20],
        concat(&[
            &[0, 0, 16, 0],
            &[0x00, 0x01, 0x00, 0xc7, 0x00, 0x01, 0x00, 0xc2],
            &[0, 0, 0, 0, 1, 0, 0, 0]
        ])
    );
    // PROTOCOL_VERSION, VENDORID, PARTICIPANT_GUID, BUILTIN_ENDPOINT_SET,
    // PARTICIPANT_LEASE_DURATION, SENTINEL.
    assert_eq!(
        rtps_parameter_ids(data),
        [0x0015, 0x0016, 0x0050, 0x0058, 0x0002, 0x0001]
    );
    let guid = concat(&[prefix, &[0, 0, 1, 0xc1]]);
    assert!(data.windows(guid.len()).any(|window| window == guid));

    // A participant's announcement, as a little-endian participant writes it.
    let other: [u8; 12] = *b"\x01\x0f\xfe\xedpeer-001";
    let reply = concat(&[
        b"RTPS\x02\x03\x00\x00",
        &other,
        &[0x15, 0x05, 52, 0, 0, 0, 16, 0],
        &[0x00, 0x01, 0x00, 0xc7, 0x00, 0x01, 0x00, 0xc2],
        &[0, 0, 0, 0, 1, 0, 0, 0, 0x00, 0x03, 0x00, 0x00],
        &[0x15, 0x00, 4, 0, 2, 3, 0, 0],
        &[0x50, 0x00, 16, 0],
        &other,
        &[0, 0, 1, 0xc1, 0x01, 0x00, 0, 0],
    ]);
    let discovered = captures(&rtps, "SPDP_ANNOUNCE", &reply).expect("an announcement");
    let value = |key: &str| {
        discovered
            .iter()
            .find(|(source, _)| source == key)
            .and_then(|(_, value)| value.as_bytes())
            .map(<[u8]>::to_vec)
    };
    assert_eq!(
        value("SPDP_ANNOUNCE.response.guid_prefix"),
        Some(other.to_vec())
    );
    assert_eq!(
        value("SPDP_ANNOUNCE.response.participant_guid"),
        Some(concat(&[&other, &[0, 0, 1, 0xc1]]))
    );

    // The heartbeat goes to the discovered participant: INFO_DST names it.
    let mut bindings = bytes_bound("SPDP_ANNOUNCE.response.guid_prefix", &other);
    let heartbeat = seed(&rtps, "HEARTBEAT", &bindings);
    let submessages = rtps_submessages(&heartbeat);
    assert_eq!(
        submessages.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        [0x0e, 0x07],
        "INFO_DST, HEARTBEAT"
    );
    assert_eq!(submessages[0].1, other);
    // The SEDP publications reader and writer; SN 1 to 1; count 1.
    assert_eq!(
        submessages[1].1,
        concat(&[
            &[0x00, 0x00, 0x03, 0xc7, 0x00, 0x00, 0x03, 0xc2],
            &[0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0]
        ])
    );

    // The publication carries the sequence number the ACKNACK asked for,
    // as its writerSN and as its heartbeat's last.
    bindings.bind(
        "HEARTBEAT.response.missing_sn_low",
        BoundValue::Int { value: 7 },
    );
    let publication = seed(&rtps, "DATA_W", &bindings);
    let submessages = rtps_submessages(&publication);
    assert_eq!(
        submessages.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        [0x0e, 0x15, 0x07],
        "INFO_DST, DATA, HEARTBEAT"
    );
    let data = &submessages[1].1;
    assert_eq!(
        &data[4..12],
        [0x00, 0x00, 0x03, 0xc7, 0x00, 0x00, 0x03, 0xc2]
    );
    assert_eq!(&data[12..20], [0, 0, 0, 0, 7, 0, 0, 0], "writerSN 7");
    // ENDPOINT_GUID, TOPIC_NAME, TYPE_NAME, SENTINEL.
    assert_eq!(rtps_parameter_ids(data), [0x005a, 0x0005, 0x0007, 0x0001]);
    let topic = concat(&[&[0x05, 0x00, 16, 0, 12, 0, 0, 0], b"bhf/session\0"]);
    assert!(data.windows(topic.len()).any(|window| window == topic));
    assert_eq!(
        &submessages[2].1[16..24],
        [0, 0, 0, 0, 7, 0, 0, 0],
        "last SN 7"
    );

    // The reader's ACKNACK after an INFO_DST: SN 7 missing, then nothing.
    let acknack = |base: u8, bits: u8| {
        concat(&[
            b"RTPS\x02\x03\x00\x00",
            &other,
            &[0x0e, 0x01, 12, 0],
            prefix,
            &[
                0x06, 0x01, 28, 0, 0x00, 0x00, 0x03, 0xc7, 0x00, 0x00, 0x03, 0xc2,
            ],
            &[0, 0, 0, 0, base, 0, 0, 0, bits, 0, 0, 0],
            &[0, 0, 0, 0x80, 1, 0, 0, 0],
        ])
    };
    let nacked = captures(&rtps, "HEARTBEAT", &acknack(7, 1)).expect("an ACKNACK");
    assert_eq!(
        captured(&nacked, "HEARTBEAT.response.missing_sn_low"),
        Some(7)
    );
    assert!(captures(&rtps, "DATA_W", &acknack(8, 0)).is_ok());
    // An ACKNACK still missing the publication does not acknowledge it.
    assert_eq!(
        captures(&rtps, "DATA_W", &acknack(7, 1)),
        Err(ResponseError::OutOfRange {
            field: "num_bits".to_owned(),
            value: 1
        })
    );
}
