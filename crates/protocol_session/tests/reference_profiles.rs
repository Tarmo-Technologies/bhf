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
