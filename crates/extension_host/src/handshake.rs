// SPDX-License-Identifier: Apache-2.0

//! The `hello` exchange and capability negotiation state machine.
//!
//! Before any fuzzing work is driven, the host sends a [`HostHello`] (the
//! protocol it speaks, the capabilities it requires/wants, the formats it
//! understands, and its own wire limits) and the extension replies with an
//! [`ExtHello`] (its protocol, the capabilities it provides, its formats, and
//! optionally its own limits). [`negotiate`] then:
//!
//! - rejects an incompatible protocol version up front,
//! - rejects any *missing required* capability up front (no case is ever
//!   driven against an extension that cannot satisfy the campaign),
//! - selects the capability intersection and a common wire format, and
//! - takes the element-wise *minimum* of the two sides' limits.

use crate::wire::{read_frame, write_frame};
use crate::{ExtensionError, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

/// The host's opening handshake message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostHello {
    /// The protocol identifier the host speaks.
    pub protocol: String,
    /// Capabilities that MUST be provided or the campaign aborts.
    pub required_capabilities: Vec<String>,
    /// Capabilities the host will use if offered, but can proceed without.
    #[serde(default)]
    pub optional_capabilities: Vec<String>,
    /// Wire formats the host understands, most-preferred first.
    pub formats: Vec<String>,
    /// The host's proposed wire limits.
    pub limits: WireLimits,
}

/// The extension's handshake reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtHello {
    /// The protocol identifier the extension speaks.
    pub protocol: String,
    /// The capabilities the extension provides.
    pub provided_capabilities: Vec<String>,
    /// Wire formats the extension understands.
    pub formats: Vec<String>,
    /// The extension's declared limits, if any (merged by taking the minimum).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<WireLimits>,
    /// An optional self-reported extension name (diagnostic only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// An optional self-reported extension version (diagnostic only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Wire-level limits exchanged during the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireLimits {
    /// The maximum framed message size, in bytes.
    pub max_frame_bytes: u64,
    /// The per-call deadline, in milliseconds.
    pub call_timeout_ms: u64,
}

/// A negotiated wire format. The host speaks JSON only for now; the handshake
/// negotiates a `format` field so CBOR can be added later without a wire break.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Length-framed UTF-8 JSON (the only format this host drives today).
    Json,
}

impl Format {
    /// The wire token for this format.
    pub fn as_str(self) -> &'static str {
        match self {
            Format::Json => "json",
        }
    }
}

/// The outcome of a successful negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    /// The agreed protocol identifier.
    pub protocol: String,
    /// The capabilities both sides agreed to use (required + optional∩provided),
    /// sorted and de-duplicated for a stable provenance record.
    pub caps: Vec<String>,
    /// The negotiated wire format.
    pub format: Format,
    /// The element-wise minimum of the two sides' limits.
    pub limits: WireLimits,
    /// The extension's self-reported name, if provided.
    pub extension_name: Option<String>,
    /// The extension's self-reported version, if provided.
    pub extension_version: Option<String>,
}

/// Negotiate a session from the two `hello` messages. Pure: no I/O.
pub fn negotiate(host: &HostHello, ext: &ExtHello) -> Result<Negotiated> {
    if ext.protocol != host.protocol {
        return Err(ExtensionError::ProtocolVersion {
            expected: host.protocol.clone(),
            got: ext.protocol.clone(),
        });
    }

    let missing: Vec<String> = host
        .required_capabilities
        .iter()
        .filter(|cap| !ext.provided_capabilities.contains(cap))
        .cloned()
        .collect();
    if !missing.is_empty() {
        let mut missing = missing;
        missing.sort();
        missing.dedup();
        return Err(ExtensionError::CapabilityUnsatisfied { missing });
    }

    // JSON is the only format this host drives; require a common "json".
    let host_has_json = host.formats.iter().any(|f| f == Format::Json.as_str());
    let ext_has_json = ext.formats.iter().any(|f| f == Format::Json.as_str());
    if !(host_has_json && ext_has_json) {
        return Err(ExtensionError::NoCommonFormat {
            host: host.formats.clone(),
            ext: ext.formats.clone(),
        });
    }

    // Negotiated caps: every required cap plus any optional cap the extension
    // also provides. Sorted + de-duplicated for a stable provenance record.
    let mut caps: Vec<String> = host.required_capabilities.clone();
    for opt in &host.optional_capabilities {
        if ext.provided_capabilities.contains(opt) {
            caps.push(opt.clone());
        }
    }
    caps.sort();
    caps.dedup();

    // Take the element-wise minimum of the two sides' limits so neither side can
    // be pushed past what it declared it can handle.
    let limits = match ext.limits {
        Some(ext_limits) => WireLimits {
            max_frame_bytes: host.limits.max_frame_bytes.min(ext_limits.max_frame_bytes),
            call_timeout_ms: host.limits.call_timeout_ms.min(ext_limits.call_timeout_ms),
        },
        None => host.limits,
    };

    Ok(Negotiated {
        protocol: host.protocol.clone(),
        caps,
        format: Format::Json,
        limits,
        extension_name: ext.name.clone(),
        extension_version: ext.version.clone(),
    })
}

/// Drive the host side of the handshake over a byte duplex: write the host
/// hello, read the extension hello (bounded by `frame_cap`), and negotiate.
pub fn client_handshake<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    host: &HostHello,
    frame_cap: usize,
) -> Result<Negotiated> {
    let host_bytes = serde_json::to_vec(host)?;
    write_frame(writer, &host_bytes)?;

    let frame = read_frame(reader, frame_cap)?
        .ok_or_else(|| ExtensionError::Handshake("extension closed before sending hello".into()))?;
    let ext: ExtHello = serde_json::from_slice(&frame).map_err(|e| {
        ExtensionError::Handshake(format!("extension hello was not a valid ExtHello: {e}"))
    })?;

    negotiate(host, &ext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn host_hello() -> HostHello {
        HostHello {
            protocol: crate::PROTOCOL.to_string(),
            required_capabilities: vec!["oracle.evaluate".to_string()],
            optional_capabilities: vec!["codec.decode".to_string()],
            formats: vec!["json".to_string()],
            limits: WireLimits {
                max_frame_bytes: 1024,
                call_timeout_ms: 5000,
            },
        }
    }

    /// Serialize an `ExtHello` into a framed reader the host can consume.
    fn framed(ext: &ExtHello) -> Cursor<Vec<u8>> {
        let mut buf = Vec::new();
        write_frame(&mut buf, &serde_json::to_vec(ext).unwrap()).unwrap();
        Cursor::new(buf)
    }

    #[test]
    fn negotiation_rejects_missing_required_capability() {
        let host = host_hello();
        let mut reader = framed(&ExtHello {
            protocol: crate::PROTOCOL.to_string(),
            provided_capabilities: vec!["codec.decode".to_string()],
            formats: vec!["json".to_string()],
            limits: None,
            name: None,
            version: None,
        });
        let mut writer = Vec::new();
        let err = client_handshake(&mut reader, &mut writer, &host, 1 << 20)
            .expect_err("missing required cap must reject");
        match err {
            ExtensionError::CapabilityUnsatisfied { missing } => {
                assert_eq!(missing, vec!["oracle.evaluate".to_string()]);
            }
            other => panic!("expected CapabilityUnsatisfied, got {other:?}"),
        }
    }

    #[test]
    fn negotiation_selects_capability_intersection_and_json_format() {
        let host = host_hello();
        let mut reader = framed(&ExtHello {
            protocol: crate::PROTOCOL.to_string(),
            // Provides the required cap AND the optional one, plus an extra the
            // host never asked for (which must not leak into the negotiated set).
            provided_capabilities: vec![
                "oracle.evaluate".to_string(),
                "codec.decode".to_string(),
                "mutator.mutate".to_string(),
            ],
            formats: vec!["json".to_string()],
            limits: None,
            name: Some("ref-ext".to_string()),
            version: Some("0.1.0".to_string()),
        });
        let mut writer = Vec::new();
        let neg = client_handshake(&mut reader, &mut writer, &host, 1 << 20).expect("negotiate");
        assert_eq!(neg.format, Format::Json);
        assert_eq!(
            neg.caps,
            vec!["codec.decode".to_string(), "oracle.evaluate".to_string()]
        );
        assert_eq!(neg.extension_name.as_deref(), Some("ref-ext"));

        // The host actually wrote its own hello to the writer.
        assert!(!writer.is_empty(), "host hello must be sent");
    }

    #[test]
    fn protocol_version_mismatch_is_rejected() {
        let host = host_hello();
        let mut reader = framed(&ExtHello {
            protocol: "bhf.extension.v2".to_string(),
            provided_capabilities: vec!["oracle.evaluate".to_string()],
            formats: vec!["json".to_string()],
            limits: None,
            name: None,
            version: None,
        });
        let mut writer = Vec::new();
        let err = client_handshake(&mut reader, &mut writer, &host, 1 << 20)
            .expect_err("version mismatch must reject");
        match err {
            ExtensionError::ProtocolVersion { expected, got } => {
                assert_eq!(expected, crate::PROTOCOL);
                assert_eq!(got, "bhf.extension.v2");
            }
            other => panic!("expected ProtocolVersion, got {other:?}"),
        }
    }

    #[test]
    fn extension_declared_limits_are_captured_as_elementwise_min() {
        let host = host_hello(); // max_frame 1024, timeout 5000
        let mut reader = framed(&ExtHello {
            protocol: crate::PROTOCOL.to_string(),
            provided_capabilities: vec!["oracle.evaluate".to_string()],
            formats: vec!["json".to_string()],
            limits: Some(WireLimits {
                max_frame_bytes: 512,  // smaller than host -> wins
                call_timeout_ms: 9000, // larger than host -> host wins
            }),
            name: None,
            version: None,
        });
        let mut writer = Vec::new();
        let neg = client_handshake(&mut reader, &mut writer, &host, 1 << 20).expect("negotiate");
        assert_eq!(neg.limits.max_frame_bytes, 512);
        assert_eq!(neg.limits.call_timeout_ms, 5000);
    }

    #[test]
    fn no_common_format_is_rejected() {
        let host = host_hello();
        let mut reader = framed(&ExtHello {
            protocol: crate::PROTOCOL.to_string(),
            provided_capabilities: vec!["oracle.evaluate".to_string()],
            formats: vec!["cbor".to_string()],
            limits: None,
            name: None,
            version: None,
        });
        let mut writer = Vec::new();
        let err = client_handshake(&mut reader, &mut writer, &host, 1 << 20)
            .expect_err("no common format must reject");
        assert!(matches!(err, ExtensionError::NoCommonFormat { .. }));
    }
}
