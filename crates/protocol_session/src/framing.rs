// SPDX-License-Identifier: Apache-2.0

//! How a protocol delimits its messages on the wire: a profile's `[framing]`.
//!
//! A real protocol frames its own messages: an HTTP request ends at a blank
//! line, a TLS record carries a 16-bit length, a fixed-size command block is
//! just its size, and many binary protocols put one message in one write and
//! answer with whatever they send back. The transport applies the profile's
//! framing to every request it writes and every reply it reads, and adds
//! nothing of its own.
//!
//! ```toml
//! [framing]
//! kind = "length_prefix"   # raw (the default) | length_prefix | length_field
//!                          # | delimiter | fixed
//! width = 2                # length_prefix: 1, 2 or 4 bytes; length_field:
//!                          # those or "varint"
//! endian = "big"           # length_prefix, length_field: big or little
//! includes_prefix = false  # length_prefix: whether the length counts itself
//! # offset = 4             # length_field: where in the message its length is
//! # delimiter = "\r\n"     # delimiter: what ends each message
//! # size = 16              # fixed: every message's size
//! # reply_idle_ms = 50     # raw: how long a reply may go quiet and be complete
//! ```
//!
//! A `length_field` protocol carries each message's length in its own header,
//! as Modbus/TCP's MBAP header (a big-endian u16 at byte 4) and MQTT's fixed
//! header (a variable byte integer at byte 1) do: the profile computes the
//! field like any other `length(..)`, the transport writes the request as it
//! is, and a reply is the whole message, header included, so captures index
//! it from its first byte.
//!
//! This module owns no socket: a transport feeds the bytes it has read to
//! [`Framing::take_reply`] until a reply is complete.

use serde::Deserialize;

use crate::profile::ByteOrder;

/// How long a raw reply may go quiet before it is taken as complete, when the
/// profile does not say.
pub const DEFAULT_REPLY_IDLE_MS: u64 = 50;

/// A protocol's message framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Framing {
    /// Each request is written as it is, and a reply is every byte that
    /// arrives until the peer goes quiet for `reply_idle_ms` (or closes).
    Raw { reply_idle_ms: u64 },
    /// Each message is preceded by its length in `width` bytes.
    LengthPrefix {
        width: u8,
        endian: ByteOrder,
        /// Whether the length counts the prefix as well as the message.
        includes_prefix: bool,
    },
    /// Each message carries its length in a field at byte `offset` of its
    /// own header, counting the bytes after the field. A request is written
    /// as it is, and a reply is the whole message.
    LengthField {
        offset: usize,
        width: LengthWidth,
        endian: ByteOrder,
    },
    /// Each message ends with `delimiter`, which is not part of the message.
    Delimiter { delimiter: Vec<u8> },
    /// Every message is `size` bytes: a shorter request is padded with zeros
    /// and a longer one cut to `size`.
    Fixed { size: usize },
}

impl Default for Framing {
    fn default() -> Self {
        Framing::Raw {
            reply_idle_ms: DEFAULT_REPLY_IDLE_MS,
        }
    }
}

/// How a [`Framing::LengthField`] length is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthWidth {
    /// An unsigned integer of 1, 2 or 4 bytes, in the framing's byte order.
    Bytes(u8),
    /// A variable byte integer, as MQTT's Remaining Length is: 7 bits a byte,
    /// least significant first, the high bit set on every byte but the last,
    /// at most 4 bytes.
    Varint,
}

/// The most bytes a [`LengthWidth::Varint`] length takes.
const VARINT_MAX_BYTES: usize = 4;

/// Where reading a reply has got to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplyProgress {
    /// A whole reply: its message bytes, and how many buffered bytes it took.
    Complete { reply: Vec<u8>, consumed: usize },
    /// Not yet; read more. A raw reply is never complete by its content.
    NeedMore,
    /// The buffered bytes cannot be a reply: a declared length beyond `max`.
    Invalid(String),
}

/// A request the framing cannot carry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot frame a {len}-byte request: {reason}")]
pub struct FramingError {
    pub len: usize,
    pub reason: String,
}

impl Framing {
    /// The request as it goes on the wire.
    pub fn encode(&self, message: &[u8]) -> Result<Vec<u8>, FramingError> {
        match self {
            // A length field is the message's own, which the profile computes.
            Framing::Raw { .. } | Framing::LengthField { .. } => Ok(message.to_vec()),
            Framing::LengthPrefix {
                width,
                endian,
                includes_prefix,
            } => {
                let width = usize::from(*width);
                let len = message.len() + if *includes_prefix { width } else { 0 };
                let limit = if width >= 8 {
                    u64::MAX
                } else {
                    (1u64 << (8 * width)) - 1
                };
                if len as u64 > limit {
                    return Err(FramingError {
                        len: message.len(),
                        reason: format!("its length does not fit the {width}-byte prefix"),
                    });
                }
                let be = (len as u64).to_be_bytes();
                let mut prefix = be[8 - width..].to_vec();
                if *endian == ByteOrder::Little {
                    prefix.reverse();
                }
                prefix.extend_from_slice(message);
                Ok(prefix)
            }
            Framing::Delimiter { delimiter } => {
                let mut out = message.to_vec();
                out.extend_from_slice(delimiter);
                Ok(out)
            }
            Framing::Fixed { size } => {
                let mut out = message.to_vec();
                out.resize(*size, 0);
                Ok(out)
            }
        }
    }

    /// The first reply in `buffered`, if it is all there. `max` bounds a
    /// reply's declared or accumulated size.
    pub fn take_reply(&self, buffered: &[u8], max: usize) -> ReplyProgress {
        match self {
            Framing::Raw { .. } => {
                if buffered.len() > max {
                    ReplyProgress::Invalid(format!("reply exceeds the {max}-byte cap"))
                } else {
                    ReplyProgress::NeedMore
                }
            }
            Framing::LengthPrefix {
                width,
                endian,
                includes_prefix,
            } => {
                let width = usize::from(*width);
                let Some(prefix) = buffered.get(..width) else {
                    return ReplyProgress::NeedMore;
                };
                let mut bytes = prefix.to_vec();
                if *endian == ByteOrder::Little {
                    bytes.reverse();
                }
                let declared = bytes.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
                let body = if *includes_prefix {
                    match declared.checked_sub(width as u64) {
                        Some(body) => body,
                        None => {
                            return ReplyProgress::Invalid(format!(
                                "declared length {declared} is shorter than its own \
                                 {width}-byte prefix"
                            ))
                        }
                    }
                } else {
                    declared
                };
                if body > max as u64 {
                    return ReplyProgress::Invalid(format!(
                        "reply length {body} exceeds the {max}-byte cap"
                    ));
                }
                let end = width + body as usize;
                match buffered.get(width..end) {
                    Some(reply) => ReplyProgress::Complete {
                        reply: reply.to_vec(),
                        consumed: end,
                    },
                    None => ReplyProgress::NeedMore,
                }
            }
            Framing::LengthField {
                offset,
                width,
                endian,
            } => {
                let (declared, field_len) =
                    match read_length_field(buffered, *offset, *width, *endian) {
                        Ok(Some(length)) => length,
                        Ok(None) => return ReplyProgress::NeedMore,
                        Err(reason) => return ReplyProgress::Invalid(reason),
                    };
                if declared > max as u64 {
                    return ReplyProgress::Invalid(format!(
                        "reply length {declared} exceeds the {max}-byte cap"
                    ));
                }
                let end = (offset + field_len).saturating_add(declared as usize);
                match buffered.get(..end) {
                    Some(reply) => ReplyProgress::Complete {
                        reply: reply.to_vec(),
                        consumed: end,
                    },
                    None => ReplyProgress::NeedMore,
                }
            }
            Framing::Delimiter { delimiter } => {
                match buffered
                    .windows(delimiter.len())
                    .position(|window| window == delimiter.as_slice())
                {
                    Some(at) => ReplyProgress::Complete {
                        reply: buffered[..at].to_vec(),
                        consumed: at + delimiter.len(),
                    },
                    None if buffered.len() > max => ReplyProgress::Invalid(format!(
                        "no delimiter within the {max}-byte reply cap"
                    )),
                    None => ReplyProgress::NeedMore,
                }
            }
            Framing::Fixed { size } => match buffered.get(..*size) {
                Some(reply) => ReplyProgress::Complete {
                    reply: reply.to_vec(),
                    consumed: *size,
                },
                None => ReplyProgress::NeedMore,
            },
        }
    }

    /// The reply in one datagram: the framing removed, or `Invalid` when the
    /// datagram does not hold a whole reply.
    pub fn datagram_reply(&self, datagram: &[u8], max: usize) -> ReplyProgress {
        match self {
            Framing::Raw { .. } if datagram.len() <= max => ReplyProgress::Complete {
                reply: datagram.to_vec(),
                consumed: datagram.len(),
            },
            _ => match self.take_reply(datagram, max) {
                ReplyProgress::NeedMore => {
                    ReplyProgress::Invalid("the datagram holds part of a reply".to_owned())
                }
                done => done,
            },
        }
    }

    /// How long a raw reply may go quiet before it is complete; `None` for a
    /// framing whose replies end by their content.
    pub fn reply_idle_ms(&self) -> Option<u64> {
        match self {
            Framing::Raw { reply_idle_ms } => Some(*reply_idle_ms),
            _ => None,
        }
    }

    /// A short label for a run summary: `raw`, `length_prefix(u16 big)`,
    /// `delimiter(0d0a)`, `fixed(16)`.
    pub fn label(&self) -> String {
        match self {
            Framing::Raw { .. } => "raw".to_owned(),
            Framing::LengthPrefix {
                width,
                endian,
                includes_prefix,
            } => format!(
                "length_prefix(u{} {}{})",
                u32::from(*width) * 8,
                match endian {
                    ByteOrder::Big => "big",
                    ByteOrder::Little => "little",
                },
                if *includes_prefix {
                    ", includes prefix"
                } else {
                    ""
                }
            ),
            Framing::LengthField {
                offset,
                width: LengthWidth::Varint,
                ..
            } => format!("length_field(varint at {offset})"),
            Framing::LengthField {
                offset,
                width: LengthWidth::Bytes(width),
                endian,
            } => format!(
                "length_field(u{} {} at {offset})",
                u32::from(*width) * 8,
                match endian {
                    ByteOrder::Big => "big",
                    ByteOrder::Little => "little",
                }
            ),
            Framing::Delimiter { delimiter } => format!(
                "delimiter({})",
                delimiter
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ),
            Framing::Fixed { size } => format!("fixed({size})"),
        }
    }
}

/// The length a [`Framing::LengthField`] declares at `offset`, and how many
/// bytes the field takes: `Ok(None)` until the field is all there.
fn read_length_field(
    buffered: &[u8],
    offset: usize,
    width: LengthWidth,
    endian: ByteOrder,
) -> Result<Option<(u64, usize)>, String> {
    match width {
        LengthWidth::Bytes(width) => {
            let width = usize::from(width);
            let Some(field) = buffered.get(offset..offset + width) else {
                return Ok(None);
            };
            let mut bytes = field.to_vec();
            if endian == ByteOrder::Little {
                bytes.reverse();
            }
            let length = bytes.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
            Ok(Some((length, width)))
        }
        LengthWidth::Varint => {
            let mut length = 0u64;
            for i in 0..VARINT_MAX_BYTES {
                let Some(&byte) = buffered.get(offset + i) else {
                    return Ok(None);
                };
                length |= u64::from(byte & 0x7f) << (7 * i);
                if byte & 0x80 == 0 {
                    return Ok(Some((length, i + 1)));
                }
            }
            Err(format!(
                "the variable byte integer at byte {offset} runs past {VARINT_MAX_BYTES} bytes"
            ))
        }
    }
}

/// A `width` as written: a byte count, or `"varint"`.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum WidthDef {
    Bytes(u8),
    Named(String),
}

/// The `[framing]` table as written.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FramingDef {
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    width: Option<WidthDef>,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    endian: Option<ByteOrder>,
    #[serde(default)]
    includes_prefix: Option<bool>,
    #[serde(default)]
    delimiter: Option<String>,
    #[serde(default)]
    size: Option<usize>,
    #[serde(default)]
    reply_idle_ms: Option<u64>,
}

impl FramingDef {
    /// The framing this table declares, or why it declares none.
    pub(crate) fn resolve(&self) -> Result<Framing, String> {
        let kind = self.kind.as_deref().unwrap_or("raw");
        let unused = |keys: &[(&str, bool)]| -> Result<(), String> {
            match keys.iter().find(|(_, set)| *set) {
                Some((key, _)) => Err(format!("`{key}` does not apply to {kind} framing")),
                None => Ok(()),
            }
        };
        let prefix_keys = [
            ("width", self.width.is_some()),
            ("endian", self.endian.is_some()),
            ("includes_prefix", self.includes_prefix.is_some()),
            ("offset", self.offset.is_some()),
        ];
        let framing = match kind {
            "raw" => {
                unused(&prefix_keys)?;
                unused(&[
                    ("delimiter", self.delimiter.is_some()),
                    ("size", self.size.is_some()),
                ])?;
                let reply_idle_ms = self.reply_idle_ms.unwrap_or(DEFAULT_REPLY_IDLE_MS);
                if reply_idle_ms == 0 {
                    return Err("`reply_idle_ms` must be at least 1".to_owned());
                }
                return Ok(Framing::Raw { reply_idle_ms });
            }
            "length_prefix" => {
                unused(&[
                    ("offset", self.offset.is_some()),
                    ("delimiter", self.delimiter.is_some()),
                    ("size", self.size.is_some()),
                ])?;
                Framing::LengthPrefix {
                    width: self.byte_width("1, 2 or 4")?,
                    endian: self.endian.unwrap_or(ByteOrder::Big),
                    includes_prefix: self.includes_prefix.unwrap_or(false),
                }
            }
            "length_field" => {
                unused(&[
                    ("includes_prefix", self.includes_prefix.is_some()),
                    ("delimiter", self.delimiter.is_some()),
                    ("size", self.size.is_some()),
                ])?;
                let width = match &self.width {
                    Some(WidthDef::Named(name)) if name == "varint" => {
                        if self.endian.is_some() {
                            return Err("`endian` does not apply to a varint length".to_owned());
                        }
                        LengthWidth::Varint
                    }
                    _ => LengthWidth::Bytes(self.byte_width("1, 2, 4 or \"varint\"")?),
                };
                Framing::LengthField {
                    offset: self.offset.unwrap_or(0),
                    width,
                    endian: self.endian.unwrap_or(ByteOrder::Big),
                }
            }
            "delimiter" => {
                unused(&prefix_keys)?;
                unused(&[("size", self.size.is_some())])?;
                let delimiter = self
                    .delimiter
                    .as_deref()
                    .ok_or("delimiter framing needs `delimiter`")?;
                if delimiter.is_empty() {
                    return Err("`delimiter` is empty".to_owned());
                }
                Framing::Delimiter {
                    delimiter: delimiter.as_bytes().to_vec(),
                }
            }
            "fixed" => {
                unused(&prefix_keys)?;
                unused(&[("delimiter", self.delimiter.is_some())])?;
                let size = self.size.ok_or("fixed framing needs `size`")?;
                if size == 0 {
                    return Err("`size` must be at least 1".to_owned());
                }
                Framing::Fixed { size }
            }
            other => {
                return Err(format!(
                    "unknown framing kind {other:?}; expected raw, length_prefix, length_field, \
                     delimiter or fixed"
                ))
            }
        };
        if self.reply_idle_ms.is_some() {
            return Err(format!("`reply_idle_ms` does not apply to {kind} framing"));
        }
        Ok(framing)
    }

    /// The `width` as a byte count, 2 when the table gives none; `expected`
    /// names the widths the framing takes.
    fn byte_width(&self, expected: &str) -> Result<u8, String> {
        match &self.width {
            None => Ok(2),
            Some(WidthDef::Bytes(width @ (1 | 2 | 4))) => Ok(*width),
            Some(WidthDef::Bytes(width)) => Err(format!("`width` is {width}; expected {expected}")),
            Some(WidthDef::Named(name)) => Err(format!("`width` is {name:?}; expected {expected}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve(toml_text: &str) -> Result<Framing, String> {
        toml::from_str::<FramingDef>(toml_text)
            .map_err(|e| e.to_string())?
            .resolve()
    }

    #[test]
    fn raw_is_the_default_and_completes_only_when_the_peer_goes_quiet() {
        let raw = resolve("").unwrap();
        assert_eq!(raw, Framing::default());
        assert_eq!(raw.reply_idle_ms(), Some(DEFAULT_REPLY_IDLE_MS));
        assert_eq!(raw.encode(b"PING").unwrap(), b"PING");
        assert_eq!(raw.take_reply(b"PONG", 64), ReplyProgress::NeedMore);
        assert!(matches!(
            raw.take_reply(&[0; 65], 64),
            ReplyProgress::Invalid(_)
        ));
        assert_eq!(
            raw.datagram_reply(b"PONG", 64),
            ReplyProgress::Complete {
                reply: b"PONG".to_vec(),
                consumed: 4
            }
        );
        assert_eq!(
            resolve("reply_idle_ms = 200").unwrap(),
            Framing::Raw { reply_idle_ms: 200 }
        );
    }

    #[test]
    fn a_length_prefix_is_written_and_read_at_its_width_and_byte_order() {
        let u16_be = resolve("kind = \"length_prefix\"").unwrap();
        assert_eq!(u16_be.label(), "length_prefix(u16 big)");
        assert_eq!(u16_be.encode(b"abc").unwrap(), b"\x00\x03abc");
        assert_eq!(
            u16_be.take_reply(b"\x00\x03ab", 64),
            ReplyProgress::NeedMore
        );
        assert_eq!(
            u16_be.take_reply(b"\x00\x03abcNEXT", 64),
            ReplyProgress::Complete {
                reply: b"abc".to_vec(),
                consumed: 5
            }
        );
        assert!(matches!(
            u16_be.take_reply(b"\xff\xff", 64),
            ReplyProgress::Invalid(_)
        ));

        let u32_le_inclusive = resolve(
            "kind = \"length_prefix\"\nwidth = 4\nendian = \"little\"\nincludes_prefix = true",
        )
        .unwrap();
        assert_eq!(
            u32_le_inclusive.encode(b"ab").unwrap(),
            b"\x06\x00\x00\x00ab"
        );
        assert_eq!(
            u32_le_inclusive.take_reply(b"\x06\x00\x00\x00ab", 64),
            ReplyProgress::Complete {
                reply: b"ab".to_vec(),
                consumed: 6
            }
        );
        assert!(matches!(
            u32_le_inclusive.take_reply(b"\x02\x00\x00\x00", 64),
            ReplyProgress::Invalid(_)
        ));

        let u8_prefix = resolve("kind = \"length_prefix\"\nwidth = 1").unwrap();
        assert!(u8_prefix.encode(&[0; 256]).is_err());
        assert_eq!(u8_prefix.encode(&[7; 255]).unwrap().len(), 256);
    }

    #[test]
    fn a_length_field_in_the_message_header_ends_the_reply_and_stays_in_it() {
        // Modbus/TCP: the MBAP length, a big-endian u16 at byte 4, counts the
        // unit id and the PDU after it.
        let mbap = resolve("kind = \"length_field\"\noffset = 4").unwrap();
        assert_eq!(mbap.label(), "length_field(u16 big at 4)");
        let request = [0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 1];
        assert_eq!(
            mbap.encode(&request).unwrap(),
            request,
            "the request carries its own length"
        );
        let reply = [0, 1, 0, 0, 0, 5, 1, 3, 2, 0xbe, 0xef];
        assert_eq!(mbap.take_reply(&reply[..5], 64), ReplyProgress::NeedMore);
        assert_eq!(mbap.take_reply(&reply[..10], 64), ReplyProgress::NeedMore);
        let mut two = reply.to_vec();
        two.extend_from_slice(&reply);
        assert_eq!(
            mbap.take_reply(&two, 64),
            ReplyProgress::Complete {
                reply: reply.to_vec(),
                consumed: 11
            }
        );
        assert!(matches!(
            mbap.take_reply(&[0, 1, 0, 0, 0xff, 0xff], 64),
            ReplyProgress::Invalid(_)
        ));

        let u32_le =
            resolve("kind = \"length_field\"\noffset = 1\nwidth = 4\nendian = \"little\"").unwrap();
        assert_eq!(u32_le.label(), "length_field(u32 little at 1)");
        assert_eq!(
            u32_le.take_reply(b"\x07\x02\x00\x00\x00abX", 64),
            ReplyProgress::Complete {
                reply: b"\x07\x02\x00\x00\x00ab".to_vec(),
                consumed: 7
            }
        );
    }

    #[test]
    fn a_varint_length_field_reads_an_mqtt_remaining_length() {
        let mqtt = resolve("kind = \"length_field\"\noffset = 1\nwidth = \"varint\"").unwrap();
        assert_eq!(mqtt.label(), "length_field(varint at 1)");
        // CONNACK: a one-byte remaining length, then the next packet.
        assert_eq!(
            mqtt.take_reply(&[0x20, 0x02, 0x00, 0x00, 0xd0], 64),
            ReplyProgress::Complete {
                reply: vec![0x20, 0x02, 0x00, 0x00],
                consumed: 4
            }
        );
        // 200 bytes take two: 0xc8 (0x48 and more to come), then 0x01.
        let mut publish = vec![0x30, 0xc8, 0x01];
        publish.extend_from_slice(&[7; 200]);
        assert_eq!(mqtt.take_reply(&publish[..2], 512), ReplyProgress::NeedMore);
        assert_eq!(
            mqtt.take_reply(&publish[..202], 512),
            ReplyProgress::NeedMore
        );
        assert_eq!(
            mqtt.take_reply(&publish, 512),
            ReplyProgress::Complete {
                reply: publish.clone(),
                consumed: 203
            }
        );
        assert!(matches!(
            mqtt.take_reply(&publish, 100),
            ReplyProgress::Invalid(_)
        ));
        let ReplyProgress::Invalid(reason) =
            mqtt.take_reply(&[0x30, 0xff, 0xff, 0xff, 0xff, 0x01], 1 << 30)
        else {
            panic!("a fifth length byte is not a variable byte integer");
        };
        assert!(reason.contains("runs past 4 bytes"), "{reason}");
        assert_eq!(
            mqtt.datagram_reply(&[0xd0, 0x00], 64),
            ReplyProgress::Complete {
                reply: vec![0xd0, 0x00],
                consumed: 2
            }
        );
    }

    #[test]
    fn a_delimiter_ends_each_message_and_is_not_part_of_it() {
        let crlf = resolve("kind = \"delimiter\"\ndelimiter = \"\\r\\n\"").unwrap();
        assert_eq!(crlf.label(), "delimiter(0d0a)");
        assert_eq!(crlf.encode(b"USER x").unwrap(), b"USER x\r\n");
        assert_eq!(crlf.take_reply(b"331 ok\r", 64), ReplyProgress::NeedMore);
        assert_eq!(
            crlf.take_reply(b"331 ok\r\n230", 64),
            ReplyProgress::Complete {
                reply: b"331 ok".to_vec(),
                consumed: 8
            }
        );
        assert!(matches!(
            crlf.take_reply(&[b'x'; 65], 64),
            ReplyProgress::Invalid(_)
        ));
        assert!(matches!(
            crlf.datagram_reply(b"no end", 64),
            ReplyProgress::Invalid(_)
        ));
    }

    #[test]
    fn a_fixed_size_message_is_padded_or_cut_to_its_size() {
        let fixed = resolve("kind = \"fixed\"\nsize = 4").unwrap();
        assert_eq!(fixed.encode(b"ab").unwrap(), b"ab\x00\x00");
        assert_eq!(fixed.encode(b"abcdef").unwrap(), b"abcd");
        assert_eq!(fixed.take_reply(b"abc", 64), ReplyProgress::NeedMore);
        assert_eq!(
            fixed.take_reply(b"abcdef", 64),
            ReplyProgress::Complete {
                reply: b"abcd".to_vec(),
                consumed: 4
            }
        );
    }

    #[test]
    fn a_framing_table_that_does_not_add_up_is_refused() {
        for (table, expected) in [
            ("kind = \"length_prefix\"\nwidth = 3", "expected 1, 2 or 4"),
            ("kind = \"delimiter\"", "needs `delimiter`"),
            ("kind = \"fixed\"", "needs `size`"),
            (
                "kind = \"fixed\"\nsize = 4\nwidth = 2",
                "`width` does not apply",
            ),
            (
                "kind = \"length_prefix\"\nreply_idle_ms = 5",
                "`reply_idle_ms` does not apply",
            ),
            (
                "kind = \"length_field\"\nwidth = \"varint\"\nendian = \"big\"",
                "`endian` does not apply to a varint length",
            ),
            (
                "kind = \"length_field\"\nwidth = \"nibble\"",
                "expected 1, 2, 4 or \"varint\"",
            ),
            (
                "kind = \"length_field\"\nwidth = 3",
                "expected 1, 2, 4 or \"varint\"",
            ),
            (
                "kind = \"length_field\"\nincludes_prefix = true",
                "`includes_prefix` does not apply",
            ),
            (
                "kind = \"length_prefix\"\noffset = 4",
                "`offset` does not apply",
            ),
            (
                "kind = \"length_prefix\"\nwidth = \"varint\"",
                "expected 1, 2 or 4",
            ),
            ("offset = 1", "`offset` does not apply"),
            ("kind = \"cobs\"", "unknown framing kind"),
            ("reply_idle_ms = 0", "at least 1"),
            ("knd = \"raw\"", "unknown field"),
        ] {
            let error = resolve(table).unwrap_err();
            assert!(error.contains(expected), "{table}: {error}");
        }
    }
}
