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
//! kind = "length_prefix"   # raw (the default) | length_prefix | delimiter | fixed
//! width = 2                # length_prefix: 1, 2 or 4 bytes
//! endian = "big"           # length_prefix: big or little
//! includes_prefix = false  # length_prefix: whether the length counts itself
//! # delimiter = "\r\n"     # delimiter: what ends each message
//! # size = 16              # fixed: every message's size
//! # reply_idle_ms = 50     # raw: how long a reply may go quiet and be complete
//! ```
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
            Framing::Raw { .. } => Ok(message.to_vec()),
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

/// The `[framing]` table as written.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FramingDef {
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    width: Option<u8>,
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
                    ("delimiter", self.delimiter.is_some()),
                    ("size", self.size.is_some()),
                ])?;
                let width = self.width.unwrap_or(2);
                if !matches!(width, 1 | 2 | 4) {
                    return Err(format!("`width` is {width}; expected 1, 2 or 4"));
                }
                Framing::LengthPrefix {
                    width,
                    endian: self.endian.unwrap_or(ByteOrder::Big),
                    includes_prefix: self.includes_prefix.unwrap_or(false),
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
                    "unknown framing kind {other:?}; expected raw, length_prefix, delimiter \
                     or fixed"
                ))
            }
        };
        if self.reply_idle_ms.is_some() {
            return Err(format!("`reply_idle_ms` does not apply to {kind} framing"));
        }
        Ok(framing)
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
            ("kind = \"cobs\"", "unknown framing kind"),
            ("reply_idle_ms = 0", "at least 1"),
            ("knd = \"raw\"", "unknown field"),
        ] {
            let error = resolve(table).unwrap_err();
            assert!(error.contains(expected), "{table}: {error}");
        }
    }
}
