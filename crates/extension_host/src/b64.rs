// SPDX-License-Identifier: Apache-2.0

//! A tiny, dependency-free standard base64 (RFC 4648) codec.
//!
//! Test inputs are arbitrary bytes, not valid UTF-8, so the `oracle.evaluate`
//! payload carries them base64-encoded in a JSON string. We hand-roll the codec
//! here rather than add a crate: it keeps the RHEL 7 / Windows-MSVC / cross
//! matrices dependency-free, and the out-of-tree reference extensions use their
//! own language's stdlib base64 (Python's `base64`, etc.), which must agree with
//! this one byte-for-byte.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const PAD: u8 = b'=';

/// Encode bytes as standard base64 with padding.
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0b11) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(((b1 & 0b1111) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push(PAD as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(b2 & 0b111111) as usize] as char);
        } else {
            out.push(PAD as char);
        }
    }
    out
}

/// Decode standard base64 with padding, rejecting any malformed input with a
/// descriptive error (never a silent partial result).
pub fn decode(input: &str) -> Result<Vec<u8>, String> {
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err(format!(
            "base64 length {} is not a multiple of 4",
            bytes.len()
        ));
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (block_idx, block) in bytes.chunks(4).enumerate() {
        let mut vals = [0u8; 4];
        let mut pad = 0usize;
        for (i, &c) in block.iter().enumerate() {
            if c == PAD {
                // Padding is only legal in the final block's last positions.
                if block_idx != bytes.len() / 4 - 1 || i < 2 {
                    return Err("misplaced base64 padding".to_string());
                }
                pad += 1;
                vals[i] = 0;
            } else {
                if pad != 0 {
                    return Err("base64 data byte after padding".to_string());
                }
                vals[i] = decode_symbol(c)?;
            }
        }
        let n = (u32::from(vals[0]) << 18)
            | (u32::from(vals[1]) << 12)
            | (u32::from(vals[2]) << 6)
            | u32::from(vals[3]);
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

fn decode_symbol(c: u8) -> Result<u8, String> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        other => Err(format!("invalid base64 symbol: 0x{other:02x}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_arbitrary_bytes_including_non_utf8() {
        for case in [
            b"".to_vec(),
            b"f".to_vec(),
            b"fo".to_vec(),
            b"foo".to_vec(),
            b"foob".to_vec(),
            b"fooba".to_vec(),
            b"foobar".to_vec(),
            vec![0x00, 0xff, 0x80, 0x7f, 0x01, 0xfe],
        ] {
            let encoded = encode(&case);
            let decoded = decode(&encoded).expect("roundtrip decode");
            assert_eq!(decoded, case, "failed roundtrip for {case:?}");
        }
    }

    #[test]
    fn matches_known_vectors() {
        // RFC 4648 test vectors.
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(decode("Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(decode("abc").is_err(), "length not multiple of 4");
        assert!(decode("ab*d").is_err(), "invalid symbol");
        assert!(decode("a=cd").is_err(), "misplaced padding");
    }
}
