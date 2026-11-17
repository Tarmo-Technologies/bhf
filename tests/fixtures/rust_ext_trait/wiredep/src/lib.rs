// SPDX-License-Identifier: Apache-2.0
//! A dependency that defines the decoding trait its users implement.

pub trait Decode: Sized {
    fn decode(bytes: &[u8]) -> Self;
}
