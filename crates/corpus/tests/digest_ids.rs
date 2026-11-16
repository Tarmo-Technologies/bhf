// SPDX-License-Identifier: Apache-2.0

//! Ids and signatures derived from SHA-256 digests keep their spelling across
//! sha2 releases: lowercase hex, two digits a byte. The expected values were
//! computed with `sha256sum`, not with this code.

#[test]
fn a_digest_is_spelled_as_lowercase_hex() {
    use sha2::Digest;
    assert_eq!(
        corpus::hex_lower(&sha2::Sha256::digest(b"widget")),
        "8ac140ceb6ca8d6e51a987a9828b9f97b95bbc3ae6bdb0558e2631cb8da232b8"
    );
    assert_eq!(corpus::hex_lower(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
    assert_eq!(corpus::hex_lower(&[]), "");
}

#[test]
fn an_extension_finding_signature_is_unchanged() {
    // `printf 'extension\x1fwidget\x1fcopy_at' | sha256sum`
    assert_eq!(
        corpus::finding::extension_signature(&["widget".to_owned(), "copy_at".to_owned()]),
        "296b38353d55270845b356cb6d6442b71b0a0adabbda1eccebc83eb97695f3ae"
    );
}
