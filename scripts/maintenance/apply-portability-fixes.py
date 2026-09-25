#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One-shot, hash-pinned source edits for a reviewed portability repair.

This helper and its workflow are removed from the tested result commit.
It deliberately cannot apply to unknown versions or overwrite local edits.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import subprocess

EXPECTED = {
    "crates/governance/src/lib.rs": "4815be81f11a650b0897951ab5a71eb118cfe24a",
    "crates/daemon/src/lib.rs": "6899260b3ddd03f76003de63f9a7e2635b32c3fa",
    ".github/workflows/ci.yml": "0253d24bcbe3b5f31ead950676ee5237532868a6",
}

OLD_DAEMON_TEST = r'''    #[test]
    fn oversized_request_id_uses_compact_error_without_losing_frame_alignment() {
        let source = temp_dir("large-request-id").join("many.c");
        let functions = (0..30)
            .map(|index| format!("int f{index}(int x) {{ return x; }}\n"))
            .collect::<String>();
        fs::write(&source, functions).unwrap();
        let id = "x".repeat(380);
        let input = format!(
            "{}{}",
            frame(serde_json::json!({
                "jsonrpc": "2.0", "id": id, "method": "listTargets",
                "params": { "path": source }
            })),
            frame(serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "missingMethod"
            }))
        );
        let mut output = Vec::new();
        super::run_json_rpc_with_limit(
            BufReader::new(input.as_bytes()),
            &mut output,
            super::DaemonSecurityConfig::local_single_user(),
            512,
        )
        .unwrap();
        let responses = parse_frames(&output);
        assert_eq!(responses.len(), 2);
        assert!(responses[0]["id"].is_null());
        assert_eq!(responses[0]["error"]["code"], -32000);
        assert_eq!(responses[1]["id"], 2);
    }
'''

NEW_DAEMON_TEST = r'''    #[test]
    fn oversized_request_id_uses_compact_error_without_losing_frame_alignment() {
        // Keep this framing test independent of temporary-directory lengths,
        // Windows path escaping, source discovery, and compiler availability.
        // The request must fit; both the normal and ID-preserving error
        // responses must exceed the same budget to exercise the compact path.
        let limit = 512;
        let id = "x".repeat(450);
        let request = serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "missingMethod"
        });
        assert!(serde_json::to_vec(&request).unwrap().len() <= limit);
        let normal = super::error_response(
            request["id"].clone(),
            super::RpcFailure::method_not_found(),
        );
        assert!(serde_json::to_vec(&normal).unwrap().len() > limit);
        let input = format!(
            "{}{}",
            frame(request),
            frame(serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "missingMethod"
            }))
        );
        let mut output = Vec::new();
        super::run_json_rpc_with_limit(
            BufReader::new(input.as_bytes()),
            &mut output,
            super::DaemonSecurityConfig::local_single_user(),
            limit,
        )
        .unwrap();
        let responses = parse_frames(&output);
        assert_eq!(responses.len(), 2);
        assert!(responses[0]["id"].is_null());
        assert_eq!(responses[0]["error"]["code"], -32000);
        assert_eq!(responses[0]["error"]["message"], "response exceeds byte limit");
        assert_eq!(responses[1]["id"], 2);
        assert_eq!(responses[1]["error"]["code"], -32601);
        let mut reader = BufReader::new(output.as_slice());
        assert!(super::read_frame_with_limit(&mut reader, limit).unwrap().is_some());
        assert!(super::read_frame_with_limit(&mut reader, limit).unwrap().is_some());
        assert!(super::read_frame_with_limit(&mut reader, limit).unwrap().is_none());
    }

    #[test]
    fn json_rpc_reader_accepts_exact_body_limit_and_preserves_next_frame() {
        let limit = 512;
        let mut request = serde_json::json!({
            "jsonrpc": "2.0", "id": "", "method": "missingMethod"
        });
        let overhead = serde_json::to_vec(&request).unwrap().len();
        request["id"] = serde_json::json!("x".repeat(limit - overhead));
        let body = serde_json::to_vec(&request).unwrap();
        assert_eq!(body.len(), limit);
        let next = serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "missingMethod"});
        let stream = format!("{}{}", frame(request), frame(next.clone()));
        let mut reader = BufReader::new(stream.as_bytes());
        assert_eq!(super::read_frame_with_limit(&mut reader, limit).unwrap(), Some(body));
        assert_eq!(super::read_frame_with_limit(&mut reader, limit).unwrap(),
            Some(serde_json::to_vec(&next).unwrap()));
        assert!(super::read_frame_with_limit(&mut reader, limit).unwrap().is_none());
    }

    #[test]
    fn json_rpc_reader_rejects_body_one_byte_above_limit() {
        let limit = 512;
        let mut request = serde_json::json!({
            "jsonrpc": "2.0", "id": "", "method": "missingMethod"
        });
        let overhead = serde_json::to_vec(&request).unwrap().len();
        request["id"] = serde_json::json!("x".repeat(limit + 1 - overhead));
        assert_eq!(serde_json::to_vec(&request).unwrap().len(), limit + 1);
        let stream = frame(request);
        let error = super::read_frame_with_limit(
            &mut BufReader::new(stream.as_bytes()), limit,
        ).unwrap_err();
        assert!(error.to_string().contains("frame exceeds"), "{error}");
    }
'''


NEW_DAEMON_TEST += r'''
    #[test]
    fn json_rpc_reader_rejects_duplicate_content_lengths() {
        for (second_name, second_length) in [
            ("Content-Length", "2"),
            ("content-length", "2"),
            ("CONTENT-LENGTH", "3"),
        ] {
            let input = format!("Content-Length: 2\r\n{second_name}: {second_length}\r\n\r\n{{}}");
            let error = super::read_frame_with_limit(
                &mut BufReader::new(input.as_bytes()), 512,
            ).unwrap_err();
            assert!(error.to_string().contains("duplicate Content-Length"), "{error}");
        }
    }

    #[test]
    fn json_rpc_reader_requires_unsigned_decimal_content_length() {
        for length in ["", "+2", "-2", "2.0", "0x2", "\u{0662}"] {
            let input = format!("Content-Length: {length}\r\n\r\n{{}}");
            let error = super::read_frame_with_limit(
                &mut BufReader::new(input.as_bytes()), 512,
            ).unwrap_err();
            assert!(error.to_string().contains("invalid Content-Length"), "{error}");
        }
    }
'''


def replace_once(text: str, before: str, after: str) -> str:
    if text.count(before) != 1:
        raise RuntimeError("reviewed edit context is missing or ambiguous")
    return text.replace(before, after, 1)


def transform(path: str, text: str) -> str:
    if path == "crates/governance/src/lib.rs":
        text = replace_once(text,
            "        let status = unsafe {\n            libc::renameat2(\n",
            "        // Call the kernel interface without requiring glibc's renameat2\n"
            "        // wrapper (introduced in glibc 2.28). Keep RENAME_NOREPLACE:\n"
            "        // unsupported kernels/filesystems must fail, never fall back\n"
            "        // to a check-then-rename sequence that can overwrite a winner.\n"
            "        // SAFETY: both CString pointers remain valid through this call;\n"
            "        // the syscall number and arguments match Linux renameat2(2).\n"
            "        let status = unsafe {\n"
            "            libc::syscall(\n"
            "                libc::SYS_renameat2,\n")
        return text + '\n#[cfg(all(test, target_os = "linux"))]\nmod publication_tests;\n'
    if path == "crates/daemon/src/lib.rs":
        text = replace_once(text, OLD_DAEMON_TEST, NEW_DAEMON_TEST)
        return replace_once(text,
            "                content_length = Some(value.trim().parse::<usize>().map_err(|error| {\n",
            "                if content_length.is_some() {\n"
            "                    return Err(JsonRpcServerError::InvalidFrame(\n"
            "                        \"duplicate Content-Length header\".to_owned(),\n"
            "                    ));\n"
            "                }\n"
            "                let digits = value.trim();\n"
            "                if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {\n"
            "                    return Err(JsonRpcServerError::InvalidFrame(\n"
            "                        \"invalid Content-Length: expected unsigned decimal digits\".to_owned(),\n"
            "                    ));\n"
            "                }\n"
            "                content_length = Some(digits.parse::<usize>().map_err(|error| {\n")
    if path == ".github/workflows/ci.yml":
        return replace_once(text,
            "              cargo test --locked -p bhf --test offline_dist_scripts -- --nocapture\n",
            "              cargo test --locked -p governance --lib\n"
            "              cargo test --locked -p bhf --test offline_dist_scripts -- --nocapture\n")
    raise ValueError(path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True)
    args = parser.parse_args()
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True, timeout=10).strip()
    if head != args.expected_head:
        raise RuntimeError("checkout is not the requested exact revision")
    subprocess.run(["git", "diff", "--exit-code"], check=True, timeout=10)
    subprocess.run(["git", "diff", "--cached", "--exit-code"], check=True, timeout=10)
    edits: dict[Path, bytes] = {}
    for name, expected in EXPECTED.items():
        raw = subprocess.check_output(["git", "show", f"HEAD:{name}"], timeout=10)
        actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if actual != expected:
            raise RuntimeError(f"{name}: refusing an unreviewed source version ({actual})")
        edits[Path(name)] = transform(name, raw.decode("utf-8")).encode("utf-8")
    for path, data in edits.items():
        path.write_bytes(data)
    subprocess.run(["git", "diff", "--check"], check=True, timeout=10)
    print("Applied three hash-pinned edits; original runtime limits and no-overwrite flags retained.")


if __name__ == "__main__":
    main()
