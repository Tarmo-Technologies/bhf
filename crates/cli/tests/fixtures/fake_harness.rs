// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Result};

fn main() -> Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let event_path = std::env::var("BHF_EVENTS_PATH").map_err(std::io::Error::other)?;
    let mut bytes = Vec::new();
    push_begin(&mut bytes, 1);
    push_target(&mut bytes, 0x42);
    push_crumb(&mut bytes, 1);
    // Exceptions that escape the target: an explicit raise with a message,
    // and a failed runtime check GNAT locates in its message.
    match input.as_str() {
        "escaped" => {
            push_raise(&mut bytes, "Program_Error", "widgets.adb", 6, 1);
            push_top_level(&mut bytes, "PROGRAM_ERROR", "empty record");
            push_end(&mut bytes, 0);
            return std::fs::write(event_path, bytes);
        }
        "index" => {
            push_top_level(
                &mut bytes,
                "CONSTRAINT_ERROR",
                "widgets.adb:16 index check failed",
            );
            push_end(&mut bytes, 0);
            return std::fs::write(event_path, bytes);
        }
        // A user exception raised and caught, then a failed check in the
        // handler that escapes.
        "handled-then-escaped" => {
            push_crumb(&mut bytes, 4);
            push_raise(&mut bytes, "Widget_Error", "widgets.adb", 17, 4);
            push_handler(
                &mut bytes,
                HandlerFields {
                    exception_name: "WIDGET_ERROR",
                    exception_message: "bad widget",
                    handler_file: "widgets.adb",
                    handler_line: 21,
                    last_breadcrumb: 4,
                    target_id: 0x42,
                    testcase_id: 1,
                },
            );
            push_top_level(
                &mut bytes,
                "CONSTRAINT_ERROR",
                "widgets.adb:22 index check failed",
            );
            push_end(&mut bytes, 0);
            return std::fs::write(event_path, bytes);
        }
        _ => {}
    }
    let handler_line = match input.as_str() {
        "match" => 9,
        "mismatch" => 10,
        _ if input.contains("crash") => 9,
        _ => 10,
    };
    push_handler(
        &mut bytes,
        HandlerFields {
            exception_name: "CONSTRAINT_ERROR",
            exception_message: "bad input",
            handler_file: "pkg.adb",
            handler_line,
            last_breadcrumb: 1,
            target_id: 0x42,
            testcase_id: 1,
        },
    );
    push_end(&mut bytes, 0);
    std::fs::write(event_path, bytes)
}

fn push_begin(bytes: &mut Vec<u8>, testcase_id: u64) {
    bytes.push(1);
    bytes.extend_from_slice(&testcase_id.to_le_bytes());
}

fn push_end(bytes: &mut Vec<u8>, result_class: u8) {
    bytes.push(2);
    bytes.push(result_class);
}

fn push_crumb(bytes: &mut Vec<u8>, id: u32) {
    bytes.push(3);
    bytes.extend_from_slice(&id.to_le_bytes());
}

fn push_target(bytes: &mut Vec<u8>, id: u32) {
    bytes.push(4);
    bytes.extend_from_slice(&id.to_le_bytes());
}

struct HandlerFields<'a> {
    exception_name: &'a str,
    exception_message: &'a str,
    handler_file: &'a str,
    handler_line: u32,
    last_breadcrumb: u32,
    target_id: u32,
    testcase_id: u64,
}

fn push_handler(bytes: &mut Vec<u8>, fields: HandlerFields<'_>) {
    bytes.push(5);
    push_string(bytes, fields.exception_name);
    push_string(bytes, fields.exception_message);
    push_string(bytes, fields.handler_file);
    bytes.extend_from_slice(&fields.handler_line.to_le_bytes());
    bytes.extend_from_slice(&fields.last_breadcrumb.to_le_bytes());
    bytes.extend_from_slice(&fields.target_id.to_le_bytes());
    bytes.extend_from_slice(&fields.testcase_id.to_le_bytes());
}

fn push_string(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn push_raise(bytes: &mut Vec<u8>, name: &str, file: &str, line: u32, breadcrumb: u32) {
    bytes.push(6);
    push_string(bytes, name);
    push_string(bytes, file);
    bytes.extend_from_slice(&line.to_le_bytes());
    bytes.extend_from_slice(&breadcrumb.to_le_bytes());
}

fn push_top_level(bytes: &mut Vec<u8>, name: &str, message: &str) {
    bytes.push(8);
    push_string(bytes, name);
    push_string(bytes, message);
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&0x42_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u64.to_le_bytes());
}
