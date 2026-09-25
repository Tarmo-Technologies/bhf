// SPDX-License-Identifier: Apache-2.0

//! Host-side readers for the two off-host coverage channels that the Ada
//! runtime already emits but nothing yet consumes.
//!
//! Both channels carry the same `BHF_EVENTS` tag-length event stream defined by
//! `ada_runtime/adafuzz-probe.adb` and decoded by [`event_log::EventReader`]
//! (the wire-format source of truth). This module reuses that reader and adds:
//!
//! * [`SemihostingReader`] — the stream arrives as a flat byte channel (the
//!   semihosting `fd 2` writer, `ada_runtime/adafuzz-probe-semihosting.adb`).
//! * [`MemoryBufferReader`] — the stream lives in the 64 KiB in-RAM ring
//!   exported as `adafuzz_probe_memory_buffer` with companion
//!   `_write` / `_wrapped` / `_capacity` symbols
//!   (`ada_runtime/adafuzz-probe-memory_buffer.adb`); the reader honors the
//!   wrap so the in-order byte stream is reconstructed before decoding.
//!
//! Coverage edges are the `Crumb` breadcrumb ids — the edge markers the
//! source-rewrite instrumenter plants (`crates/instrumenter/src/breadcrumbs.rs`).
//! `Target` ids identify the entered target function, not an edge, so they are
//! not treated as coverage.

use crate::error::Result;
use crate::outcome::RunOutcome;
use event_log::{Event, EventReader};

/// Extract coverage edge ids from a decoded event slice.
///
/// Edges are the `Crumb` breadcrumb ids, in emission order (multiplicity
/// preserved — the engine's bitmap deduplicates downstream; a raw trace keeps
/// loop/repeat structure available to callers that want it).
pub fn edges_from_events(events: &[Event]) -> Vec<u32> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Crumb { id } => Some(*id),
            _ => None,
        })
        .collect()
}

/// Decode every event from `bytes` (a linear `BHF_EVENTS` stream).
fn decode_events(bytes: &[u8]) -> Result<Vec<Event>> {
    let events = EventReader::new(bytes)
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(events)
}

/// Reader for the semihosting coverage channel.
///
/// The semihosting probe writes the `BHF_EVENTS` stream verbatim to a byte
/// channel (`fd 2`). On the host that channel is whatever the debug adapter
/// hands us — a captured file, a socket, an emulator semihosting sink — so the
/// reader is generic over [`std::io::Read`].
pub struct SemihostingReader<R: std::io::Read> {
    inner: R,
}

impl<R: std::io::Read> SemihostingReader<R> {
    /// Wrap a byte channel carrying the semihosting event stream.
    pub fn new(inner: R) -> Self {
        Self { inner }
    }

    /// Decode the full event stream.
    pub fn read_events(self) -> Result<Vec<Event>> {
        let events = EventReader::new(self.inner)
            .into_iter()
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(events)
    }

    /// Decode the stream and return just the coverage edge ids.
    pub fn read_edges(self) -> Result<Vec<u32>> {
        Ok(edges_from_events(&self.read_events()?))
    }
}

/// Reader for the in-RAM ring-buffer coverage channel.
///
/// Constructed from a raw ring image plus the companion control words a debug
/// probe / emulator reads out of target memory:
///
/// * `image` — the bytes of `adafuzz_probe_memory_buffer` (`_capacity` long).
/// * `write` — `adafuzz_probe_memory_buffer_write`, the next-write index.
/// * `wrapped` — `adafuzz_probe_memory_buffer_wrapped` (`0`/`1`).
///
/// The Ada `Write_Byte` fills the ring linearly and, on reaching the last slot,
/// resets `write` to 0 and sets `wrapped`. [`MemoryBufferReader::linearize`]
/// inverts that: unwrapped, the live bytes are `image[..write]`; wrapped, the
/// oldest surviving byte is at `image[write]`, so the in-order stream is
/// `image[write..]` followed by `image[..write]`.
#[derive(Debug, Clone)]
pub struct MemoryBufferReader {
    image: Vec<u8>,
    write: usize,
    wrapped: bool,
}

impl MemoryBufferReader {
    /// The capacity the Ada `memory_buffer` backend exports
    /// (`adafuzz_probe_memory_buffer_capacity`).
    pub const ADA_CAPACITY: usize = 65_536;

    /// Build a reader from a captured ring image and its control words.
    ///
    /// `write` must index within the image; a wrapped ring must be non-empty.
    /// Both are validated so a corrupt capture surfaces as a descriptive error
    /// rather than a later panic.
    pub fn new(image: Vec<u8>, write: u32, wrapped: bool) -> Result<Self> {
        let write = write as usize;
        if write > image.len() {
            return Err(crate::error::TransportError::protocol(format!(
                "memory-buffer write cursor {write} exceeds ring image length {}",
                image.len()
            )));
        }
        if wrapped && image.is_empty() {
            return Err(crate::error::TransportError::protocol(
                "memory-buffer marked wrapped but the ring image is empty",
            ));
        }
        Ok(Self {
            image,
            write,
            wrapped,
        })
    }

    /// The ring capacity (length of the captured image).
    pub fn capacity(&self) -> usize {
        self.image.len()
    }

    /// Reconstruct the in-order `BHF_EVENTS` byte stream, honoring the wrap.
    pub fn linearize(&self) -> Vec<u8> {
        if !self.wrapped {
            self.image[..self.write].to_vec()
        } else {
            let mut out = Vec::with_capacity(self.image.len());
            out.extend_from_slice(&self.image[self.write..]);
            out.extend_from_slice(&self.image[..self.write]);
            out
        }
    }

    /// Decode the reconstructed stream into events.
    pub fn read_events(&self) -> Result<Vec<Event>> {
        decode_events(&self.linearize())
    }

    /// Decode the reconstructed stream and return just the coverage edge ids.
    pub fn read_edges(&self) -> Result<Vec<u32>> {
        Ok(edges_from_events(&self.read_events()?))
    }

    /// Build a clean [`RunOutcome`] from the ring's coverage (no fault; fault
    /// classification over this channel is HDF-2).
    pub fn to_outcome(&self) -> Result<RunOutcome> {
        Ok(RunOutcome::clean(self.read_edges()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::{encode_event_stream, simulate_ring};
    use event_log::Event;

    fn crumb(id: u32) -> Event {
        Event::Crumb { id }
    }

    #[test]
    fn edges_from_events_keeps_only_breadcrumbs_in_order() {
        let events = vec![
            Event::Begin { testcase_id: 1 },
            Event::Target { id: 0x42 },
            crumb(10),
            crumb(20),
            Event::TargetEntry,
            crumb(10),
            Event::End { result_class: 0 },
        ];
        // Target id 0x42 is not an edge; breadcrumbs keep order and repeats.
        assert_eq!(edges_from_events(&events), vec![10, 20, 10]);
    }

    #[test]
    fn semihosting_reader_decodes_known_stream_to_expected_edges() {
        let events = vec![
            Event::Begin { testcase_id: 7 },
            Event::Target { id: 1 },
            Event::TargetEntry,
            crumb(100),
            crumb(200),
            crumb(300),
            Event::End { result_class: 0 },
        ];
        let bytes = encode_event_stream(&events);

        let reader = SemihostingReader::new(bytes.as_slice());
        assert_eq!(reader.read_edges().unwrap(), vec![100, 200, 300]);
    }

    #[test]
    fn memory_buffer_reader_unwrapped_reconstructs_prefix() {
        let events = vec![crumb(1), crumb(2)];
        let stream = encode_event_stream(&events);
        // A 64-byte ring that has only taken `stream.len()` bytes, no wrap.
        let mut image = vec![0_u8; 64];
        image[..stream.len()].copy_from_slice(&stream);

        let reader = MemoryBufferReader::new(image, stream.len() as u32, false).unwrap();
        assert_eq!(reader.linearize(), stream);
        assert_eq!(reader.read_edges().unwrap(), vec![1, 2]);
    }

    #[test]
    fn memory_buffer_reader_reconstructs_wrapped_stream_byte_for_byte() {
        // Five 5-byte Crumb records = 25 bytes written into a 15-byte ring
        // (three records). The ring wraps and keeps the LAST 15 bytes — the
        // three most-recent whole records — in chronological order.
        let events = vec![crumb(1), crumb(2), crumb(3), crumb(4), crumb(5)];
        let full = encode_event_stream(&events);
        assert_eq!(full.len(), 25, "each Crumb record is tag(1) + u32(4)");

        let capacity = 15;
        let (image, write, wrapped) = simulate_ring(&full, capacity);
        assert!(wrapped, "25 bytes into a 15-byte ring must wrap");

        // Byte-for-byte: the reconstructed stream is exactly the last
        // `capacity` bytes that were written, in order.
        let expected: Vec<u8> = full[full.len() - capacity..].to_vec();
        let reader = MemoryBufferReader::new(image, write, wrapped).unwrap();
        assert_eq!(reader.linearize(), expected);

        // And those surviving whole records decode to the last three edges.
        assert_eq!(reader.read_edges().unwrap(), vec![3, 4, 5]);
    }

    #[test]
    fn memory_buffer_reader_wrap_at_cursor_zero_is_full_buffer_in_order() {
        // Exactly `capacity` bytes written: the Ada backend wraps `write` back
        // to 0 and sets `wrapped`, so the whole buffer is the stream in order.
        let events = vec![crumb(1), crumb(2), crumb(3)];
        let full = encode_event_stream(&events); // 15 bytes
        let capacity = 15;
        let (image, write, wrapped) = simulate_ring(&full, capacity);
        assert_eq!(write, 0);
        assert!(wrapped);

        let reader = MemoryBufferReader::new(image, write, wrapped).unwrap();
        assert_eq!(reader.linearize(), full);
        assert_eq!(reader.read_edges().unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn memory_buffer_reader_rejects_out_of_range_cursor() {
        let error = MemoryBufferReader::new(vec![0_u8; 8], 9, false).unwrap_err();
        assert!(
            error.to_string().contains("exceeds ring image length"),
            "unexpected error: {error}"
        );
    }
}
