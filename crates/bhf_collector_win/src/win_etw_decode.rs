// SPDX-License-Identifier: Apache-2.0

//! Pure, platform-neutral decode of ETW kernel-provider event payloads.
//!
//! This is the real `EVENT_RECORD` → [`WinRawRecord`] decode logic for the three
//! kernel providers the collector subscribes to:
//!
//! * **Process** (`{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}`): `CreateProcess*` and
//!   process-rundown start/stop events (`Process_TypeGroup1`), including the
//!   descendant processes a `ShellExecute*` ultimately launches — at the kernel
//!   level a `ShellExecuteEx` call surfaces as the resulting process creation.
//! * **FileIo** (`{90cbdc39-4a3e-11d1-84f4-0000f80464e3}`): file
//!   create/open/write/rename/delete. Path-carrying events (`FileIo_Create`,
//!   `FileIo_Name`/rundown) populate a `FileObject → path` map; the
//!   `FileObject`-only read/write/info events (`FileIo_ReadWrite`,
//!   `FileIo_Info`) resolve their path through that map.
//! * **Image** (`{2cb15d1d-5fc1-11d2-abe1-00a0c911f518}`): `LoadLibrary*` /
//!   image-load events (`Image_Load`).
//!
//! The decode operates on the raw `UserData` byte buffer plus the routing fields
//! (`ProviderId`, `Opcode`, `Version`, 32/64-bit pointer size, the acting
//! process id from the `EVENT_HEADER`, and the timestamp). None of that needs
//! Windows, so the full MOF offset arithmetic, the pointer-size handling, the
//! SID parse, the `FileObject` correlation and the create-vs-open disposition
//! classification are all exercised by the unit tests at the bottom of this file
//! on a Linux CI host with synthetic ETW-shaped buffers. The `#[cfg(windows)]`
//! consumer in [`crate::etw`] only has to pull those routing fields off a live
//! `EVENT_RECORD` and hand the `UserData` slice here.

use crate::win_core::{WinFileOp, WinRawRecord};
use std::collections::BTreeMap;

/// Pointer width of the traced process, taken from
/// `EVENT_HEADER_FLAG_32_BIT_HEADER`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerSize {
    Four,
    Eight,
}

impl PointerSize {
    fn bytes(self) -> usize {
        match self {
            PointerSize::Four => 4,
            PointerSize::Eight => 8,
        }
    }
}

/// A kernel provider the collector decodes. `Other` is any provider we subscribe
/// to incidentally but do not decode (its events are ignored, never fabricated).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtwProvider {
    Process,
    FileIo,
    Image,
    Other,
}

/// A COM `GUID` in its field form: `Data1` (LE u32), `Data2`/`Data3` (LE u16),
/// `Data4` (8 bytes, written in order). This matches `windows_sys`'s `GUID`
/// struct field-for-field, so the live consumer passes the `ProviderId` straight
/// through with no endianness juggling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EtwGuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl EtwGuid {
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        EtwGuid {
            data1,
            data2,
            data3,
            data4,
        }
    }
}

/// `{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}` — NT Kernel Logger process provider.
pub const PROCESS_GUID: EtwGuid = EtwGuid::new(
    0x3d6f_a8d0,
    0xfe05,
    0x11d0,
    [0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c],
);

/// `{90cbdc39-4a3e-11d1-84f4-0000f80464e3}` — NT Kernel Logger file-I/O provider.
pub const FILEIO_GUID: EtwGuid = EtwGuid::new(
    0x90cb_dc39,
    0x4a3e,
    0x11d1,
    [0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3],
);

/// `{2cb15d1d-5fc1-11d2-abe1-00a0c911f518}` — NT Kernel Logger image-load provider.
pub const IMAGE_GUID: EtwGuid = EtwGuid::new(
    0x2cb1_5d1d,
    0x5fc1,
    0x11d2,
    [0xab, 0xe1, 0x00, 0xa0, 0xc9, 0x11, 0xf5, 0x18],
);

impl EtwProvider {
    /// Classify an event's `ProviderId` GUID.
    pub fn from_guid(guid: &EtwGuid) -> EtwProvider {
        if *guid == PROCESS_GUID {
            EtwProvider::Process
        } else if *guid == FILEIO_GUID {
            EtwProvider::FileIo
        } else if *guid == IMAGE_GUID {
            EtwProvider::Image
        } else {
            EtwProvider::Other
        }
    }
}

// --- Process (Process_TypeGroup1) opcodes. ---
const OP_PROCESS_START: u8 = 1;
const OP_PROCESS_END: u8 = 2;
const OP_PROCESS_DC_START: u8 = 3;
const OP_PROCESS_DC_END: u8 = 4;
const OP_PROCESS_DEFUNCT: u8 = 39;

// --- Image (Image_Load) opcodes. ---
const OP_IMAGE_UNLOAD: u8 = 2;
const OP_IMAGE_DC_START: u8 = 3;
const OP_IMAGE_LOAD: u8 = 10;

// --- FileIo opcodes. ---
const OP_FILE_NAME: u8 = 0;
const OP_FILE_FILE_CREATE: u8 = 32;
const OP_FILE_FILE_DELETE: u8 = 35;
const OP_FILE_FILE_RUNDOWN: u8 = 36;
const OP_FILE_CREATE: u8 = 64;
const OP_FILE_READ: u8 = 67;
const OP_FILE_WRITE: u8 = 68;
const OP_FILE_SET_INFO: u8 = 69;
const OP_FILE_DELETE: u8 = 70;
const OP_FILE_RENAME: u8 = 71;

/// The routing fields plus the raw `UserData` buffer of one ETW event, decoded
/// by [`EtwDecoder::decode`]. The live consumer builds this from an
/// `EVENT_RECORD`; the tests build it directly from synthetic bytes.
#[derive(Debug, Clone)]
pub struct RawEtwEvent<'a> {
    pub provider: EtwProvider,
    pub opcode: u8,
    pub version: u8,
    pub pointer_size: PointerSize,
    /// Acting process id from `EVENT_HEADER.ProcessId` — the file-I/O and
    /// image-load MOF payloads do not repeat it, so it comes from the header.
    pub header_pid: u32,
    /// Event timestamp in fractional Unix seconds (converted from the
    /// `EVENT_HEADER` `FILETIME`).
    pub timestamp: f64,
    pub user_data: &'a [u8],
}

/// Decoder state. The only state is the `FileObject → path` map that file-I/O
/// correlation needs: a kernel `FileIo_ReadWrite` / `FileIo_Info` event carries
/// only the `FileObject`, so its path is recovered from the earlier
/// `FileIo_Create` / `FileIo_Name` rundown event that named the same object.
#[derive(Debug, Default)]
pub struct EtwDecoder {
    file_objects: BTreeMap<u64, String>,
}

impl EtwDecoder {
    pub fn new() -> Self {
        EtwDecoder::default()
    }

    /// Decode one ETW event into a [`WinRawRecord`], or `None` when the event is
    /// not one of the classes the collector observes (or its payload is
    /// truncated / its `FileObject` has no known path).
    pub fn decode(&mut self, ev: &RawEtwEvent<'_>) -> Option<WinRawRecord> {
        match ev.provider {
            EtwProvider::Process => self.decode_process(ev),
            EtwProvider::Image => decode_image(ev),
            EtwProvider::FileIo => self.decode_fileio(ev),
            EtwProvider::Other => None,
        }
    }

    fn decode_process(&self, ev: &RawEtwEvent<'_>) -> Option<WinRawRecord> {
        match ev.opcode {
            OP_PROCESS_START | OP_PROCESS_DC_START => decode_process_start(ev),
            OP_PROCESS_END | OP_PROCESS_DC_END | OP_PROCESS_DEFUNCT => {
                let mut c = Cursor::new(ev.user_data, ev.pointer_size);
                c.skip(ev.pointer_size.bytes())?; // UniqueProcessKey
                let pid = c.u32()?;
                Some(WinRawRecord::ProcessStop {
                    pid,
                    ts: ev.timestamp,
                })
            }
            _ => None,
        }
    }

    fn decode_fileio(&mut self, ev: &RawEtwEvent<'_>) -> Option<WinRawRecord> {
        match ev.opcode {
            // Name / create / delete / rundown: `FileObject` + `FileName`. These
            // establish the object→path mapping; `FileIo_FileCreate` also stands
            // in as a file-create observation.
            OP_FILE_NAME | OP_FILE_FILE_CREATE | OP_FILE_FILE_DELETE | OP_FILE_FILE_RUNDOWN => {
                let mut c = Cursor::new(ev.user_data, ev.pointer_size);
                let file_object = c.ptr()?;
                let path = c.utf16z()?;
                if !path.is_empty() {
                    self.file_objects.insert(file_object, path.clone());
                }
                match ev.opcode {
                    OP_FILE_FILE_CREATE if !path.is_empty() => Some(WinRawRecord::FileOp {
                        pid: ev.header_pid,
                        op: WinFileOp::Create,
                        path,
                        ts: ev.timestamp,
                    }),
                    OP_FILE_FILE_DELETE if !path.is_empty() => Some(WinRawRecord::FileOp {
                        pid: ev.header_pid,
                        op: WinFileOp::Delete,
                        path,
                        ts: ev.timestamp,
                    }),
                    // A bare name/rundown is a mapping, not an observed operation.
                    _ => None,
                }
            }
            // FileIo_Create: a real open/create carrying the full `OpenPath`.
            OP_FILE_CREATE => {
                let mut c = Cursor::new(ev.user_data, ev.pointer_size);
                c.skip(ev.pointer_size.bytes())?; // IrpPtr
                let file_object = c.ptr()?;
                c.skip(4)?; // IssuingThreadId (v3+)
                let create_options = c.u32()?;
                c.skip(4)?; // FileAttributes
                c.skip(4)?; // ShareAccess
                let path = c.utf16z()?;
                if path.is_empty() {
                    return None;
                }
                self.file_objects.insert(file_object, path.clone());
                Some(WinRawRecord::FileOp {
                    pid: ev.header_pid,
                    op: create_disposition_op(create_options),
                    path,
                    ts: ev.timestamp,
                })
            }
            // FileIo_ReadWrite: `FileObject`-only; resolve the path from the map.
            OP_FILE_READ | OP_FILE_WRITE => {
                let mut c = Cursor::new(ev.user_data, ev.pointer_size);
                c.skip(8)?; // ByteOffset (u64)
                c.skip(ev.pointer_size.bytes())?; // IrpPtr
                let file_object = c.ptr()?;
                let path = self.file_objects.get(&file_object)?.clone();
                let op = if ev.opcode == OP_FILE_WRITE {
                    WinFileOp::Write
                } else {
                    WinFileOp::Open
                };
                Some(WinRawRecord::FileOp {
                    pid: ev.header_pid,
                    op,
                    path,
                    ts: ev.timestamp,
                })
            }
            // FileIo_Info: SetInfo / Delete / Rename, `FileObject`-only.
            OP_FILE_SET_INFO | OP_FILE_DELETE | OP_FILE_RENAME => {
                let mut c = Cursor::new(ev.user_data, ev.pointer_size);
                c.skip(ev.pointer_size.bytes())?; // IrpPtr
                let file_object = c.ptr()?;
                let path = self.file_objects.get(&file_object)?.clone();
                let op = match ev.opcode {
                    OP_FILE_DELETE => WinFileOp::Delete,
                    OP_FILE_RENAME => WinFileOp::Rename,
                    // SetInfo is only treated as an observed op when it is not a
                    // delete/rename variant; a plain attribute set is ignored.
                    _ => return None,
                };
                Some(WinRawRecord::FileOp {
                    pid: ev.header_pid,
                    op,
                    path,
                    ts: ev.timestamp,
                })
            }
            _ => None,
        }
    }

    /// Current `FileObject → path` table size (diagnostics / tests).
    pub fn tracked_file_objects(&self) -> usize {
        self.file_objects.len()
    }
}

/// `Process_TypeGroup1` start decode (pointer-size and version aware).
fn decode_process_start(ev: &RawEtwEvent<'_>) -> Option<WinRawRecord> {
    let mut c = Cursor::new(ev.user_data, ev.pointer_size);
    c.skip(ev.pointer_size.bytes())?; // UniqueProcessKey
    let pid = c.u32()?;
    let parent_pid = c.u32()?;
    let session = c.u32()?;
    let _exit_status = c.i32()?;
    c.skip(ev.pointer_size.bytes())?; // DirectoryTableBase
    if ev.version >= 4 {
        c.skip(4)?; // Flags (v4+)
    }
    // UserSID (variable). A rendered SID becomes the event's `user`.
    let user = c.wmi_sid();
    let image = c.ansiz()?;
    let command_line = c.utf16z().unwrap_or_default();
    Some(WinRawRecord::ProcessStart {
        pid,
        parent_pid,
        image,
        command_line,
        user,
        session: Some(session),
        ts: ev.timestamp,
    })
}

/// `Image_Load` decode (pointer-size and version aware). Only the fields the
/// collector needs — acting pid and image path — are surfaced; the rest of the
/// MOF record is skipped by width.
fn decode_image(ev: &RawEtwEvent<'_>) -> Option<WinRawRecord> {
    if !matches!(ev.opcode, OP_IMAGE_LOAD | OP_IMAGE_DC_START) {
        // Unload and other image opcodes are not an observed "load".
        let _ = OP_IMAGE_UNLOAD;
        return None;
    }
    let mut c = Cursor::new(ev.user_data, ev.pointer_size);
    c.skip(ev.pointer_size.bytes())?; // ImageBase
    c.skip(ev.pointer_size.bytes())?; // ImageSize
    let payload_pid = c.u32()?;
    c.skip(4)?; // ImageChecksum
    c.skip(4)?; // TimeDateStamp
    if ev.version >= 3 {
        c.skip(2)?; // SignatureLevel
        c.skip(2)?; // SignatureType
    } else {
        c.skip(4)?; // Reserved0
    }
    c.skip(ev.pointer_size.bytes())?; // DefaultBase
    c.skip(4 * 4)?; // Reserved1..4
    let path = c.utf16z()?;
    if path.is_empty() {
        return None;
    }
    // Prefer the payload pid (the process the image loaded into); fall back to
    // the header pid if the payload carried the sentinel 0.
    let pid = if payload_pid != 0 {
        payload_pid
    } else {
        ev.header_pid
    };
    Some(WinRawRecord::ImageLoad {
        pid,
        path,
        ts: ev.timestamp,
    })
}

/// Map an `NtCreateFile` `CreateOptions`/disposition word to a create-vs-open
/// classification. The create-disposition is packed into the top byte.
fn create_disposition_op(create_options: u32) -> WinFileOp {
    const FILE_SUPERSEDE: u32 = 0;
    const FILE_OPEN: u32 = 1;
    const FILE_CREATE: u32 = 2;
    const FILE_OPEN_IF: u32 = 3;
    const FILE_OVERWRITE: u32 = 4;
    const FILE_OVERWRITE_IF: u32 = 5;
    let disposition = (create_options >> 24) & 0xff;
    match disposition {
        FILE_CREATE | FILE_SUPERSEDE | FILE_OVERWRITE | FILE_OVERWRITE_IF => WinFileOp::Create,
        FILE_OPEN | FILE_OPEN_IF => WinFileOp::Open,
        // An unrecognized disposition defaults to Open (the conservative, least
        // alarming classification — a genuine create still trips create/write
        // observation elsewhere).
        _ => WinFileOp::Open,
    }
}

/// A bounds-checked little-endian reader over an ETW `UserData` buffer. Every
/// read returns `None` past the end rather than panicking, so a truncated or
/// unexpected payload degrades to "not decoded" instead of a crash.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
    ptr: PointerSize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8], ptr: PointerSize) -> Self {
        Cursor { buf, pos: 0, ptr }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    fn u32(&mut self) -> Option<u32> {
        let b = self.take(4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn i32(&mut self) -> Option<i32> {
        self.u32().map(|v| v as i32)
    }

    fn u64(&mut self) -> Option<u64> {
        let b = self.take(8)?;
        Some(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Read a pointer-sized value as a `u64`.
    fn ptr(&mut self) -> Option<u64> {
        match self.ptr {
            PointerSize::Four => self.u32().map(u64::from),
            PointerSize::Eight => self.u64(),
        }
    }

    /// Read a NUL-terminated UTF-16LE string from the current position. Consumes
    /// up to and including the terminator; stops at the buffer end if unterminated.
    fn utf16z(&mut self) -> Option<String> {
        let start = self.pos;
        let mut units: Vec<u16> = Vec::new();
        loop {
            if self.pos + 1 >= self.buf.len() {
                // Unterminated: consume the rest and decode what we have.
                if self.pos < self.buf.len() {
                    self.pos = self.buf.len();
                }
                break;
            }
            let unit = u16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
            self.pos += 2;
            if unit == 0 {
                break;
            }
            units.push(unit);
        }
        let _ = start;
        Some(String::from_utf16_lossy(&units))
    }

    /// Read a NUL-terminated ANSI (bytes, lossy-UTF-8) string.
    fn ansiz(&mut self) -> Option<String> {
        let mut bytes: Vec<u8> = Vec::new();
        loop {
            let b = *self.buf.get(self.pos)?;
            self.pos += 1;
            if b == 0 {
                break;
            }
            bytes.push(b);
        }
        Some(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Consume the variable-length `UserSID` field of a process event and render
    /// it as an `S-1-…` string when present.
    ///
    /// Layout: the field begins with a pointer-sized token. A zero token means
    /// "no SID" and occupies a single pointer. A non-zero token is a
    /// `SID_AND_ATTRIBUTES` header (`PSID` + `DWORD Attributes`, i.e. two
    /// pointer-sized slots with alignment padding), followed by the SID body:
    /// `Revision(1) SubAuthorityCount(1) IdentifierAuthority(6)
    /// SubAuthority[count](4 each)`.
    fn wmi_sid(&mut self) -> Option<String> {
        // Peek the leading token without committing, so an empty SID still
        // advances exactly one pointer.
        let token = match self.ptr {
            PointerSize::Four => {
                let b = self.buf.get(self.pos..self.pos + 4)?;
                u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64
            }
            PointerSize::Eight => {
                let b = self.buf.get(self.pos..self.pos + 8)?;
                u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
            }
        };
        if token == 0 {
            self.skip(self.ptr.bytes());
            return None;
        }
        // Skip the SID_AND_ATTRIBUTES header (two pointer-sized slots).
        self.skip(2 * self.ptr.bytes())?;
        let revision = *self.buf.get(self.pos)?;
        let sub_count = *self.buf.get(self.pos + 1)? as usize;
        self.pos += 2;
        let authority = self.take(6)?;
        // IdentifierAuthority is a 6-byte big-endian value.
        let auth = authority
            .iter()
            .fold(0u64, |acc, &byte| (acc << 8) | byte as u64);
        let mut subs = Vec::with_capacity(sub_count);
        for _ in 0..sub_count {
            subs.push(self.u32()?);
        }
        let mut out = format!("S-{revision}-{auth}");
        for sub in subs {
            out.push('-');
            out.push_str(&sub.to_string());
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds synthetic ETW `UserData` buffers matching the real MOF layouts.
    #[derive(Default)]
    struct Buf {
        bytes: Vec<u8>,
        ptr: usize,
    }

    impl Buf {
        fn new(ptr_size: PointerSize) -> Self {
            Buf {
                bytes: Vec::new(),
                ptr: ptr_size.bytes(),
            }
        }
        fn u16(mut self, v: u16) -> Self {
            self.bytes.extend_from_slice(&v.to_le_bytes());
            self
        }
        fn u32(mut self, v: u32) -> Self {
            self.bytes.extend_from_slice(&v.to_le_bytes());
            self
        }
        fn i32(self, v: i32) -> Self {
            self.u32(v as u32)
        }
        fn u64(mut self, v: u64) -> Self {
            self.bytes.extend_from_slice(&v.to_le_bytes());
            self
        }
        fn ptr(mut self, v: u64) -> Self {
            if self.ptr == 4 {
                self.bytes.extend_from_slice(&(v as u32).to_le_bytes());
            } else {
                self.bytes.extend_from_slice(&v.to_le_bytes());
            }
            self
        }
        fn utf16z(mut self, s: &str) -> Self {
            for u in s.encode_utf16() {
                self.bytes.extend_from_slice(&u.to_le_bytes());
            }
            self.bytes.extend_from_slice(&0u16.to_le_bytes());
            self
        }
        fn ansiz(mut self, s: &str) -> Self {
            self.bytes.extend_from_slice(s.as_bytes());
            self.bytes.push(0);
            self
        }
        /// A SID_AND_ATTRIBUTES header + SID body (e.g. S-1-5-18).
        fn sid(mut self, revision: u8, authority: u64, subs: &[u32]) -> Self {
            // Non-zero header token so the decoder treats a SID as present.
            self = self.ptr(0xdead_beef); // PSID pointer
            self = self.ptr(0); // attributes (+padding) slot
            self.bytes.push(revision);
            self.bytes.push(subs.len() as u8);
            let auth = authority.to_be_bytes();
            self.bytes.extend_from_slice(&auth[2..8]); // 6-byte authority
            for s in subs {
                self.bytes.extend_from_slice(&s.to_le_bytes());
            }
            self
        }
        /// An absent SID: a single zero pointer slot.
        fn no_sid(self) -> Self {
            self.ptr(0)
        }
        fn done(self) -> Vec<u8> {
            self.bytes
        }
    }

    fn ev<'a>(
        provider: EtwProvider,
        opcode: u8,
        version: u8,
        ptr: PointerSize,
        pid: u32,
        data: &'a [u8],
    ) -> RawEtwEvent<'a> {
        RawEtwEvent {
            provider,
            opcode,
            version,
            pointer_size: ptr,
            header_pid: pid,
            timestamp: 1.5,
            user_data: data,
        }
    }

    #[test]
    fn provider_guid_classification() {
        assert_eq!(EtwProvider::from_guid(&PROCESS_GUID), EtwProvider::Process);
        assert_eq!(EtwProvider::from_guid(&FILEIO_GUID), EtwProvider::FileIo);
        assert_eq!(EtwProvider::from_guid(&IMAGE_GUID), EtwProvider::Image);
        let other = EtwGuid::new(0, 0, 0, [0; 8]);
        assert_eq!(EtwProvider::from_guid(&other), EtwProvider::Other);
    }

    // --- Class 1: CreateProcess* + descendants. ---

    #[test]
    fn decodes_process_start_64bit_v3_with_sid() {
        let data = Buf::new(PointerSize::Eight)
            .ptr(0x1111) // UniqueProcessKey
            .u32(4321) // ProcessId
            .u32(1000) // ParentId
            .u32(1) // SessionId
            .i32(0) // ExitStatus
            .ptr(0x2222) // DirectoryTableBase
            .sid(1, 5, &[18]) // UserSID -> S-1-5-18
            .ansiz("target.exe") // ImageFileName
            .utf16z("target.exe --go") // CommandLine
            .done();
        let mut d = EtwDecoder::new();
        let rec = d
            .decode(&ev(
                EtwProvider::Process,
                OP_PROCESS_START,
                3,
                PointerSize::Eight,
                1000,
                &data,
            ))
            .expect("process start decodes");
        match rec {
            WinRawRecord::ProcessStart {
                pid,
                parent_pid,
                image,
                command_line,
                user,
                session,
                ..
            } => {
                assert_eq!(pid, 4321);
                assert_eq!(parent_pid, 1000);
                assert_eq!(image, "target.exe");
                assert_eq!(command_line, "target.exe --go");
                assert_eq!(user.as_deref(), Some("S-1-5-18"));
                assert_eq!(session, Some(1));
            }
            other => panic!("expected ProcessStart, got {other:?}"),
        }
    }

    #[test]
    fn decodes_process_start_v4_flags_and_no_sid() {
        let data = Buf::new(PointerSize::Eight)
            .ptr(0x1) // UniqueProcessKey
            .u32(2002) // ProcessId
            .u32(1000) // ParentId
            .u32(2) // SessionId
            .i32(0) // ExitStatus
            .ptr(0x2) // DirectoryTableBase
            .u32(0) // Flags (v4)
            .no_sid()
            .ansiz("child.exe")
            .utf16z("child.exe")
            .done();
        let mut d = EtwDecoder::new();
        let rec = d
            .decode(&ev(
                EtwProvider::Process,
                OP_PROCESS_DC_START,
                4,
                PointerSize::Eight,
                1000,
                &data,
            ))
            .expect("v4 process start decodes");
        match rec {
            WinRawRecord::ProcessStart {
                pid,
                parent_pid,
                image,
                user,
                ..
            } => {
                assert_eq!(pid, 2002);
                assert_eq!(parent_pid, 1000);
                assert_eq!(image, "child.exe");
                assert_eq!(user, None, "a null SID yields no user");
            }
            other => panic!("expected ProcessStart, got {other:?}"),
        }
    }

    #[test]
    fn decodes_process_start_32bit() {
        let data = Buf::new(PointerSize::Four)
            .ptr(0x1) // UniqueProcessKey (4 bytes)
            .u32(777) // ProcessId
            .u32(1000) // ParentId
            .u32(1) // SessionId
            .i32(0) // ExitStatus
            .ptr(0x2) // DirectoryTableBase (4 bytes)
            .no_sid()
            .ansiz("w32.exe")
            .utf16z("w32.exe arg")
            .done();
        let mut d = EtwDecoder::new();
        let rec = d
            .decode(&ev(
                EtwProvider::Process,
                OP_PROCESS_START,
                3,
                PointerSize::Four,
                1000,
                &data,
            ))
            .expect("32-bit process start decodes");
        match rec {
            WinRawRecord::ProcessStart { pid, image, .. } => {
                assert_eq!(pid, 777);
                assert_eq!(image, "w32.exe");
            }
            other => panic!("expected ProcessStart, got {other:?}"),
        }
    }

    #[test]
    fn decodes_process_stop() {
        let data = Buf::new(PointerSize::Eight)
            .ptr(0x1) // UniqueProcessKey
            .u32(4321) // ProcessId
            .u32(1000) // ParentId
            .done();
        let mut d = EtwDecoder::new();
        let rec = d
            .decode(&ev(
                EtwProvider::Process,
                OP_PROCESS_END,
                3,
                PointerSize::Eight,
                1000,
                &data,
            ))
            .expect("process stop decodes");
        match rec {
            WinRawRecord::ProcessStop { pid, .. } => assert_eq!(pid, 4321),
            other => panic!("expected ProcessStop, got {other:?}"),
        }
    }

    // --- Class 3: file create/open/write/rename/delete with resolved paths. ---

    #[test]
    fn decodes_fileio_create_classifies_create_vs_open() {
        // CreateDisposition packed in the top byte. FILE_CREATE (2) -> Create.
        let create_options = 2u32 << 24;
        let data = Buf::new(PointerSize::Eight)
            .ptr(0xAAAA) // IrpPtr
            .ptr(0xF00D) // FileObject
            .u32(99) // IssuingThreadId
            .u32(create_options)
            .u32(0) // FileAttributes
            .u32(0) // ShareAccess
            .utf16z("\\Device\\HarddiskVolume2\\sandbox\\out.bin")
            .done();
        let mut d = EtwDecoder::new();
        let rec = d
            .decode(&ev(
                EtwProvider::FileIo,
                OP_FILE_CREATE,
                3,
                PointerSize::Eight,
                1000,
                &data,
            ))
            .expect("fileio create decodes");
        match rec {
            WinRawRecord::FileOp { pid, op, path, .. } => {
                assert_eq!(pid, 1000);
                assert_eq!(op, WinFileOp::Create);
                assert!(path.ends_with("out.bin"));
            }
            other => panic!("expected FileOp, got {other:?}"),
        }
        assert_eq!(d.tracked_file_objects(), 1, "create records the mapping");

        // FILE_OPEN (1) -> Open.
        let open_options = 1u32 << 24;
        let data = Buf::new(PointerSize::Eight)
            .ptr(0xAAAA)
            .ptr(0xBEEF)
            .u32(99)
            .u32(open_options)
            .u32(0)
            .u32(0)
            .utf16z("\\Device\\HarddiskVolume2\\sandbox\\read.txt")
            .done();
        let rec = d
            .decode(&ev(
                EtwProvider::FileIo,
                OP_FILE_CREATE,
                3,
                PointerSize::Eight,
                1000,
                &data,
            ))
            .expect("fileio open decodes");
        assert!(matches!(
            rec,
            WinRawRecord::FileOp {
                op: WinFileOp::Open,
                ..
            }
        ));
    }

    #[test]
    fn decodes_fileio_write_resolving_path_from_name_mapping() {
        let mut d = EtwDecoder::new();
        // A FileIo_Name rundown maps FileObject 0xF00D -> a path.
        let name = Buf::new(PointerSize::Eight)
            .ptr(0xF00D)
            .utf16z("\\Device\\HarddiskVolume2\\sandbox\\data.db")
            .done();
        assert!(
            d.decode(&ev(
                EtwProvider::FileIo,
                OP_FILE_NAME,
                2,
                PointerSize::Eight,
                1000,
                &name
            ))
            .is_none(),
            "a bare name event is a mapping, not an operation"
        );
        // A FileIo_ReadWrite (write) carries only the FileObject.
        let write = Buf::new(PointerSize::Eight)
            .u64(4096) // ByteOffset
            .ptr(0xAAAA) // IrpPtr
            .ptr(0xF00D) // FileObject
            .done();
        let rec = d
            .decode(&ev(
                EtwProvider::FileIo,
                OP_FILE_WRITE,
                3,
                PointerSize::Eight,
                1000,
                &write,
            ))
            .expect("write resolves through the mapping");
        match rec {
            WinRawRecord::FileOp { op, path, .. } => {
                assert_eq!(op, WinFileOp::Write);
                assert!(path.ends_with("data.db"));
            }
            other => panic!("expected FileOp Write, got {other:?}"),
        }
    }

    #[test]
    fn unresolved_fileobject_write_is_dropped_not_fabricated() {
        let mut d = EtwDecoder::new();
        let write = Buf::new(PointerSize::Eight)
            .u64(0)
            .ptr(0xAAAA)
            .ptr(0x9999) // never mapped
            .done();
        assert!(
            d.decode(&ev(
                EtwProvider::FileIo,
                OP_FILE_WRITE,
                3,
                PointerSize::Eight,
                1000,
                &write
            ))
            .is_none(),
            "a write to an unknown FileObject is dropped, never given a fake path"
        );
    }

    #[test]
    fn decodes_fileio_delete_and_rename_from_info() {
        let mut d = EtwDecoder::new();
        let create = Buf::new(PointerSize::Eight)
            .ptr(0xAAAA)
            .ptr(0xC0DE)
            .u32(0)
            .u32(2u32 << 24)
            .u32(0)
            .u32(0)
            .utf16z("\\Device\\HarddiskVolume2\\sandbox\\victim")
            .done();
        d.decode(&ev(
            EtwProvider::FileIo,
            OP_FILE_CREATE,
            3,
            PointerSize::Eight,
            1000,
            &create,
        ));
        for (opcode, want) in [
            (OP_FILE_DELETE, WinFileOp::Delete),
            (OP_FILE_RENAME, WinFileOp::Rename),
        ] {
            let info = Buf::new(PointerSize::Eight)
                .ptr(0xAAAA) // IrpPtr
                .ptr(0xC0DE) // FileObject
                .done();
            let rec = d
                .decode(&ev(
                    EtwProvider::FileIo,
                    opcode,
                    3,
                    PointerSize::Eight,
                    1000,
                    &info,
                ))
                .expect("info op resolves");
            match rec {
                WinRawRecord::FileOp { op, path, .. } => {
                    assert_eq!(op, want);
                    assert!(path.ends_with("victim"));
                }
                other => panic!("expected FileOp, got {other:?}"),
            }
        }
    }

    #[test]
    fn fileio_filecreate_and_filedelete_name_events_emit_ops() {
        let mut d = EtwDecoder::new();
        let fc = Buf::new(PointerSize::Eight)
            .ptr(0x1)
            .utf16z("\\Device\\HarddiskVolume2\\sandbox\\new.bin")
            .done();
        let rec = d
            .decode(&ev(
                EtwProvider::FileIo,
                OP_FILE_FILE_CREATE,
                2,
                PointerSize::Eight,
                1000,
                &fc,
            ))
            .expect("FileCreate emits a create op");
        assert!(matches!(
            rec,
            WinRawRecord::FileOp {
                op: WinFileOp::Create,
                ..
            }
        ));
        let fd = Buf::new(PointerSize::Eight)
            .ptr(0x2)
            .utf16z("\\Device\\HarddiskVolume2\\sandbox\\gone.bin")
            .done();
        let rec = d
            .decode(&ev(
                EtwProvider::FileIo,
                OP_FILE_FILE_DELETE,
                2,
                PointerSize::Eight,
                1000,
                &fd,
            ))
            .expect("FileDelete emits a delete op");
        assert!(matches!(
            rec,
            WinRawRecord::FileOp {
                op: WinFileOp::Delete,
                ..
            }
        ));
    }

    // --- Class 4: LoadLibrary* / image-load. ---

    #[test]
    fn decodes_image_load_64bit_v2() {
        let data = Buf::new(PointerSize::Eight)
            .ptr(0x7FF0_0000) // ImageBase
            .ptr(0x20000) // ImageSize
            .u32(1000) // ProcessId
            .u32(0) // ImageChecksum
            .u32(0) // TimeDateStamp
            .u32(0) // Reserved0 (v2)
            .ptr(0x7FF0_0000) // DefaultBase
            .u32(0) // Reserved1
            .u32(0) // Reserved2
            .u32(0) // Reserved3
            .u32(0) // Reserved4
            .utf16z("\\Device\\HarddiskVolume2\\plugins\\evil.dll")
            .done();
        let mut d = EtwDecoder::new();
        let rec = d
            .decode(&ev(
                EtwProvider::Image,
                OP_IMAGE_LOAD,
                2,
                PointerSize::Eight,
                1000,
                &data,
            ))
            .expect("image load v2 decodes");
        match rec {
            WinRawRecord::ImageLoad { pid, path, .. } => {
                assert_eq!(pid, 1000);
                assert!(path.ends_with("evil.dll"));
            }
            other => panic!("expected ImageLoad, got {other:?}"),
        }
    }

    #[test]
    fn decodes_image_load_v3_with_signature_fields() {
        let data = Buf::new(PointerSize::Eight)
            .ptr(0x7FF0_0000) // ImageBase
            .ptr(0x20000) // ImageSize
            .u32(0) // ProcessId (0 -> falls back to header pid)
            .u32(0) // ImageChecksum
            .u32(0) // TimeDateStamp
            .u16(0) // SignatureLevel (v3)
            .u16(0) // SignatureType (v3)
            .ptr(0x7FF0_0000) // DefaultBase
            .u32(0)
            .u32(0)
            .u32(0)
            .u32(0)
            .utf16z("\\Device\\HarddiskVolume2\\windows\\system32\\ok.dll")
            .done();
        let mut d = EtwDecoder::new();
        let rec = d
            .decode(&ev(
                EtwProvider::Image,
                OP_IMAGE_LOAD,
                3,
                PointerSize::Eight,
                2048,
                &data,
            ))
            .expect("image load v3 decodes");
        match rec {
            WinRawRecord::ImageLoad { pid, path, .. } => {
                assert_eq!(pid, 2048, "zero payload pid falls back to the header pid");
                assert!(path.ends_with("ok.dll"));
            }
            other => panic!("expected ImageLoad, got {other:?}"),
        }
    }

    #[test]
    fn image_unload_is_not_a_load() {
        let data = Buf::new(PointerSize::Eight).ptr(0).ptr(0).u32(1).done();
        let mut d = EtwDecoder::new();
        assert!(d
            .decode(&ev(
                EtwProvider::Image,
                OP_IMAGE_UNLOAD,
                2,
                PointerSize::Eight,
                1,
                &data
            ))
            .is_none());
    }

    // --- Robustness: truncation and unknown providers never panic. ---

    #[test]
    fn truncated_payload_decodes_to_none() {
        let mut d = EtwDecoder::new();
        // Far too short for any layout.
        let short = [0u8, 1, 2];
        assert!(d
            .decode(&ev(
                EtwProvider::Process,
                OP_PROCESS_START,
                3,
                PointerSize::Eight,
                1,
                &short
            ))
            .is_none());
        assert!(d
            .decode(&ev(
                EtwProvider::Image,
                OP_IMAGE_LOAD,
                2,
                PointerSize::Eight,
                1,
                &short
            ))
            .is_none());
    }

    #[test]
    fn unknown_provider_and_opcode_decode_to_none() {
        let mut d = EtwDecoder::new();
        let data = [0u8; 64];
        assert!(d
            .decode(&ev(
                EtwProvider::Other,
                1,
                1,
                PointerSize::Eight,
                1,
                &data
            ))
            .is_none());
        assert!(d
            .decode(&ev(
                EtwProvider::FileIo,
                200,
                3,
                PointerSize::Eight,
                1,
                &data
            ))
            .is_none());
    }
}
