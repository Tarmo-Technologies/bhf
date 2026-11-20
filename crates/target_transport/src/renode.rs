// SPDX-License-Identifier: Apache-2.0

//! Full-system transport over a Renode board (#340).
//!
//! Renode models many MCU SoCs that `qemu-system` does not (most STM32, nRF52,
//! i.MX RT and SiFive parts). [`RenodeTransport`] fuzzes firmware on such a
//! board with the same snapshot/reset loop as
//! [`crate::fullsystem::FullSystemTransport`]; only the control channel
//! differs. Renode's monitor is a line-oriented telnet CLI, not QMP, so a
//! [`RenodeMonitor`] client drives it: `pause`, `Save @path` and `Load @path`
//! stand in for QMP's `stop`, `savevm` and `loadvm`. The run itself (stage the
//! input over gdb, continue to the completion breakpoint, classify the stop,
//! read the coverage ring) is [`crate::fullsystem::run_from_baseline`],
//! shared with the qemu-system lane.
//!
//! # The snapshot/reset state machine
//!
//! ```text
//! arm():   monitor connect (telnet greeting up to the first prompt)
//!          monitor pause                     (quiesce before the baseline)
//!          note the selected machine         (from the prompt)
//!          monitor Save @<path>              (baseline state file)
//!
//! run_input(input):
//!          monitor pause
//!          monitor Load @<path>              (reset to the baseline)
//!          monitor mach set "<machine>"      (Load leaves none selected)
//!          monitor machine StartGdbServer <port>
//!          gdb dial + attach, plant the done breakpoint
//!          stage input, continue, classify, read coverage (shared with qemu)
//! ```
//!
//! `Load` replaces the emulated machine, and its gdb server goes with it: the
//! old gdb link reads EOF and the port refuses connections until the server
//! is started again. Renode 1.17.0 also leaves no machine selected after
//! `Load` (the prompt reads `(monitor)`). So each run selects the machine
//! again, starts the server on it, dials it afresh, and plants the completion
//! breakpoint on that new link.
//!
//! # Renode's protocol quirks handled here
//!
//! * The monitor opens with telnet option negotiation (`IAC DO/WILL ...`),
//!   echoes each command line, and colours its prompt and errors with ANSI
//!   escapes unless Renode runs with `--plain`. [`RenodeMonitor`] drops the
//!   telnet commands and the escapes, strips the echo, and ends each reply at
//!   the next `(<machine>) ` prompt.
//! * A failed command prints `There was an error executing command ...` or
//!   `No such command or device: ...` and returns to the prompt; both are a
//!   [`TransportError::TargetError`], never a silent success.
//! * Renode's gdb server announces `S05` as a debugger connects and repeats
//!   `S05` after each breakpoint stop. [`crate::gdb::GdbConnection`] drops
//!   such unsolicited stop replies, so they never shift a reply.
//!
//! # Bounding
//!
//! A monitor reply is capped at [`RenodeLimits::max_reply_bytes`] raw bytes,
//! telnet and escape bytes included, so a monitor that never prints its prompt
//! is a descriptive error, not an unbounded read. The channel's read timeout
//! (the CLI's `--timeout`) bounds each wait.
//!
//! # What is gated
//!
//! Everything here is tested against the in-process
//! [`crate::testsupport::MockRenodeMonitor`] and
//! [`crate::testsupport::MockGdbStub`]. The live path, a real `renode`
//! process, runs in `tests/live_renode.rs` when Renode is installed.

use crate::error::{Result, TransportError};
use crate::fullsystem::{run_from_baseline, GuestFaultStatus, RunSettings};
use crate::gdb::{GdbClient, GdbMemoryMap, InputContract, ReadDeadline};
use crate::outcome::RunOutcome;
use crate::transport::{TargetSession, TargetTransport};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

/// The baseline state file when the spec names none, resolved by Renode
/// against its own working directory.
pub const DEFAULT_SNAPSHOT_PATH: &str = "bhf-baseline.save";

/// Telnet "interpret as command".
const IAC: u8 = 0xFF;
/// Telnet subnegotiation begin / end.
const SB: u8 = 0xFA;
const SE: u8 = 0xF0;
/// Telnet `WILL`, `WONT`, `DO`, `DONT`: each takes one option byte.
const WILL: u8 = 0xFB;
const DONT: u8 = 0xFE;
/// The silent command [`RenodeMonitor::connect`] syncs on: a monitor
/// variable assignment, which prints nothing.
pub const SYNC_COMMAND: &str = "$bhf_sync=\"bhf\"";

/// ANSI escape.
const ESC: u8 = 0x1B;
/// The ANSI string terminator BEL.
const BEL: u8 = 0x07;

/// Bounds on what the monitor client reads.
#[derive(Debug, Clone, Copy)]
pub struct RenodeLimits {
    /// Cap on the raw bytes of one reply (a command's output up to and
    /// including the prompt, or the greeting).
    pub max_reply_bytes: usize,
}

impl Default for RenodeLimits {
    fn default() -> Self {
        Self {
            // The snapshot commands answer with a line or nothing; a full
            // `help` listing is a few KiB.
            max_reply_bytes: 1024 * 1024,
        }
    }
}

/// A client for Renode's telnet monitor (`renode -P <port>`).
pub struct RenodeMonitor<C> {
    channel: C,
    limits: RenodeLimits,
    /// Raw bytes this reply may still read.
    budget: usize,
    /// The name in the last prompt read: a machine's, or `monitor` when
    /// none is selected.
    prompt: String,
}

impl<C: Read + Write> RenodeMonitor<C> {
    /// Wrap a channel with default [`RenodeLimits`].
    pub fn new(channel: C) -> Self {
        Self::with_limits(channel, RenodeLimits::default())
    }

    /// Wrap a channel with explicit limits.
    pub fn with_limits(channel: C, limits: RenodeLimits) -> Self {
        Self {
            channel,
            limits,
            budget: limits.max_reply_bytes,
            prompt: String::new(),
        }
    }

    /// The machine the monitor has selected, from its last prompt; `None`
    /// at the bare `(monitor) ` prompt.
    pub fn selected_machine(&self) -> Option<&str> {
        (!self.prompt.is_empty() && self.prompt != "monitor").then_some(self.prompt.as_str())
    }

    fn read_byte(&mut self) -> Result<Option<u8>> {
        if self.budget == 0 {
            return Err(TransportError::protocol(format!(
                "Renode monitor reply exceeded {} bytes without a prompt",
                self.limits.max_reply_bytes
            )));
        }
        self.budget -= 1;
        let mut buf = [0_u8; 1];
        match self.channel.read(&mut buf)? {
            0 => Ok(None),
            _ => Ok(Some(buf[0])),
        }
    }

    /// The next byte of text, past telnet commands and ANSI escapes; `None`
    /// at EOF.
    fn next_text_byte(&mut self) -> Result<Option<u8>> {
        loop {
            let Some(byte) = self.read_byte()? else {
                return Ok(None);
            };
            match byte {
                IAC => {
                    let Some(command) = self.read_byte()? else {
                        return Ok(None);
                    };
                    match command {
                        // An escaped 0xFF data byte.
                        IAC => return Ok(Some(IAC)),
                        WILL..=DONT => {
                            self.read_byte()?;
                        }
                        SB => self.skip_subnegotiation()?,
                        _ => {}
                    }
                }
                ESC => self.skip_escape()?,
                _ => return Ok(Some(byte)),
            }
        }
    }

    /// Skip a telnet subnegotiation up to its `IAC SE`.
    fn skip_subnegotiation(&mut self) -> Result<()> {
        let mut previous = 0_u8;
        while let Some(byte) = self.read_byte()? {
            if previous == IAC && byte == SE {
                return Ok(());
            }
            previous = if previous == IAC && byte == IAC {
                0
            } else {
                byte
            };
        }
        Ok(())
    }

    /// Skip an ANSI escape: a CSI sequence (`ESC [ ... final`), an OSC string
    /// (`ESC ] ... BEL`), or a two-byte escape.
    fn skip_escape(&mut self) -> Result<()> {
        match self.read_byte()? {
            Some(b'[') => {
                while let Some(byte) = self.read_byte()? {
                    if (0x40..=0x7E).contains(&byte) {
                        break;
                    }
                }
            }
            Some(b']') => {
                let mut previous = 0_u8;
                while let Some(byte) = self.read_byte()? {
                    if byte == BEL || (previous == ESC && byte == b'\\') {
                        break;
                    }
                    previous = byte;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Read text up to the next prompt and return what came before it.
    fn read_reply(&mut self) -> Result<String> {
        let mut text = Vec::new();
        loop {
            let Some(byte) = self.next_text_byte()? else {
                let tail = String::from_utf8_lossy(&text);
                return Err(TransportError::protocol(format!(
                    "Renode monitor closed the link before its prompt (after {:?})",
                    tail.trim()
                )));
            };
            text.push(byte);
            if byte == b' ' {
                if let Some(start) = prompt_start(&text) {
                    // `(name) `
                    let name = &text[start + 1..text.len() - 2];
                    self.prompt = String::from_utf8_lossy(name).into_owned();
                    text.truncate(start);
                    return Ok(String::from_utf8_lossy(&text).into_owned());
                }
            }
        }
    }

    /// Read the greeting up to the first prompt and return the banner
    /// (`Renode, version ...`), then skip whatever else the monitor has
    /// printed so far. Call once, before any command.
    ///
    /// A board script Renode was started with (`renode -P N board.resc`)
    /// prints its `i @board.resc` line and its commands' output after the
    /// first prompt, possibly while this runs. A silent variable assignment,
    /// [`SYNC_COMMAND`], is sent and everything up to its echo dropped, so
    /// the first real command reads its own reply.
    pub fn connect(&mut self) -> Result<String> {
        self.budget = self.limits.max_reply_bytes;
        let banner = clean_lines(&self.read_reply()?);
        self.send_line(SYNC_COMMAND)?;
        self.read_echoed_reply(SYNC_COMMAND)?;
        Ok(banner)
    }

    fn send_line(&mut self, command: &str) -> Result<()> {
        if command.chars().any(char::is_control) {
            return Err(TransportError::protocol(format!(
                "Renode monitor command {command:?} contains a control character"
            )));
        }
        self.channel.write_all(command.as_bytes())?;
        self.channel.write_all(b"\n")?;
        self.channel.flush()?;
        Ok(())
    }

    /// Read prompt-delimited replies until the one that echoes `command`, and
    /// return what follows the echo. Replies before it are output the monitor
    /// printed before it read `command`.
    fn read_echoed_reply(&mut self, command: &str) -> Result<String> {
        self.budget = self.limits.max_reply_bytes;
        loop {
            let reply = clean_lines(&self.read_reply()?);
            let mut lines = reply.lines();
            if lines.any(|line| line.trim() == command) {
                return Ok(lines.collect::<Vec<_>>().join("\n").trim().to_owned());
            }
        }
    }

    /// Run one monitor command line and return its output, echo and prompt
    /// stripped. Output Renode prints for a failed command is a
    /// [`TransportError::TargetError`].
    pub fn execute(&mut self, command: &str) -> Result<String> {
        self.send_line(command)?;
        let output = self.read_echoed_reply(command)?;
        if is_error_output(&output) {
            return Err(TransportError::TargetError(format!(
                "Renode monitor command {command:?} failed: {output}"
            )));
        }
        Ok(output)
    }

    /// Run `command`, accepting only empty output or one of `expected`.
    fn execute_quiet(&mut self, command: &str, expected: &[&str]) -> Result<()> {
        let output = self.execute(command)?;
        if output.is_empty() || expected.contains(&output.as_str()) {
            Ok(())
        } else {
            Err(TransportError::TargetError(format!(
                "Renode monitor command {command:?} printed {output:?}"
            )))
        }
    }

    /// `pause`: stop the emulation (idempotent).
    pub fn pause(&mut self) -> Result<()> {
        self.execute_quiet("pause", &["Pausing emulation..."])
    }

    /// `start`: run the emulation.
    pub fn start(&mut self) -> Result<()> {
        self.execute_quiet("start", &["Starting emulation..."])
    }

    /// `Save @path`: write the whole emulation's state to `path` on the
    /// Renode host, replacing a file already there.
    pub fn save(&mut self, path: &str) -> Result<()> {
        validate_snapshot_path(path)?;
        self.execute_quiet(&format!("Save @{path}"), &[])
    }

    /// `Load @path`: replace the emulation with the state saved in `path`.
    pub fn load(&mut self, path: &str) -> Result<()> {
        validate_snapshot_path(path)?;
        self.execute_quiet(&format!("Load @{path}"), &[])
    }

    /// `mach set "<name>"`: select a machine. Renode 1.17.0 selects none
    /// after `Load`, so `machine ...` commands would find no `machine`.
    pub fn select_machine(&mut self, name: &str) -> Result<()> {
        if name.is_empty() || name.contains('"') || name.chars().any(char::is_control) {
            return Err(TransportError::protocol(format!(
                "Renode machine name {name:?} cannot be quoted in a monitor command"
            )));
        }
        let command = format!("mach set \"{name}\"");
        let output = self.execute(&command)?;
        if output.is_empty() && self.selected_machine() == Some(name) {
            Ok(())
        } else {
            Err(TransportError::TargetError(format!(
                "Renode monitor command {command:?} did not select the machine: {output:?}"
            )))
        }
    }

    /// `machine StartGdbServer <port>` on the selected machine. A server
    /// already running on that port is accepted.
    pub fn start_gdb_server(&mut self, port: u16) -> Result<()> {
        let command = format!("machine StartGdbServer {port}");
        match self.execute_quiet(&command, &[]) {
            Err(TransportError::TargetError(message))
                if message.contains("already attached to an existing GDB server")
                    && message.contains(&format!(":{port}")) =>
            {
                Ok(())
            }
            other => other,
        }
    }
}

/// Where the trailing `(<name>) ` prompt starts in `text`, if `text` ends
/// with one on a line of its own.
fn prompt_start(text: &[u8]) -> Option<usize> {
    let start = text
        .iter()
        .rposition(|&byte| byte == b'\n' || byte == b'\r')
        .map_or(0, |index| index + 1);
    let line = &text[start..];
    let name = line.strip_prefix(b"(")?.strip_suffix(b") ")?;
    (!name.is_empty() && !name.iter().any(|&byte| byte == b'(' || byte == b')')).then_some(start)
}

/// Normalise the monitor's `\n\r` / `\r\r\n` line ends to `\n`, trim each
/// line's end and the whole text.
fn clean_lines(text: &str) -> String {
    text.split(['\n', '\r'])
        .map(str::trim_end)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Whether `output` is Renode's report of a failed command.
fn is_error_output(output: &str) -> bool {
    output.lines().any(|line| {
        line.starts_with("There was an error executing command")
            || line.starts_with("No such command or device")
    })
}

/// Validate a state-file path before it is spliced into a monitor command
/// line (`Save @path`): a space or a quote would end the path token there,
/// and a control character could start a second command.
fn validate_snapshot_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(TransportError::protocol(
            "Renode snapshot path must not be empty",
        ));
    }
    if let Some(bad) = path
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | '\\' | ':')))
    {
        return Err(TransportError::protocol(format!(
            "Renode snapshot path {path:?} contains disallowed character {bad:?}; \
             use only [A-Za-z0-9._/\\:-] (it is spliced into a monitor command line)"
        )));
    }
    Ok(())
}

/// A full-system transport over a Renode board: the monitor saves and loads
/// the baseline, gdb runs each input.
///
/// `connect_monitor` dials Renode's monitor port once per
/// [`TargetTransport::arm`]; `connect_gdb` dials the gdb server Renode starts
/// on `gdb_server_port` after each `Load`. `map` locates the input staging
/// region and the coverage ring; `snapshot_path` names the state file on the
/// Renode host.
pub struct RenodeTransport<FM, FG> {
    connect_monitor: FM,
    connect_gdb: Arc<FG>,
    gdb_server_port: u16,
    snapshot_path: String,
    harness_breakpoint: Option<(u64, u32)>,
    run: RunSettings,
}

impl<FM, FG> RenodeTransport<FM, FG> {
    /// Build a transport. The `snapshot_path` is validated up front because
    /// it is spliced into a monitor command line on every input.
    pub fn new(
        connect_monitor: FM,
        connect_gdb: FG,
        gdb_server_port: u16,
        map: GdbMemoryMap,
        snapshot_path: impl Into<String>,
    ) -> Result<Self> {
        let snapshot_path = snapshot_path.into();
        validate_snapshot_path(&snapshot_path)?;
        if gdb_server_port == 0 {
            return Err(TransportError::protocol(
                "Renode gdb server port must not be 0",
            ));
        }
        Ok(Self {
            connect_monitor,
            connect_gdb: Arc::new(connect_gdb),
            gdb_server_port,
            snapshot_path,
            harness_breakpoint: None,
            run: RunSettings::new(map, "renode"),
        })
    }

    /// Plant a software breakpoint at the harness "done" symbol (RSP `kind`,
    /// `2` for Thumb) on each run's fresh gdb link, so `continue` stops when
    /// the run completes.
    pub fn with_harness_breakpoint(mut self, address: u64, kind: u32) -> Self {
        self.harness_breakpoint = Some((address, kind));
        self
    }

    /// Read the firmware fault-status word after each run, as
    /// [`crate::fullsystem::FullSystemTransport::with_fault_status`] does.
    pub fn with_fault_status(mut self, status: GuestFaultStatus) -> Self {
        self.run.fault_status = Some(status);
        self
    }

    /// Bound each run's `continue` by `deadline`; a run that does not reach
    /// its completion stop in time is an [`crate::ExitKind::Timeout`].
    pub fn with_exec_deadline(mut self, deadline: Option<Duration>) -> Self {
        self.run.exec_deadline = deadline;
        self
    }

    /// Stage each input under `contract`.
    pub fn with_input_contract(mut self, contract: Option<InputContract>) -> Self {
        self.run.input_contract = contract;
        self
    }

    /// Read `counter` around each run (#251).
    pub fn with_cycle_counter(mut self, counter: Option<crate::cycles::CycleCounter>) -> Self {
        self.run.cycle_counter = counter;
        self
    }

    /// Read the 32-bit task identity word at `address` after each run (#252).
    pub fn with_task_id(mut self, address: Option<u64>) -> Self {
        self.run.task_id_address = address;
        self
    }

    /// Clear and read the firmware's CmpLog record in `region` (#386).
    pub fn with_cmplog(mut self, region: Option<crate::cmplog::CmpLogRegion>) -> Self {
        self.run.cmplog = region;
        self
    }

    /// Decode coverage from the semihosting channel instead of the ring (#292).
    pub fn with_semihosting_coverage(mut self, semihosting: bool) -> Self {
        self.run.semihosting_coverage = semihosting;
        self
    }
}

impl<FM, FG, CM, CG> TargetTransport for RenodeTransport<FM, FG>
where
    FM: Fn() -> Result<CM>,
    FG: Fn() -> Result<CG> + 'static,
    CM: Read + Write + 'static,
    CG: Read + Write + ReadDeadline + 'static,
{
    fn arm(&self) -> Result<Box<dyn TargetSession>> {
        let mut monitor = RenodeMonitor::new((self.connect_monitor)()?);
        monitor.connect()?;
        // Quiesce, then save the baseline every input restores.
        monitor.pause()?;
        let machine = monitor
            .selected_machine()
            .ok_or_else(|| {
                TransportError::TargetError(
                    "Renode has no machine selected (its prompt is `(monitor)`): start it with \
                     the board's script, which creates and loads the machine"
                        .to_owned(),
                )
            })?
            .to_owned();
        monitor.save(&self.snapshot_path)?;
        Ok(Box::new(RenodeSession {
            monitor,
            machine,
            connect_gdb: Arc::clone(&self.connect_gdb),
            gdb: None,
            gdb_server_port: self.gdb_server_port,
            snapshot_path: self.snapshot_path.clone(),
            harness_breakpoint: self.harness_breakpoint,
            run: self.run.clone(),
        }))
    }
}

/// A live Renode session: load the baseline, start and dial the gdb server,
/// run one input — once per [`TargetSession::run_input`].
pub struct RenodeSession<CM, CG, FG> {
    monitor: RenodeMonitor<CM>,
    /// The machine selected when the baseline was saved.
    machine: String,
    connect_gdb: Arc<FG>,
    /// The last run's gdb link, kept open while the machine sits paused.
    gdb: Option<GdbClient<CG>>,
    gdb_server_port: u16,
    snapshot_path: String,
    harness_breakpoint: Option<(u64, u32)>,
    run: RunSettings,
}

impl<CM, CG, FG> TargetSession for RenodeSession<CM, CG, FG>
where
    CM: Read + Write,
    CG: Read + Write + ReadDeadline,
    FG: Fn() -> Result<CG>,
{
    fn run_input(&mut self, input: &[u8]) -> Result<RunOutcome> {
        self.monitor.pause()?;
        // Load disposes of the machine the old link was attached to.
        self.gdb = None;
        self.monitor.load(&self.snapshot_path)?;
        self.monitor.select_machine(&self.machine)?;
        self.monitor.start_gdb_server(self.gdb_server_port)?;
        let gdb = self.gdb.insert(GdbClient::new((self.connect_gdb)()?));
        gdb.attach()?;
        if let Some((address, kind)) = self.harness_breakpoint {
            gdb.insert_sw_breakpoint(address, kind)?;
        }
        run_from_baseline(gdb, &self.run, input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A channel that serves a fixed byte script to reads (EOF after it) and
    /// records what the client writes.
    struct Scripted {
        to_read: std::collections::VecDeque<u8>,
        written: Vec<u8>,
    }

    impl Read for Scripted {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.to_read.pop_front() {
                Some(byte) => {
                    buf[0] = byte;
                    Ok(1)
                }
                None => Ok(0),
            }
        }
    }

    impl Write for Scripted {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn monitor_over(bytes: &[u8]) -> RenodeMonitor<Scripted> {
        RenodeMonitor::new(Scripted {
            to_read: bytes.iter().copied().collect(),
            written: Vec::new(),
        })
    }

    /// Renode 1.17's greeting, byte for byte, with colours on.
    const GREETING: &[u8] = b"\xff\xfd\x00\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03\xff\xfc\"\
        \x1b[0mRenode, version 1.17.0 (1.17.0+20261117git8e500459a)\n\r\n\r\
        \x1b[91m(monitor) \x1b[0m";

    /// The reply to [`SYNC_COMMAND`].
    const SYNC_REPLY: &[u8] = b"$bhf_sync=\"bhf\"\n\r\x1b[33m(machine-0) \x1b[0m";

    /// The greeting and the sync reply, then `rest`.
    fn session(rest: &[u8]) -> Vec<u8> {
        [GREETING, SYNC_REPLY, rest].concat()
    }

    #[test]
    fn connect_reads_the_telnet_greeting_up_to_the_prompt_and_syncs() {
        let mut monitor = monitor_over(&session(b""));
        assert_eq!(
            monitor.connect().unwrap(),
            "Renode, version 1.17.0 (1.17.0+20261117git8e500459a)"
        );
        assert_eq!(monitor.channel.written, b"$bhf_sync=\"bhf\"\n");
    }

    /// Renode started with a board script prints the script's `i @...` line
    /// and another prompt after the greeting. Without the sync, `pause` would
    /// read that as its reply and every later reply would lag one behind.
    #[test]
    fn output_of_the_startup_script_is_skipped_before_the_first_command() {
        let bytes = [
            GREETING,
            b"i @/work/board.resc\n\r\x1b[33m(machine-0) \x1b[0m",
            SYNC_REPLY,
            b"pause\n\rPausing emulation...\r\n\r\x1b[33m(machine-0) \x1b[0m",
            b"Save @base.save\n\r(machine-0) ",
        ]
        .concat();
        let mut monitor = monitor_over(&bytes);
        monitor.connect().unwrap();
        monitor.pause().unwrap();
        monitor.save("base.save").unwrap();
    }

    #[test]
    fn execute_strips_echo_colour_and_prompt_and_sends_one_line() {
        let mut monitor = monitor_over(&session(
            b"pause\n\rPausing emulation...\r\n\r\x1b[33m(machine-0) \x1b[0m",
        ));
        monitor.connect().unwrap();
        monitor.channel.written.clear();
        assert_eq!(monitor.execute("pause").unwrap(), "Pausing emulation...");
        assert_eq!(monitor.channel.written, b"pause\n");
    }

    #[test]
    fn save_and_load_send_the_at_path_form_and_accept_silence() {
        let mut monitor = monitor_over(&session(
            b"Save @/tmp/base.save\n\r\x1b[33m(machine-0) \x1b[0m\
              Load @/tmp/base.save\n\r(machine-0) ",
        ));
        monitor.connect().unwrap();
        monitor.channel.written.clear();
        monitor.save("/tmp/base.save").unwrap();
        monitor.load("/tmp/base.save").unwrap();
        assert_eq!(
            monitor.channel.written,
            b"Save @/tmp/base.save\nLoad @/tmp/base.save\n"
        );
    }

    #[test]
    fn a_failed_command_is_a_target_error_with_renodes_text() {
        let mut bytes = session(b"");
        bytes.extend_from_slice(
            b"Load @missing.save\n\r\r\nThe following methods are available:\r\n\r \
              - Void Load (ReadFilePath path, Boolean preserveState = False)\r\n\r\r\n\r\
              There was an error executing command 'Load @missing.save': \r\n\
              Parameters did not match the signature\r\n(machine-0) ",
        );
        let mut monitor = monitor_over(&bytes);
        monitor.connect().unwrap();
        let err = monitor.load("missing.save").unwrap_err();
        assert!(
            matches!(&err, TransportError::TargetError(m) if m.contains("did not match")),
            "{err}"
        );
    }

    #[test]
    fn an_unknown_command_is_a_target_error() {
        let mut bytes = session(b"");
        bytes.extend_from_slice(
            b"machine StartGdbServer 3333\n\r\x1b[91mNo such command or device: machine\r\n\
              \x1b[0m\x1b[91m(monitor) \x1b[0m",
        );
        let mut monitor = monitor_over(&bytes);
        monitor.connect().unwrap();
        let err = monitor.start_gdb_server(3333).unwrap_err();
        assert!(err.to_string().contains("No such command"), "{err}");
    }

    #[test]
    fn a_gdb_server_already_on_the_port_is_accepted_and_another_port_is_not() {
        let already = |port: u16| {
            let mut bytes = session(b"");
            bytes.extend_from_slice(
                format!(
                    "machine StartGdbServer {port}\n\r\x1b[91mThere was an error executing \
                     command 'machine StartGdbServer {port}': \r\n\x1b[0m\x1b[91mCPU: \
                     machine-0.cpu is already attached to an existing GDB server, running on \
                     port :3333\r\n\x1b[0m\x1b[33m(machine-0) \x1b[0m"
                )
                .as_bytes(),
            );
            let mut monitor = monitor_over(&bytes);
            monitor.connect().unwrap();
            monitor.start_gdb_server(port)
        };
        already(3333).unwrap();
        assert!(already(4444).is_err());
    }

    #[test]
    fn unexpected_output_from_a_snapshot_command_is_an_error() {
        let mut bytes = session(b"");
        bytes.extend_from_slice(b"Save @base.save\n\rsomething odd\r\n(machine-0) ");
        let mut monitor = monitor_over(&bytes);
        monitor.connect().unwrap();
        let err = monitor.save("base.save").unwrap_err();
        assert!(err.to_string().contains("something odd"), "{err}");
    }

    #[test]
    fn a_monitor_that_closes_before_its_prompt_is_a_descriptive_error() {
        // `Save` into a missing directory makes Renode 1.17 exit.
        let mut bytes = session(b"");
        bytes.extend_from_slice(b"Save @/nonexistent/x.save\n\r");
        let mut monitor = monitor_over(&bytes);
        monitor.connect().unwrap();
        let err = monitor.save("/nonexistent/x.save").unwrap_err();
        assert!(err.to_string().contains("closed the link"), "{err}");
    }

    #[test]
    fn a_reply_without_a_prompt_is_bounded() {
        let mut bytes = b"x".repeat(64);
        bytes.extend_from_slice(b"(monitor) ");
        let mut monitor = RenodeMonitor::with_limits(
            Scripted {
                to_read: bytes.into_iter().collect(),
                written: Vec::new(),
            },
            RenodeLimits {
                max_reply_bytes: 32,
            },
        );
        let err = monitor.connect().unwrap_err();
        assert!(err.to_string().contains("exceeded 32 bytes"), "{err}");
    }

    #[test]
    fn telnet_subnegotiation_and_escaped_iac_are_decoded() {
        let bytes = [
            &b"\xff\xfa\x1f\x00\x50\xff\xff\x00\x18\xff\xf0A\xff\xffB\n\r(monitor) "[..],
            SYNC_REPLY,
        ]
        .concat();
        let mut monitor = monitor_over(&bytes);
        assert_eq!(monitor.connect().unwrap(), "A\u{fffd}B");
    }

    #[test]
    fn a_line_that_only_looks_like_a_prompt_mid_line_does_not_end_the_reply() {
        let mut bytes = session(b"");
        bytes.extend_from_slice(b"cpu PC\n\rvalue (hex) 0x10\r\n(machine-0) ");
        let mut monitor = monitor_over(&bytes);
        monitor.connect().unwrap();
        assert_eq!(monitor.execute("cpu PC").unwrap(), "value (hex) 0x10");
    }

    #[test]
    fn snapshot_paths_that_could_split_the_command_are_refused() {
        for bad in ["", "a b.save", "x;quit", "x\nquit", "\"q\".save", "x@y"] {
            assert!(validate_snapshot_path(bad).is_err(), "{bad:?} accepted");
        }
        for good in ["bhf-baseline.save", "/tmp/a_b.save", r"C:\renode\base.save"] {
            validate_snapshot_path(good).unwrap();
        }
    }

    /// Renode 1.17.0 leaves no machine selected after `Load`; `mach set`
    /// selects it again, and a name it does not know is an error although
    /// Renode prints no error prefix for it.
    #[test]
    fn the_machine_is_selected_again_after_load_and_an_unknown_one_is_an_error() {
        let mut monitor = monitor_over(&session(
            b"Load @base.save\n\r\x1b[91m(monitor) \x1b[0m\
              mach set \"machine-0\"\n\r\x1b[33m(machine-0) \x1b[0m\
              Load @base.save\n\r(monitor) \
              mach set \"board\"\n\rMachine board not found.\r\n(monitor) ",
        ));
        monitor.connect().unwrap();
        assert_eq!(monitor.selected_machine(), Some("machine-0"));
        monitor.load("base.save").unwrap();
        assert_eq!(monitor.selected_machine(), None);
        monitor.select_machine("machine-0").unwrap();
        assert_eq!(monitor.selected_machine(), Some("machine-0"));
        monitor.load("base.save").unwrap();
        let err = monitor.select_machine("board").unwrap_err();
        assert!(err.to_string().contains("not found"), "{err}");
        assert!(monitor.select_machine("a\"b").is_err());
    }

    /// Renode started without a board script has no machine: arming says so
    /// instead of saving a baseline no run could select again.
    #[test]
    fn arming_with_no_machine_selected_is_a_descriptive_error() {
        let bytes = [
            GREETING,
            b"$bhf_sync=\"bhf\"\n\r(monitor) ",
            b"pause\n\rPausing emulation...\r\n\r(monitor) ",
        ]
        .concat();
        let channel = std::sync::Mutex::new(Some(Scripted {
            to_read: bytes.into_iter().collect(),
            written: Vec::new(),
        }));
        let transport = RenodeTransport::new(
            move || {
                channel
                    .lock()
                    .unwrap()
                    .take()
                    .ok_or_else(|| TransportError::protocol("dialed twice"))
            },
            || -> Result<crate::testsupport::DuplexStream> {
                Err(TransportError::protocol("gdb is not dialed at arm"))
            },
            3333,
            GdbMemoryMap {
                input_address: 0,
                ring_address: 0,
                ring_write_address: 0,
                ring_wrapped_address: 0,
                ring_capacity: 1,
            },
            DEFAULT_SNAPSHOT_PATH,
        )
        .unwrap();
        let err = transport.arm().err().expect("arm must fail");
        assert!(err.to_string().contains("no machine selected"), "{err}");
    }

    #[test]
    fn a_command_with_a_newline_is_refused_before_it_is_sent() {
        let mut monitor = monitor_over(&session(b""));
        monitor.connect().unwrap();
        monitor.channel.written.clear();
        assert!(monitor.execute("pause\nquit").is_err());
        assert!(monitor.channel.written.is_empty());
    }
}
