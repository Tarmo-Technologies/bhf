// SPDX-License-Identifier: Apache-2.0

//! The serial device behind `--target-transport agent:serial:PATH`, opened
//! raw. A tty's default line discipline echoes, edits lines and turns a
//! 0x0A byte into 0x0D 0x0A, which corrupts the agent's binary frames, and a
//! plain read blocks forever on a silent device. The port here passes every
//! byte through unchanged at the requested baud rate, 8N1 with no flow
//! control, and bounds every read by the run's `--timeout`.

use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;

/// An open serial port in raw mode.
pub(crate) struct SerialPort {
    file: std::fs::File,
    timeout: Option<Duration>,
}

/// Open `path` raw, at `baud` when given (else at its current rate), with
/// reads bounded by `timeout`.
pub(crate) fn open(
    path: &Path,
    baud: Option<u32>,
    timeout: Option<Duration>,
) -> io::Result<SerialPort> {
    let file = platform::open(path)?;
    platform::configure(&file, baud, timeout)?;
    Ok(SerialPort { file, timeout })
}

fn timed_out(timeout: Option<Duration>) -> io::Error {
    let after = timeout.map_or_else(String::new, |t| format!(" within {}ms", t.as_millis()));
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!("the serial device sent nothing{after}"),
    )
}

impl Read for SerialPort {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        platform::wait_readable(&self.file, self.timeout)?;
        match self.file.read(buf)? {
            // A raw port's read returns nothing only when its deadline passed.
            0 => Err(timed_out(self.timeout)),
            n => Ok(n),
        }
    }
}

impl Write for SerialPort {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(unix)]
mod platform {
    use std::io;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;
    use std::time::Duration;

    pub(super) fn open(path: &Path) -> io::Result<std::fs::File> {
        // O_NOCTTY: opening the port must not make it this process's
        // controlling terminal.
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open(path)
    }

    fn speed(baud: u32) -> io::Result<libc::speed_t> {
        Ok(match baud {
            1200 => libc::B1200,
            2400 => libc::B2400,
            4800 => libc::B4800,
            9600 => libc::B9600,
            19200 => libc::B19200,
            38400 => libc::B38400,
            57600 => libc::B57600,
            115200 => libc::B115200,
            230400 => libc::B230400,
            #[cfg(target_os = "linux")]
            460800 => libc::B460800,
            #[cfg(target_os = "linux")]
            921600 => libc::B921600,
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("baud rate {other} is not one this host's serial driver takes"),
                ))
            }
        })
    }

    pub(super) fn configure(
        file: &std::fs::File,
        baud: Option<u32>,
        _timeout: Option<Duration>,
    ) -> io::Result<()> {
        let fd = file.as_raw_fd();
        // SAFETY: `termios` is plain data that tcgetattr fills in full.
        let mut tio: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: `fd` is an open descriptor and `tio` a valid termios.
        if unsafe { libc::tcgetattr(fd, &mut tio) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `tio` is a valid termios from tcgetattr.
        unsafe { libc::cfmakeraw(&mut tio) };
        tio.c_cflag |= libc::CLOCAL | libc::CREAD;
        tio.c_cflag &= !(libc::CSTOPB | libc::PARENB);
        // Reads return what has arrived; `wait_readable` bounds the wait.
        tio.c_cc[libc::VMIN] = 0;
        tio.c_cc[libc::VTIME] = 0;
        if let Some(baud) = baud {
            let speed = speed(baud)?;
            // SAFETY: `tio` is a valid termios.
            if unsafe { libc::cfsetispeed(&mut tio, speed) } != 0
                || unsafe { libc::cfsetospeed(&mut tio, speed) } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        // SAFETY: `fd` is open and `tio` a valid termios.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &tio) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn wait_readable(file: &std::fs::File, timeout: Option<Duration>) -> io::Result<()> {
        let millis = timeout.map_or(-1, |t| i32::try_from(t.as_millis()).unwrap_or(i32::MAX));
        let mut poll = libc::pollfd {
            fd: file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            // SAFETY: `poll` points at one valid pollfd.
            match unsafe { libc::poll(&mut poll, 1, millis) } {
                0 => return Err(super::timed_out(timeout)),
                n if n > 0 => return Ok(()),
                _ => {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::Interrupted {
                        return Err(error);
                    }
                }
            }
        }
    }
}

#[cfg(windows)]
mod platform {
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    type Handle = *mut core::ffi::c_void;

    /// `DCB` (winbase.h): the port's line settings. 28 bytes.
    #[repr(C)]
    #[derive(Default)]
    struct Dcb {
        dcb_length: u32,
        baud_rate: u32,
        flags: u32,
        w_reserved: u16,
        xon_lim: u16,
        xoff_lim: u16,
        byte_size: u8,
        parity: u8,
        stop_bits: u8,
        xon_char: i8,
        xoff_char: i8,
        error_char: i8,
        eof_char: i8,
        evt_char: i8,
        w_reserved1: u16,
    }

    /// `COMMTIMEOUTS` (winbase.h), in milliseconds.
    #[repr(C)]
    struct CommTimeouts {
        read_interval: u32,
        read_total_multiplier: u32,
        read_total_constant: u32,
        write_total_multiplier: u32,
        write_total_constant: u32,
    }

    extern "system" {
        fn GetCommState(file: Handle, dcb: *mut Dcb) -> i32;
        fn SetCommState(file: Handle, dcb: *const Dcb) -> i32;
        fn SetCommTimeouts(file: Handle, timeouts: *const CommTimeouts) -> i32;
    }

    /// `fBinary`: Windows supports binary transfers only, and says so.
    const F_BINARY: u32 = 1;
    /// `fDtrControl = DTR_CONTROL_ENABLE` and `fRtsControl = RTS_CONTROL_ENABLE`:
    /// hold both lines up, as most boards expect, with no hardware flow control.
    const DTR_ENABLE: u32 = 1 << 4;
    const RTS_ENABLE: u32 = 1 << 12;

    /// `COM10` and above open only as `\\.\COM10`; a bare `COMn` gets the prefix.
    fn device_path(path: &Path) -> PathBuf {
        let text = path.to_string_lossy();
        let is_bare_com = text.len() > 3
            && text[..3].eq_ignore_ascii_case("com")
            && text[3..].bytes().all(|b| b.is_ascii_digit());
        if is_bare_com {
            PathBuf::from(format!(r"\\.\{text}"))
        } else {
            path.to_path_buf()
        }
    }

    pub(super) fn open(path: &Path) -> io::Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(device_path(path))
    }

    pub(super) fn configure(
        file: &std::fs::File,
        baud: Option<u32>,
        timeout: Option<Duration>,
    ) -> io::Result<()> {
        let handle = file.as_raw_handle() as Handle;
        let mut dcb = Dcb {
            dcb_length: std::mem::size_of::<Dcb>() as u32,
            ..Dcb::default()
        };
        // SAFETY: `handle` is an open comm handle and `dcb` a sized DCB.
        if unsafe { GetCommState(handle, &mut dcb) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if let Some(baud) = baud {
            dcb.baud_rate = baud;
        }
        // Raw 8N1: no parity, no software or hardware flow control, no
        // character replacement, no abort on error.
        dcb.flags = F_BINARY | DTR_ENABLE | RTS_ENABLE;
        dcb.byte_size = 8;
        dcb.parity = 0;
        dcb.stop_bits = 0;
        // SAFETY: as above.
        if unsafe { SetCommState(handle, &dcb) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // A read returns once what it asked for has arrived or the deadline
        // passed, with what it got; a write gives up at the same deadline.
        let millis = timeout.map_or(0, |t| u32::try_from(t.as_millis()).unwrap_or(u32::MAX));
        let timeouts = CommTimeouts {
            read_interval: 0,
            read_total_multiplier: 0,
            read_total_constant: millis,
            write_total_multiplier: 0,
            write_total_constant: millis,
        };
        // SAFETY: `handle` is open and `timeouts` a valid COMMTIMEOUTS.
        if unsafe { SetCommTimeouts(handle, &timeouts) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// The comm timeouts bound the read itself.
    pub(super) fn wait_readable(
        _file: &std::fs::File,
        _timeout: Option<Duration>,
    ) -> io::Result<()> {
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::device_path;
        use std::path::{Path, PathBuf};

        #[test]
        fn a_bare_com_name_gets_the_device_namespace_prefix() {
            assert_eq!(device_path(Path::new("COM10")), PathBuf::from(r"\\.\COM10"));
            assert_eq!(device_path(Path::new("com3")), PathBuf::from(r"\\.\com3"));
            assert_eq!(
                device_path(Path::new(r"\\.\COM4")),
                PathBuf::from(r"\\.\COM4")
            );
            assert_eq!(device_path(Path::new("COMX")), PathBuf::from("COMX"));
        }

        #[test]
        fn the_dcb_has_the_windows_layout() {
            assert_eq!(std::mem::size_of::<super::Dcb>(), 28);
        }

        /// Over a virtual null-modem pair (com0com, `BHF_SERIAL_LOOPBACK_PAIR=
        /// COM10,COM11`), a frame of CR/LF bytes crosses unchanged and a silent
        /// port times out within its timeout. No physical UART is needed.
        #[test]
        fn a_loopback_pair_passes_frames_unchanged_and_a_silent_port_times_out() {
            use std::io::{Read, Write};
            use std::time::{Duration, Instant};
            let Ok(pair) = std::env::var("BHF_SERIAL_LOOPBACK_PAIR") else {
                eprintln!("skipping: BHF_SERIAL_LOOPBACK_PAIR names no COM port pair");
                return;
            };
            let (host, agent) = pair
                .split_once(',')
                .expect("BHF_SERIAL_LOOPBACK_PAIR=COMa,COMb");
            let timeout = Some(Duration::from_millis(500));
            let mut host =
                super::super::open(Path::new(host.trim()), Some(115_200), timeout).unwrap();
            let mut agent =
                super::super::open(Path::new(agent.trim()), Some(115_200), timeout).unwrap();
            let frame = [4, 0, 0, 0, 0x0A, 0x0D, 0x0A, b'x'];
            host.write_all(&frame).unwrap();
            let mut got = [0_u8; 8];
            agent.read_exact(&mut got).unwrap();
            assert_eq!(got, frame);

            let started = Instant::now();
            let mut byte = [0_u8; 1];
            let error = host.read(&mut byte).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::TimedOut, "{error}");
            assert!(
                started.elapsed() < Duration::from_secs(3),
                "{:?}",
                started.elapsed()
            );
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::ffi::CStr;
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::time::Instant;

    /// A pseudo-terminal: the master end and the slave's path. The slave
    /// starts in the default cooked mode, as a real tty does.
    fn pty() -> (std::fs::File, std::path::PathBuf) {
        // SAFETY: plain libc calls on a fresh descriptor, checked below.
        unsafe {
            let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            assert!(master >= 0, "posix_openpt: {}", io::Error::last_os_error());
            assert_eq!(libc::grantpt(master), 0);
            assert_eq!(libc::unlockpt(master), 0);
            let mut name = [0 as libc::c_char; 128];
            assert_eq!(libc::ptsname_r(master, name.as_mut_ptr(), name.len()), 0);
            let path = CStr::from_ptr(name.as_ptr()).to_string_lossy().into_owned();
            (
                std::fs::File::from(OwnedFd::from_raw_fd(master)),
                std::path::PathBuf::from(path),
            )
        }
    }

    /// Read exactly `n` bytes from the master, giving up after five seconds.
    fn read_master(master: &mut std::fs::File, n: usize) -> Vec<u8> {
        let mut got = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        while got.len() < n && Instant::now() < deadline {
            platform::wait_readable(master, Some(Duration::from_millis(200))).ok();
            let mut chunk = [0_u8; 64];
            if let Ok(read) = master.read(&mut chunk[..(n - got.len()).min(64)]) {
                got.extend_from_slice(&chunk[..read]);
            }
        }
        got
    }

    #[test]
    fn a_frame_with_newline_bytes_crosses_a_pty_unchanged_both_ways() {
        let (mut master, slave) = pty();
        let mut port = open(&slave, Some(115_200), Some(Duration::from_secs(2))).unwrap();
        let frame = [4, 0, 0, 0, 0x0A, 0x0D, 0x0A, b'x'];
        port.write_all(&frame).unwrap();
        assert_eq!(read_master(&mut master, frame.len()), frame);

        let reply = [0x0D, 0x0A, 0x0D, 0x0A, 0x7F, 0x03];
        master.write_all(&reply).unwrap();
        let mut back = [0_u8; 6];
        port.read_exact(&mut back).unwrap();
        assert_eq!(back, reply);
    }

    #[test]
    fn a_silent_device_times_out_within_the_timeout() {
        let (_master, slave) = pty();
        let mut port = open(&slave, None, Some(Duration::from_millis(300))).unwrap();
        let started = Instant::now();
        let mut byte = [0_u8; 1];
        let error = port.read(&mut byte).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{error}");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn an_unknown_baud_rate_is_refused() {
        let (_master, slave) = pty();
        let error = open(&slave, Some(12_345), None).err().unwrap();
        assert!(error.to_string().contains("baud rate 12345"), "{error}");
    }
}
