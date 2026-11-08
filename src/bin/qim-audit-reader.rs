//! Receive audit records from the kernel and write them to an inherited fd.
//!
//! Usage: qim-audit-reader <fd>
//!
//! Registers itself as the audit daemon, configures the kernel queue so that it
//! never drops records for backlog or rate reasons, and writes every record as a
//! line in the format auditd uses for log_format = RAW:
//!
//!     type=<NAME> msg=<payload>
//!
//! EOE records are not written, matching auditd's RAW logs. SIGTERM makes the
//! reader drain what the socket already holds, flush and exit. The exit status
//! is 0, or 2 if the socket ever overflowed (ENOBUFS), in which case records may
//! be missing even though the kernel's lost counter does not say so.

use std::borrow::Cow;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const AUDIT_SET: u16 = 1001;
const AUDIT_EOE: u16 = 1320;
const STATUS_ENABLED: u32 = 0x1;
const STATUS_FAILURE: u32 = 0x2;
const STATUS_PID: u32 = 0x4;
const STATUS_RATE_LIMIT: u32 = 0x8;
const STATUS_BACKLOG_LIMIT: u32 = 0x10;
const FAILURE_PRINTK: u32 = 1;
/// struct nlmsghdr: length, type, flags, sequence number, port id.
const HEADER_LENGTH: usize = 16;

static STOPPING: AtomicBool = AtomicBool::new(false);

extern "C" fn on_term(_signal: libc::c_int) {
    STOPPING.store(true, Ordering::SeqCst);
}

/// The AUDIT_SET request that registers `pid` as the audit daemon and lifts the
/// rate and backlog limits.
fn status_message(pid: u32) -> Vec<u8> {
    let mask = STATUS_ENABLED | STATUS_FAILURE | STATUS_PID | STATUS_RATE_LIMIT | STATUS_BACKLOG_LIMIT;
    // struct audit_status: mask, enabled, failure, pid, rate_limit, backlog_limit (then fields left 0)
    let payload: [u32; 11] = [mask, 1, FAILURE_PRINTK, pid, 0, 0, 0, 0, 0, 0, 0];
    let length = (HEADER_LENGTH + size_of_val(&payload)) as u32;
    let mut message = Vec::with_capacity(length as usize);
    message.extend(length.to_ne_bytes());
    message.extend(AUDIT_SET.to_ne_bytes());
    message.extend((NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    message.extend(1u32.to_ne_bytes());
    message.extend(0u32.to_ne_bytes());
    for field in payload {
        message.extend(field.to_ne_bytes());
    }
    message
}

fn type_name(kind: u16) -> Cow<'static, str> {
    Cow::Borrowed(match kind {
        1100 => "USER_AUTH",
        1101 => "USER_ACCT",
        1102 => "USER_MGMT",
        1103 => "CRED_ACQ",
        1104 => "CRED_DISP",
        1105 => "USER_START",
        1106 => "USER_END",
        1107 => "USER_AVC",
        1108 => "USER_CHAUTHTOK",
        1109 => "USER_ERR",
        1110 => "CRED_REFR",
        1111 => "USYS_CONFIG",
        1112 => "USER_LOGIN",
        1113 => "USER_LOGOUT",
        1114 => "ADD_USER",
        1115 => "DEL_USER",
        1116 => "ADD_GROUP",
        1117 => "DEL_GROUP",
        1124 => "USER_CMD",
        1125 => "USER_TTY",
        1130 => "SERVICE_START",
        1131 => "SERVICE_STOP",
        1200 => "DAEMON_START",
        1201 => "DAEMON_END",
        1202 => "DAEMON_ABORT",
        1203 => "DAEMON_CONFIG",
        1300 => "SYSCALL",
        1302 => "PATH",
        1303 => "IPC",
        1304 => "SOCKETCALL",
        1305 => "CONFIG_CHANGE",
        1306 => "SOCKADDR",
        1307 => "CWD",
        1309 => "EXECVE",
        1311 => "IPC_SET_PERM",
        1316 => "KERNEL_OTHER",
        1317 => "FD_PAIR",
        1318 => "OBJ_PID",
        1319 => "TTY",
        1321 => "BPRM_FCAPS",
        1322 => "CAPSET",
        1323 => "MMAP",
        1324 => "NETFILTER_PKT",
        1325 => "NETFILTER_CFG",
        1326 => "SECCOMP",
        1327 => "PROCTITLE",
        1328 => "FEATURE_CHANGE",
        1329 => "REPLACE",
        1330 => "KERN_MODULE",
        1331 => "FANOTIFY",
        1334 => "BPF",
        1336 => "URINGOP",
        1337 => "OPENAT2",
        2000 => "KERNEL",
        _ => return Cow::Owned(format!("UNKNOWN[{kind}]")),
    })
}

/// What one datagram from the audit socket means for the output.
#[derive(Debug, PartialEq)]
enum Datagram {
    /// Nothing to write: too short, an acknowledgement or an EOE record.
    Skip,
    /// The kernel rejected the request with this (negative) errno.
    Rejected(i32),
    /// A record line, ending with a newline.
    Line(Vec<u8>),
}

fn classify(datagram: &[u8]) -> Datagram {
    // Each datagram carries one message. Records sent to the audit daemon have
    // nlmsg_len set to the payload length without the header (a kernel quirk
    // kept for compatibility), so it cannot be used to walk the datagram.
    let Some((header, payload)) = datagram.split_at_checked(HEADER_LENGTH) else {
        return Datagram::Skip;
    };
    match u16::from_ne_bytes([header[4], header[5]]) {
        NLMSG_ERROR => match payload.first_chunk::<4>().map(|error| i32::from_ne_bytes(*error)) {
            Some(0) => Datagram::Skip,
            Some(error) => Datagram::Rejected(error),
            None => Datagram::Rejected(-libc::EBADMSG),
        },
        AUDIT_EOE => Datagram::Skip,
        kind => {
            let end = payload.iter().rposition(|&byte| byte != 0 && byte != b'\n').map_or(0, |last| last + 1);
            let mut line = format!("type={} msg=", type_name(kind)).into_bytes();
            line.extend_from_slice(&payload[..end]);
            line.push(b'\n');
            Datagram::Line(line)
        }
    }
}

fn os_error(call: &str) -> String {
    format!("{call}: {}", io::Error::last_os_error())
}

fn set_socket_option<T>(socket: &OwnedFd, option: libc::c_int, value: &T) -> Result<(), String> {
    // SAFETY: `value` is valid for size_of::<T>() bytes.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            (value as *const T).cast(),
            size_of::<T>() as libc::socklen_t,
        )
    };
    if result < 0 { Err(os_error("setsockopt")) } else { Ok(()) }
}

fn audit_socket() -> Result<OwnedFd, String> {
    // SAFETY: socket has no memory preconditions; a valid result is owned here.
    let socket = unsafe {
        let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_AUDIT);
        if fd < 0 {
            return Err(os_error("socket"));
        }
        OwnedFd::from_raw_fd(fd)
    };
    // SAFETY: an all-zero sockaddr_nl is valid.
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    // SAFETY: the address is valid for its size.
    let bound = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&raw const address).cast(),
            size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if bound < 0 {
        return Err(os_error("bind"));
    }
    // SO_RCVBUF is capped by net.core.rmem_max; the forced variant (root) is not.
    set_socket_option(&socket, libc::SO_RCVBUFFORCE, &((256 << 20) as libc::c_int))?;
    Ok(socket)
}

fn run() -> Result<u8, String> {
    let fd: RawFd = std::env::args()
        .nth(1)
        .and_then(|argument| argument.parse().ok())
        .ok_or("usage: qim-audit-reader <fd>")?;
    // SAFETY: the fd is inherited for this program's exclusive use.
    let mut out = BufWriter::with_capacity(1 << 20, unsafe { File::from_raw_fd(fd) });
    let socket = audit_socket()?;
    let message = status_message(std::process::id());
    // SAFETY: the message is valid for its length.
    if unsafe { libc::send(socket.as_raw_fd(), message.as_ptr().cast(), message.len(), 0) } < 0 {
        return Err(os_error("send"));
    }
    // SAFETY: the handler only stores to an atomic, which is async-signal-safe.
    unsafe { libc::signal(libc::SIGTERM, on_term as extern "C" fn(libc::c_int) as libc::sighandler_t) };
    set_socket_option(&socket, libc::SO_RCVTIMEO, &libc::timeval { tv_sec: 0, tv_usec: 500_000 })?;
    let mut buffer = vec![0u8; 1 << 16];
    let mut overflows = 0u64;
    loop {
        // SAFETY: the buffer is valid for its length.
        let received = unsafe { libc::recv(socket.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len(), 0) };
        if received < 0 {
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                // The receive timeout passed without a record.
                Some(libc::EAGAIN) if STOPPING.load(Ordering::SeqCst) => break,
                Some(libc::EAGAIN | libc::EINTR) => continue,
                Some(libc::ENOBUFS) => {
                    overflows += 1;
                    continue;
                }
                _ => return Err(format!("recv: {error}")),
            }
        }
        match classify(&buffer[..received as usize]) {
            Datagram::Skip => {}
            Datagram::Rejected(error) => {
                eprintln!("audit-reader: kernel rejected a request: errno {}", -error);
                return Ok(1);
            }
            Datagram::Line(line) => out.write_all(&line).map_err(|error| format!("write: {error}"))?,
        }
    }
    out.flush().map_err(|error| format!("write: {error}"))?;
    if overflows > 0 {
        eprintln!("audit-reader: the socket overflowed {overflows} times");
        return Ok(2);
    }
    Ok(0)
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("audit-reader: {message}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn datagram(kind: u16, nlmsg_len: u32, payload: &[u8]) -> Vec<u8> {
        let mut datagram = nlmsg_len.to_ne_bytes().to_vec();
        datagram.extend(kind.to_ne_bytes());
        datagram.extend(0u16.to_ne_bytes());
        datagram.extend(7u32.to_ne_bytes());
        datagram.extend(0u32.to_ne_bytes());
        datagram.extend_from_slice(payload);
        datagram
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn status_message_registers_the_reader_and_lifts_the_limits() {
        // struct.pack("=IHHII", 60, 1001, 5, 1, 0) + struct.pack("=11I", 0x1f, 1, 1, 1234, 0, ...)
        let mut expected = b"\x3c\x00\x00\x00\xe9\x03\x05\x00\x01\x00\x00\x00\x00\x00\x00\x00".to_vec();
        expected.extend(b"\x1f\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\xd2\x04\x00\x00");
        expected.extend([0; 28]);
        assert_eq!(status_message(1234), expected);
    }

    #[test]
    fn records_are_written_whole_whatever_nlmsg_len_says() {
        let payload = b"audit(1.002:3): arch=c000003e syscall=59 success=yes";
        let line = classify(&datagram(1300, payload.len() as u32, payload));
        assert_eq!(line, Datagram::Line(b"type=SYSCALL msg=audit(1.002:3): arch=c000003e syscall=59 success=yes\n".to_vec()));
    }

    #[test]
    fn trailing_nul_and_newline_are_stripped() {
        let line = classify(&datagram(1302, 0, b"audit(1.002:3): item=0 name=\"/\"\n\0\n\0"));
        assert_eq!(line, Datagram::Line(b"type=PATH msg=audit(1.002:3): item=0 name=\"/\"\n".to_vec()));
    }

    #[test]
    fn unknown_types_are_named_by_number() {
        assert_eq!(classify(&datagram(1400, 0, b"x")), Datagram::Line(b"type=UNKNOWN[1400] msg=x\n".to_vec()));
    }

    #[test]
    fn eoe_acknowledgements_and_short_datagrams_are_skipped() {
        assert_eq!(classify(&datagram(AUDIT_EOE, 0, b"audit(1.002:3): ")), Datagram::Skip);
        assert_eq!(classify(&datagram(NLMSG_ERROR, 36, &[0; 20])), Datagram::Skip);
        assert_eq!(classify(&[0; 15]), Datagram::Skip);
    }

    #[test]
    fn a_rejected_request_carries_the_errno() {
        let mut payload = (-libc::EPERM).to_ne_bytes().to_vec();
        payload.extend([0; 16]);
        assert_eq!(classify(&datagram(NLMSG_ERROR, 36, &payload)), Datagram::Rejected(-libc::EPERM));
        assert_eq!(classify(&datagram(NLMSG_ERROR, 16, b"")), Datagram::Rejected(-libc::EBADMSG));
    }
}
