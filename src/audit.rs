//! Conversion of the guest audit log and the host-side network records into
//! events.json (docs/events.md).

use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap, HashMap};
use std::fmt::Write as _;
use std::io::BufRead;

use serde_json::{Map, Value, json};

use crate::errnos;

/// A syscall event record may arrive after event records with serials up to
/// this much larger. An event is processed once an event record with a serial
/// at least this much larger has been seen: no record of it, or of any event
/// before it, can be accepted after that.
pub const REORDER_WINDOW: i64 = 10000;

const SCHEMA_VERSION: u64 = 1;

const SYS_OPEN: i64 = 2;
const SYS_CLOSE: i64 = 3;
const SYS_DUP: i64 = 32;
const SYS_DUP2: i64 = 33;
const SYS_FCNTL: i64 = 72;
const SYS_RENAME: i64 = 82;
const SYS_MKDIR: i64 = 83;
const SYS_RMDIR: i64 = 84;
const SYS_CREAT: i64 = 85;
const SYS_LINK: i64 = 86;
const SYS_UNLINK: i64 = 87;
const SYS_SYMLINK: i64 = 88;
const SYS_OPENAT: i64 = 257;
const SYS_MKDIRAT: i64 = 258;
const SYS_UNLINKAT: i64 = 263;
const SYS_RENAMEAT: i64 = 264;
const SYS_LINKAT: i64 = 265;
const SYS_SYMLINKAT: i64 = 266;
const SYS_DUP3: i64 = 292;
const SYS_RENAMEAT2: i64 = 316;
const SYS_EXECVEAT: i64 = 322;
const SYS_CLOSE_RANGE: i64 = 436;
const SYS_OPENAT2: i64 = 437;

const AT_FDCWD: i64 = -100;
const AT_REMOVEDIR: u64 = 0x200;
const CLOSE_RANGE_CLOEXEC: u64 = 0x4;
const F_DUPFD: u64 = 0;
const F_DUPFD_CLOEXEC: u64 = 0x406;
const O_TRUNC: u64 = 0x200;
const O_PATH: u64 = 0x200000;
const CREAT_FLAGS: u64 = 0x241; // O_WRONLY | O_CREAT | O_TRUNC

fn is_exec(nr: i64) -> bool {
    nr == 59 || nr == SYS_EXECVEAT
}

fn is_clone(nr: i64) -> bool {
    matches!(nr, 56 | 57 | 58 | 435)
}

fn is_open(nr: i64) -> bool {
    matches!(nr, SYS_OPEN | SYS_OPENAT | SYS_OPENAT2 | SYS_CREAT)
}

/// Two-path syscalls: (source op, destination op).
fn two_path_ops(nr: i64) -> Option<(&'static str, &'static str)> {
    match nr {
        SYS_RENAME | SYS_RENAMEAT | SYS_RENAMEAT2 => Some(("rename_from", "rename_to")),
        SYS_LINK | SYS_LINKAT => Some(("link_source", "link")),
        _ => None,
    }
}

fn network_syscall(nr: i64) -> Option<&'static str> {
    match nr {
        42 => Some("connect"),
        44 => Some("sendto"),
        46 => Some("sendmsg"),
        307 => Some("sendmmsg"),
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Syscall,
    Execve,
    Cwd,
    Path,
    Sockaddr,
    Proctitle,
}

fn event_kind(rtype: &str) -> Option<Kind> {
    match rtype {
        "SYSCALL" => Some(Kind::Syscall),
        "EXECVE" => Some(Kind::Execve),
        "CWD" => Some(Kind::Cwd),
        "PATH" => Some(Kind::Path),
        "SOCKADDR" => Some(Kind::Sockaddr),
        "PROCTITLE" => Some(Kind::Proctitle),
        _ => None,
    }
}

/// ASCII whitespace as in Python's `\s` with `re.ASCII`.
fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

fn digits_end(b: &[u8], start: usize) -> Option<usize> {
    let end = start + b[start..].iter().take_while(|c| c.is_ascii_digit()).count();
    (end > start).then_some(end)
}

/// Match `type=(\S+) msg=audit\(\d+\.\d+:(\d+)\): ?` at the start of the line.
/// Returns (type, serial digits, end of the match).
fn parse_header(line: &str) -> Option<(&str, &str, usize)> {
    let b = line.as_bytes();
    let rest = line.strip_prefix("type=")?;
    let type_len = rest.bytes().position(is_space).unwrap_or(rest.len());
    if type_len == 0 {
        return None;
    }
    let mut i = 5 + type_len;
    let tag = b" msg=audit(";
    if !b[i..].starts_with(tag) {
        return None;
    }
    i = digits_end(b, i + tag.len())?;
    if b.get(i) != Some(&b'.') {
        return None;
    }
    i = digits_end(b, i + 1)?;
    if b.get(i) != Some(&b':') {
        return None;
    }
    let serial_start = i + 1;
    i = digits_end(b, serial_start)?;
    let serial = &line[serial_start..i];
    if !b[i..].starts_with(b"):") {
        return None;
    }
    i += 2;
    if b.get(i) == Some(&b' ') {
        i += 1;
    }
    Some((&rest[..type_len], serial, i))
}

/// The fields of a record body, like `dict(re.findall(r'([^\s=]+)=("[^"]*"|\S*)'))`
/// with ASCII classes: a later duplicate key wins.
fn parse_fields(body: &str) -> HashMap<&str, &str> {
    let b = body.as_bytes();
    let mut fields = HashMap::new();
    let mut i = 0;
    while i < b.len() {
        let key_end = i + b[i..].iter().take_while(|&&c| !is_space(c) && c != b'=').count();
        if key_end == i || b.get(key_end) != Some(&b'=') {
            // Every start inside this run fails the same way.
            i = key_end.max(i + 1);
            continue;
        }
        let v = key_end + 1;
        let unquoted_end = || v + b[v..].iter().take_while(|&&c| !is_space(c)).count();
        let value_end = if b.get(v) == Some(&b'"') {
            match b[v + 1..].iter().position(|&c| c == b'"') {
                Some(p) => v + 1 + p + 1,
                None => unquoted_end(),
            }
        } else {
            unquoted_end()
        };
        fields.insert(&body[i..key_end], &body[v..value_end]);
        i = value_end;
    }
    fields
}

fn field<'a>(fields: &HashMap<&str, &'a str>, key: &str) -> Result<&'a str, String> {
    fields.get(key).copied().ok_or_else(|| format!("missing field {key}"))
}

/// A decimal field: ASCII digits with an optional minus, as a signed 64-bit value.
fn dec(token: &str) -> Result<i64, String> {
    let digits = token.strip_prefix('-').unwrap_or(token);
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return Err(format!("not a 64-bit decimal number: {token:?}"));
    }
    token.parse().map_err(|_| format!("not a 64-bit decimal number: {token:?}"))
}

/// A register field: ASCII hex digits without 0x, as an unsigned 64-bit value.
fn hex(token: &str) -> Result<u64, String> {
    if token.is_empty() || !token.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("not a 64-bit hexadecimal number: {token:?}"));
    }
    u64::from_str_radix(token, 16).map_err(|_| format!("not a 64-bit hexadecimal number: {token:?}"))
}

/// An fd argument: the low 32 bits of the register as a signed integer.
fn fd_arg(token: &str) -> Result<i64, String> {
    Ok(i64::from(hex(token)? as u32 as i32))
}

fn is_quoted(token: &str) -> bool {
    token.len() >= 2 && token.starts_with('"') && token.ends_with('"')
}

fn hex_bytes(token: &str) -> Result<Vec<u8>, String> {
    let error = || format!("not hexadecimal bytes: {token:?}");
    let b = token.as_bytes();
    if b.len() % 2 != 0 {
        return Err(error());
    }
    let nibble = |c: u8| char::from(c).to_digit(16).ok_or_else(error);
    b.chunks(2).map(|pair| Ok((nibble(pair[0])? * 16 + nibble(pair[1])?) as u8)).collect()
}

/// Bytes of a value whose unquoted form is hex (EXECVE, PATH name, CWD, exe).
fn raw_bytes(token: &str) -> Result<Vec<u8>, String> {
    if is_quoted(token) {
        Ok(token[1..token.len() - 1].as_bytes().to_vec())
    } else {
        hex_bytes(token)
    }
}

fn decode(token: &str) -> Result<Option<String>, String> {
    if token == "(null)" {
        return Ok(None);
    }
    if is_quoted(token) {
        return Ok(Some(token[1..token.len() - 1].to_string()));
    }
    Ok(Some(backslashreplace(&hex_bytes(token)?)))
}

/// UTF-8 decoding with Python's `errors="backslashreplace"`.
fn backslashreplace(mut bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    loop {
        match std::str::from_utf8(bytes) {
            Ok(text) => {
                out.push_str(text);
                return out;
            }
            Err(e) => {
                let (valid, rest) = bytes.split_at(e.valid_up_to());
                out.push_str(std::str::from_utf8(valid).expect("valid_up_to marks valid UTF-8"));
                let bad = e.error_len().unwrap_or(rest.len());
                for byte in &rest[..bad] {
                    let _ = write!(out, "\\x{byte:02x}");
                }
                bytes = &rest[bad..];
            }
        }
    }
}

/// Collapse slashes, drop '.' components and a trailing slash; keep '..'.
fn normalize(path: &str) -> String {
    let joined = path.split('/').filter(|p| !p.is_empty() && *p != ".").collect::<Vec<_>>().join("/");
    let path = if path.starts_with('/') { format!("/{joined}") } else { joined };
    if path.is_empty() { "/".to_string() } else { path }
}

fn argv(fields: &HashMap<&str, &str>) -> Result<Vec<Value>, String> {
    let mut args = Vec::new();
    for i in 0..dec(field(fields, "argc")?)? {
        let key = format!("a{i}");
        if let Some(token) = fields.get(key.as_str()) {
            args.push(decode(token)?.map_or(Value::Null, Value::String));
            continue;
        }
        if !fields.contains_key(format!("{key}_len").as_str()) {
            return Err(format!("EXECVE argument {key} is missing"));
        }
        let mut bytes = Vec::new();
        let mut chunk = 0;
        while let Some(token) = fields.get(format!("{key}[{chunk}]").as_str()) {
            bytes.extend(raw_bytes(token)?);
            chunk += 1;
        }
        args.push(Value::String(backslashreplace(&bytes)));
    }
    Ok(args)
}

/// RFC 5952 text, with IPv4-mapped addresses as ::ffff:a.b.c.d (Python's ipaddress).
pub(crate) fn ipv6_text(b: &[u8]) -> String {
    let h: Vec<u16> = (0..8).map(|i| u16::from_be_bytes([b[2 * i], b[2 * i + 1]])).collect();
    if h[..5].iter().all(|&x| x == 0) && h[5] == 0xffff {
        return format!("::ffff:{}.{}.{}.{}", b[12], b[13], b[14], b[15]);
    }
    // The first longest run of at least two zero groups becomes "::".
    let (mut best_start, mut best_len, mut i) = (0, 0, 0);
    while i < 8 {
        if h[i] != 0 {
            i += 1;
            continue;
        }
        let start = i;
        while i < 8 && h[i] == 0 {
            i += 1;
        }
        if i - start > best_len {
            (best_start, best_len) = (start, i - start);
        }
    }
    let groups = |s: &[u16]| s.iter().map(|x| format!("{x:x}")).collect::<Vec<_>>().join(":");
    if best_len > 1 {
        format!("{}::{}", groups(&h[..best_start]), groups(&h[best_start + best_len..]))
    } else {
        groups(&h)
    }
}

/// Decode a SOCKADDR saddr into (family, address, port).
fn sockaddr(token: &str) -> Result<(String, Option<String>, Option<i64>), String> {
    let data = hex_bytes(token)?;
    if data.len() < 2 {
        return Err(format!("saddr too short: {token}"));
    }
    let port = || i64::from(u16::from_be_bytes([data[2], data[3]]));
    match u16::from_le_bytes([data[0], data[1]]) {
        1 => {
            let path = &data[2..];
            let address = if path.first() == Some(&0) {
                let rest: Vec<u8> = path[1..].iter().copied().filter(|&b| b != 0).collect();
                format!("@{}", backslashreplace(&rest))
            } else {
                backslashreplace(&path[..path.iter().position(|&b| b == 0).unwrap_or(path.len())])
            };
            Ok(("unix".to_string(), Some(address), None))
        }
        2 => {
            if data.len() < 8 {
                return Err(format!("inet saddr too short: {token}"));
            }
            let address = format!("{}.{}.{}.{}", data[4], data[5], data[6], data[7]);
            Ok(("inet".to_string(), Some(address), Some(port())))
        }
        10 => {
            if data.len() < 24 {
                return Err(format!("inet6 saddr too short: {token}"));
            }
            Ok(("inet6".to_string(), Some(ipv6_text(&data[8..24])), Some(port())))
        }
        16 => Ok(("netlink".to_string(), None, None)),
        family => Ok((format!("af{family}"), Some(token.to_ascii_lowercase()), None)),
    }
}

/// Ops of the index-th remaining PATH record (PARENT and (null) skipped).
fn file_ops(
    nr: i64,
    sc: &HashMap<&str, &str>,
    nametype: &str,
    index: usize,
) -> Result<Vec<&'static str>, String> {
    if is_exec(nr) {
        return Ok(vec!["exec"]);
    }
    if is_open(nr) {
        if nr == SYS_OPENAT2 {
            return Ok(vec!["open"]);
        }
        let flags = if nr == SYS_CREAT {
            CREAT_FLAGS
        } else {
            hex(field(sc, if nr == SYS_OPEN { "a1" } else { "a2" })?)?
        };
        if flags & O_PATH != 0 {
            return Ok(vec!["path"]);
        }
        let mut ops = match flags & 3 {
            0 => vec!["read"],
            1 => vec!["write"],
            2 => vec!["read", "write"],
            _ => vec!["open"],
        };
        if nametype == "CREATE" {
            ops.push("create");
        }
        if flags & O_TRUNC != 0 {
            ops.push("truncate");
        }
        return Ok(ops);
    }
    if let Some((source_op, destination_op)) = two_path_ops(nr) {
        if index == 0 {
            return Ok(vec![source_op]);
        }
        return Ok(vec![if nametype == "DELETE" { "delete" } else { destination_op }]);
    }
    Ok(match nr {
        SYS_UNLINK => vec!["delete"],
        SYS_UNLINKAT if hex(field(sc, "a2")?)? & AT_REMOVEDIR != 0 => vec!["rmdir"],
        SYS_UNLINKAT => vec!["delete"],
        SYS_RMDIR => vec!["rmdir"],
        SYS_MKDIR | SYS_MKDIRAT => vec!["mkdir"],
        SYS_SYMLINK | SYS_SYMLINKAT => vec!["symlink"],
        _ => vec![],
    })
}

/// The SYSCALL field holding the directory fd for a relative name, if any.
fn dirfd_arg(nr: i64, index: usize) -> Option<&'static str> {
    match nr {
        SYS_OPENAT | SYS_OPENAT2 | SYS_MKDIRAT | SYS_UNLINKAT | SYS_EXECVEAT => Some("a0"),
        SYS_RENAMEAT | SYS_RENAMEAT2 | SYS_LINKAT => Some(if index == 0 { "a0" } else { "a2" }),
        SYS_SYMLINKAT => Some("a1"),
        _ => None,
    }
}

type Fds = HashMap<i64, Option<String>>; // fd -> resolved path, or None when unknown

/// Return (path, dirfd); path is None when the base is unknown.
fn resolve(
    nr: i64,
    sc: &HashMap<&str, &str>,
    index: usize,
    name: &str,
    cwd: Option<&str>,
    fds: &Fds,
) -> Result<(Option<String>, Option<i64>), String> {
    if name.starts_with('/') {
        return Ok((Some(normalize(name)), None));
    }
    if let Some(arg) = dirfd_arg(nr, index) {
        let fd = fd_arg(field(sc, arg)?)?;
        if fd != AT_FDCWD {
            return Ok(match fds.get(&fd) {
                Some(Some(base)) => (Some(normalize(&format!("{base}/{name}"))), None),
                _ => (None, Some(fd)),
            });
        }
    }
    Ok(match cwd {
        Some(cwd) => (Some(normalize(&format!("{cwd}/{name}"))), None),
        None => (None, None),
    })
}

/// Per-pid state: current image, fd table and origin (ppid, serial).
struct State {
    current: Option<u64>,
    fds: Fds,
    origin: (i64, i64),
}

#[derive(PartialEq, Eq, Hash)]
struct FileKey {
    path: Option<String>,
    op: &'static str,
    ok: bool,
    errno: Option<String>,
    dirfd: Option<i64>,
    name: Option<String>,
}

#[derive(PartialEq, Eq, Hash)]
struct NetworkKey {
    syscall: &'static str,
    family: String,
    address: Option<String>,
    port: Option<i64>,
    ok: bool,
    errno: Option<String>,
}

fn add<K: Eq + std::hash::Hash>(entries: &mut HashMap<K, BTreeSet<u64>>, key: K, process: Option<u64>) {
    let processes = entries.entry(key).or_default();
    if let Some(process) = process {
        processes.insert(process);
    }
}

fn dup(fds: &mut Fds, old: i64, new: i64) {
    match fds.get(&old).cloned() {
        Some(path) => {
            fds.insert(new, path);
        }
        None => {
            fds.remove(&new);
        }
    }
}

struct Converter {
    pending: HashMap<i64, Vec<(Kind, String)>>,
    heap: BinaryHeap<Reverse<i64>>,
    max_serial: i64,
    ignored_records: u64,
    syscall_events: u64,
    processes: Vec<Value>,
    states: HashMap<i64, State>,
    files: HashMap<FileKey, BTreeSet<u64>>,
    network: HashMap<NetworkKey, BTreeSet<u64>>,
}

impl Converter {
    fn new() -> Self {
        Converter {
            pending: HashMap::new(),
            heap: BinaryHeap::new(),
            max_serial: -1,
            ignored_records: 0,
            syscall_events: 0,
            processes: Vec::new(),
            states: HashMap::new(),
            files: HashMap::new(),
            network: HashMap::new(),
        }
    }

    fn feed(&mut self, line: &str) -> Result<(), String> {
        let malformed = || format!("malformed audit record: {:?}", line.chars().take(200).collect::<String>());
        let (rtype, serial, body_start) = parse_header(line).ok_or_else(malformed)?;
        let Some(kind) = event_kind(rtype) else {
            self.ignored_records += 1;
            return Ok(());
        };
        let serial = dec(serial)?;
        if i128::from(serial) + i128::from(REORDER_WINDOW) <= i128::from(self.max_serial) {
            return Err(format!(
                "record with serial {serial} after a record with serial {} (reorder window {REORDER_WINDOW})",
                self.max_serial
            ));
        }
        self.max_serial = self.max_serial.max(serial);
        if kind != Kind::Proctitle {
            let records = self.pending.entry(serial).or_insert_with(|| {
                self.heap.push(Reverse(serial));
                Vec::new()
            });
            records.push((kind, line[body_start..].to_string()));
        }
        while let Some(&Reverse(top)) = self.heap.peek() {
            if self.max_serial - top < REORDER_WINDOW {
                break;
            }
            self.process_next()?;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<Value, String> {
        while !self.heap.is_empty() {
            self.process_next()?;
        }
        Ok(self.document())
    }

    fn process_next(&mut self) -> Result<(), String> {
        let Some(Reverse(serial)) = self.heap.pop() else { return Ok(()) };
        let records = self.pending.remove(&serial).expect("a queued serial has records");
        self.process(serial, &records).map_err(|e| format!("event {serial}: {e}"))
    }

    fn process(&mut self, serial: i64, records: &[(Kind, String)]) -> Result<(), String> {
        let mut sc: Option<HashMap<&str, &str>> = None;
        let mut execve: HashMap<&str, &str> = HashMap::new();
        let mut cwd: Option<&str> = None;
        let mut paths: Vec<(i64, &str, &str)> = Vec::new();
        let mut saddr: Option<&str> = None;
        for (kind, body) in records {
            let fields = parse_fields(body);
            match kind {
                Kind::Path => paths.push((
                    dec(field(&fields, "item")?)?,
                    field(&fields, "name")?,
                    field(&fields, "nametype")?,
                )),
                Kind::Execve => execve.extend(fields),
                Kind::Syscall => {
                    if sc.is_some() {
                        return Err("more than one SYSCALL record".to_string());
                    }
                    sc = Some(fields);
                }
                Kind::Cwd => {
                    if cwd.is_some() {
                        return Err("more than one CWD record".to_string());
                    }
                    cwd = Some(field(&fields, "cwd")?);
                }
                Kind::Sockaddr => {
                    if saddr.is_some() {
                        return Err("more than one SOCKADDR record".to_string());
                    }
                    saddr = Some(field(&fields, "saddr")?);
                }
                Kind::Proctitle => {}
            }
        }
        let Some(sc) = sc else { return Ok(()) };
        self.syscall_events += 1;

        let nr = dec(field(&sc, "syscall")?)?;
        let ok = field(&sc, "success")? == "yes";
        let exit_code = dec(field(&sc, "exit")?)?;
        let pid = dec(field(&sc, "pid")?)?;
        let ppid = dec(field(&sc, "ppid")?)?;
        let err = if ok {
            None
        } else {
            let number = -i128::from(exit_code);
            Some(errnos::name(number).map_or_else(|| number.to_string(), str::to_string))
        };
        let cwd = match cwd {
            Some(token) => decode(token)?,
            None => None,
        };

        self.states.entry(pid).or_insert_with(|| State { current: None, fds: Fds::new(), origin: (ppid, serial) });
        let inherited = self.states.get(&ppid).and_then(|s| s.current);
        let origin = self.states[&pid].origin;
        if ok && is_exec(nr) && origin.0 != ppid && i128::from(origin.1) <= i128::from(serial) - i128::from(REORDER_WINDOW) {
            // A new process reusing the pid: reset as if ppid had just created it.
            // (A recent origin with another ppid is a reparented process.)
            let fds = self.states.get(&ppid).map(|s| s.fds.clone()).unwrap_or_default();
            self.states.insert(pid, State { current: inherited, fds, origin: (ppid, serial) });
        }
        let process = if ok && is_exec(nr) {
            let id = self.processes.len() as u64 + 1;
            let parent = self.states[&pid].current.or(inherited);
            let exe = decode(field(&sc, "exe")?)?;
            let args = argv(&execve)?;
            self.processes.push(json!({"id": id, "parent": parent, "exe": exe, "argv": args, "cwd": cwd}));
            if let Some(state) = self.states.get_mut(&pid) {
                state.current = Some(id);
            }
            Some(id)
        } else {
            self.states[&pid].current.or(inherited)
        };

        let mut remaining: Vec<&(i64, &str, &str)> =
            paths.iter().filter(|p| p.2 != "PARENT" && p.1 != "(null)").collect();
        remaining.sort_by_key(|p| p.0);
        let mut opened = None;
        let fds = &self.states[&pid].fds;
        for (index, &&(_, raw_name, nametype)) in remaining.iter().enumerate() {
            let name = decode(raw_name)?.expect("(null) names were skipped");
            let (path, dirfd) = resolve(nr, &sc, index, &name, cwd.as_deref(), fds)?;
            if index == 0 {
                opened = path.clone();
            }
            for op in file_ops(nr, &sc, nametype, index)? {
                let key = FileKey {
                    path: path.clone(),
                    op,
                    ok,
                    errno: err.clone(),
                    dirfd,
                    name: if path.is_none() { Some(name.clone()) } else { None },
                };
                add(&mut self.files, key, process);
            }
        }

        if let (Some(syscall), Some(token)) = (network_syscall(nr), saddr) {
            let (family, address, port) = sockaddr(token)?;
            let key = NetworkKey { syscall, family, address, port, ok, errno: err };
            add(&mut self.network, key, process);
        }

        if ok {
            self.update_state(serial, nr, &sc, exit_code, pid, opened)?;
        }
        Ok(())
    }

    fn update_state(
        &mut self,
        serial: i64,
        nr: i64,
        sc: &HashMap<&str, &str>,
        exit_code: i64,
        pid: i64,
        opened: Option<String>,
    ) -> Result<(), String> {
        if is_clone(nr) && exit_code > 0 {
            let parent_fds = self.states[&pid].fds.clone();
            let keep = self.states.get(&exit_code).is_some_and(|child| {
                child.origin.0 == pid
                    && i128::from(serial) - i128::from(REORDER_WINDOW) < i128::from(child.origin.1)
                    && child.origin.1 < serial
            });
            if keep {
                // The child ran (e.g. with CLONE_VFORK) before its creation was logged.
                if let Some(child) = self.states.get_mut(&exit_code) {
                    for (fd, path) in parent_fds {
                        child.fds.entry(fd).or_insert(path);
                    }
                }
            } else {
                let current = self.states[&pid].current;
                self.states.insert(exit_code, State { current, fds: parent_fds, origin: (pid, serial) });
            }
            return Ok(());
        }
        let fds = &mut self.states.get_mut(&pid).expect("the event's pid has state").fds;
        if is_open(nr) {
            fds.insert(exit_code, opened);
        } else if nr == SYS_CLOSE {
            fds.remove(&fd_arg(field(sc, "a0")?)?);
        } else if nr == SYS_CLOSE_RANGE {
            if hex(field(sc, "a2")?)? & CLOSE_RANGE_CLOEXEC == 0 {
                let low = i64::from(hex(field(sc, "a0")?)? as u32);
                let high = i64::from(hex(field(sc, "a1")?)? as u32);
                fds.retain(|&fd, _| !(low <= fd && fd <= high));
            }
        } else if nr == SYS_DUP {
            dup(fds, fd_arg(field(sc, "a0")?)?, exit_code);
        } else if nr == SYS_DUP2 || nr == SYS_DUP3 {
            let old = fd_arg(field(sc, "a0")?)?;
            dup(fds, old, fd_arg(field(sc, "a1")?)?);
        } else if nr == SYS_FCNTL && matches!(hex(field(sc, "a1")?)?, F_DUPFD | F_DUPFD_CLOEXEC) {
            dup(fds, fd_arg(field(sc, "a0")?)?, exit_code);
        }
        Ok(())
    }

    fn document(self) -> Value {
        let mut files: Vec<((bool, String, &str, bool, String, String), Value)> = self
            .files
            .into_iter()
            .map(|(key, processes)| {
                let mut entry = Map::new();
                entry.insert("path".into(), json!(key.path));
                entry.insert("op".into(), json!(key.op));
                entry.insert("ok".into(), json!(key.ok));
                entry.insert("errno".into(), json!(key.errno));
                entry.insert("processes".into(), json!(processes));
                if key.path.is_none() {
                    entry.insert("unresolved".into(), json!({"dirfd": key.dirfd, "name": key.name}));
                }
                let entry = Value::Object(entry);
                let sort_key = (
                    key.path.is_none(),
                    key.path.unwrap_or_default(),
                    key.op,
                    key.ok,
                    key.errno.unwrap_or_default(),
                    canonical(&entry),
                );
                (sort_key, entry)
            })
            .collect();
        files.sort_by(|a, b| a.0.cmp(&b.0));
        let unresolved_paths = files.iter().filter(|(key, _)| key.0).count();

        let mut network: Vec<((String, String, i64, &str, bool, String, String), Value)> = self
            .network
            .into_iter()
            .map(|(key, processes)| {
                let entry = json!({
                    "syscall": key.syscall, "family": key.family, "address": key.address,
                    "port": key.port, "ok": key.ok, "errno": key.errno, "processes": processes,
                });
                let sort_key = (
                    key.family,
                    key.address.unwrap_or_default(),
                    key.port.unwrap_or(-1),
                    key.syscall,
                    key.ok,
                    key.errno.unwrap_or_default(),
                    canonical(&entry),
                );
                (sort_key, entry)
            })
            .collect();
        network.sort_by(|a, b| a.0.cmp(&b.0));

        json!({
            "schema_version": SCHEMA_VERSION,
            "processes": self.processes,
            "files": files.into_iter().map(|(_, e)| e).collect::<Vec<_>>(),
            "network": network.into_iter().map(|(_, e)| e).collect::<Vec<_>>(),
            "counts": {
                "syscall_events": self.syscall_events,
                "ignored_records": self.ignored_records,
                "unresolved_paths": unresolved_paths,
            },
        })
    }
}

/// `json.dumps(entry, sort_keys=True, ensure_ascii=False, separators=(",", ":"))`.
fn canonical(entry: &Value) -> String {
    serde_json::to_string(entry).expect("a JSON value always serializes")
}

/// The objects of a host-side record (dns.log or packets.log), one JSON object
/// per line; `valid` checks that an object has exactly the record's keys and
/// value types.
fn host_records<R: BufRead>(
    input: R,
    record: &str,
    valid: fn(&Map<String, Value>) -> bool,
) -> Result<Vec<Map<String, Value>>, String> {
    let mut objects = Vec::new();
    for (index, line) in input.lines().enumerate() {
        let line = line.map_err(|e| format!("{record} line {}: {e}", index + 1))?;
        match serde_json::from_str(&line) {
            Ok(Value::Object(object)) if valid(&object) => objects.push(object),
            _ => {
                let shown = line.chars().take(200).collect::<String>();
                return Err(format!("{record} line {}: not a valid record: {shown:?}", index + 1));
            }
        }
    }
    Ok(objects)
}

fn is_string_or_null(value: &Value) -> bool {
    value.is_string() || value.is_null()
}

fn is_integer(value: &Value) -> bool {
    value.is_i64() || value.is_u64()
}

fn is_dns_record(object: &Map<String, Value>) -> bool {
    object.len() == 4
        && object.get("name").is_some_and(Value::is_string)
        && object.get("type").is_some_and(Value::is_string)
        && object.get("rcode").is_some_and(is_string_or_null)
        && object.get("answers").and_then(Value::as_array).is_some_and(|answers| answers.iter().all(Value::is_string))
}

fn is_packet_record(object: &Map<String, Value>) -> bool {
    object.len() == 4
        && object.get("protocol").is_some_and(Value::is_string)
        && object.get("family").is_some_and(Value::is_string)
        && object.get("address").is_some_and(Value::is_string)
        && object.get("port").is_some_and(|port| port.is_null() || is_integer(port))
}

fn text(value: &Value) -> String {
    value.as_str().expect("checked to be a string").to_string()
}

/// The distinct entries, ordered by their sort keys; the canonical JSON that
/// ends every key makes equal keys mean equal entries.
fn distinct<K: Ord>(mut entries: Vec<(K, Value)>) -> Vec<Value> {
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries.dedup_by(|a, b| a.0 == b.0);
    entries.into_iter().map(|(_, entry)| entry).collect()
}

/// `dns`: the distinct dns.log objects with sorted, deduplicated answers.
fn dns_entries(objects: Vec<Map<String, Value>>) -> Vec<Value> {
    let entries = objects
        .into_iter()
        .map(|mut object| {
            let answers: BTreeSet<String> = object["answers"].as_array().expect("checked").iter().map(text).collect();
            object.insert("answers".into(), json!(answers));
            let entry = Value::Object(object);
            ((text(&entry["name"]), text(&entry["type"]), canonical(&entry)), entry)
        })
        .collect();
    distinct(entries)
}

/// `wire`: the distinct packets.log objects.
fn wire_entries(objects: Vec<Map<String, Value>>) -> Vec<Value> {
    let entries = objects
        .into_iter()
        .map(|object| {
            let entry = Value::Object(object);
            let port = &entry["port"];
            let port = port.as_i64().map(i128::from).or(port.as_u64().map(i128::from)).unwrap_or(-1);
            ((text(&entry["family"]), text(&entry["address"]), port, text(&entry["protocol"]), canonical(&entry)), entry)
        })
        .collect();
    distinct(entries)
}

/// Convert an audit log (one record per line) and the host's DNS and packet
/// records into the events.json document. A record that is None is missing
/// and yields an empty list. Audit log lines are decoded as UTF-8 with
/// replacement characters; the host records must be UTF-8.
pub fn convert<A: BufRead, R: BufRead>(mut audit: A, dns: Option<R>, packets: Option<R>) -> Result<Value, String> {
    let mut converter = Converter::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        if audit.read_until(b'\n', &mut line).map_err(|e| e.to_string())? == 0 {
            break;
        }
        converter.feed(&String::from_utf8_lossy(&line))?;
    }
    let mut doc = converter.finish()?;
    let dns = dns.map(|dns| host_records(dns, "DNS record", is_dns_record)).transpose()?;
    let packets = packets.map(|packets| host_records(packets, "packet record", is_packet_record)).transpose()?;
    doc["dns"] = json!(dns_entries(dns.unwrap_or_default()));
    doc["wire"] = json!(wire_entries(packets.unwrap_or_default()));
    Ok(doc)
}

/// Serialize the document exactly as docs/events.md specifies:
/// `json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False) + "\n"`.
pub fn dump(doc: &Value) -> String {
    let mut out = serde_json::to_string_pretty(doc).expect("a JSON value always serializes");
    out.push('\n');
    out
}
