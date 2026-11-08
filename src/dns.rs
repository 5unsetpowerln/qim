//! qim's DNS forwarder on the gateway address (docs/events.md, "Host-side
//! network records").
//!
//! All guest traffic to port 53 is redirected here. Only the question of a
//! query (and an EDNS OPT record without options) is sent on to the
//! container's resolver, so dns.log accounts for everything the guest sends
//! upstream; the response is relayed unchanged once it parses. The guest is
//! untrusted: parsing is strict, every loop is bounded and nothing panics.

use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::json;

use crate::audit::ipv6_text;

const HEADER_LENGTH: usize = 12;
/// RFC 1035 section 2.3.4: a name takes at most 255 octets on the wire.
const MAX_NAME_LENGTH: usize = 255;
const QR: u16 = 0x8000;
const OPCODE: u16 = 0x7800;
const TC: u16 = 0x0200;
/// The header flags passed upstream: RD, AD and CD.
const FORWARDED_FLAGS: u16 = 0x0100 | 0x0020 | 0x0010;
const RCODE: u16 = 0x000f;
const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;
const TYPE_OPT: u16 = 41;
/// The DNSSEC OK bit in the flags of an OPT record (RFC 3225).
const DNSSEC_OK: u16 = 0x8000;
/// Larger than any UDP payload.
const DATAGRAM_BUFFER: usize = 1 << 16;

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a guest TCP connection may stay silent.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// UDP queries, and TCP connections, handled at the same time. A UDP query
/// beyond the limit is logged without an answer; a connection is closed.
const MAX_ACTIVE: usize = 64;

fn u16_at(packet: &[u8], offset: usize) -> Option<u16> {
    let bytes = packet.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// The labels of the (possibly compressed) name at `start` and the offset
/// after it. A pointer must point before the start of the label sequence that
/// contains it, so every name ends, and the name may take at most 255 octets.
fn read_name(packet: &[u8], start: usize) -> Option<(Vec<Vec<u8>>, usize)> {
    let mut labels = Vec::new();
    let mut length = 1; // the root label
    let (mut position, mut limit, mut end) = (start, start, None);
    loop {
        let byte = *packet.get(position)?;
        match byte & 0xc0 {
            0x00 if byte == 0 => return Some((labels, end.unwrap_or(position + 1))),
            0x00 => {
                let label = packet.get(position + 1..position + 1 + usize::from(byte))?;
                length += 1 + label.len();
                if length > MAX_NAME_LENGTH {
                    return None;
                }
                labels.push(label.to_vec());
                position += 1 + label.len();
            }
            0xc0 => {
                let target = usize::from(u16_at(packet, position)? & 0x3fff);
                if target >= limit {
                    return None;
                }
                end.get_or_insert(position + 2);
                (position, limit) = (target, target);
            }
            // 0x40 and 0x80 are the obsolete extended and the reserved label types.
            _ => return None,
        }
    }
}

/// The name in lower case without the trailing dot. Within a label, `.` and
/// `\` are escaped with `\` and bytes outside printable ASCII are written as
/// `\DDD` (the presentation format of RFC 1035 section 5.1).
fn name_text(labels: &[Vec<u8>]) -> String {
    let mut text = String::new();
    for (index, label) in labels.iter().enumerate() {
        if index > 0 {
            text.push('.');
        }
        for byte in label.iter().map(u8::to_ascii_lowercase) {
            match byte {
                b'.' | b'\\' => {
                    text.push('\\');
                    text.push(char::from(byte));
                }
                0x21..=0x7e => text.push(char::from(byte)),
                _ => write!(text, "\\{byte:03}").expect("writing to a String"),
            }
        }
    }
    text
}

/// The mnemonic of a TYPE (IANA "Resource Record (RR) TYPEs"), or TYPE<n>.
fn type_text(value: u16) -> String {
    let mnemonic = match value {
        1 => "A",
        2 => "NS",
        3 => "MD",
        4 => "MF",
        5 => "CNAME",
        6 => "SOA",
        7 => "MB",
        8 => "MG",
        9 => "MR",
        10 => "NULL",
        11 => "WKS",
        12 => "PTR",
        13 => "HINFO",
        14 => "MINFO",
        15 => "MX",
        16 => "TXT",
        17 => "RP",
        18 => "AFSDB",
        24 => "SIG",
        25 => "KEY",
        28 => "AAAA",
        29 => "LOC",
        33 => "SRV",
        35 => "NAPTR",
        36 => "KX",
        37 => "CERT",
        39 => "DNAME",
        41 => "OPT",
        42 => "APL",
        43 => "DS",
        44 => "SSHFP",
        45 => "IPSECKEY",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        49 => "DHCID",
        50 => "NSEC3",
        51 => "NSEC3PARAM",
        52 => "TLSA",
        53 => "SMIMEA",
        55 => "HIP",
        59 => "CDS",
        60 => "CDNSKEY",
        61 => "OPENPGPKEY",
        62 => "CSYNC",
        63 => "ZONEMD",
        64 => "SVCB",
        65 => "HTTPS",
        99 => "SPF",
        249 => "TKEY",
        250 => "TSIG",
        251 => "IXFR",
        252 => "AXFR",
        253 => "MAILB",
        254 => "MAILA",
        255 => "ANY",
        256 => "URI",
        257 => "CAA",
        _ => return format!("TYPE{value}"),
    };
    mnemonic.to_string()
}

/// The mnemonic of a header RCODE (RFC 1035, RFC 2136), or RCODE<n>.
fn rcode_text(value: u16) -> String {
    let mnemonic = match value {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        _ => return format!("RCODE{value}"),
    };
    mnemonic.to_string()
}

#[derive(Debug, PartialEq)]
struct Query {
    id: u16,
    /// Only the forwarded flags.
    flags: u16,
    labels: Vec<Vec<u8>>,
    qtype: u16,
    qclass: u16,
    /// The requestor's UDP payload size and DNSSEC OK bit, if it sent an OPT record.
    edns: Option<(u16, bool)>,
}

/// A standard query (QR 0, OPCODE 0, TC 0) with exactly one question and
/// nothing after it except at most an OPT record (RFC 6891).
fn parse_query(packet: &[u8]) -> Option<Query> {
    let field = |index: usize| u16_at(packet, 2 * index);
    let (id, flags) = (field(0)?, field(1)?);
    let counts = (field(2)?, field(3)?, field(4)?, field(5)?);
    if flags & (QR | OPCODE | TC) != 0 || !matches!(counts, (1, 0, 0, 0 | 1)) {
        return None;
    }
    let (labels, after_name) = read_name(packet, HEADER_LENGTH)?;
    let (qtype, qclass) = (u16_at(packet, after_name)?, u16_at(packet, after_name + 2)?);
    let mut end = after_name + 4;
    let mut edns = None;
    if counts.3 == 1 {
        // OPT: root owner, TYPE 41, CLASS = UDP payload size, TTL = extended
        // RCODE, version and flags, RDATA = options.
        let (owner, after_owner) = read_name(packet, end)?;
        if !owner.is_empty() || u16_at(packet, after_owner)? != TYPE_OPT {
            return None;
        }
        let size = u16_at(packet, after_owner + 2)?;
        let opt_flags = u16_at(packet, after_owner + 6)?;
        end = after_owner + 10 + usize::from(u16_at(packet, after_owner + 8)?);
        edns = Some((size, opt_flags & DNSSEC_OK != 0));
    }
    (end == packet.len()).then_some(Query { id, flags: flags & FORWARDED_FLAGS, labels, qtype, qclass, edns })
}

impl Query {
    /// The query sent upstream: the header, the question and, if the guest
    /// sent one, an OPT record with its payload size and DNSSEC OK bit only.
    fn upstream(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(HEADER_LENGTH + MAX_NAME_LENGTH + 4 + 11);
        for value in [self.id, self.flags, 1, 0, 0, u16::from(self.edns.is_some())] {
            packet.extend(value.to_be_bytes());
        }
        for label in &self.labels {
            packet.push(label.len() as u8);
            packet.extend(label);
        }
        packet.push(0);
        packet.extend(self.qtype.to_be_bytes());
        packet.extend(self.qclass.to_be_bytes());
        if let Some((size, dnssec_ok)) = self.edns {
            packet.push(0);
            let flags = if dnssec_ok { DNSSEC_OK } else { 0 };
            for value in [TYPE_OPT, size, 0, flags, 0] {
                packet.extend(value.to_be_bytes());
            }
        }
        packet
    }
}

/// What dns.log keeps of a response.
#[derive(Debug, PartialEq)]
struct Answer {
    rcode: u16,
    /// A and AAAA addresses and CNAME targets of the answer section, in order.
    answers: Vec<String>,
}

/// The response to `query`, if its header, question section and answer
/// section parse. The authority and additional sections are not read.
fn parse_response(packet: &[u8], query: &Query) -> Option<Answer> {
    let field = |index: usize| u16_at(packet, 2 * index);
    let flags = field(1)?;
    if field(0)? != query.id || flags & QR == 0 || flags & OPCODE != 0 {
        return None;
    }
    let mut position = HEADER_LENGTH;
    for _ in 0..field(2)? {
        position = read_name(packet, position)?.1 + 4;
    }
    let mut answers = Vec::new();
    for _ in 0..field(3)? {
        let (_, after_owner) = read_name(packet, position)?;
        let rtype = u16_at(packet, after_owner)?;
        let start = after_owner + 10;
        let end = start + usize::from(u16_at(packet, after_owner + 8)?);
        let rdata = packet.get(start..end)?;
        match rtype {
            TYPE_A => answers.push(Ipv4Addr::from(<[u8; 4]>::try_from(rdata).ok()?).to_string()),
            TYPE_AAAA if rdata.len() == 16 => answers.push(ipv6_text(rdata)),
            TYPE_AAAA => return None,
            TYPE_CNAME => match read_name(packet, start)? {
                (labels, after) if after == end => answers.push(name_text(&labels)),
                _ => return None,
            },
            _ => {}
        }
        position = end;
    }
    (position <= packet.len()).then_some(Answer { rcode: flags & RCODE, answers })
}

/// The dns.log line of a query and of its answer, if one came back.
fn record(query: &Query, answer: Option<&Answer>) -> String {
    let line = json!({
        "name": name_text(&query.labels),
        "type": type_text(query.qtype),
        "rcode": answer.map(|answer| rcode_text(answer.rcode)),
        "answers": answer.map_or(&[][..], |answer| &answer.answers),
    });
    format!("{line}\n")
}

// --- Serving -----------------------------------------------------------------------

struct Log {
    file: File,
    error: Option<io::Error>,
}

struct Shared {
    upstream: SocketAddr,
    log: Mutex<Log>,
    stop: AtomicBool,
}

impl Shared {
    fn log(&self, query: &Query, answer: Option<&Answer>) {
        let line = record(query, answer);
        let mut log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        if let Err(error) = log.file.write_all(line.as_bytes()) {
            log.error.get_or_insert(error);
        }
    }

    fn stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }
}

/// Errors that concern one exchange only.
fn is_transient(error: &io::Error) -> bool {
    use io::ErrorKind::*;
    matches!(error.kind(), WouldBlock | TimedOut | Interrupted | ConnectionRefused | ConnectionReset | ConnectionAborted)
}

/// Ask the upstream resolver over UDP: its response, if one that parses came back in time.
fn ask_udp(upstream: SocketAddr, query: &Query) -> Option<(Vec<u8>, Answer)> {
    let local: SocketAddr =
        if upstream.is_ipv4() { (Ipv4Addr::UNSPECIFIED, 0).into() } else { (Ipv6Addr::UNSPECIFIED, 0).into() };
    let socket = UdpSocket::bind(local).ok()?;
    socket.connect(upstream).ok()?;
    socket.set_read_timeout(Some(UPSTREAM_TIMEOUT)).ok()?;
    socket.send(&query.upstream()).ok()?;
    let mut response = vec![0; DATAGRAM_BUFFER];
    let length = socket.recv(&mut response).ok()?;
    response.truncate(length);
    let answer = parse_response(&response, query)?;
    Some((response, answer))
}

/// A DNS message over TCP: a two-byte length, then the message (RFC 1035 section 4.2.2).
fn read_message(stream: &mut impl Read) -> Option<Vec<u8>> {
    let mut length = [0; 2];
    stream.read_exact(&mut length).ok()?;
    let mut message = vec![0; usize::from(u16::from_be_bytes(length))];
    stream.read_exact(&mut message).ok()?;
    Some(message)
}

fn write_message(stream: &mut impl Write, message: &[u8]) -> Option<()> {
    let mut framed = u16::try_from(message.len()).ok()?.to_be_bytes().to_vec();
    framed.extend(message);
    stream.write_all(&framed).ok()
}

/// Ask the upstream resolver over TCP: its response, if one that parses came back in time.
fn ask_tcp(upstream: SocketAddr, query: &Query) -> Option<(Vec<u8>, Answer)> {
    let mut stream = TcpStream::connect_timeout(&upstream, UPSTREAM_TIMEOUT).ok()?;
    stream.set_read_timeout(Some(UPSTREAM_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(UPSTREAM_TIMEOUT)).ok()?;
    write_message(&mut stream, &query.upstream())?;
    let response = read_message(&mut stream)?;
    let answer = parse_response(&response, query)?;
    Some((response, answer))
}

/// Answer UDP queries, each in its own thread, until stopped. A datagram that
/// is not a valid query is dropped.
fn serve_udp(socket: &UdpSocket, shared: &Shared) -> Result<(), String> {
    let active = AtomicUsize::new(0);
    let mut buffer = vec![0; DATAGRAM_BUFFER];
    thread::scope(|scope| {
        while !shared.stopping() {
            let (length, peer) = match socket.recv_from(&mut buffer) {
                Ok(received) => received,
                Err(error) if is_transient(&error) => continue,
                Err(error) => return Err(format!("DNS forwarder (UDP): {error}")),
            };
            let Some(query) = parse_query(&buffer[..length]) else { continue };
            if active.load(Ordering::SeqCst) >= MAX_ACTIVE {
                shared.log(&query, None);
                continue;
            }
            active.fetch_add(1, Ordering::SeqCst);
            let active = &active;
            let exchange = move || {
                let answer = ask_udp(shared.upstream, &query);
                if let Some((response, _)) = &answer {
                    let _ = socket.send_to(response, peer);
                }
                shared.log(&query, answer.as_ref().map(|(_, answer)| answer));
                active.fetch_sub(1, Ordering::SeqCst);
            };
            if thread::Builder::new().spawn_scoped(scope, exchange).is_err() {
                // The closure, and with it the query, is gone; the guest will ask again.
                active.fetch_sub(1, Ordering::SeqCst);
            }
        }
        Ok(())
    })
}

/// Answer the queries of one TCP connection in turn. The connection is closed
/// at the first invalid or unanswered query.
fn serve_connection(mut stream: TcpStream, shared: &Shared) {
    let configured = stream.set_nonblocking(false).is_ok()
        && stream.set_read_timeout(Some(CLIENT_TIMEOUT)).is_ok()
        && stream.set_write_timeout(Some(CLIENT_TIMEOUT)).is_ok();
    while configured && !shared.stopping() {
        let Some(query) = read_message(&mut stream).and_then(|message| parse_query(&message)) else { return };
        let answer = ask_tcp(shared.upstream, &query);
        shared.log(&query, answer.as_ref().map(|(_, answer)| answer));
        if answer.and_then(|(response, _)| write_message(&mut stream, &response)).is_none() {
            return;
        }
    }
}

/// Serve TCP connections, each in its own thread, until stopped.
fn serve_tcp(listener: &TcpListener, shared: &Shared) -> Result<(), String> {
    let active = AtomicUsize::new(0);
    thread::scope(|scope| {
        while !shared.stopping() {
            let stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(POLL_INTERVAL);
                    continue;
                }
                Err(error) if is_transient(&error) => continue,
                Err(error) => return Err(format!("DNS forwarder (TCP): {error}")),
            };
            if active.load(Ordering::SeqCst) >= MAX_ACTIVE {
                continue;
            }
            active.fetch_add(1, Ordering::SeqCst);
            let active = &active;
            let connection = move || {
                serve_connection(stream, shared);
                active.fetch_sub(1, Ordering::SeqCst);
            };
            if thread::Builder::new().spawn_scoped(scope, connection).is_err() {
                active.fetch_sub(1, Ordering::SeqCst);
            }
        }
        Ok(())
    })
}

/// The running forwarder; dropping it without stop() lets its threads end on their own.
pub struct Forwarder {
    shared: Arc<Shared>,
    threads: Vec<JoinHandle<Result<(), String>>>,
    address: SocketAddr,
}

/// Answer DNS over UDP and TCP on `listen` (both on the port the UDP socket
/// gets) by asking `upstream`, writing one dns.log line per query to `log`.
pub fn start(listen: SocketAddr, upstream: SocketAddr, log: File) -> Result<Forwarder, String> {
    let udp = UdpSocket::bind(listen).map_err(|error| format!("cannot listen on {listen}/udp: {error}"))?;
    let address = udp.local_addr().map_err(|error| format!("{listen}/udp: {error}"))?;
    let tcp = TcpListener::bind(address).map_err(|error| format!("cannot listen on {address}/tcp: {error}"))?;
    udp.set_read_timeout(Some(POLL_INTERVAL)).map_err(|error| format!("{address}/udp: {error}"))?;
    tcp.set_nonblocking(true).map_err(|error| format!("{address}/tcp: {error}"))?;
    let shared = Arc::new(Shared { upstream, log: Mutex::new(Log { file: log, error: None }), stop: AtomicBool::new(false) });
    let mut forwarder = Forwarder { shared: Arc::clone(&shared), threads: Vec::new(), address };
    forwarder.threads.push(spawn_server("dns-udp", &shared, move |shared| serve_udp(&udp, shared))?);
    forwarder.threads.push(spawn_server("dns-tcp", &shared, move |shared| serve_tcp(&tcp, shared))?);
    Ok(forwarder)
}

fn spawn_server(
    name: &str,
    shared: &Arc<Shared>,
    serve: impl FnOnce(&Shared) -> Result<(), String> + Send + 'static,
) -> Result<JoinHandle<Result<(), String>>, String> {
    let shared = Arc::clone(shared);
    thread::Builder::new()
        .name(name.to_string())
        .spawn(move || serve(&shared))
        .map_err(|error| format!("cannot start the DNS forwarder: {error}"))
}

impl Forwarder {
    /// The address the forwarder listens on, over UDP and TCP.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Stop serving, wait for the queries in progress to be logged, and
    /// report why dns.log may be incomplete.
    pub fn stop(mut self) -> Result<(), String> {
        self.shared.stop.store(true, Ordering::SeqCst);
        let mut problems = Vec::new();
        for thread in std::mem::take(&mut self.threads) {
            match thread.join() {
                Ok(Ok(())) => {}
                Ok(Err(problem)) => problems.push(problem),
                Err(_) => problems.push("the DNS forwarder failed".to_string()),
            }
        }
        let mut log = self.shared.log.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(error) = log.error.take() {
            problems.push(format!("cannot write dns.log: {error}"));
        }
        if problems.is_empty() { Ok(()) } else { Err(problems.join("; ")) }
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wire bytes of a name given in dotted form ("" is the root).
    fn name(dotted: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        for label in dotted.split('.').filter(|label| !label.is_empty()) {
            bytes.push(label.len() as u8);
            bytes.extend(label.as_bytes());
        }
        bytes.push(0);
        bytes
    }

    fn header(id: u16, flags: u16, counts: [u16; 4]) -> Vec<u8> {
        [id, flags].iter().chain(&counts).flat_map(|value| value.to_be_bytes()).collect()
    }

    /// A query for (name, type) with class IN and RD set, as a stub resolver sends it.
    fn query_bytes(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
        let mut packet = header(id, 0x0100, [1, 0, 0, 0]);
        packet.extend(name(qname));
        packet.extend(qtype.to_be_bytes());
        packet.extend(1u16.to_be_bytes());
        packet
    }

    fn rr(owner: &[u8], rtype: u16, rdata: &[u8]) -> Vec<u8> {
        let mut bytes = owner.to_vec();
        bytes.extend(rtype.to_be_bytes());
        bytes.extend(1u16.to_be_bytes()); // IN
        bytes.extend(300u32.to_be_bytes());
        bytes.extend((rdata.len() as u16).to_be_bytes());
        bytes.extend(rdata);
        bytes
    }

    /// A pointer to `offset` (RFC 1035 section 4.1.4).
    fn pointer(offset: u16) -> [u8; 2] {
        (0xc000 | offset).to_be_bytes()
    }

    #[test]
    fn a_stub_query_is_parsed_and_forwarded_as_it_came() {
        let packet = query_bytes(0x1234, "Example.COM", 28);
        let query = parse_query(&packet).unwrap();
        assert_eq!(
            query,
            Query {
                id: 0x1234,
                flags: 0x0100,
                labels: vec![b"Example".to_vec(), b"COM".to_vec()],
                qtype: 28,
                qclass: 1,
                edns: None
            }
        );
        // Without extra sections the forwarded query is the same message, case included.
        assert_eq!(query.upstream(), packet);
    }

    #[test]
    fn only_the_question_and_a_bare_opt_record_go_upstream() {
        // flags: RD | AD | CD plus the Z bit (0x0040), which is not forwarded.
        let mut packet = header(7, 0x0100 | 0x0040 | 0x0020 | 0x0010, [1, 0, 0, 1]);
        packet.extend(name("a.example"));
        packet.extend([0, 1, 0, 1]);
        // OPT: root, TYPE 41, payload size 1232, ext-rcode 0, version 0, DO, an 8-byte COOKIE option.
        packet.extend([0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 12, 0, 10, 0, 8]);
        packet.extend(b"secret!!");
        let query = parse_query(&packet).unwrap();
        assert_eq!(query.edns, Some((1232, true)));
        let mut expected = header(7, 0x0130, [1, 0, 0, 1]);
        expected.extend(name("a.example"));
        expected.extend([0, 1, 0, 1]);
        expected.extend([0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0]);
        assert_eq!(query.upstream(), expected);
    }

    #[test]
    fn anything_but_a_single_standard_question_is_rejected() {
        let valid = query_bytes(1, "example.com", 1);
        let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
        let mut with = |what, change: &dyn Fn(&mut Vec<u8>)| {
            let mut packet = valid.clone();
            change(&mut packet);
            cases.push((what, packet));
        };
        with("a response", &|p| p[2] |= 0x80);
        with("opcode IQUERY", &|p| p[2] |= 0x08);
        with("truncated flag", &|p| p[2] |= 0x02);
        with("two questions", &|p| p[5] = 2);
        with("no question", &|p| p[5] = 0);
        with("an answer record", &|p| p[7] = 1);
        with("an authority record", &|p| p[9] = 1);
        with("an additional record that is missing", &|p| p[11] = 1);
        with("a trailing byte", &|p| p.push(0));
        with("a short header", &|p| p.truncate(11));
        with("a missing class", &|p| p.truncate(p.len() - 2));
        with("label type 0x40", &|p| p[12] = 0x47);
        with("label type 0x80", &|p| p[12] = 0x87);
        with("a label past the end", &|p| {
            p.truncate(12);
            p.push(5);
            p.extend(b"ab");
        });
        for (what, packet) in cases {
            assert_eq!(parse_query(&packet), None, "{what}");
        }
        // An additional record that is not OPT, or OPT with a non-root owner.
        let mut not_opt = header(1, 0x0100, [1, 0, 0, 1]);
        not_opt.extend(name("x"));
        not_opt.extend([0, 1, 0, 1]);
        not_opt.extend(rr(&name(""), 1, &[1, 2, 3, 4]));
        assert_eq!(parse_query(&not_opt), None);
        let mut owned_opt = header(1, 0x0100, [1, 0, 0, 1]);
        owned_opt.extend(name("x"));
        owned_opt.extend([0, 1, 0, 1]);
        owned_opt.extend(rr(&name("x"), 41, &[]));
        assert_eq!(parse_query(&owned_opt), None);
    }

    #[test]
    fn names_are_bounded_and_pointers_only_go_backwards() {
        // 63-octet labels: four of them take 4 * 64 + 1 = 257 octets, over the limit.
        let label = "a".repeat(63);
        let long = [label.as_str(); 4].join(".");
        assert_eq!(parse_query(&query_bytes(1, &long, 1)), None);
        // Three labels of 63 and one of 61: exactly 255 octets.
        let longest = format!("{label}.{label}.{label}.{}", "b".repeat(61));
        assert_eq!(parse_query(&query_bytes(1, &longest, 1)).unwrap().labels.len(), 4);
        // A pointer to itself, a forward pointer and two pointers into each other never parse.
        let mut packet = vec![0; 12];
        packet.extend(pointer(12));
        assert_eq!(read_name(&packet, 12), None);
        let mut packet = vec![0; 12];
        packet.extend(pointer(14));
        packet.extend(name("x"));
        assert_eq!(read_name(&packet, 12), None);
        let mut packet = vec![0; 12];
        packet.extend([1, b'a']);
        packet.extend(pointer(16));
        packet.extend([1, b'b']);
        packet.extend(pointer(12));
        assert_eq!(read_name(&packet, 16), None);
        // A backward pointer: "www" then the name at offset 12; the name ends after the pointer.
        let mut packet = vec![0; 12];
        packet.extend(name("example.com"));
        let start = packet.len();
        packet.extend([3, b'w', b'w', b'w']);
        packet.extend(pointer(12));
        let (labels, end) = read_name(&packet, start).unwrap();
        assert_eq!(name_text(&labels), "www.example.com");
        assert_eq!(end, packet.len());
        // Compression cannot be used to exceed 255 octets either.
        let mut packet = vec![0; 12];
        packet.extend(name(&long[..64 * 3 - 1]));
        let start = packet.len();
        packet.push(63);
        packet.extend(label.as_bytes());
        packet.extend(pointer(12));
        assert_eq!(read_name(&packet, start), None);
    }

    #[test]
    fn name_text_is_lower_case_without_the_trailing_dot() {
        assert_eq!(name_text(&[b"WWW".to_vec(), b"Example".to_vec(), b"org".to_vec()]), "www.example.org");
        assert_eq!(name_text(&[]), "");
        assert_eq!(name_text(&[b"a.b".to_vec(), b"c\\d".to_vec()]), "a\\.b.c\\\\d");
        assert_eq!(name_text(&[b"\x00 \x7f\xff\xc3\x89".to_vec()]), "\\000\\032\\127\\255\\195\\137");
    }

    #[test]
    fn mnemonics() {
        assert_eq!(
            [1, 5, 28, 65, 255, 0, 999, 65535].map(type_text),
            ["A", "CNAME", "AAAA", "HTTPS", "ANY", "TYPE0", "TYPE999", "TYPE65535"]
        );
        assert_eq!([0, 2, 3, 5, 10, 11, 15].map(rcode_text), ["NOERROR", "SERVFAIL", "NXDOMAIN", "REFUSED", "NOTZONE", "RCODE11", "RCODE15"]);
    }

    /// A response to query_bytes(0xbeef, "www.example.com", 1): a CNAME to
    /// "edge.example.net" and two A records, all owners compressed, then an
    /// AAAA record with an IPv4-mapped address.
    fn response_bytes(flags: u16) -> Vec<u8> {
        let mut packet = header(0xbeef, flags, [1, 4, 0, 0]);
        packet.extend(name("www.example.com"));
        packet.extend([0, 1, 0, 1]);
        packet.extend(rr(&pointer(12), TYPE_CNAME, &[4, b'E', b'D', b'G', b'E', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'n', b'e', b't', 0]));
        let edge = 12 + 17 + 4 + 12;
        packet.extend(rr(&pointer(edge), TYPE_A, &[93, 184, 216, 34]));
        packet.extend(rr(&pointer(edge), TYPE_A, &[10, 0, 0, 1]));
        packet.extend(rr(&pointer(edge), TYPE_AAAA, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1]));
        packet
    }

    #[test]
    fn a_response_yields_its_rcode_addresses_and_cname_targets() {
        let query = parse_query(&query_bytes(0xbeef, "www.example.com", 1)).unwrap();
        let answer = parse_response(&response_bytes(0x8180), &query).unwrap();
        assert_eq!(
            answer,
            Answer { rcode: 0, answers: ["edge.example.net", "93.184.216.34", "10.0.0.1", "::ffff:192.0.2.1"].map(String::from).to_vec() }
        );
        // NXDOMAIN without records.
        let mut packet = header(0xbeef, 0x8183, [1, 0, 0, 0]);
        packet.extend(name("www.example.com"));
        packet.extend([0, 1, 0, 1]);
        assert_eq!(parse_response(&packet, &query), Some(Answer { rcode: 3, answers: Vec::new() }));
    }

    #[test]
    fn aaaa_text_follows_rfc_5952() {
        let query = parse_query(&query_bytes(9, "v6.example", 28)).unwrap();
        let mut packet = header(9, 0x8180, [1, 1, 0, 0]);
        packet.extend(name("v6.example"));
        packet.extend([0, 28, 0, 1]);
        packet.extend(rr(&pointer(12), TYPE_AAAA, &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
        assert_eq!(parse_response(&packet, &query).unwrap().answers, ["2001:db8::1"]);
    }

    #[test]
    fn a_response_that_does_not_parse_is_no_answer() {
        let query = parse_query(&query_bytes(0xbeef, "www.example.com", 1)).unwrap();
        let valid = response_bytes(0x8180);
        assert!(parse_response(&valid, &query).is_some());
        let mut wrong_id = valid.clone();
        wrong_id[1] ^= 1;
        assert_eq!(parse_response(&wrong_id, &query), None);
        assert_eq!(parse_response(&response_bytes(0x0180), &query), None, "QR clear");
        let mut short_a = header(0xbeef, 0x8180, [0, 1, 0, 0]);
        short_a.extend(rr(&name("x"), TYPE_A, &[1, 2, 3]));
        assert_eq!(parse_response(&short_a, &query), None);
        let mut long_aaaa = header(0xbeef, 0x8180, [0, 1, 0, 0]);
        long_aaaa.extend(rr(&name("x"), TYPE_AAAA, &[0; 17]));
        assert_eq!(parse_response(&long_aaaa, &query), None);
        // A CNAME whose target runs past its RDATA.
        let mut cname = header(0xbeef, 0x8180, [0, 1, 0, 0]);
        cname.extend(rr(&name("x"), TYPE_CNAME, &[1, b'a']));
        cname.extend([1, b'b', 0]);
        assert_eq!(parse_response(&cname, &query), None);
        // More records announced than present.
        let mut missing = valid.clone();
        missing[7] = 5;
        assert_eq!(parse_response(&missing, &query), None);
    }

    #[test]
    fn records_have_the_spec_format() {
        let query = parse_query(&query_bytes(1, "WWW.Example.com", 65)).unwrap();
        assert_eq!(record(&query, None), "{\"answers\":[],\"name\":\"www.example.com\",\"rcode\":null,\"type\":\"HTTPS\"}\n");
        let answer = Answer { rcode: 3, answers: vec!["a.example".to_string(), "192.0.2.7".to_string()] };
        let line: serde_json::Value = serde_json::from_str(&record(&query, Some(&answer))).unwrap();
        assert_eq!(line, json!({"name": "www.example.com", "type": "HTTPS", "rcode": "NXDOMAIN", "answers": ["a.example", "192.0.2.7"]}));
    }

    /// A deterministic sequence of pseudo-random bytes (xorshift).
    fn noise(seed: u64, length: usize) -> Vec<u8> {
        let mut state = seed | 1;
        (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    #[test]
    fn malformed_packets_never_panic() {
        let query = parse_query(&query_bytes(0xbeef, "www.example.com", 1)).unwrap();
        let valid = [query_bytes(0xbeef, "www.example.com", 1), response_bytes(0x8180)];
        for packet in &valid {
            for end in 0..packet.len() {
                let _ = parse_query(&packet[..end]);
                let _ = parse_response(&packet[..end], &query);
            }
            for seed in 0..2000u64 {
                let mut mutated = packet.clone();
                for (index, byte) in noise(seed, 4).chunks(2).map(|pair| (usize::from(pair[0]) % packet.len(), pair[1])) {
                    mutated[index] = byte;
                }
                let _ = parse_query(&mutated);
                let _ = parse_response(&mutated, &query);
            }
        }
        for seed in 0..2000u64 {
            let mut packet = noise(seed, 12 + (seed as usize % 300));
            packet[4..6].copy_from_slice(&[0, 1]);
            let _ = parse_query(&packet);
            packet[0..2].copy_from_slice(&[0xbe, 0xef]);
            packet[2] |= 0x80;
            let _ = parse_response(&packet, &query);
        }
    }

    // --- The forwarder, against a stand-in upstream on the loopback interface ---------

    /// The response the stand-in upstream gives to a query: one A record 192.0.2.1.
    fn upstream_response(query: &[u8]) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2] |= 0x80;
        response[7] = 1; // ANCOUNT 1
        response[11] = 0; // no OPT record in the response
        response.truncate(read_name(query, 12).unwrap().1 + 4);
        response.extend(rr(&pointer(12), TYPE_A, &[192, 0, 2, 1]));
        response
    }

    /// A log file of its own for each test.
    fn log_path(test: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("qim-dns-{test}-{}.log", std::process::id()))
    }

    #[test]
    fn udp_queries_are_forwarded_answered_and_logged() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        let upstream_thread = thread::spawn(move || {
            let mut buffer = [0; 512];
            let (length, peer) = upstream.recv_from(&mut buffer).unwrap();
            upstream.send_to(&upstream_response(&buffer[..length]), peer).unwrap();
            buffer[..length].to_vec()
        });
        let path = log_path("udp");
        let forwarder = start("127.0.0.1:0".parse().unwrap(), upstream_address, File::create(&path).unwrap()).unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        // A malformed datagram is dropped without a log line; then a query with an EDNS option.
        client.send_to(b"\x00\x01garbage", forwarder.address()).unwrap();
        let mut query = header(0x4242, 0x0100, [1, 0, 0, 1]);
        query.extend(name("Pkg.Example"));
        query.extend([0, 1, 0, 1]);
        query.extend([0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 6, 0, 12, 0, 2, 0xab, 0xcd]);
        client.send_to(&query, forwarder.address()).unwrap();
        let mut buffer = [0; 512];
        let length = client.recv(&mut buffer).unwrap();
        let forwarded = upstream_thread.join().unwrap();
        let mut expected_forwarded = header(0x4242, 0x0100, [1, 0, 0, 1]);
        expected_forwarded.extend(name("Pkg.Example"));
        expected_forwarded.extend([0, 1, 0, 1, 0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(forwarded, expected_forwarded);
        assert_eq!(&buffer[..length], upstream_response(&forwarded).as_slice());
        forwarder.stop().unwrap();
        let logged = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(logged, "{\"answers\":[\"192.0.2.1\"],\"name\":\"pkg.example\",\"rcode\":\"NOERROR\",\"type\":\"A\"}\n");
    }

    #[test]
    fn tcp_queries_are_forwarded_answered_and_logged() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        let upstream_thread = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let query = read_message(&mut stream).unwrap();
            write_message(&mut stream, &upstream_response(&query)).unwrap();
        });
        let path = log_path("tcp");
        let forwarder = start("127.0.0.1:0".parse().unwrap(), upstream_address, File::create(&path).unwrap()).unwrap();
        let mut client = TcpStream::connect(forwarder.address()).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let query = query_bytes(0x0707, "files.example", 1);
        write_message(&mut client, &query).unwrap();
        assert_eq!(read_message(&mut client).unwrap(), upstream_response(&query));
        upstream_thread.join().unwrap();
        drop(client);
        forwarder.stop().unwrap();
        let logged = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(logged, "{\"answers\":[\"192.0.2.1\"],\"name\":\"files.example\",\"rcode\":\"NOERROR\",\"type\":\"A\"}\n");
    }
}
