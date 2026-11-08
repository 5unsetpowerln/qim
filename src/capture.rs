//! qim's capture on the tap device (docs/events.md, "Host-side network
//! records"): every distinct flow that a packet from the guest starts or
//! attempts is written once to packets.log, whether or not the egress filter
//! lets it through.

use std::collections::HashSet;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::json;

use crate::audit::ipv6_text;

const ETHERNET_HEADER_LENGTH: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const IPV6_HEADER_LENGTH: usize = 40;
const ICMP: u8 = 1;
const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMPV6: u8 = 58;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;
// IPv6 extension headers that precede the upper-layer header (RFC 8200 section 4, RFC 4302).
const HOP_BY_HOP: u8 = 0;
const ROUTING: u8 = 43;
const FRAGMENT: u8 = 44;
const AUTHENTICATION: u8 = 51;
const DESTINATION_OPTIONS: u8 = 60;
/// Larger than any frame, including a guest's segmentation offload frames.
const FRAME_BUFFER: usize = 1 << 17;
const RECEIVE_BUFFER: libc::c_int = 8 << 20;
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// A packet that starts or attempts a flow, as packets.log records it.
#[derive(Debug, PartialEq, Eq, Hash)]
struct Flow {
    protocol: String,
    family: &'static str,
    address: String,
    port: Option<u16>,
}

fn u16_at(packet: &[u8], offset: usize) -> Option<u16> {
    let bytes = packet.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// The protocol name and destination port of an upper-layer header that
/// starts or attempts a flow: a TCP SYN without ACK, a UDP datagram, an echo
/// request of the family's ICMP, or any other protocol.
fn upper_layer(protocol: u8, header: &[u8], icmp: (u8, u8, &str)) -> Option<(String, Option<u16>)> {
    let (icmp_protocol, echo_request, icmp_name) = icmp;
    match protocol {
        TCP if header.len() >= 20 => {
            (header[13] & (TCP_SYN | TCP_ACK) == TCP_SYN).then(|| ("tcp".to_string(), u16_at(header, 2)))
        }
        UDP if header.len() >= 8 => Some(("udp".to_string(), u16_at(header, 2))),
        TCP | UDP => None,
        _ if protocol == icmp_protocol => {
            (header.len() >= 8 && header[0] == echo_request).then(|| (icmp_name.to_string(), None))
        }
        _ => Some((format!("ip{protocol}"), None)),
    }
}

/// An IPv4 packet from `guest`, cut to its total length. Only the first
/// fragment holds the upper-layer header.
fn ipv4_flow(packet: &[u8], guest: Ipv4Addr) -> Option<Flow> {
    let first = *packet.first()?;
    let header_length = usize::from(first & 0x0f) * 4;
    let total_length = usize::from(u16_at(packet, 2)?);
    if first >> 4 != 4 || header_length < 20 || total_length < header_length || total_length > packet.len() {
        return None;
    }
    if packet[12..16] != guest.octets() || u16_at(packet, 6)? & 0x1fff != 0 {
        return None;
    }
    let address = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]).to_string();
    let (protocol, port) =
        upper_layer(packet[9], &packet[header_length..total_length], (ICMP, ICMP_ECHO_REQUEST, "icmp"))?;
    Some(Flow { protocol, family: "inet", address, port })
}

/// An IPv6 packet, cut to its payload length, whose extension headers are
/// skipped up to the upper-layer header. Only the first fragment holds it.
fn ipv6_flow(packet: &[u8]) -> Option<Flow> {
    if packet.first()? >> 4 != 6 {
        return None;
    }
    let packet = packet.get(..IPV6_HEADER_LENGTH + usize::from(u16_at(packet, 4)?))?;
    let address = ipv6_text(&packet[24..40]);
    let (mut next, mut offset) = (packet[6], IPV6_HEADER_LENGTH);
    // Every extension header takes at least 8 bytes, so this ends.
    loop {
        let length = match next {
            HOP_BY_HOP | ROUTING | DESTINATION_OPTIONS => (usize::from(*packet.get(offset + 1)?) + 1) * 8,
            FRAGMENT if u16_at(packet, offset + 2)? & 0xfff8 != 0 => return None,
            FRAGMENT => 8,
            AUTHENTICATION => (usize::from(*packet.get(offset + 1)?) + 2) * 4,
            _ => break,
        };
        next = *packet.get(offset)?;
        offset += length;
    }
    let (protocol, port) = upper_layer(next, packet.get(offset..)?, (ICMPV6, ICMPV6_ECHO_REQUEST, "icmpv6"))?;
    Some(Flow { protocol, family: "inet6", address, port })
}

/// The flow an Ethernet frame from the guest starts, if any. IPv4 packets
/// count only with the guest's address as their source; the guest has no
/// fixed IPv6 address, so every IPv6 packet counts.
fn flow(frame: &[u8], guest: Ipv4Addr) -> Option<Flow> {
    let packet = frame.get(ETHERNET_HEADER_LENGTH..)?;
    match u16_at(frame, 12)? {
        ETHERTYPE_IPV4 => ipv4_flow(packet, guest),
        ETHERTYPE_IPV6 => ipv6_flow(packet),
        _ => None,
    }
}

fn record(flow: &Flow) -> String {
    let line = json!({"protocol": flow.protocol, "family": flow.family, "address": flow.address, "port": flow.port});
    format!("{line}\n")
}

/// packets.log: each distinct flow once, in the order of first occurrence, so
/// that retransmissions and repeated datagrams do not make it grow.
struct FlowLog<W: Write> {
    out: W,
    written: HashSet<Flow>,
}

impl<W: Write> FlowLog<W> {
    fn new(out: W) -> Self {
        FlowLog { out, written: HashSet::new() }
    }

    fn add(&mut self, flow: Flow) -> io::Result<()> {
        if !self.written.contains(&flow) {
            self.out.write_all(record(&flow).as_bytes())?;
            self.written.insert(flow);
        }
        Ok(())
    }
}

// --- Capturing ---------------------------------------------------------------------

fn last_error(what: &str) -> String {
    format!("{what}: {}", io::Error::last_os_error())
}

fn set_option<T>(socket: &OwnedFd, level: libc::c_int, name: libc::c_int, value: &T, what: &str) -> Result<(), String> {
    // SAFETY: value points to a live T of the given size.
    let result = unsafe {
        libc::setsockopt(socket.as_raw_fd(), level, name, (value as *const T).cast(), size_of::<T>() as libc::socklen_t)
    };
    if result == 0 { Ok(()) } else { Err(last_error(what)) }
}

/// A packet socket that receives every frame of `interface`, with a receive
/// timeout so that the capture notices when it is stopped.
fn packet_socket(interface: &str) -> Result<OwnedFd, String> {
    let name = CString::new(interface).map_err(|_| format!("{interface}: contains a NUL byte"))?;
    // SAFETY: name is a NUL-terminated string.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(last_error(interface));
    }
    // Protocol 0 receives nothing until bind() names the interface, so no
    // frame of another interface gets in.
    // SAFETY: plain system call.
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(last_error("cannot open a packet socket"));
    }
    // SAFETY: fd is a new descriptor that nothing else owns.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: sockaddr_ll is plain data, valid when zeroed.
    let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    address.sll_family = libc::AF_PACKET as libc::c_ushort;
    address.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    address.sll_ifindex = index as libc::c_int;
    // SAFETY: address is a sockaddr_ll of the given size.
    let bound = unsafe {
        libc::bind(fd, (&raw const address).cast(), size_of::<libc::sockaddr_ll>() as libc::socklen_t)
    };
    if bound != 0 {
        return Err(last_error(&format!("cannot capture on {interface}")));
    }
    let timeout = libc::timeval { tv_sec: 0, tv_usec: POLL_INTERVAL.as_micros() as _ };
    set_option(&socket, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &timeout, "SO_RCVTIMEO")?;
    // Capped by net.core.rmem_max; the drop count tells whether it was enough.
    set_option(&socket, libc::SOL_SOCKET, libc::SO_RCVBUF, &RECEIVE_BUFFER, "SO_RCVBUF")?;
    Ok(socket)
}

/// The number of frames the kernel dropped because the socket was full.
fn drops(socket: &OwnedFd) -> Result<u32, String> {
    // SAFETY: tpacket_stats is plain data, valid when zeroed.
    let mut stats: libc::tpacket_stats = unsafe { std::mem::zeroed() };
    let mut length = size_of::<libc::tpacket_stats>() as libc::socklen_t;
    // SAFETY: stats and length describe a writable tpacket_stats.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_PACKET,
            libc::PACKET_STATISTICS,
            (&raw mut stats).cast(),
            &mut length,
        )
    };
    if result == 0 { Ok(stats.tp_drops) } else { Err(last_error("PACKET_STATISTICS")) }
}

/// Record frames until stopped, then until the socket has been idle for a poll interval.
fn capture(socket: &OwnedFd, guest: Ipv4Addr, log: File, stop: &AtomicBool) -> Result<(), String> {
    let mut log = FlowLog::new(BufWriter::new(log));
    let write_failed = |error: io::Error| format!("cannot write packets.log: {error}");
    let mut frame = vec![0u8; FRAME_BUFFER];
    loop {
        // SAFETY: sockaddr_ll is plain data, valid when zeroed.
        let mut from: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut from_length = size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        // SAFETY: frame and from are writable buffers of the given sizes.
        let received = unsafe {
            libc::recvfrom(
                socket.as_raw_fd(),
                frame.as_mut_ptr().cast(),
                frame.len(),
                0,
                (&raw mut from).cast(),
                &mut from_length,
            )
        };
        if received < 0 {
            let error = io::Error::last_os_error();
            if !matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) {
                return Err(format!("capture: {error}"));
            }
            log.out.flush().map_err(write_failed)?;
            if stop.load(Ordering::SeqCst) {
                break;
            }
            continue;
        }
        // Frames that the host sends to the guest are seen as outgoing.
        if from.sll_pkttype == libc::PACKET_OUTGOING {
            continue;
        }
        if let Some(flow) = flow(&frame[..received as usize], guest) {
            log.add(flow).map_err(write_failed)?;
        }
    }
    log.out.flush().map_err(write_failed)?;
    match drops(socket)? {
        0 => Ok(()),
        dropped => Err(format!("the capture missed {dropped} frames")),
    }
}

/// The running capture; dropping it without stop() lets its thread end on its own.
pub struct Capture {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<(), String>>>,
}

/// Write the flows that `guest` starts on `interface` to `log`.
pub fn start(interface: &str, guest: Ipv4Addr, log: File) -> Result<Capture, String> {
    let socket = packet_socket(interface)?;
    let stop = Arc::new(AtomicBool::new(false));
    let thread = {
        let stop = Arc::clone(&stop);
        thread::Builder::new()
            .name("capture".to_string())
            .spawn(move || capture(&socket, guest, log, &stop))
            .map_err(|error| format!("cannot start the capture: {error}"))?
    };
    Ok(Capture { stop, thread: Some(thread) })
}

impl Capture {
    /// Record what the socket still holds, stop, and report why packets.log may be incomplete.
    pub fn stop(mut self) -> Result<(), String> {
        self.stop.store(true, Ordering::SeqCst);
        match self.thread.take().expect("a running capture").join() {
            Ok(result) => result,
            Err(_) => Err("the capture failed".to_string()),
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUEST: Ipv4Addr = Ipv4Addr::new(192, 168, 100, 2);

    fn ethernet(ethertype: u16, packet: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2];
        frame.extend(ethertype.to_be_bytes());
        frame.extend(packet);
        frame
    }

    /// An IPv4 header without options (IHL 5) followed by `payload`.
    fn ipv4(source: [u8; 4], destination: [u8; 4], protocol: u8, fragment: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0x45, 0];
        packet.extend(((20 + payload.len()) as u16).to_be_bytes());
        packet.extend([0, 0]);
        packet.extend(fragment.to_be_bytes());
        packet.extend([64, protocol, 0, 0]);
        packet.extend(source);
        packet.extend(destination);
        packet.extend(payload);
        packet
    }

    fn ipv6(next_header: u8, destination: [u8; 16], payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0x60, 0, 0, 0];
        packet.extend((payload.len() as u16).to_be_bytes());
        packet.extend([next_header, 64]);
        packet.extend([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet.extend(destination);
        packet.extend(payload);
        packet
    }

    /// A 20-byte TCP header from port 40000 to `port` with `flags`.
    fn tcp(port: u16, flags: u8) -> Vec<u8> {
        let mut header = 40000u16.to_be_bytes().to_vec();
        header.extend(port.to_be_bytes());
        header.extend([0; 8]);
        header.extend([0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        header
    }

    fn udp(port: u16, data: &[u8]) -> Vec<u8> {
        let mut header = 40000u16.to_be_bytes().to_vec();
        header.extend(port.to_be_bytes());
        header.extend(((8 + data.len()) as u16).to_be_bytes());
        header.extend([0, 0]);
        header.extend(data);
        header
    }

    fn echo(kind: u8) -> Vec<u8> {
        vec![kind, 0, 0, 0, 0, 1, 0, 1]
    }

    const ME: [u8; 4] = [192, 168, 100, 2];
    const V6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    fn flow_of(frame: &[u8]) -> Option<Flow> {
        flow(frame, GUEST)
    }

    fn expected(protocol: &str, family: &'static str, address: &str, port: Option<u16>) -> Option<Flow> {
        Some(Flow { protocol: protocol.to_string(), family, address: address.to_string(), port })
    }

    #[test]
    fn ipv4_flow_starts() {
        let frame = |protocol, payload: &[u8]| ethernet(ETHERTYPE_IPV4, &ipv4(ME, [1, 2, 3, 4], protocol, 0, payload));
        assert_eq!(flow_of(&frame(TCP, &tcp(443, 0x02))), expected("tcp", "inet", "1.2.3.4", Some(443)));
        // SYN with ECE and CWR is still a SYN without ACK.
        assert_eq!(flow_of(&frame(TCP, &tcp(80, 0xc2))), expected("tcp", "inet", "1.2.3.4", Some(80)));
        assert_eq!(flow_of(&frame(UDP, &udp(53, b"q"))), expected("udp", "inet", "1.2.3.4", Some(53)));
        assert_eq!(flow_of(&frame(ICMP, &echo(8))), expected("icmp", "inet", "1.2.3.4", None));
        assert_eq!(flow_of(&frame(47, b"gre")), expected("ip47", "inet", "1.2.3.4", None));
        // ICMPv6 inside IPv4 is just another protocol.
        assert_eq!(flow_of(&frame(ICMPV6, &echo(128))), expected("ip58", "inet", "1.2.3.4", None));
    }

    #[test]
    fn ipv4_packets_within_a_flow_are_not_recorded() {
        let frame = |protocol, payload: &[u8]| ethernet(ETHERTYPE_IPV4, &ipv4(ME, [1, 2, 3, 4], protocol, 0, payload));
        assert_eq!(flow_of(&frame(TCP, &tcp(443, 0x12))), None, "SYN-ACK");
        assert_eq!(flow_of(&frame(TCP, &tcp(443, 0x10))), None, "ACK");
        assert_eq!(flow_of(&frame(TCP, &tcp(443, 0x18))), None, "PSH-ACK");
        assert_eq!(flow_of(&frame(TCP, &tcp(443, 0x04))), None, "RST");
        assert_eq!(flow_of(&frame(ICMP, &echo(0))), None, "echo reply");
        assert_eq!(flow_of(&frame(ICMP, &echo(3))), None, "destination unreachable");
    }

    #[test]
    fn ipv4_packets_that_are_not_from_the_guest_or_not_whole_are_not_recorded() {
        let other_source = ethernet(ETHERTYPE_IPV4, &ipv4([192, 168, 100, 3], [1, 2, 3, 4], UDP, 0, &udp(53, b"")));
        assert_eq!(flow_of(&other_source), None);
        // A later fragment, while the first fragment (MF set, offset 0) counts.
        let later = ethernet(ETHERTYPE_IPV4, &ipv4(ME, [1, 2, 3, 4], UDP, 0x0010, &udp(53, b"")));
        assert_eq!(flow_of(&later), None);
        let first = ethernet(ETHERTYPE_IPV4, &ipv4(ME, [1, 2, 3, 4], UDP, 0x2000, &udp(53, b"")));
        assert_eq!(flow_of(&first), expected("udp", "inet", "1.2.3.4", Some(53)));
        // A UDP header cut short by the total length is not taken from the padding.
        let mut short = ipv4(ME, [1, 2, 3, 4], UDP, 0, &[0x9c, 0x40, 0, 53]);
        short.extend([0; 22]);
        assert_eq!(flow_of(&ethernet(ETHERTYPE_IPV4, &short)), None);
        // A total length beyond the frame.
        let mut long = ipv4(ME, [1, 2, 3, 4], UDP, 0, &udp(53, b""));
        long[3] += 1;
        assert_eq!(flow_of(&ethernet(ETHERTYPE_IPV4, &long)), None);
        // ARP is not IP.
        assert_eq!(flow_of(&ethernet(0x0806, &[0; 28])), None);
    }

    #[test]
    fn ipv4_options_are_skipped() {
        let mut packet = ipv4(ME, [8, 8, 8, 8], TCP, 0, &[]);
        packet[0] = 0x46;
        packet.extend([1, 1, 1, 0]); // NOP, NOP, NOP, end of options
        packet.extend(tcp(22, 0x02));
        packet[3] = packet.len() as u8;
        assert_eq!(flow_of(&ethernet(ETHERTYPE_IPV4, &packet)), expected("tcp", "inet", "8.8.8.8", Some(22)));
    }

    #[test]
    fn ipv6_flow_starts() {
        let frame = |next, payload: &[u8]| ethernet(ETHERTYPE_IPV6, &ipv6(next, V6, payload));
        assert_eq!(flow_of(&frame(TCP, &tcp(443, 0x02))), expected("tcp", "inet6", "2001:db8::1", Some(443)));
        assert_eq!(flow_of(&frame(UDP, &udp(123, b"ntp"))), expected("udp", "inet6", "2001:db8::1", Some(123)));
        assert_eq!(flow_of(&frame(ICMPV6, &echo(128))), expected("icmpv6", "inet6", "2001:db8::1", None));
        assert_eq!(flow_of(&frame(ICMPV6, &echo(135))), None, "neighbor solicitation");
        assert_eq!(flow_of(&frame(ICMP, &echo(8))), expected("ip1", "inet6", "2001:db8::1", None));
        assert_eq!(flow_of(&frame(59, b"")), expected("ip59", "inet6", "2001:db8::1", None));
    }

    #[test]
    fn ipv6_extension_headers_are_skipped() {
        // Hop-by-hop (8 bytes), destination options (16 bytes), then UDP.
        let mut payload = vec![60, 0, 1, 4, 0, 0, 0, 0];
        payload.extend([UDP, 1, 1, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        payload.extend(udp(443, b"quic"));
        let mapped = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1];
        let frame = ethernet(ETHERTYPE_IPV6, &ipv6(HOP_BY_HOP, mapped, &payload));
        assert_eq!(flow_of(&frame), expected("udp", "inet6", "::ffff:192.0.2.1", Some(443)));
        // A first fragment counts, a later one does not.
        let mut first = vec![TCP, 0, 0, 1, 0, 0, 0, 7];
        first.extend(tcp(80, 0x02));
        assert_eq!(
            flow_of(&ethernet(ETHERTYPE_IPV6, &ipv6(FRAGMENT, V6, &first))),
            expected("tcp", "inet6", "2001:db8::1", Some(80))
        );
        let mut later = vec![TCP, 0, 0, 0x08, 0, 0, 0, 7];
        later.extend(tcp(80, 0x02));
        assert_eq!(flow_of(&ethernet(ETHERTYPE_IPV6, &ipv6(FRAGMENT, V6, &later))), None);
        // An extension header that runs past the payload.
        assert_eq!(flow_of(&ethernet(ETHERTYPE_IPV6, &ipv6(ROUTING, V6, &[UDP, 3, 0, 0]))), None);
        // An authentication header: (2 + 2) * 4 = 16 bytes.
        let mut authenticated = vec![TCP, 2];
        authenticated.extend([0; 14]);
        authenticated.extend(tcp(25, 0x02));
        assert_eq!(
            flow_of(&ethernet(ETHERTYPE_IPV6, &ipv6(AUTHENTICATION, V6, &authenticated))),
            expected("tcp", "inet6", "2001:db8::1", Some(25))
        );
    }

    #[test]
    fn records_have_the_spec_format() {
        let flow = expected("udp", "inet", "1.2.3.4", Some(53)).unwrap();
        assert_eq!(record(&flow), "{\"address\":\"1.2.3.4\",\"family\":\"inet\",\"port\":53,\"protocol\":\"udp\"}\n");
        let flow = expected("icmpv6", "inet6", "2001:db8::1", None).unwrap();
        assert_eq!(record(&flow), "{\"address\":\"2001:db8::1\",\"family\":\"inet6\",\"port\":null,\"protocol\":\"icmpv6\"}\n");
    }

    #[test]
    fn each_distinct_flow_is_written_once_in_the_order_of_first_occurrence() {
        let syn = || expected("tcp", "inet", "1.2.3.4", Some(443)).unwrap();
        let other_port = || expected("tcp", "inet", "1.2.3.4", Some(80)).unwrap();
        let udp = || expected("udp", "inet", "1.2.3.4", Some(443)).unwrap();
        let echo = || expected("icmpv6", "inet6", "2001:db8::1", None).unwrap();
        let mut log = FlowLog::new(Vec::new());
        // Retransmitted SYNs and repeated datagrams between new flows.
        for flow in [syn(), syn(), udp(), syn(), echo(), udp(), other_port(), echo(), syn()] {
            log.add(flow).unwrap();
        }
        assert_eq!(
            String::from_utf8(log.out).unwrap(),
            concat!(
                "{\"address\":\"1.2.3.4\",\"family\":\"inet\",\"port\":443,\"protocol\":\"tcp\"}\n",
                "{\"address\":\"1.2.3.4\",\"family\":\"inet\",\"port\":443,\"protocol\":\"udp\"}\n",
                "{\"address\":\"2001:db8::1\",\"family\":\"inet6\",\"port\":null,\"protocol\":\"icmpv6\"}\n",
                "{\"address\":\"1.2.3.4\",\"family\":\"inet\",\"port\":80,\"protocol\":\"tcp\"}\n",
            )
        );
    }

    #[test]
    fn truncated_frames_never_panic() {
        let frames = [
            ethernet(ETHERTYPE_IPV4, &ipv4(ME, [1, 2, 3, 4], TCP, 0, &tcp(443, 0x02))),
            ethernet(ETHERTYPE_IPV6, &ipv6(HOP_BY_HOP, V6, &[UDP, 0, 0, 0, 0, 0, 0, 0, 0x9c, 0x40, 0, 53, 0, 8, 0, 0])),
        ];
        for frame in frames {
            for end in 0..frame.len() {
                let _ = flow_of(&frame[..end]);
            }
            for index in ETHERNET_HEADER_LENGTH..frame.len() {
                for byte in [0, 1, 0x0f, 0x45, 0x80, 0xff] {
                    let mut mutated = frame.clone();
                    mutated[index] = byte;
                    let _ = flow_of(&mutated);
                }
            }
        }
    }
}
