//! The guest's network: a tap device with NAT and an egress filter, DNS
//! answered by qim's forwarder on the gateway address, and a capture of the
//! guest's packets (docs/events.md, "Host-side network records").
//!
//! Everything lives in the network namespace of the container that runs qim.

use std::fs::{self, File};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::{Command, Stdio};

use crate::image::{self, at};
use crate::{capture, dns};

pub const TAP: &str = "qim0";
pub const TABLE: &str = "qim";
pub const GATEWAY: &str = "192.168.100.1";
pub const GUEST_ADDRESS: &str = "192.168.100.2/24";
const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 100, 1);
const GUEST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 100, 2);
const DNS_PORT: u16 = 53;

/// The IPv4 ranges that are not the public internet: "this network",
/// private, CGNAT, loopback, link-local, IETF protocol assignments,
/// documentation, the 6to4 relay anycast, benchmarking, multicast, and the
/// reserved range with the limited broadcast address (RFC 6890 and the IANA
/// IPv4 Special-Purpose Address Registry).
const NON_PUBLIC: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
];

/// The first nameserver of the container, to which the forwarder sends the guest's queries.
fn host_nameserver() -> Result<IpAddr, String> {
    let resolv = fs::read_to_string("/etc/resolv.conf").map_err(|error| format!("/etc/resolv.conf: {error}"))?;
    let nameserver = resolv
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .find(|fields| fields.len() >= 2 && fields[0] == "nameserver")
        .map(|fields| fields[1].to_string())
        .ok_or_else(|| "no nameserver in /etc/resolv.conf".to_string())?;
    nameserver.parse().map_err(|_| format!("/etc/resolv.conf: not an IP address: {nameserver}"))
}

/// The IPv4 addresses of the container's interfaces.
fn own_addresses() -> Result<Vec<Ipv4Addr>, String> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills in a list that is released below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(format!("cannot list the network addresses: {}", io::Error::last_os_error()));
    }
    let mut addresses = Vec::new();
    let mut entry = list;
    while !entry.is_null() {
        // SAFETY: entry is an element of the list getifaddrs returned, and an
        // AF_INET address is a sockaddr_in.
        unsafe {
            let address = (*entry).ifa_addr;
            if !address.is_null() && i32::from((*address).sa_family) == libc::AF_INET {
                let address = &*address.cast::<libc::sockaddr_in>();
                addresses.push(Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)));
            }
            entry = (*entry).ifa_next;
        }
    }
    // SAFETY: list came from getifaddrs and is not used afterwards.
    unsafe { libc::freeifaddrs(list) };
    addresses.sort();
    addresses.dedup();
    Ok(addresses)
}

/// The nftables ruleset for the guest, given the container's own addresses.
///
/// The guest may reach the public internet over IPv4 only, from its own
/// address; DNS, whatever its destination, goes to qim's forwarder, the only
/// service of the container that the guest may reach.
pub fn ruleset(own_addresses: &[Ipv4Addr]) -> String {
    let blocked: Vec<String> =
        NON_PUBLIC.iter().map(|range| range.to_string()).chain(own_addresses.iter().map(Ipv4Addr::to_string)).collect();
    let blocked = blocked.join(", ");
    format!(
        r#"table inet {TABLE} {{
  set blocked {{
    type ipv4_addr
    flags interval
    auto-merge
    elements = {{ {blocked} }}
  }}
  chain prerouting {{
    type nat hook prerouting priority dstnat; policy accept;
    iifname "{TAP}" meta nfproto ipv4 meta l4proto {{ tcp, udp }} th dport {DNS_PORT} dnat ip to {GATEWAY_IP}
  }}
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    oifname != "{TAP}" ip saddr {GUEST_IP} masquerade
  }}
  chain input {{
    type filter hook input priority filter; policy accept;
    iifname "{TAP}" ip saddr {GUEST_IP} ip daddr {GATEWAY_IP} meta l4proto {{ tcp, udp }} th dport {DNS_PORT} accept
    iifname "{TAP}" drop
  }}
  chain forward {{
    type filter hook forward priority filter; policy accept;
    iifname "{TAP}" meta nfproto != ipv4 drop
    iifname "{TAP}" ip saddr != {GUEST_IP} drop
    iifname "{TAP}" ip daddr @blocked drop
  }}
}}
"#
    )
}

fn nft(ruleset: &str) -> Result<(), String> {
    let mut command = Command::new("nft");
    command.args(["-f", "-"]).stdin(Stdio::piped());
    let mut child = image::spawn(&mut command)?;
    let mut stdin = child.stdin.take().expect("stdin is piped");
    // Like subprocess, a command that exits without reading its input is judged by its status.
    match stdin.write_all(ruleset.as_bytes()) {
        Err(error) if error.kind() != io::ErrorKind::BrokenPipe => return Err(format!("{command:?}: {error}")),
        _ => drop(stdin),
    }
    let status = image::wait(&command, &mut child, None)?;
    image::check(&command, status)
}

/// The tap device with its filter, the DNS forwarder writing dns.log and the
/// capture writing packets.log; dropping it removes them.
pub struct GuestNetwork {
    monitors: Option<(dns::Forwarder, capture::Capture)>,
}

pub fn guest_network(output_dir: &Path) -> Result<GuestNetwork, String> {
    let upstream = SocketAddr::new(host_nameserver()?, DNS_PORT);
    image::run(Command::new("ip").args(["tuntap", "add", "mode", "tap", "vnet_hdr", TAP]))?;
    let mut network = GuestNetwork { monitors: None };
    image::run(Command::new("ip").args(["addr", "add", &format!("{GATEWAY}/24"), "dev", TAP]))?;
    image::run(Command::new("ip").args(["link", "set", TAP, "up"]))?;
    nft(&ruleset(&own_addresses()?))?;
    let create = |name: &str| {
        let path = output_dir.join(name);
        File::create(&path).map_err(at(&path))
    };
    let capture = capture::start(TAP, GUEST_IP, create("packets.log")?)?;
    let forwarder = dns::start(SocketAddr::from((GATEWAY_IP, DNS_PORT)), upstream, create("dns.log")?)?;
    network.monitors = Some((forwarder, capture));
    Ok(network)
}

impl GuestNetwork {
    /// Stop the forwarder and the capture once the guest is gone, and report
    /// why dns.log or packets.log may be incomplete.
    pub fn finish(mut self) -> Vec<String> {
        let Some((forwarder, capture)) = self.monitors.take() else { return Vec::new() };
        [forwarder.stop(), capture.stop()].into_iter().filter_map(Result::err).collect()
    }
}

impl Drop for GuestNetwork {
    fn drop(&mut self) {
        drop(self.monitors.take());
        let _ = Command::new("nft").args(["delete", "table", "inet", TABLE]).stderr(Stdio::null()).status();
        let _ = Command::new("ip").args(["link", "delete", TAP]).stderr(Stdio::null()).status();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rules of a chain, one per line, without the chain's type line.
    fn chain<'a>(ruleset: &'a str, name: &str) -> Vec<&'a str> {
        let start = ruleset.find(&format!("chain {name} {{")).unwrap();
        ruleset[start..]
            .lines()
            .skip(2)
            .map(str::trim)
            .take_while(|line| *line != "}")
            .collect()
    }

    #[test]
    fn the_string_constants_match_the_addresses() {
        assert_eq!(GATEWAY.parse::<Ipv4Addr>().unwrap(), GATEWAY_IP);
        assert_eq!(GUEST_ADDRESS, format!("{GUEST_IP}/24"));
    }

    #[test]
    fn dns_to_any_destination_goes_to_the_forwarder() {
        assert_eq!(
            chain(&ruleset(&[]), "prerouting"),
            [r#"iifname "qim0" meta nfproto ipv4 meta l4proto { tcp, udp } th dport 53 dnat ip to 192.168.100.1"#]
        );
    }

    #[test]
    fn the_guest_reaches_only_the_forwarder_in_the_container() {
        assert_eq!(
            chain(&ruleset(&[]), "input"),
            [
                r#"iifname "qim0" ip saddr 192.168.100.2 ip daddr 192.168.100.1 meta l4proto { tcp, udp } th dport 53 accept"#,
                r#"iifname "qim0" drop"#,
            ]
        );
    }

    #[test]
    fn forwarding_is_ipv4_from_the_guest_to_public_addresses_only() {
        assert_eq!(
            chain(&ruleset(&[]), "forward"),
            [
                r#"iifname "qim0" meta nfproto != ipv4 drop"#,
                r#"iifname "qim0" ip saddr != 192.168.100.2 drop"#,
                r#"iifname "qim0" ip daddr @blocked drop"#,
            ]
        );
        assert_eq!(chain(&ruleset(&[]), "postrouting"), [r#"oifname != "qim0" ip saddr 192.168.100.2 masquerade"#]);
    }

    #[test]
    fn the_blocked_set_holds_the_non_public_ranges_and_the_container_addresses() {
        let own = [Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(203, 0, 114, 9)];
        let rules = ruleset(&own);
        let elements = rules.lines().find_map(|line| line.trim().strip_prefix("elements = { ")).unwrap();
        let elements: Vec<&str> = elements.strip_suffix(" }").unwrap().split(", ").collect();
        assert_eq!(
            elements,
            [
                "0.0.0.0/8",
                "10.0.0.0/8",
                "100.64.0.0/10",
                "127.0.0.0/8",
                "169.254.0.0/16",
                "172.16.0.0/12",
                "192.0.0.0/24",
                "192.0.2.0/24",
                "192.88.99.0/24",
                "192.168.0.0/16",
                "198.18.0.0/15",
                "198.51.100.0/24",
                "203.0.113.0/24",
                "224.0.0.0/4",
                "240.0.0.0/4",
                "127.0.0.1",
                "203.0.114.9",
            ]
        );
    }
}
