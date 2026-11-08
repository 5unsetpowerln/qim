//! The guest's network: a tap device with NAT, and DNS on the gateway address.

use std::fs;
use std::io::{self, Write};
use std::process::{Command, Stdio};

use crate::image;

pub const TAP: &str = "qim0";
pub const TABLE: &str = "qim";
pub const SUBNET: &str = "192.168.100.0/24";
pub const GATEWAY: &str = "192.168.100.1";
pub const GUEST_ADDRESS: &str = "192.168.100.2/24";

fn host_nameserver() -> Result<String, String> {
    let resolv = fs::read_to_string("/etc/resolv.conf").map_err(|error| format!("/etc/resolv.conf: {error}"))?;
    resolv
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .find(|fields| fields.len() >= 2 && fields[0] == "nameserver")
        .map(|fields| fields[1].to_string())
        .ok_or_else(|| "no nameserver in /etc/resolv.conf".to_string())
}

fn ruleset(nameserver: &str) -> String {
    format!(
        r#"
table ip {TABLE} {{
  chain prerouting {{
    type nat hook prerouting priority dstnat;
    iifname "{TAP}" ip daddr {GATEWAY} udp dport 53 dnat to {nameserver}
    iifname "{TAP}" ip daddr {GATEWAY} tcp dport 53 dnat to {nameserver}
  }}
  chain postrouting {{
    type nat hook postrouting priority srcnat;
    ip saddr {SUBNET} oifname != "{TAP}" masquerade
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

/// The tap device and NAT for the guest; dropping it removes them.
pub struct GuestNetwork(());

pub fn guest_network() -> Result<GuestNetwork, String> {
    let nameserver = host_nameserver()?;
    image::run(Command::new("ip").args(["tuntap", "add", "mode", "tap", "vnet_hdr", TAP]))?;
    let network = GuestNetwork(());
    image::run(Command::new("ip").args(["addr", "add", &format!("{GATEWAY}/24"), "dev", TAP]))?;
    image::run(Command::new("ip").args(["link", "set", TAP, "up"]))?;
    nft(&ruleset(&nameserver))?;
    Ok(network)
}

impl Drop for GuestNetwork {
    fn drop(&mut self) {
        let _ = Command::new("nft").args(["delete", "table", "ip", TABLE]).stderr(Stdio::null()).status();
        let _ = Command::new("ip").args(["link", "delete", TAP]).stderr(Stdio::null()).status();
    }
}
