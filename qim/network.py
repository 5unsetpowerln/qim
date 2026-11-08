"""The guest's network: a tap device with NAT, and DNS on the gateway address."""
import contextlib
import subprocess

TAP = "qim0"
TABLE = "qim"
SUBNET = "192.168.100.0/24"
GATEWAY = "192.168.100.1"
GUEST_ADDRESS = "192.168.100.2/24"


def host_nameserver() -> str:
    with open("/etc/resolv.conf") as resolv:
        for line in resolv:
            fields = line.split()
            if len(fields) >= 2 and fields[0] == "nameserver":
                return fields[1]
    raise SystemExit("no nameserver in /etc/resolv.conf")


def nft(ruleset: str) -> None:
    subprocess.run(["nft", "-f", "-"], input=ruleset, text=True, check=True)


@contextlib.contextmanager
def guest_network():
    """Create the tap device and NAT for the guest, and remove them afterwards."""
    nameserver = host_nameserver()
    subprocess.run(["ip", "tuntap", "add", "mode", "tap", "vnet_hdr", TAP], check=True)
    try:
        subprocess.run(["ip", "addr", "add", f"{GATEWAY}/24", "dev", TAP], check=True)
        subprocess.run(["ip", "link", "set", TAP, "up"], check=True)
        nft(f"""
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
""")
        yield
    finally:
        subprocess.run(["nft", "delete", "table", "ip", TABLE], check=False, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "delete", TAP], check=False, stderr=subprocess.DEVNULL)
