"""Profiles: what a base image contains and how the install command runs."""
from dataclasses import dataclass

# Packages every guest needs for qim itself (recording, networking, output).
RUNTIME_PACKAGES = ("base", "linux", "audit", "iproute2", "zstd")


@dataclass(frozen=True)
class Profile:
    name: str
    packages: tuple[str, ...]
    # The user that runs the install command; None runs it as root.
    user: str | None = None
    # Commands the user may run as root through sudo without a password.
    sudo_commands: tuple[str, ...] = ()
    # Shell script run at image build time as `user` inside the image root, with network.
    setup: str = ""


# paru is itself an AUR package, so it is built from the AUR inside the image.
AUR_SETUP = """\
set -eu
cd /tmp
git clone --depth 1 https://aur.archlinux.org/paru.git
cd paru
makepkg --syncdeps --install --rmdeps --noconfirm
cd /
rm -rf "$HOME/.cargo" "$HOME/.cache"
"""


PROFILES = {
    "default": Profile("default", RUNTIME_PACKAGES),
    # makepkg refuses to run as root, and paru only needs root to call pacman.
    "aur": Profile("aur", RUNTIME_PACKAGES + ("base-devel", "git", "sudo"),
                   user="qim", sudo_commands=("/usr/bin/pacman",), setup=AUR_SETUP),
}


def get(name: str) -> Profile:
    try:
        return PROFILES[name]
    except KeyError:
        raise SystemExit(f"unknown profile: {name} (known: {', '.join(sorted(PROFILES))})") from None
