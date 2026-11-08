//! Profiles: what a base image contains and how the install command runs.

/// Packages every guest needs for qim itself (recording, networking, output).
/// The audit reader is a static binary carried on the input disk, so it needs
/// no runtime of its own.
pub const RUNTIME_PACKAGES: &[&str] = &["base", "linux", "audit", "iproute2", "zstd"];

#[derive(Debug)]
pub struct Profile {
    pub name: &'static str,
    /// Packages on top of RUNTIME_PACKAGES.
    extra_packages: &'static [&'static str],
    /// The user that runs the install command; None runs it as root.
    pub user: Option<&'static str>,
    /// Commands the user may run as root through sudo without a password.
    pub sudo_commands: &'static [&'static str],
    /// Shell script run at image build time as `user` inside the image root, with network.
    pub setup: &'static str,
}

impl Profile {
    pub fn packages(&self) -> impl Iterator<Item = &'static str> {
        RUNTIME_PACKAGES.iter().chain(self.extra_packages).copied()
    }
}

// paru is itself an AUR package, so it is built from the AUR inside the image.
const AUR_SETUP: &str = "\
set -eu
cd /tmp
git clone --depth 1 https://aur.archlinux.org/paru.git
cd paru
makepkg --syncdeps --install --rmdeps --noconfirm
cd /
rm -rf \"$HOME/.cargo\" \"$HOME/.cache\"
";

pub const PROFILES: &[Profile] = &[
    Profile {
        name: "default",
        extra_packages: &[],
        user: None,
        sudo_commands: &[],
        setup: "",
    },
    // makepkg refuses to run as root, and paru only needs root to call pacman.
    Profile {
        name: "aur",
        extra_packages: &["base-devel", "git", "sudo"],
        user: Some("qim"),
        sudo_commands: &["/usr/bin/pacman"],
        setup: AUR_SETUP,
    },
];

/// The profile names, sorted.
pub fn names() -> Vec<&'static str> {
    let mut names: Vec<_> = PROFILES.iter().map(|profile| profile.name).collect();
    names.sort_unstable();
    names
}

pub fn get(name: &str) -> Result<&'static Profile, String> {
    PROFILES
        .iter()
        .find(|profile| profile.name == name)
        .ok_or_else(|| format!("unknown profile: {name} (known: {})", names().join(", ")))
}
