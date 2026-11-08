"""Build a base guest image from a dated Arch Linux Archive snapshot.

The packages come from https://archive.archlinux.org/repos/<date>/, so the
image content and the repository packages the guest installs later are both
fixed by the date. The image is built with pacman --root under bind mounts,
because pacstrap needs a devtmpfs mount that rootless containers refuse.
"""
import contextlib
import datetime
import hashlib
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

from qim import network, profiles

GUEST_DIR = Path(__file__).parent / "guest"

ARCHIVE_SERVER = "https://archive.archlinux.org/repos/{date}/$repo/os/$arch"
REPOSITORIES = ("core", "extra")


def home() -> Path:
    return Path(os.environ.get("QIM_HOME") or Path.home() / ".cache" / "qim")


def images_dir() -> Path:
    return home() / "images"


def default_date(today: datetime.date | None = None) -> datetime.date:
    """The previous day (UTC): the archive for the current day may still be incomplete."""
    today = today or datetime.datetime.now(datetime.timezone.utc).date()
    return today - datetime.timedelta(days=1)


def pacman_conf(date: datetime.date, cache_dir: Path | None = None) -> str:
    """A pacman.conf for the snapshot of `date`.

    It deliberately has no NoExtract lines: container images commonly exclude
    etc/pacman.conf, the mirrorlist, man pages and locales, and those
    exclusions must not leak into the guest.
    """
    server = ARCHIVE_SERVER.format(date=date.strftime("%Y/%m/%d"))
    lines = [
        "[options]",
        "Architecture = auto",
        "SigLevel = Required DatabaseOptional",
        "LocalFileSigLevel = Optional",
        "ParallelDownloads = 5",
    ]
    if cache_dir is not None:
        lines.append(f"CacheDir = {cache_dir}")
    for repository in REPOSITORIES:
        lines += ["", f"[{repository}]", f"Server = {server}"]
    return "\n".join(lines) + "\n"


def run(*command) -> subprocess.CompletedProcess:
    return subprocess.run([str(part) for part in command], check=True)


@contextlib.contextmanager
def chroot_mounts(root: Path):
    """Provide /dev, /proc and /sys inside `root` for package scriptlets and chroot."""
    mounted = []
    try:
        for source, target, options in (("/dev", "dev", ["--rbind"]),
                                        ("proc", "proc", ["-t", "proc"]),
                                        ("/sys", "sys", ["--rbind"])):
            path = root / target
            path.mkdir(parents=True, exist_ok=True)
            run("mount", *options, source, path)
            mounted.append(path)
        yield
    finally:
        for path in reversed(mounted):
            subprocess.run(["umount", "-R", "-l", str(path)], check=False)


def configure(root: Path, profile: profiles.Profile) -> None:
    (root / "etc/hostname").write_text("qim-guest\n")
    boot = root / "usr/lib/qim/boot"
    boot.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(GUEST_DIR / "boot", boot)
    boot.chmod(0o755)
    # The gateway answers DNS (network.guest_network), so the guest never needs to change this file.
    resolv = root / "etc/resolv.conf"
    if resolv.is_symlink() or resolv.exists():
        resolv.unlink()
    resolv.write_text(f"nameserver {network.GATEWAY}\n")
    if profile.user is None:
        return
    run("chroot", root, "useradd", "--create-home", profile.user)
    if profile.sudo_commands:
        sudoers = root / "etc/sudoers.d/qim"
        sudoers.write_text(f"{profile.user} ALL=(root) NOPASSWD: {', '.join(profile.sudo_commands)}\n")
        sudoers.chmod(0o440)


def manifest(root: Path) -> list[dict]:
    """Every path under `root` with its type, metadata and content hash, sorted by path."""
    entries = []
    for directory, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            path = Path(directory, name)
            info = path.lstat()
            entry = {
                "path": "/" + path.relative_to(root).as_posix(),
                "mode": f"{stat.S_IMODE(info.st_mode):04o}",
                "uid": info.st_uid,
                "gid": info.st_gid,
            }
            if stat.S_ISLNK(info.st_mode):
                entry.update(type="symlink", target=os.readlink(path))
            elif stat.S_ISDIR(info.st_mode):
                entry["type"] = "dir"
            elif stat.S_ISREG(info.st_mode):
                entry.update(type="file", size=info.st_size, sha256=file_sha256(path))
            else:
                entry["type"] = "other"
            xattrs = {}
            if not stat.S_ISLNK(info.st_mode):
                for attribute in sorted(os.listxattr(path)):
                    xattrs[attribute] = os.getxattr(path, attribute).hex()
            if xattrs:
                entry["xattrs"] = xattrs
            entries.append(entry)
    entries.sort(key=lambda entry: entry["path"])
    return entries


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build(profile_name: str, date: datetime.date, name: str | None = None) -> Path:
    if os.geteuid() != 0:
        raise SystemExit("qim image build must run as root (it bind-mounts /dev, /proc and /sys)")
    profile = profiles.get(profile_name)
    name = name or f"{profile.name}-{date:%Y%m%d}"
    base = images_dir() / name
    if base.exists():
        raise SystemExit(f"image {name} already exists: {base}")
    root = base / "root"
    (root / "var/lib/pacman").mkdir(parents=True)
    cache_dir = home() / "pkg"
    cache_dir.mkdir(parents=True, exist_ok=True)
    build_conf = base / "pacman.conf"
    build_conf.write_text(pacman_conf(date, cache_dir))

    with chroot_mounts(root):
        run("pacman", "--config", build_conf, "--root", root, "-Sy", "--noconfirm", *profile.packages)
        (root / "etc/pacman.conf").write_text(pacman_conf(date))
        run("chroot", root, "pacman-key", "--init")
        run("chroot", root, "pacman-key", "--populate", "archlinux")
        # pacman-key starts gpg-agent; stop it so that its sockets do not end up in the image.
        run("chroot", root, "gpgconf", "--homedir", "/etc/pacman.d/gnupg", "--kill", "all")
        for leftover in (root / "etc/pacman.d/gnupg").glob("S.*"):
            leftover.unlink()
        configure(root, profile)

    kernels = sorted((root / "usr/lib/modules").glob("*/vmlinuz"))
    if len(kernels) != 1:
        raise SystemExit(f"expected one kernel in the image, found {len(kernels)}")
    shutil.copyfile(kernels[0], base / "vmlinuz")

    entries = manifest(root)
    manifest_bytes = (json.dumps(entries, sort_keys=True, indent=1) + "\n").encode()
    (base / "manifest.json").write_bytes(manifest_bytes)
    packages = subprocess.run(["pacman", "--root", str(root), "-Q"], check=True,
                              capture_output=True, text=True).stdout.splitlines()
    content_bytes = sum(entry.get("size", 0) for entry in entries)
    size_mib = content_bytes * 2 // (1 << 20) + 2048
    run("mkfs.ext4", "-q", "-L", "qim-base", "-d", root, base / "root.img", f"{size_mib}M")
    info = {
        "name": name,
        "profile": profile.name,
        "date": date.isoformat(),
        "kernel": kernels[0].parent.name,
        "packages": packages,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    }
    (base / "image.json").write_text(json.dumps(info, sort_keys=True, indent=2) + "\n")
    return base
