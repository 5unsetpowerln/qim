"""Run a command in a crosvm guest built from a base image.

The guest boots the base image read-only and writes every change into an
overlay whose upper layer lives on a per-run disk. When the command ends, the
guest writes a tar with the run's metadata and the upper layer to the output
disk, which is read back here without trusting its content.
"""
import io
import json
import shlex
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from qim import image, network, profiles

# The overlay's upper layer and the output disk are sparse; these are limits, not allocations.
UPPER_DISK_SIZE = 64 << 30
OUTPUT_DISK_SIZE = UPPER_DISK_SIZE + (8 << 30)
META_FILES = {"meta/exit_code", "meta/command.log", "meta/audit_status", "meta/audit_reader_exit"}


def input_tar(argv: list[str], user: str | None, timeout: int) -> bytes:
    config = {
        "QIM_USER": user or "",
        "QIM_ADDRESS": network.GUEST_ADDRESS,
        "QIM_GATEWAY": network.GATEWAY,
        "QIM_TIMEOUT": str(timeout),
    }
    files = {
        "init": (image.GUEST_DIR / "init").read_bytes(),
        "audit-reader": (image.GUEST_DIR / "audit-reader").read_bytes(),
        "config": "".join(f"{key}={shlex.quote(value)}\n" for key, value in config.items()).encode(),
        "argv": b"".join(argument.encode() + b"\0" for argument in argv),
    }
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = 0o755 if name in ("init", "audit-reader") else 0o644
            archive.addfile(member, io.BytesIO(data))
    return buffer.getvalue()


def read_output(raw: Path, output_dir: Path) -> None:
    """Split the guest's output tar into meta files and upper.tar.

    The guest controls this stream, so nothing is extracted onto the host
    filesystem except the known meta files, as regular files.
    """
    meta_dir = output_dir / "meta"
    meta_dir.mkdir()
    with tarfile.open(raw, mode="r|") as source, \
            tarfile.open(output_dir / "upper.tar", mode="w", format=tarfile.PAX_FORMAT) as upper:
        for member in source:
            if member.name in META_FILES and member.isreg():
                (meta_dir / Path(member.name).name).write_bytes(source.extractfile(member).read())
            elif member.name == "upper" or member.name.startswith("upper/"):
                upper.addfile(member, source.extractfile(member) if member.isreg() else None)


def sparse_file(path: Path, size: int) -> None:
    with open(path, "wb") as stream:
        stream.truncate(size)


def run(image_name: str, argv: list[str], output_dir: Path, timeout: int, memory_mib: int, cpus: int) -> int:
    base = image.images_dir() / image_name
    info = json.loads((base / "image.json").read_text())
    profile = profiles.get(info["profile"])
    output_dir.mkdir(parents=True)
    with tempfile.TemporaryDirectory(dir=image.home()) as directory:
        work = Path(directory)
        (work / "input.tar").write_bytes(input_tar(argv, profile.user, timeout))
        sparse_file(work / "upper.img", UPPER_DISK_SIZE)
        subprocess.run(["mkfs.ext4", "-q", "-L", "qim-upper", str(work / "upper.img")], check=True)
        sparse_file(work / "output.raw", OUTPUT_DISK_SIZE)
        command = [
            "crosvm", "run", "--disable-sandbox",
            "--mem", str(memory_mib), "--cpus", str(cpus),
            "--block", f"path={base / 'root.img'},ro,root",
            "--block", f"path={work / 'upper.img'}",
            "--block", f"path={work / 'input.tar'},ro",
            "--block", f"path={work / 'output.raw'}",
            "--net", f"tap-name={network.TAP}",
            "--serial", f"type=file,path={output_dir / 'console.log'},hardware=serial,console",
            # The guest streams audit records to this file while the command runs (/dev/hvc0).
            "--serial", f"type=file,path={output_dir / 'audit.log'},hardware=virtio-console,num=1",
            "-p", "init=/usr/lib/qim/boot quiet audit=1",
            str(base / "vmlinuz"),
        ]
        with network.guest_network():
            with open(output_dir / "crosvm.log", "wb") as log:
                subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=timeout + 300, check=False)
        read_output(work / "output.raw", output_dir)
    exit_code = output_dir / "meta" / "exit_code"
    if not exit_code.exists():
        raise SystemExit(f"the guest did not report a result; see {output_dir / 'console.log'}")
    for problem in recording_problems(output_dir / "meta"):
        print(f"qim: warning: the audit record may be incomplete: {problem}", file=sys.stderr)
    return int(exit_code.read_text())


def recording_problems(meta_dir: Path) -> list[str]:
    """Reasons to doubt that audit.log holds every record.

    The kernel's lost counter alone is not enough: records produced while no
    reader is registered go to the kernel log instead, without being counted.
    """
    try:
        status = dict(line.split(None, 1) for line in (meta_dir / "audit_status").read_text().splitlines() if " " in line)
        reader_exit = (meta_dir / "audit_reader_exit").read_text().strip()
    except FileNotFoundError as missing:
        return [f"{missing.filename} is missing"]
    problems = []
    if status.get("lost", "").strip() != "0":
        problems.append(f"the kernel lost {status.get('lost', '?').strip()} records")
    if status.get("pid", "0").strip() == "0":
        problems.append("the reader was no longer registered when the command ended")
    if reader_exit != "0":
        problems.append(f"the reader exited with status {reader_exit}")
    return problems

