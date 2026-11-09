# qim: Quarantined Installation Monitor

qim runs an install command inside a throwaway crosvm virtual machine and
reports what the installation did, so that you can look at its actual
behaviour before deciding whether to install the result on your host. It
writes:

- `events.json`: the programs that were executed, the network destinations
  that were contacted (with the DNS names that were looked up), and the files
  that were accessed, derived deterministically from the guest's audit record
  ([docs/events.md](docs/events.md));
- `diff.json`: the changes the installation made to the guest's filesystem
  ([docs/diff.md](docs/diff.md));
- `artifacts/`: the files a profile selects from those changes, for example
  the built packages of an AUR installation.

qim is a general tool; its first profile installs AUR packages with paru.

qim makes no guarantees. It shows what happened in one run, and it takes care
that the command cannot hide its activity from the record or reach your host
and local network (see "Recording and isolation").

## Requirements

qim runs on Arch Linux userland as root: it uses pacman, mkfs.ext4 and
crosvm (AUR package `crosvm-git`), KVM (`/dev/kvm`), a tap device and
nftables. On other hosts, use the development container below.

## Development container (any Linux host with rootless podman and KVM)

    dev/podman build --tag qim-dev -f dev/Containerfile dev   # once
    dev/cargo test --release                                  # unit tests
    dev/qim image build --profile aur --date 2026-11-08       # base image
    dev/qim run --image aur-20261108 --output /work/out/tty-clock \
        -- paru -S --noconfirm --skipreview tty-clock

`dev/podman` keeps all container storage in `build/containers`, `dev/cargo`
builds static musl binaries into `build/target`, and `dev/qim` builds qim and
runs it in the container with the devices and capabilities it needs. Inside
the container `/work` is `build/`, so the run above writes to
`build/out/tty-clock`.

## Commands

- `qim image build [--profile default|aur] [--date YYYY-MM-DD] [--name NAME]`
  builds a base image from the Arch Linux Archive snapshot of the date
  (default: yesterday). The packages, and the repository packages the guest
  installs later, are fixed by the date. The `aur` profile adds base-devel,
  git, sudo (for pacman only) and paru, and runs commands as the user `qim`.
- `qim run --image NAME --output DIR [--timeout S] [--memory MIB] [--cpus N] -- COMMAND...`
  boots the image read-only with a writable overlay, runs the command
  (stdin is /dev/null) and writes the outputs to DIR. Its exit code is the
  command's.
- `qim convert AUDIT_LOG [--dns FILE] [--packets FILE] [-o OUTPUT]`
  derives events.json again from a run's records; the result is byte for
  byte the same.

## Outputs of a run

| file | content |
|---|---|
| `events.json` | executed programs as a process tree, file accesses, network sends, DNS lookups, flows seen on the wire |
| `diff.json` | added, modified, metadata-only, deleted and replaced paths compared with the base image |
| `artifacts/`, `artifacts.json` | the files selected by the profile (no setuid bits, ownership or xattrs) |
| `audit.log`, `dns.log`, `packets.log` | the raw records events.json is derived from |
| `upper.tar` | the overlay's upper layer as the guest returned it |
| `meta/` | exit code, command output, audit diagnostics (`samples`), kernel log |

qim warns when the audit record may be incomplete (records lost, the reader
stopped early or its socket overflowed).

## Recording and isolation

- The guest records syscalls with Linux audit and streams them to a raw disk
  as they happen; records already written survive a crashed or killed guest.
- Only the command and its descendants are recorded (they carry an audit
  loginuid marker), plus whatever kernel-started helper programs execute.
- The command runs without the capabilities to change the audit
  configuration, load modules, create device nodes, mount, signal or trace
  the recorder, or change kernel settings; io_uring and module autoloading
  are disabled, and kernel helpers run without capabilities.
- The guest reaches only public internet addresses. All its DNS traffic goes
  to a forwarder on the host that logs it, and a packet capture on the host
  logs every flow the guest starts, whatever happens inside the guest.

Known limits: only 64-bit syscalls are recorded; file descriptors passed over
UNIX sockets and some early-child cases cannot be resolved to paths; a small
share of processes (about 0.2% in a large build) get no parent; a kernel
helper's own work is visible only through the programs it executes; and
crosvm runs without its own sandbox in the development container.
