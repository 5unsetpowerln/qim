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
    dev/qim run --profile aur -- paru -S --noconfirm --skipreview tty-clock

`dev/podman` keeps all container storage in `build/containers`, `dev/cargo`
builds static musl binaries into `build/target`, and `dev/qim` builds qim and
runs it in the container with the devices and capabilities it needs. Inside
the container `/work` is `build/` and qim's directory is `/work/qim`, so the
run above writes to `build/qim/runs/<UTC time>` (qim prints the directory as
`/work/qim/runs/...`).

## Commands

- `qim run [--profile default|aur] [--output DIR] [--timeout S] [--memory MIB] [--cpus N] -- COMMAND...`
  boots the profile's base image read-only with a writable overlay, runs the
  command (stdin is /dev/null), shows its output while it runs and its exit
  status at the end, and writes the outputs to DIR, by default
  `runs/<UTC time>` in qim's directory (`$QIM_HOME`, or `~/.cache/qim`). The
  output shown leaves out escape sequences and control characters, which the
  guest could use to control the terminal; meta/command.log keeps it as it
  was. The exit code is the command's. When the host's pacman state has no
  image yet, qim builds one first.
- `qim image build [--profile default|aur]` builds that image ahead of time
  and prints its directory.

A base image follows the host's pacman state: it is built with the host's
pacman configuration (as `pacman-conf` prints it, without the options that
locate the host's own files) from a copy of the host's sync databases, which
is never refreshed, and it carries the host's makepkg.conf and
makepkg.conf.d. So the guest has, and installs, the package versions the
host's pacman would install now, much like paru's `--chroot` but without
moving ahead to the mirrors' newest packages. Every image contains base,
linux, audit, iproute2 and zstd, which qim uses in the guest; the `aur`
profile adds base-devel, git, sudo (for pacman only) and paru, and runs
commands as the user `qim`. Images are named after a digest of the host
state, so updating the host leads to a new image.
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
| `meta/` | exit code, command output, audit diagnostics (`samples`), kernel log, the guest's packages at the end (`packages`) |

qim warns when the audit record may be incomplete (records lost, the reader
stopped early or its socket overflowed), and when the guest ended with a
repository package in another version than the host has installed: then the
host has updates it has not applied, and what was built may need library
versions the host does not have.

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
