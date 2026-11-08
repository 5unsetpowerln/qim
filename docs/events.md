# events.json (schema version 1)

`events.json` summarizes what happened inside the guest while the install
command ran: which programs were executed, which network destinations were
contacted, and which files were accessed. It is derived from the Linux audit
log recorded inside the guest and from the DNS and packet records kept by the
host (see "Host-side network records").

## Determinism

The output is a pure function of the input: the same audit log always yields
the same bytes. The output contains no timestamps and no PIDs. Every list has a
defined order (see "Ordering"), and the document is serialized as

    json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False) + "\n"

encoded as UTF-8.

## Input

The input is an audit log written by auditd with `log_format = RAW`. Each line
is one record:

    type=<TYPE> msg=audit(<seconds>.<millis>:<serial>): <key>=<value> ...

- Records of the types `SYSCALL`, `EXECVE`, `CWD`, `PATH`, `SOCKADDR` and
  `PROCTITLE` with the same serial belong to one syscall event. An event
  consists of one `SYSCALL` record, optionally `EXECVE` (one or more), `CWD`,
  `PATH` (zero or more) and `SOCKADDR` records, and ends with a `PROCTITLE`
  record. There are no `EOE` records. Records of different events may
  interleave, so records must be grouped by serial, not by position.
- Records of all other types (`USER_*`, `CRED_*`, `CONFIG_CHANGE`,
  `DAEMON_*`, `MAC_*`, `UNKNOWN[...]`, ...) are not grouped; they are only
  counted, even when they share a serial with a syscall event.
- Events are processed in ascending numeric order of their serial. The serial
  is assigned when the kernel emits the event (at syscall exit), so records
  can arrive out of serial order. An input in which a record of one of the
  syscall event types with serial `s` appears after such a record with
  serial `s + 10000` or larger (the reorder window) is rejected, as are
  malformed lines. Records of other types do not take part in this check
  (auditd numbers its own `DAEMON_*` records independently).
- A value is either a double-quoted string (taken literally without the
  quotes), the literal `(null)`, or an unquoted token. In `EXECVE`, `PATH`
  `name`, `CWD` `cwd` and `SYSCALL` `exe`, an unquoted token that is not
  `(null)` is the hexadecimal encoding of the bytes. A `CWD` of `(null)`
  counts as a missing `CWD`. Decoded bytes are converted to text as
  UTF-8 with `errors="backslashreplace"`.
- `SYSCALL` fields used: `syscall` (decimal, x86_64 numbers), `success`
  (`yes`/`no`), `exit` (decimal), `a0`..`a3` (hexadecimal without `0x`),
  `pid`, `ppid` (decimal), `exe` (string).
- `EXECVE`: `argc` and `a0`, `a1`, ... . The arguments of a long command
  line are spread over several `EXECVE` records of the same event, in order.
  A long argument `aN` is split into `aN_len=<len>` followed by chunks
  `aN[0]`, `aN[1]`, ...; the chunks are concatenated in index order before
  decoding.
- `PATH`: `item` (decimal), `name`, `nametype` (`NORMAL`, `PARENT`, `CREATE`,
  `DELETE`, `UNKNOWN`).
- `SOCKADDR`: `saddr`, the raw `struct sockaddr` as hexadecimal.

`AT_FDCWD` appears in the `a` fields as `ffffff9c` (or `ffffffffffffff9c`).

## Processes

A process image is created by every successful `execve` (59) or `execveat`
(322). Images get integer ids 1, 2, 3, ... in the order of their exec events.

The converter keeps, per pid, the image currently attributed to it
(`current[pid]`), its fd table (below), and the `ppid` and serial of the first
event seen from that pid since its state was last reset (`origin[pid]`).

- The first event from a pid without state creates an empty state with that
  event's `ppid` and serial as its origin.
- A successful exec at serial `S` by `pid` whose `ppid` differs from the ppid
  of `origin[pid]` and whose origin serial `o` is old (`o <= S - 10000`)
  comes from a new process that reuses the pid of an earlier one, so the
  state of `pid` is first reset as if `ppid` had just created it at this
  serial (`current[pid] = current[ppid]`, its fd table becomes a copy of
  `ppid`'s, its origin is `(ppid, S)`). Then `current[pid]` is the new image.
  A recent origin with another ppid is a process that was reparented (to
  pid 1, typically after a double fork) and keeps its state. A pid reused
  within the window is not detected.
- A successful `clone` (56), `clone3` (435), `fork` (57) or `vfork` (58) at
  serial `S` in pid `p` whose `exit` is a positive child pid `c`:
  - If `c` already has state whose origin has `ppid == p` and a serial `o`
    with `S - 10000 < o < S`, the child already ran before its creation was
    logged (with `CLONE_VFORK` the parent's clone only exits after the
    child's exec, so the child's events get smaller serials). Its state is
    kept; only fds missing from its table are copied from `p`'s table.
  - Otherwise (no state, or state left by an earlier process with the same
    pid) the state of `c` is reset: `current[c] = current[p]` (none if `p` has
    none), its fd table becomes a copy of `p`'s, and its origin is `(p, S)`.

Each image records:

- `id`
- `exe`: the `exe` field of the exec event
- `argv`: the reassembled `EXECVE` arguments
- `cwd`: the `CWD` of the exec event (or null if absent)
- `parent`: `current[pid]` just before the exec if it exists, otherwise
  `current[ppid]` if it exists, otherwise null. (So the parent of an image is
  the image that forked it, or the image it replaced.)

Every syscall event is attributed to a process id: for an exec event, the new
image; otherwise `current[pid]`, else `current[ppid]`, else null.

## File events

### Path resolution

`PATH` records with `nametype` `PARENT` and records whose `name` is `(null)`
(the kernel's anonymous references) produce no file events and are skipped
everywhere below. For every other `PATH` record:

1. If `name` is absolute, it is used as is.
2. Otherwise the base directory depends on the syscall and the record:
   - For the `*at` syscalls, the base is the directory file descriptor
     argument: `a0` for `openat` (257), `openat2` (437), `mkdirat` (258),
     `unlinkat` (263) and `execveat` (322); for `renameat` (264),
     `renameat2` (316) and `linkat` (265) it is `a0` for the source record
     and `a2` for the other records (see "Two-path syscalls"); for
     `symlinkat` (266) it is `a1`.
     If that argument is `AT_FDCWD`, the base is the event's `CWD`.
     Otherwise the base is the path the fd table (below) maps that fd to.
   - For all other syscalls the base is the event's `CWD`.
   - The resolved path is `base + "/" + name`.
3. The path is normalized lexically: repeated slashes are collapsed, `.`
   components and a trailing slash are removed (a path that becomes empty is
   `/`). `..` components are kept (resolving them lexically is wrong when
   symlinks are involved).

If the base is unknown (an fd the converter has no mapping for, or a missing
`CWD`), the path is unresolved: the file event gets `"path": null` and
`"unresolved": {"dirfd": <fd as decimal int>, "name": "<name>"}` (with
`"dirfd": null` when the `CWD` was missing).

### The fd table

The converter keeps an fd table per pid (mapping fd number to resolved path or
unknown), updated by successful syscalls only:

- `open` (2), `openat` (257), `openat2` (437), `creat` (85): `exit` is the new
  fd; it maps to the resolved path of the first non-`PARENT` `PATH` record
  (unknown if unresolved).
- `close` (3): remove `a0`. `close_range` (436): remove every fd from `a0` to
  `a1` inclusive (as unsigned 32-bit numbers), unless `a2` has
  `CLOSE_RANGE_CLOEXEC` (0x4), which closes nothing immediately.
- `dup` (32): `exit` maps to what `a0` maps to. `dup2` (33), `dup3` (292):
  `a1` maps to what `a0` maps to. `fcntl` (72) with `a1` equal to 0
  (`F_DUPFD`) or 0x406 (`F_DUPFD_CLOEXEC`): `exit` maps to what `a0` maps to.
- `clone`, `clone3`, `fork`, `vfork` with positive `exit` `c`: see
  "Processes" (the child's table is replaced by or completed from `pid`'s).

File descriptor arguments (`a0` of `close`, `dup*`, `fcntl` and the `*at`
directory arguments) are the low 32 bits of the register as a signed integer.

Known limitations, accepted in version 1: `O_CLOEXEC` is not applied at exec,
`CLONE_FILES` sharing is treated as a copy, fds received over `SCM_RIGHTS`
are unknown, and for a child whose events were logged before its creation,
fds it closed before that point are filled in again from the parent.

### Operations

Each non-`PARENT` `PATH` record yields one or more file events, each with an
`op`:

| syscall | op |
|---|---|
| `execve`, `execveat` | `exec` |
| `open`, `openat`, `openat2`, `creat` | from the flags (below) |
| `unlink` (87), `unlinkat` (263) | `delete`; `unlinkat` with `AT_REMOVEDIR` (0x200) in `a2` gives `rmdir` |
| `rmdir` (84) | `rmdir` |
| `mkdir` (83), `mkdirat` (258) | `mkdir` |
| `rename` (82), `renameat` (264), `renameat2` (316) | see "Two-path syscalls" |
| `link` (86), `linkat` (265) | see "Two-path syscalls" |
| `symlink` (88), `symlinkat` (266) | `symlink` |

Other syscalls (`close`, `dup*`, `fcntl`, `chdir`, `fchdir`, `clone*`,
`connect`, ...) yield no file events.

Two-path syscalls (`rename`, `renameat`, `renameat2`, `link`, `linkat`): the
first remaining record (lowest `item`) is the source and gets `rename_from`
or `link_source`. Each later record with `nametype` `CREATE` is the
destination and gets `rename_to` or `link`. Each later record with
`nametype` `DELETE` is a destination that the call replaced and gets
`delete`. Any other later record gets the destination op.

Open flags are `a1` for `open`, `a2` for `openat`; `creat` behaves like
`O_WRONLY|O_CREAT|O_TRUNC`; for `openat2` the flags are not in the record and
the op is `open`. From the flags:

- `O_PATH` (0x200000): only `path`.
- Otherwise by `flags & 3`: 0 gives `read`, 1 gives `write`, 2 gives `read`
  and `write`, 3 gives `open`.
- In addition, `create` if the record's `nametype` is `CREATE`, and `truncate`
  if `O_TRUNC` (0x200) is set.

### Entry

    {"path": "/etc/out", "op": "write", "ok": true, "errno": null, "processes": [2]}

`ok` is `success == "yes"`. `errno` is null when `ok`, otherwise the Linux
x86-64 name of `-exit` from the table in `qim/errnos.py` (which uses the
kernel's primary names: `EAGAIN`, `EDEADLK`, `EOPNOTSUPP`), or the decimal
number as a string if it has no name. File events with the same path (or the
same `unresolved` value), `op`, `ok` and `errno` form one entry, whose
`processes` is the sorted list of the distinct process ids of those events
(events attributed to no process add nothing).

## Network events

Every `connect` (42), `sendto` (44), `sendmsg` (46) or `sendmmsg` (307) event
that has a `SOCKADDR` record yields one entry:

    {"syscall": "connect", "family": "inet", "address": "169.254.1.1",
     "port": 53, "ok": true, "errno": null, "processes": [2]}

`saddr` is decoded by its first two bytes (little-endian family):

- 1, `unix`: `address` is the path (bytes after the family up to the first
  NUL); an abstract address (first path byte NUL) is written as `@` followed by
  the remaining bytes up to the end, with NULs removed. `port` is null.
- 2, `inet`: `port` is bytes 2-3 big-endian, `address` bytes 4-7 in dotted
  form.
- 10, `inet6`: `port` is bytes 2-3 big-endian, `address` bytes 8-23 in the
  text form of RFC 5952, with IPv4-mapped addresses written as
  `::ffff:a.b.c.d` (as Python 3.13 and later print them).
- 16, `netlink`: `address` and `port` are null.
- other: `family` is `af<number>`, `address` is the full `saddr` hex in lower
  case, `port` is null.

`ok`/`errno` are as for file events. Events with the same `syscall`,
`family`, `address`, `port`, `ok` and `errno` form one entry with the sorted
list of their process ids.

## Host-side network records

The guest's audit record attributes network sends to processes, but it can
miss destinations (one `SOCKADDR` per syscall, so `sendmmsg` keeps only one)
and a command that gains root could interfere with it. The host therefore
keeps two more records while the guest runs, outside the guest's reach:

- `dns.log`: written by qim's DNS forwarder on the gateway address, to which
  all guest traffic to port 53 is redirected. One JSON object per line and
  per query: `{"name": "<qname>", "type": "<qtype>", "rcode": "<rcode>",
  "answers": ["<address or name>", ...]}`. `name` is the query name in lower
  case without the trailing dot; `type` is the mnemonic (`A`, `AAAA`, `CNAME`,
  `HTTPS`, ...) or `TYPE<n>`; `rcode` is the mnemonic (`NOERROR`, `NXDOMAIN`,
  `SERVFAIL`, ...) or `RCODE<n>`, or null if no answer came back; `answers`
  holds the A and AAAA addresses (text as for socket addresses) and the
  CNAME targets of the answer section.
- `packets.log`: written by qim's capture on the tap device, one JSON object
  per line and per packet from the guest that starts or attempts a flow: a
  TCP segment with SYN and without ACK, any UDP datagram, an ICMP or ICMPv6
  echo request, or any other IP protocol:
  `{"protocol": "tcp"|"udp"|"icmp"|"icmpv6"|"ip<n>", "family": "inet"|"inet6",
  "address": "<destination>", "port": <destination port or null>}`.

From them the converter derives:

- `dns`: the distinct `dns.log` objects, with `answers` sorted and
  deduplicated.
- `wire`: the distinct `packets.log` objects.

A missing log yields an empty list. A line that is not a JSON object with
exactly these keys and value types is rejected.

## Document

    {
      "schema_version": 1,
      "processes": [ {"id", "parent", "exe", "argv", "cwd"}, ... ],
      "files": [ ... ],
      "network": [ ... ],
      "dns": [ ... ],
      "wire": [ ... ],
      "counts": {"syscall_events": N, "ignored_records": N, "unresolved_paths": N}
    }

`syscall_events` is the number of events with a `SYSCALL` record,
`ignored_records` the number of records of ignored types, and
`unresolved_paths` the number of distinct file entries with `"path": null`.

## Ordering

- `processes`: by `id`.
- `files`: by the tuple (resolved entries before unresolved ones, `path` or
  "", `op`, `ok` false before true, `errno` or "", canonical JSON of the
  entry), where canonical JSON is
  `json.dumps(entry, sort_keys=True, ensure_ascii=False, separators=(",", ":"))`.
- `network`: by (`family`, `address` or "", `port` or -1, `syscall`, `ok`
  false before true, `errno` or "", canonical JSON).
- `dns`: by (`name`, `type`, canonical JSON).
- `wire`: by (`family`, `address`, `port` or -1, `protocol`).

## Worked example

Input (only an audit log; fields not used by the converter are omitted):

    type=SYSCALL msg=audit(1.000:10): arch=c000003e syscall=59 success=yes exit=0 a0=0 a1=0 a2=0 a3=0 items=1 ppid=1 pid=100 comm="sh" exe="/usr/bin/sh"
    type=EXECVE msg=audit(1.000:10): argc=3 a0="sh" a1="-c" a2="x"
    type=CWD msg=audit(1.000:10): cwd="/root"
    type=PATH msg=audit(1.000:10): item=0 name="/usr/bin/sh" nametype=NORMAL
    type=PROCTITLE msg=audit(1.000:10): proctitle=7368
    type=SYSCALL msg=audit(1.000:11): arch=c000003e syscall=56 success=yes exit=101 a0=0 a1=0 a2=0 a3=0 items=0 ppid=1 pid=100 comm="sh" exe="/usr/bin/sh"
    type=PROCTITLE msg=audit(1.000:11): proctitle=7368
    type=SYSCALL msg=audit(1.000:12): arch=c000003e syscall=59 success=yes exit=0 a0=0 a1=0 a2=0 a3=0 items=1 ppid=100 pid=101 comm="cat" exe="/usr/bin/cat"
    type=EXECVE msg=audit(1.000:12): argc=2 a0="cat" a1="a.txt"
    type=CWD msg=audit(1.000:12): cwd="/root"
    type=PATH msg=audit(1.000:12): item=0 name="/usr/bin/cat" nametype=NORMAL
    type=PROCTITLE msg=audit(1.000:12): proctitle=636174
    type=SYSCALL msg=audit(1.000:13): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=0 a2=0 a3=0 items=1 ppid=100 pid=101 comm="cat" exe="/usr/bin/cat"
    type=CWD msg=audit(1.000:13): cwd="/root"
    type=PATH msg=audit(1.000:13): item=0 name="a.txt" nametype=NORMAL
    type=PROCTITLE msg=audit(1.000:13): proctitle=636174
    type=SYSCALL msg=audit(1.000:14): arch=c000003e syscall=257 success=yes exit=4 a0=ffffff9c a1=0 a2=10000 a3=0 items=1 ppid=100 pid=101 comm="cat" exe="/usr/bin/cat"
    type=CWD msg=audit(1.000:14): cwd="/root"
    type=PATH msg=audit(1.000:14): item=0 name="/etc" nametype=NORMAL
    type=PROCTITLE msg=audit(1.000:14): proctitle=636174
    type=SYSCALL msg=audit(1.000:15): arch=c000003e syscall=257 success=yes exit=5 a0=4 a1=0 a2=241 a3=1a4 items=2 ppid=100 pid=101 comm="cat" exe="/usr/bin/cat"
    type=CWD msg=audit(1.000:15): cwd="/root"
    type=PATH msg=audit(1.000:15): item=0 name="/etc" nametype=PARENT
    type=PATH msg=audit(1.000:15): item=1 name="out" nametype=CREATE
    type=PROCTITLE msg=audit(1.000:15): proctitle=636174
    type=SYSCALL msg=audit(1.000:16): arch=c000003e syscall=42 success=yes exit=0 a0=6 a1=0 a2=10 a3=0 items=0 ppid=100 pid=101 comm="cat" exe="/usr/bin/cat"
    type=SOCKADDR msg=audit(1.000:16): saddr=02000035A9FE01010000000000000000
    type=PROCTITLE msg=audit(1.000:16): proctitle=636174
    type=SYSCALL msg=audit(1.000:17): arch=c000003e syscall=263 success=no exit=-2 a0=7 a1=0 a2=0 a3=0 items=1 ppid=100 pid=101 comm="cat" exe="/usr/bin/cat"
    type=CWD msg=audit(1.000:17): cwd="/root"
    type=PATH msg=audit(1.000:17): item=0 name="zz" nametype=UNKNOWN
    type=PROCTITLE msg=audit(1.000:17): proctitle=636174
    type=DAEMON_START msg=audit(1.000:9): op=start

Output:

    {
      "counts": {"ignored_records": 1, "syscall_events": 8, "unresolved_paths": 1},
      "dns": [],
      "files": [
        {"errno": null, "ok": true, "op": "read", "path": "/etc", "processes": [2]},
        {"errno": null, "ok": true, "op": "create", "path": "/etc/out", "processes": [2]},
        {"errno": null, "ok": true, "op": "truncate", "path": "/etc/out", "processes": [2]},
        {"errno": null, "ok": true, "op": "write", "path": "/etc/out", "processes": [2]},
        {"errno": null, "ok": true, "op": "read", "path": "/root/a.txt", "processes": [2]},
        {"errno": null, "ok": true, "op": "exec", "path": "/usr/bin/cat", "processes": [2]},
        {"errno": null, "ok": true, "op": "exec", "path": "/usr/bin/sh", "processes": [1]},
        {"errno": "ENOENT", "ok": false, "op": "delete", "path": null, "processes": [2],
         "unresolved": {"dirfd": 7, "name": "zz"}}
      ],
      "network": [
        {"address": "169.254.1.1", "errno": null, "family": "inet", "ok": true,
         "port": 53, "processes": [2], "syscall": "connect"}
      ],
      "processes": [
        {"argv": ["sh", "-c", "x"], "cwd": "/root", "exe": "/usr/bin/sh", "id": 1, "parent": null},
        {"argv": ["cat", "a.txt"], "cwd": "/root", "exe": "/usr/bin/cat", "id": 2, "parent": 1}
      ],
      "schema_version": 1,
      "wire": []
    }

(The output is shown compacted; the real serialization uses `indent=2`.)
