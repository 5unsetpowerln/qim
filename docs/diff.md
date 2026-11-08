# diff.json and artifacts

After a run, the guest returns the overlay's upper layer as `upper.tar`. Every
change the command made to the filesystem is in it, but not everything in it
is a change: the overlay copies a file up when it is opened for writing or
its metadata is touched, even if nothing ends up different, and it creates
every ancestor directory of a changed path. `diff.json` is the list of real
changes, obtained by comparing the upper layer with the base image's
manifest. Artifacts are the subset of those changes that a profile's rules
select; their content is copied out of the run.

Both are pure functions of `upper.tar`, the base image's `manifest.json` and
the profile.

## Reading upper.tar

- Member names are `upper` (the layer's root, ignored) and `upper/<path>`;
  the guest path is `/<path>`, normalized like the manifest (no trailing
  slash).
- `security.capability` is the only xattr compared. `trusted.overlay.*`
  xattrs are overlay bookkeeping (`origin`, `impure`, `uuid`, ...) and are
  ignored, except `trusted.overlay.opaque` (below).
- A hard link member (`LNKTYPE`) is treated as a regular file with the
  content of its link target in the tar.
- Member names that are not `upper` or under `upper/`, or that contain `..`
  components, are rejected as malformed input.

## Classification

Each upper member (other than the root) is compared with the manifest entry
of the same path, if any:

| upper member | manifest entry | change |
|---|---|---|
| character device 0:0 (whiteout) | any | `deleted` |
| directory with `trusted.overlay.opaque` = `y` | any | `replaced` (the base content below it is hidden) |
| any other member | none | `added` |
| same type, same content (file: size and sha256; symlink: target), same mode, uid, gid and `security.capability` | present | none: not reported (a copy-up without change) |
| same type, same content, different mode, uid, gid or `security.capability` | present | `metadata` |
| different type, or different content | present | `modified` |

A directory that exists in the base and differs only in its own timestamps
is therefore not reported; timestamps are never compared.

## Entry

    {"path": "/usr/bin/tty-clock", "change": "added", "type": "file",
     "mode": "0755", "uid": 0, "gid": 0, "size": 26712, "sha256": "..."}

- `type` is `file`, `dir`, `symlink`, `whiteout` or `other`.
- `mode`, `uid`, `gid` are those of the upper member (absent for `deleted`).
- `size` and `sha256` for files, `target` for symlinks, `xattrs` (only
  `security.capability`, hex) when present.
- `diff.json` is `{"schema_version": 1, "changes": [...]}` with changes
  sorted by `path` (as UTF-8 bytes), serialized like events.json.

## Artifacts

A profile has `include` and `exclude` lists of path patterns. A change is an
artifact when its `change` is `added` or `modified`, its `type` is `file`, it
matches at least one `include` pattern and no `exclude` pattern.

Patterns match the whole guest path:

- `*` matches any sequence of characters other than `/`;
- `**` as a whole component matches zero or more components;
- every other character matches itself.

So `/var/lib/qim/packages/*.pkg.tar.zst` matches files directly in that
directory, and `/home/**` matches everything below `/home`.

Artifacts are written to `<output>/artifacts/<path>` as regular files with
the content from `upper.tar`. Their mode is the upper mode masked with
`0755` (no setuid, setgid or sticky bits, no write for others); ownership
and xattrs are not reproduced. Directories are created as needed with mode
`0755`. Nothing else from `upper.tar` is written to the host. `artifacts.json`
lists the artifacts (path, size, sha256) in path order.

### Profiles

- `aur`: makepkg is configured in the image (`/etc/makepkg.conf.d/qim.conf`)
  with `PKGDEST=/var/lib/qim/packages`, a directory owned by the build user.
  `include`: `/var/lib/qim/packages/*.pkg.tar.zst`; `exclude`: none. Debug
  packages (`*-debug-*.pkg.tar.zst`) that makepkg builds by default are
  artifacts too.
- `default`: `include`: `/**`; `exclude`: `/tmp/**`, `/var/tmp/**`,
  `/run/**`, `/var/cache/**`, `/var/log/**`, `/root/.cache/**`,
  `/home/*/.cache/**`, `/var/lib/pacman/sync/**`, `/etc/ld.so.cache`.

## Example

For the tty-clock installation with the `aur` profile (before PKGDEST was
configured, so the packages were still in paru's clone directory), the upper
layer held 45 new files, 25 new directories, 16 directories and 3 files that
also exist in the base. The classification gives:

- `/usr/bin/tty-clock`: `added` (not in the manifest);
- `/home/qim/.cache/paru/clone/tty-clock/tty-clock-2.3-2-x86_64.pkg.tar.zst`:
  `added`;
- `/etc/ld.so.cache`: not reported (rewritten by ldconfig with the same
  content, mode and owner);
- `/var/log/pacman.log`: `modified` (content differs);
- `/usr/bin`: not reported (copied up as an ancestor, same mode and owner).
