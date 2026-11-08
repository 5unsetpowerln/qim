//! diff.json and artifacts (docs/diff.md).
//!
//! The real changes of a run are found by comparing the overlay's upper layer
//! (upper.tar) with the base image's manifest. The files among them that the
//! profile selects are copied out of upper.tar. upper.tar comes from the
//! guest: its names are checked before anything is written, and artifacts are
//! written as plain regular files without following any symlink on the host.

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tar::EntryType;

use crate::guest_tar;

use crate::image::{self, Entry, Kind, at};
use crate::profiles::Profile;

const XATTR_RECORD: &[u8] = b"SCHILY.xattr.";
const CAPABILITY: &[u8] = b"security.capability";
const OPAQUE: &[u8] = b"trusted.overlay.opaque";

/// One member of upper.tar.
struct Member {
    /// The guest path, type, content and metadata; `xattrs` holds only security.capability.
    entry: Entry,
    whiteout: bool,
    opaque: bool,
    /// For a file, the path of the member whose data is its content: its own,
    /// or for a hard link, that of its target.
    source: Option<Vec<u8>>,
}

struct Change {
    change: &'static str,
    member: Member,
}

struct Artifact<'a> {
    member: &'a Member,
    size: u64,
    sha256: &'a str,
}

/// Write diff.json, the artifacts and artifacts.json into `output_dir`, which
/// holds the run's upper.tar.
pub fn write(output_dir: &Path, manifest: &Path, profile: &Profile) -> Result<(), String> {
    let base = image::read_manifest(manifest)?;
    let upper_path = output_dir.join("upper.tar");
    let in_upper = |problem: String| format!("{}: {problem}", upper_path.display());
    let open_upper = || File::open(&upper_path).map(|file| BufReader::with_capacity(1 << 20, file)).map_err(at(&upper_path));
    let changes = changes(open_upper()?, &base).map_err(in_upper)?;
    let diff_path = output_dir.join("diff.json");
    fs::write(&diff_path, diff_json(&changes)).map_err(at(&diff_path))?;
    let artifacts = artifacts(&changes, profile.include, profile.exclude);
    if !artifacts.is_empty() {
        write_artifacts(open_upper()?, output_dir, &artifacts)?;
    }
    let list_path = output_dir.join("artifacts.json");
    fs::write(&list_path, artifacts_json(&artifacts)).map_err(at(&list_path))
}

/// The changes that upper.tar makes to the base, sorted as diff.json lists them.
fn changes(upper: impl Read, base: &[Entry]) -> Result<Vec<Change>, String> {
    let base: HashMap<&[u8], &Entry> = base.iter().map(|entry| (entry.path.as_slice(), entry)).collect();
    let mut changes: Vec<Change> = read_upper(upper)?
        .into_iter()
        .filter_map(|member| {
            let change = classify(&member, base.get(member.entry.path.as_slice()).copied())?;
            Some(Change { change, member })
        })
        .collect();
    changes.sort_by_cached_key(|change| path_text(&change.member.entry.path));
    Ok(changes)
}

/// The guest path of an upper.tar member name, or None for the layer's root.
fn guest_path(name: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let mut trimmed = name;
    while let Some(rest) = trimmed.strip_suffix(b"/") {
        trimmed = rest;
    }
    if trimmed == b"upper" {
        return Ok(None);
    }
    match trimmed.strip_prefix(b"upper/") {
        Some(rest) if !rest.split(|&byte| byte == b'/').any(|component| component == b"..") => {
            Ok(Some([b"/", rest].concat()))
        }
        _ => Err(format!("malformed member name {:?}", path_text(name))),
    }
}

fn read_upper(upper: impl Read) -> Result<Vec<Member>, String> {
    let mut members = Vec::new();
    let mut paths = HashSet::new();
    // The kind and source of every file so far, for the hard links that refer to it.
    let mut files: HashMap<Vec<u8>, (Kind, Vec<u8>)> = HashMap::new();
    let mut reader = guest_tar::Reader::new(upper);
    while let Some((tar_member, mut data)) = reader.next_member()? {
        image::check_signal()?;
        let Some(path) = guest_path(&tar_member.name)? else {
            continue;
        };
        if !paths.insert(path.clone()) {
            return Err(format!("{} appears twice", path_text(&path)));
        }
        let id = |value: u64| u32::try_from(value).map_err(|_| format!("{}: owner {value} is too large", path_text(&path)));
        let mut member = Member {
            entry: Entry {
                path: path.clone(),
                kind: Kind::Other,
                mode: tar_member.mode & 0o7777,
                uid: id(tar_member.uid)?,
                gid: id(tar_member.gid)?,
                xattrs: Vec::new(),
            },
            whiteout: false,
            opaque: false,
            source: None,
        };
        for (key, value) in &tar_member.records {
            match key.strip_prefix(XATTR_RECORD) {
                Some(CAPABILITY) => member.entry.xattrs = vec![(CAPABILITY.to_vec(), value.clone())],
                Some(OPAQUE) => member.opaque = value == b"y",
                _ => {}
            }
        }
        member.entry.kind = match tar_member.kind {
            _ if tar_member.is_regular() => {
                let mut digest = Sha256::new();
                let size = io::copy(&mut data, &mut digest).map_err(|error| error.to_string())?;
                member.source = Some(path.clone());
                Kind::File { size, sha256: image::hex(&digest.finalize()) }
            }
            EntryType::Link => {
                let target = guest_path(&tar_member.link_name)?;
                let file = target.and_then(|target| files.get(&target));
                let (kind, source) = file.cloned().ok_or_else(|| {
                    format!("{}: a hard link to something other than a file before it", path_text(&path))
                })?;
                member.source = Some(source);
                kind
            }
            EntryType::Symlink => Kind::Symlink { target: tar_member.link_name.clone() },
            EntryType::Directory => Kind::Dir,
            EntryType::Char => {
                member.whiteout = tar_member.device == (0, 0);
                Kind::Other
            }
            _ => Kind::Other,
        };
        if let Some(source) = &member.source {
            files.insert(path, (member.entry.kind.clone(), source.clone()));
        }
        members.push(member);
    }
    Ok(members)
}

/// The change an upper member makes (docs/diff.md, "Classification"), or
/// None for a copy-up without change.
fn classify(member: &Member, base: Option<&Entry>) -> Option<&'static str> {
    let entry = &member.entry;
    if member.whiteout {
        return Some("deleted");
    }
    if member.opaque && entry.kind == Kind::Dir {
        return Some("replaced");
    }
    let Some(base) = base else {
        return Some("added");
    };
    // Kind holds the type and the content: size and sha256, or the symlink target.
    if entry.kind != base.kind {
        return Some("modified");
    }
    let metadata = |entry: &Entry| {
        let capability = entry.xattrs.iter().find(|(name, _)| name == CAPABILITY).map(|(_, value)| value.clone());
        (entry.mode, entry.uid, entry.gid, capability)
    };
    (metadata(entry) != metadata(base)).then_some("metadata")
}

/// A path as text: UTF-8 with Python's errors="backslashreplace", as
/// events.json converts bytes (docs/events.md).
fn path_text(path: &[u8]) -> String {
    let mut text = String::with_capacity(path.len());
    for chunk in path.utf8_chunks() {
        text.push_str(chunk.valid());
        for byte in chunk.invalid() {
            let _ = write!(text, "\\x{byte:02x}");
        }
    }
    text
}

fn change_json(change: &Change) -> Value {
    let (member, entry) = (&change.member, &change.member.entry);
    let mut fields = Map::new();
    fields.insert("path".into(), path_text(&entry.path).into());
    fields.insert("change".into(), change.change.into());
    let kind = match &entry.kind {
        _ if member.whiteout => "whiteout",
        Kind::File { size, sha256 } => {
            fields.insert("size".into(), (*size).into());
            fields.insert("sha256".into(), sha256.as_str().into());
            "file"
        }
        Kind::Dir => "dir",
        Kind::Symlink { target } => {
            fields.insert("target".into(), path_text(target).into());
            "symlink"
        }
        Kind::Other => "other",
    };
    fields.insert("type".into(), kind.into());
    if !member.whiteout {
        fields.insert("mode".into(), format!("{:04o}", entry.mode).into());
        fields.insert("uid".into(), entry.uid.into());
        fields.insert("gid".into(), entry.gid.into());
    }
    if !entry.xattrs.is_empty() {
        let xattrs = entry.xattrs.iter().map(|(name, value)| (path_text(name), image::hex(value).into()));
        fields.insert("xattrs".into(), Value::Object(xattrs.collect()));
    }
    Value::Object(fields)
}

fn diff_json(changes: &[Change]) -> String {
    let changes: Vec<Value> = changes.iter().map(change_json).collect();
    crate::audit::dump(&json!({"schema_version": 1, "changes": changes}))
}

/// The added or modified files that match an `include` pattern and no `exclude` pattern.
fn artifacts<'a>(changes: &'a [Change], include: &[&str], exclude: &[&str]) -> Vec<Artifact<'a>> {
    let artifact = |change: &'a Change| {
        let Kind::File { size, sha256 } = &change.member.entry.kind else {
            return None;
        };
        let path = change.member.entry.path.as_slice();
        let selected = matches!(change.change, "added" | "modified")
            && include.iter().any(|pattern| matches(pattern, path))
            && !exclude.iter().any(|pattern| matches(pattern, path));
        selected.then_some(Artifact { member: &change.member, size: *size, sha256 })
    };
    changes.iter().filter_map(artifact).collect()
}

fn artifacts_json(artifacts: &[Artifact]) -> String {
    let artifacts = artifacts.iter().map(|artifact| {
        json!({"path": path_text(&artifact.member.entry.path), "size": artifact.size, "sha256": artifact.sha256})
    });
    crate::audit::dump(&Value::Array(artifacts.collect()))
}

/// Whether `pattern` matches the whole of `path`: `*` matches any sequence of
/// characters other than `/`, a `**` component zero or more components.
fn matches(pattern: &str, path: &[u8]) -> bool {
    let pattern: Vec<&[u8]> = pattern.as_bytes().split(|&byte| byte == b'/').collect();
    let path: Vec<&[u8]> = path.split(|&byte| byte == b'/').collect();
    components_match(&pattern, &path)
}

fn components_match(pattern: &[&[u8]], path: &[&[u8]]) -> bool {
    match pattern.split_first() {
        None => path.is_empty(),
        Some((first, rest)) if *first == b"**" => (0..=path.len()).any(|skipped| components_match(rest, &path[skipped..])),
        Some((first, rest)) => path
            .split_first()
            .is_some_and(|(component, path)| component_matches(first, component) && components_match(rest, path)),
    }
}

fn component_matches(pattern: &[u8], component: &[u8]) -> bool {
    match pattern.split_first() {
        None => component.is_empty(),
        Some((b'*', rest)) => (0..=component.len()).any(|skipped| component_matches(rest, &component[skipped..])),
        Some((byte, rest)) => component
            .split_first()
            .is_some_and(|(first, component)| first == byte && component_matches(rest, component)),
    }
}

/// Copy each artifact's content out of upper.tar to `<output_dir>/artifacts/<path>`.
fn write_artifacts(upper: impl Read, output_dir: &Path, artifacts: &[Artifact]) -> Result<(), String> {
    let directory = output_dir.join("artifacts");
    let in_directory = |path: &[u8], error: io::Error| format!("{}{}: {error}", directory.display(), path_text(path));
    let root = File::open(output_dir).and_then(|parent| open_directory(&parent, b"artifacts")).map_err(at(&directory))?;
    // The artifacts by the member whose data is their content.
    let mut pending: HashMap<&[u8], Vec<&Member>> = HashMap::new();
    for artifact in artifacts {
        let source = artifact.member.source.as_deref().expect("a file has a source");
        pending.entry(source).or_default().push(artifact.member);
    }
    let mut buffer = vec![0; 1 << 16];
    let mut reader = guest_tar::Reader::new(upper);
    while let Some((tar_member, mut data)) = reader.next_member()? {
        image::check_signal()?;
        if !tar_member.is_regular() {
            continue;
        }
        let Some(members) = guest_path(&tar_member.name)?.and_then(|path| pending.remove(path.as_slice())) else {
            continue;
        };
        let mut files = Vec::new();
        for member in &members {
            let path = member.entry.path.as_slice();
            files.push(create_file(&root, path, member.entry.mode & 0o755).map_err(|error| in_directory(path, error))?);
        }
        loop {
            let length = match data.read(&mut buffer) {
                Ok(0) => break,
                Ok(length) => length,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.to_string()),
            };
            for (file, member) in files.iter_mut().zip(&members) {
                file.write_all(&buffer[..length]).map_err(|error| in_directory(&member.entry.path, error))?;
            }
        }
    }
    match pending.keys().next() {
        Some(source) => Err(format!("upper.tar changed: {} is missing", path_text(source))),
        None => Ok(()),
    }
}

/// Create the regular file `path` (a guest path) below `root`, creating
/// missing directories with mode 0755. No symlink is followed, and no
/// existing file is replaced.
fn create_file(root: &File, path: &[u8], mode: u32) -> io::Result<File> {
    // As in the kernel's path walk, empty and "." components name the directory they are in.
    let components: Vec<&[u8]> = path.split(|&byte| byte == b'/').filter(|component| !matches!(*component, b"" | b".")).collect();
    let Some((name, directories)) = components.split_last() else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no file name"));
    };
    let mut parent = None;
    for directory in directories {
        parent = Some(open_directory(parent.as_ref().unwrap_or(root), directory)?);
    }
    let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let file = openat(parent.as_ref().unwrap_or(root), name, flags, mode)?;
    // The umask may have cleared bits of the mode.
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    Ok(file)
}

/// Open the directory `name` in `parent`, creating it with mode 0755 if it is missing.
fn open_directory(parent: &File, name: &[u8]) -> io::Result<File> {
    let c_name = CString::new(name)?;
    // SAFETY: the descriptor is open and the name is NUL-terminated.
    let created = unsafe { libc::mkdirat(parent.as_raw_fd(), c_name.as_ptr(), 0o755) } == 0;
    if !created {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(error);
        }
    }
    let directory = openat(parent, name, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0)?;
    if created {
        directory.set_permissions(fs::Permissions::from_mode(0o755))?;
    }
    Ok(directory)
}

fn openat(parent: &File, name: &[u8], flags: libc::c_int, mode: u32) -> io::Result<File> {
    let name = CString::new(name)?;
    // SAFETY: the descriptor is open and the name is NUL-terminated.
    let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags, mode as libc::c_uint) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new descriptor that nothing else owns.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profiles;
    use crate::run::TempDir;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;
    use tar::Header;

    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const HELLO: &str = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";

    /// A member of a test upper.tar.
    #[derive(Clone)]
    struct Item {
        name: Vec<u8>,
        kind: EntryType,
        mode: u32,
        owner: (u64, u64),
        data: Vec<u8>,
        link: Vec<u8>,
        device: (u32, u32),
        records: Vec<(Vec<u8>, Vec<u8>)>,
    }

    fn item(name: &[u8], kind: EntryType, mode: u32) -> Item {
        let (owner, device, data, link, records) = ((0, 0), (0, 0), Vec::new(), Vec::new(), Vec::new());
        Item { name: name.to_vec(), kind, mode, owner, data, link, device, records }
    }

    fn file(name: &str, mode: u32, data: &[u8]) -> Item {
        Item { data: data.to_vec(), ..item(name.as_bytes(), EntryType::Regular, mode) }
    }

    fn dir(name: &str) -> Item {
        item(name.as_bytes(), EntryType::Directory, 0o755)
    }

    fn symlink(name: &str, target: &str) -> Item {
        Item { link: target.into(), ..item(name.as_bytes(), EntryType::Symlink, 0o777) }
    }

    fn hard_link(name: &str, target: &str) -> Item {
        Item { link: target.into(), ..item(name.as_bytes(), EntryType::Link, 0o644) }
    }

    fn whiteout(name: &str) -> Item {
        item(name.as_bytes(), EntryType::Char, 0)
    }

    impl Item {
        fn owner(self, uid: u64, gid: u64) -> Item {
            Item { owner: (uid, gid), ..self }
        }

        fn device(self, major: u32, minor: u32) -> Item {
            Item { device: (major, minor), ..self }
        }

        fn xattr(self, name: &str, value: &[u8]) -> Item {
            self.record(&format!("SCHILY.xattr.{name}"), value)
        }

        fn record(mut self, key: &str, value: &[u8]) -> Item {
            self.records.push((key.into(), value.to_vec()));
            self
        }
    }

    /// A pax payload: "<length> <key>=<value>\n" records, each length counting its own digits.
    fn pax(records: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let mut payload = Vec::new();
        for (key, value) in records {
            let rest = key.len() + value.len() + 3;
            let mut length = rest + 1;
            while rest + length.to_string().len() != length {
                length = rest + length.to_string().len();
            }
            payload.extend(format!("{length} ").bytes());
            payload.extend(key);
            payload.push(b'=');
            payload.extend(value);
            payload.push(b'\n');
        }
        payload
    }

    fn tar(items: &[Item]) -> Vec<u8> {
        let header = |kind: EntryType, name: &[u8], mode: u32, size: usize| {
            let mut header = Header::new_ustar();
            header.as_old_mut().name[..name.len()].copy_from_slice(name);
            header.set_entry_type(kind);
            header.set_mode(mode);
            header.set_size(size as u64);
            header
        };
        let mut builder = tar::Builder::new(Vec::new());
        for item in items {
            if !item.records.is_empty() {
                let payload = pax(&item.records);
                let mut extension = header(EntryType::XHeader, b"././@PaxHeader", 0, payload.len());
                extension.set_cksum();
                builder.append(&extension, payload.as_slice()).unwrap();
            }
            let mut member = header(item.kind, &item.name, item.mode, item.data.len());
            member.as_old_mut().linkname[..item.link.len()].copy_from_slice(&item.link);
            member.set_uid(item.owner.0);
            member.set_gid(item.owner.1);
            if item.kind == EntryType::Char {
                member.set_device_major(item.device.0).unwrap();
                member.set_device_minor(item.device.1).unwrap();
            }
            member.set_cksum();
            builder.append(&member, item.data.as_slice()).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn base(path: &str, kind: Kind, mode: u32) -> Entry {
        Entry { path: path.into(), kind, mode, uid: 0, gid: 0, xattrs: Vec::new() }
    }

    fn content(size: u64, sha256: &str) -> Kind {
        Kind::File { size, sha256: sha256.into() }
    }

    fn with_capability(mut entry: Entry, value: &[u8]) -> Entry {
        entry.xattrs = vec![(b"security.capability".to_vec(), value.to_vec())];
        entry
    }

    /// The (path, change) of each reported change, in diff.json order.
    fn classified(items: &[Item], base: &[Entry]) -> Vec<(String, &'static str)> {
        let changes = changes(tar(items).as_slice(), base).unwrap();
        changes.iter().map(|change| (path_text(&change.member.entry.path), change.change)).collect()
    }

    fn reported(pairs: &[(&str, &'static str)]) -> Vec<(String, &'static str)> {
        pairs.iter().map(|&(path, change)| (path.to_string(), change)).collect()
    }

    // --- Classification ------------------------------------------------------------

    #[test]
    fn a_whiteout_is_deleted_whatever_the_base_holds() {
        let base = [base("/etc/gone", content(3, ABC), 0o644)];
        let items = [dir("upper/"), whiteout("upper/etc/gone"), whiteout("upper/never")];
        assert_eq!(classified(&items, &base), reported(&[("/etc/gone", "deleted"), ("/never", "deleted")]));
    }

    #[test]
    fn a_character_device_other_than_0_0_is_an_other_member() {
        let items = [whiteout("upper/dev/null").device(1, 3)];
        let changes = changes(tar(&items).as_slice(), &[]).unwrap();
        assert_eq!(changes[0].change, "added");
        assert_eq!(change_json(&changes[0])["type"], "other");
    }

    #[test]
    fn an_opaque_directory_is_replaced_whatever_the_base_holds() {
        let base = [base("/opt", Kind::Dir, 0o755), base("/srv", Kind::Dir, 0o755)];
        let items = [
            dir("upper/opt/").xattr("trusted.overlay.opaque", b"y"),
            dir("upper/new/").xattr("trusted.overlay.opaque", b"y"),
            // Only "y" makes a directory opaque.
            dir("upper/srv/").xattr("trusted.overlay.opaque", b"x"),
            // Only a directory can be opaque.
            file("upper/file", 0o644, b"").xattr("trusted.overlay.opaque", b"y"),
        ];
        assert_eq!(
            classified(&items, &base),
            reported(&[("/file", "added"), ("/new", "replaced"), ("/opt", "replaced")])
        );
    }

    #[test]
    fn a_member_without_a_manifest_entry_is_added() {
        let items = [
            file("upper/f", 0o644, b"abc"),
            dir("upper/d/"),
            symlink("upper/l", "f"),
            item(b"upper/p", EntryType::Fifo, 0o644),
        ];
        assert_eq!(
            classified(&items, &[]),
            reported(&[("/d", "added"), ("/f", "added"), ("/l", "added"), ("/p", "added")])
        );
    }

    #[test]
    fn a_copy_up_without_change_is_not_reported() {
        let base = [
            base("/usr", Kind::Dir, 0o755),
            base("/etc/ld.so.cache", content(6, HELLO), 0o644),
            base("/bin", Kind::Symlink { target: b"usr/bin".to_vec() }, 0o777),
            base("/dev/x", Kind::Other, 0o600),
            with_capability(base("/usr/bin/ping", content(3, ABC), 0o755), b"\x01\x00\x00\x02"),
        ];
        let items = [
            dir("upper/usr/"),
            file("upper/etc/ld.so.cache", 0o644, b"hello\n"),
            symlink("upper/bin", "usr/bin"),
            item(b"upper/dev/x", EntryType::Fifo, 0o600),
            file("upper/usr/bin/ping", 0o755, b"abc").xattr("security.capability", b"\x01\x00\x00\x02"),
        ];
        assert_eq!(classified(&items, &base), []);
    }

    #[test]
    fn a_metadata_difference_alone_is_metadata() {
        let base = [
            base("/mode", content(3, ABC), 0o644),
            base("/uid", content(3, ABC), 0o644),
            base("/gid", content(3, ABC), 0o644),
            base("/caps-added", content(3, ABC), 0o755),
            with_capability(base("/caps-changed", content(3, ABC), 0o755), b"\x01"),
            with_capability(base("/caps-removed", content(3, ABC), 0o755), b"\x01"),
            base("/dir", Kind::Dir, 0o755),
        ];
        let items = [
            file("upper/mode", 0o4755, b"abc"),
            file("upper/uid", 0o644, b"abc").owner(1000, 0),
            file("upper/gid", 0o644, b"abc").owner(0, 1000),
            file("upper/caps-added", 0o755, b"abc").xattr("security.capability", b"\x01"),
            file("upper/caps-changed", 0o755, b"abc").xattr("security.capability", b"\x02"),
            file("upper/caps-removed", 0o755, b"abc"),
            dir("upper/dir/").owner(1000, 1000),
        ];
        assert_eq!(
            classified(&items, &base),
            reported(&[
                ("/caps-added", "metadata"),
                ("/caps-changed", "metadata"),
                ("/caps-removed", "metadata"),
                ("/dir", "metadata"),
                ("/gid", "metadata"),
                ("/mode", "metadata"),
                ("/uid", "metadata"),
            ])
        );
    }

    #[test]
    fn a_different_type_or_content_is_modified() {
        let base = [
            base("/same-size", content(3, ABC), 0o644),
            base("/other-size", content(3, ABC), 0o644),
            base("/file-to-dir", content(3, ABC), 0o644),
            base("/dir-to-symlink", Kind::Dir, 0o755),
            base("/target", Kind::Symlink { target: b"a".to_vec() }, 0o777),
            base("/file-to-other", content(0, EMPTY), 0o644),
        ];
        let items = [
            file("upper/same-size", 0o644, b"xyz"),
            file("upper/other-size", 0o644, b"hello\n"),
            dir("upper/file-to-dir/"),
            symlink("upper/dir-to-symlink", "elsewhere"),
            symlink("upper/target", "b"),
            item(b"upper/file-to-other", EntryType::Fifo, 0o644),
        ];
        assert_eq!(
            classified(&items, &base),
            reported(&[
                ("/dir-to-symlink", "modified"),
                ("/file-to-dir", "modified"),
                ("/file-to-other", "modified"),
                ("/other-size", "modified"),
                ("/same-size", "modified"),
                ("/target", "modified"),
            ])
        );
    }

    #[test]
    fn overlay_xattrs_are_ignored() {
        let base = [base("/etc", Kind::Dir, 0o755), base("/etc/hosts", content(3, ABC), 0o644)];
        let items = [
            dir("upper/etc/").xattr("trusted.overlay.impure", b"y").xattr("trusted.overlay.origin", b"\x00\xfb\x21"),
            file("upper/etc/hosts", 0o644, b"abc").xattr("trusted.overlay.origin", b"\x00\xfb\x22"),
        ];
        assert_eq!(classified(&items, &base), []);
    }

    #[test]
    fn timestamps_are_not_compared() {
        let base = [base("/var", Kind::Dir, 0o755)];
        let mut upper = tar(&[dir("upper/var/")]);
        // Give the member an mtime by rewriting its header.
        let mut header = Header::from_byte_slice(&upper[..512]).clone();
        header.set_mtime(1_700_000_000);
        header.set_cksum();
        upper[..512].copy_from_slice(header.as_bytes());
        assert!(changes(upper.as_slice(), &base).unwrap().is_empty());
    }

    // --- Reading upper.tar ---------------------------------------------------------

    #[test]
    fn a_hard_link_is_a_file_with_the_content_of_its_target() {
        let base = [base("/usr/bin/b", content(3, ABC), 0o755)];
        let items = [
            file("upper/usr/bin/a", 0o755, b"abc"),
            Item { mode: 0o755, ..hard_link("upper/usr/bin/b", "upper/usr/bin/a") },
            Item { mode: 0o700, ..hard_link("upper/usr/bin/c", "upper/usr/bin/a") },
        ];
        let changes = changes(tar(&items).as_slice(), &base).unwrap();
        // b equals the base, so only a and c are reported.
        assert_eq!(changes.len(), 2);
        assert_eq!(
            change_json(&changes[1]),
            json!({
                "path": "/usr/bin/c", "change": "added", "type": "file", "mode": "0700",
                "uid": 0, "gid": 0, "size": 3, "sha256": ABC
            })
        );
    }

    #[test]
    fn a_hard_link_to_anything_but_an_earlier_file_is_rejected() {
        for items in [
            vec![hard_link("upper/b", "upper/a"), file("upper/a", 0o644, b"abc")],
            vec![dir("upper/d/"), hard_link("upper/b", "upper/d")],
            vec![hard_link("upper/b", "../a")],
        ] {
            assert!(changes(tar(&items).as_slice(), &[]).is_err());
        }
    }

    #[test]
    fn malformed_names_are_rejected() {
        for name in ["upper/../etc/passwd", "upper/a/../../b", "upper/..", "other/x", "/upper/x", "upperx/y", "..", "x"] {
            let result = changes(tar(&[file(name, 0o644, b"abc")]).as_slice(), &[]);
            assert!(result.is_err(), "{name}");
        }
    }

    #[test]
    fn the_layer_root_is_ignored() {
        assert_eq!(classified(&[dir("upper/")], &[]), []);
        assert_eq!(classified(&[dir("upper")], &[]), []);
    }

    #[test]
    fn binary_xattr_values_may_hold_newlines() {
        let base = [base("/etc", Kind::Dir, 0o755), base("/usr/bin/ping", content(3, ABC), 0o755)];
        let items = [
            // overlayfs puts the lower filesystem's UUID into trusted.overlay.origin.
            dir("upper/etc/").xattr("trusted.overlay.origin", b"\x00\xfb\x21\x00\x01\x0a\x0a"),
            file("upper/usr/bin/ping", 0o755, b"abc").xattr("security.capability", b"\x01\x0a\x00\x02"),
        ];
        let changes = changes(tar(&items).as_slice(), &base).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change, "metadata");
        assert_eq!(change_json(&changes[0])["xattrs"], json!({"security.capability": "010a0002"}));
    }

    #[test]
    fn a_binary_xattr_in_the_guest_stream_reaches_diff_json_unchanged() {
        use crate::guest_tar::testing::{header, member, pax, stream};
        let mut usr = header(b'5', b"upper/usr/", 0);
        usr.set_mode(0o755);
        let guest = stream(&[
            member(header(b'5', b"upper/", 0), b""),
            pax(b"46 SCHILY.xattr.trusted.overlay.origin=\x00\xfb\n\x00\xff\n\n"),
            member(usr, b""),
            pax(b"41 SCHILY.xattr.security.capability=\x01\n\x00\xff\n"),
            member(header(b'0', b"upper/usr/ping", 3), b"abc"),
        ]);
        let directory = TempDir::new(&std::env::temp_dir()).unwrap();
        let raw = directory.path().join("raw");
        fs::write(&raw, guest).unwrap();
        let output = directory.path().join("out");
        fs::create_dir(&output).unwrap();
        crate::run::read_output(&raw, &output).unwrap();
        let manifest = directory.path().join("manifest.json");
        let entries = [
            r#"{"gid": 0, "mode": "0755", "path": "/usr", "type": "dir", "uid": 0}"#,
            r#"{"gid": 0, "mode": "0644", "path": "/usr/ping", "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "size": 3, "type": "file", "uid": 0}"#,
        ];
        fs::write(&manifest, format!("[{}]", entries.join(", "))).unwrap();
        write(&output, &manifest, profiles::get("aur").unwrap()).unwrap();
        // /usr differs from the base only in overlay xattrs; /usr/ping gained a capability.
        assert_eq!(fs::read_to_string(output.join("diff.json")).unwrap(), r#"{
  "changes": [
    {
      "change": "metadata",
      "gid": 0,
      "mode": "0644",
      "path": "/usr/ping",
      "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      "size": 3,
      "type": "file",
      "uid": 0,
      "xattrs": {
        "security.capability": "010a00ff"
      }
    }
  ],
  "schema_version": 1
}
"#);
    }

    #[test]
    fn names_and_link_targets_in_pax_records_win_over_the_header() {
        let long = format!("upper/{}", "n".repeat(150));
        let items = [
            file("upper/short", 0o644, b"abc").record("path", long.as_bytes()),
            symlink("upper/l", "header-target").record("linkpath", b"pax-target"),
            hard_link("upper/h", "upper/wrong").record("linkpath", long.as_bytes()),
        ];
        let changes = changes(tar(&items).as_slice(), &[]).unwrap();
        let paths: Vec<String> = changes.iter().map(|change| path_text(&change.member.entry.path)).collect();
        assert_eq!(paths, ["/h", "/l", format!("/{}", "n".repeat(150)).as_str()]);
        assert_eq!(change_json(&changes[0])["sha256"], ABC);
        assert_eq!(change_json(&changes[1])["target"], "pax-target");
    }

    #[test]
    fn a_path_given_twice_is_rejected() {
        let items = [file("upper/a", 0o644, b"abc"), file("upper/a", 0o644, b"xyz")];
        assert!(changes(tar(&items).as_slice(), &[]).is_err());
    }

    // --- diff.json -----------------------------------------------------------------

    fn diff_items() -> Vec<Item> {
        vec![
            dir("upper/"),
            file("upper/usr/bin/tool", 0o755, b"abc"),
            dir("upper/usr/"),
            dir("upper/usr/bin/"),
            whiteout("upper/etc/old"),
            symlink("upper/a-b", "x"),
            file("upper/a/x", 0o644, b""),
            file("upper/etc/caps", 0o755, b"abc").xattr("security.capability", b"\x01\x00\x00\x02"),
            item(b"upper/caf\xff", EntryType::Regular, 0o644),
            Item { data: b"hello\n".to_vec(), ..item(b"upper/\xc3\xa9", EntryType::Regular, 0o600) }.owner(1000, 1000),
        ]
    }

    fn diff_base() -> Vec<Entry> {
        vec![
            base("/etc/caps", content(3, ABC), 0o755),
            base("/etc/old", content(3, ABC), 0o644),
            base("/usr", Kind::Dir, 0o755),
            base("/usr/bin", Kind::Dir, 0o755),
        ]
    }

    // ensure_ascii=False: U+00E9 is written as itself, in UTF-8.
    const DIFF_JSON: &str = concat!(
        r#"{
  "changes": [
    {
      "change": "added",
      "gid": 0,
      "mode": "0777",
      "path": "/a-b",
      "target": "x",
      "type": "symlink",
      "uid": 0
    },
    {
      "change": "added",
      "gid": 0,
      "mode": "0644",
      "path": "/a/x",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "size": 0,
      "type": "file",
      "uid": 0
    },
    {
      "change": "added",
      "gid": 0,
      "mode": "0644",
      "path": "/caf\\xff",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "size": 0,
      "type": "file",
      "uid": 0
    },
    {
      "change": "metadata",
      "gid": 0,
      "mode": "0755",
      "path": "/etc/caps",
      "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      "size": 3,
      "type": "file",
      "uid": 0,
      "xattrs": {
        "security.capability": "01000002"
      }
    },
    {
      "change": "deleted",
      "path": "/etc/old",
      "type": "whiteout"
    },
    {
      "change": "added",
      "gid": 0,
      "mode": "0755",
      "path": "/usr/bin/tool",
      "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      "size": 3,
      "type": "file",
      "uid": 0
    },
    {
      "change": "added",
      "gid": 1000,
      "mode": "0600",
      "path": "/"#,
        "\u{e9}",
        r#"",
      "sha256": "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
      "size": 6,
      "type": "file",
      "uid": 1000
    }
  ],
  "schema_version": 1
}
"#
    );

    #[test]
    fn diff_json_is_sorted_by_path_and_serialized_like_events_json() {
        let changes = changes(tar(&diff_items()).as_slice(), &diff_base()).unwrap();
        assert_eq!(diff_json(&changes), DIFF_JSON);
    }

    #[test]
    fn diff_json_does_not_depend_on_the_member_order() {
        let mut items = diff_items();
        items.reverse();
        let changes = changes(tar(&items).as_slice(), &diff_base()).unwrap();
        assert_eq!(diff_json(&changes), DIFF_JSON);
    }

    // --- Patterns and selection ----------------------------------------------------

    #[test]
    fn a_star_matches_within_one_component() {
        let packages = "/var/lib/qim/packages/*.pkg.tar.zst";
        assert!(matches(packages, b"/var/lib/qim/packages/tty-clock-2.3-2-x86_64.pkg.tar.zst"));
        assert!(matches(packages, b"/var/lib/qim/packages/.pkg.tar.zst"));
        assert!(!matches(packages, b"/var/lib/qim/packages/sub/x.pkg.tar.zst"));
        assert!(!matches(packages, b"/var/lib/qim/packages/x.pkg.tar.zst.sig"));
        assert!(!matches("/a*", b"/ab/c"));
        assert!(matches("/home/*/.cache/**", b"/home/qim/.cache/paru/x"));
        assert!(!matches("/home/*/.cache/**", b"/home/a/b/.cache/x"));
    }

    #[test]
    fn a_double_star_component_matches_zero_or_more_components() {
        assert!(matches("/home/**", b"/home/qim/a/b"));
        assert!(matches("/home/**", b"/home/qim"));
        assert!(matches("/home/**", b"/home"));
        assert!(!matches("/home/**", b"/homework"));
        assert!(matches("/a/**/b", b"/a/b"));
        assert!(matches("/a/**/b", b"/a/x/y/b"));
        assert!(!matches("/a/**/b", b"/a/x/c"));
        assert!(matches("/**", b"/etc/ld.so.cache"));
    }

    #[test]
    fn a_double_star_within_a_component_is_two_stars() {
        assert!(matches("/a/x**", b"/a/xyz"));
        assert!(!matches("/a/x**", b"/a/x/y"));
    }

    #[test]
    fn other_characters_match_themselves_and_the_whole_path_must_match() {
        assert!(matches("/etc/ld.so.cache", b"/etc/ld.so.cache"));
        assert!(!matches("/etc/ld.so.cache", b"/etc/ldxsoxcache"));
        assert!(matches("/a?[b]", b"/a?[b]"));
        assert!(!matches("/a?", b"/ab"));
        assert!(!matches("/etc/ld.so.cache", b"/etc/ld.so.cache2"));
        assert!(!matches("/etc", b"/etc/ld.so.cache"));
        assert!(!matches("/etc/ld.so.cache", b"/x/etc/ld.so.cache"));
    }

    fn selected(items: &[Item], base: &[Entry], include: &[&str], exclude: &[&str]) -> Vec<String> {
        let changes = changes(tar(items).as_slice(), base).unwrap();
        let artifacts = artifacts(&changes, include, exclude);
        artifacts.iter().map(|artifact| path_text(&artifact.member.entry.path)).collect()
    }

    #[test]
    fn an_artifact_is_an_added_or_modified_file_matching_an_include_and_no_exclude() {
        let base = [base("/keep/m", content(3, ABC), 0o644), base("/keep/meta", content(3, ABC), 0o644)];
        let items = [
            file("upper/keep/a", 0o644, b"abc"),
            file("upper/keep/skip/b", 0o644, b"abc"),
            file("upper/other/c", 0o644, b"abc"),
            file("upper/other/d", 0o644, b"abc"),
            file("upper/keep/m", 0o644, b"xyz"),
            file("upper/keep/meta", 0o600, b"abc"),
            dir("upper/keep/dir/"),
            symlink("upper/keep/link", "a"),
            whiteout("upper/keep/gone"),
            dir("upper/keep/opaque/").xattr("trusted.overlay.opaque", b"y"),
        ];
        let include = ["/keep/**", "/other/c"];
        assert_eq!(selected(&items, &base, &include, &["/keep/skip/**"]), ["/keep/a", "/keep/m", "/other/c"]);
        // An exclude wins over an include, whatever their order.
        assert_eq!(selected(&items, &base, &include, &["/keep/**"]), ["/other/c"]);
        assert_eq!(selected(&items, &base, &[], &[]), Vec::<String>::new());
    }

    fn selected_by(profile: &str, paths: &[&str]) -> Vec<String> {
        let items: Vec<Item> = paths.iter().map(|path| file(&format!("upper{path}"), 0o644, b"abc")).collect();
        let profile = profiles::get(profile).unwrap();
        selected(&items, &[], profile.include, profile.exclude)
    }

    #[test]
    fn the_aur_profile_selects_the_packages_in_pkgdest() {
        let paths = [
            "/var/lib/qim/packages/tty-clock-2.3-2-x86_64.pkg.tar.zst",
            "/var/lib/qim/packages/tty-clock-debug-2.3-2-x86_64.pkg.tar.zst",
            "/var/lib/qim/packages/tty-clock-2.3.tar.gz",
            "/home/qim/.cache/paru/clone/tty-clock/tty-clock-2.3-2-x86_64.pkg.tar.zst",
            "/usr/bin/tty-clock",
        ];
        assert_eq!(selected_by("aur", &paths), [
            "/var/lib/qim/packages/tty-clock-2.3-2-x86_64.pkg.tar.zst",
            "/var/lib/qim/packages/tty-clock-debug-2.3-2-x86_64.pkg.tar.zst",
        ]);
    }

    #[test]
    fn the_default_profile_selects_everything_but_caches_logs_and_temporary_files() {
        let excluded = [
            "/tmp/x",
            "/var/tmp/x",
            "/run/x",
            "/var/cache/ldconfig/aux-cache",
            "/var/log/pacman.log",
            "/root/.cache/x",
            "/home/qim/.cache/paru/x",
            "/var/lib/pacman/sync/core.db",
            "/etc/ld.so.cache",
        ];
        let included = ["/etc/pacman.conf", "/home/qim/.config/x", "/usr/bin/tty-clock", "/var/lib/pacman/local/x/desc"];
        assert_eq!(selected_by("default", &[&excluded[..], &included[..]].concat()), included);
    }

    // --- Writing -------------------------------------------------------------------

    /// An output directory holding upper.tar, and a manifest listing `base`.
    fn output(items: &[Item], manifest: &str) -> (TempDir, PathBuf, PathBuf) {
        let directory = TempDir::new(&std::env::temp_dir()).unwrap();
        let output = directory.path().join("out");
        fs::create_dir(&output).unwrap();
        fs::write(output.join("upper.tar"), tar(items)).unwrap();
        let manifest_path = directory.path().join("manifest.json");
        fs::write(&manifest_path, manifest).unwrap();
        (directory, output, manifest_path)
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().mode() & 0o7777
    }

    #[test]
    fn artifacts_are_regular_files_with_safe_modes_and_no_owner_or_xattrs() {
        let items = [
            dir("upper/"),
            file("upper/bin/suid", 0o4755, b"abc").owner(1000, 1000),
            file("upper/bin/sgid", 0o2775, b"abc"),
            file("upper/opt/sticky", 0o1777, b"abc"),
            file("upper/writable", 0o666, b"hello\n"),
            file("upper/private", 0o400, b""),
            file("upper/bin/capable", 0o755, b"abc").xattr("security.capability", b"\x01\x00\x00\x02"),
            Item { mode: 0o6755, ..hard_link("upper/bin/linked", "upper/bin/suid") },
            symlink("upper/bin/link", "/etc/passwd"),
            item(b"upper/fifo", EntryType::Fifo, 0o644),
            Item { mode: 0o777, ..dir("upper/open/") },
            file("upper/open/f", 0o644, b"abc"),
            file("upper/tmp/excluded", 0o644, b"abc"),
        ];
        let (_directory, output, manifest) = output(&items, "[]\n");
        write(&output, &manifest, profiles::get("default").unwrap()).unwrap();
        let artifacts = output.join("artifacts");
        let expected = [
            ("bin/suid", 0o755, &b"abc"[..]),
            ("bin/sgid", 0o755, b"abc"),
            ("opt/sticky", 0o755, b"abc"),
            ("writable", 0o644, b"hello\n"),
            ("private", 0o400, b""),
            ("bin/capable", 0o755, b"abc"),
            ("bin/linked", 0o755, b"abc"),
            ("open/f", 0o644, b"abc"),
        ];
        // SAFETY: getuid and getgid have no preconditions.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        for (path, file_mode, data) in expected {
            let path = artifacts.join(path);
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert!(metadata.file_type().is_file(), "{}", path.display());
            assert_eq!(metadata.mode() & 0o7777, file_mode, "{}", path.display());
            assert_eq!((metadata.uid(), metadata.gid()), (uid, gid), "{}", path.display());
            assert_eq!(fs::read(&path).unwrap(), data, "{}", path.display());
        }
        let capable = CString::new(artifacts.join("bin/capable").into_os_string().into_vec()).unwrap();
        // SAFETY: a NUL-terminated path, and no buffer with size 0.
        assert_eq!(unsafe { libc::listxattr(capable.as_ptr(), std::ptr::null_mut(), 0) }, 0);
        for directory in ["", "bin", "opt", "open"] {
            assert_eq!(mode(&artifacts.join(directory)), 0o755, "{directory}");
        }
        let mut names: Vec<_> = fs::read_dir(&artifacts).unwrap().map(|item| item.unwrap().file_name()).collect();
        names.sort();
        assert_eq!(names, ["bin", "open", "opt", "private", "writable"]);
        let mut bin: Vec<_> = fs::read_dir(artifacts.join("bin")).unwrap().map(|item| item.unwrap().file_name()).collect();
        bin.sort();
        assert_eq!(bin, ["capable", "linked", "sgid", "suid"]);
        assert_eq!(
            fs::read_to_string(output.join("artifacts.json")).unwrap(),
            format!(
                "[\n{}\n]\n",
                [
                    ("/bin/capable", 3, ABC),
                    ("/bin/linked", 3, ABC),
                    ("/bin/sgid", 3, ABC),
                    ("/bin/suid", 3, ABC),
                    ("/open/f", 3, ABC),
                    ("/opt/sticky", 3, ABC),
                    ("/private", 0, EMPTY),
                    ("/writable", 6, HELLO),
                ]
                .map(|(path, size, sha256)| format!(
                    "  {{\n    \"path\": \"{path}\",\n    \"sha256\": \"{sha256}\",\n    \"size\": {size}\n  }}"
                ))
                .join(",\n")
            )
        );
    }

    #[test]
    fn without_artifacts_the_list_is_empty_and_no_directory_is_made() {
        let (_directory, output, manifest) = output(&[symlink("upper/l", "x")], "[]\n");
        write(&output, &manifest, profiles::get("aur").unwrap()).unwrap();
        assert_eq!(fs::read_to_string(output.join("artifacts.json")).unwrap(), "[]\n");
        assert!(!output.join("artifacts").exists());
        assert!(fs::read_to_string(output.join("diff.json")).unwrap().contains("\"path\": \"/l\""));
    }

    #[test]
    fn the_manifest_is_the_base() {
        let manifest = r#"[
 {
  "gid": 0,
  "mode": "0644",
  "path": "/etc/ld.so.cache",
  "sha256": "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
  "size": 6,
  "type": "file",
  "uid": 0
 }
]
"#;
        let (_directory, output, manifest) = output(&[file("upper/etc/ld.so.cache", 0o644, b"hello\n")], manifest);
        write(&output, &manifest, profiles::get("default").unwrap()).unwrap();
        assert_eq!(fs::read_to_string(output.join("diff.json")).unwrap(), "{\n  \"changes\": [],\n  \"schema_version\": 1\n}\n");
    }

    /// An output directory whose artifacts tree holds `plant` before the write.
    fn refused(items: &[Item], plant: impl FnOnce(&Path, &Path)) -> (TempDir, PathBuf) {
        let (directory, output, manifest) = output(items, "[]\n");
        let outside = directory.path().join("outside");
        fs::create_dir(&outside).unwrap();
        plant(&output, &outside);
        assert!(write(&output, &manifest, profiles::get("default").unwrap()).is_err());
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
        (directory, output)
    }

    #[test]
    fn an_existing_symlink_in_the_output_tree_is_not_followed() {
        refused(&[file("upper/etc/x", 0o644, b"abc")], |output, outside| {
            fs::create_dir(output.join("artifacts")).unwrap();
            std::os::unix::fs::symlink(outside, output.join("artifacts/etc")).unwrap();
        });
        refused(&[file("upper/x", 0o644, b"abc")], |output, outside| {
            std::os::unix::fs::symlink(outside, output.join("artifacts")).unwrap();
        });
        let (_directory, output) = refused(&[file("upper/x", 0o644, b"abc")], |output, outside| {
            fs::create_dir(output.join("artifacts")).unwrap();
            std::os::unix::fs::symlink(outside.join("target"), output.join("artifacts/x")).unwrap();
        });
        assert!(fs::symlink_metadata(output.join("artifacts/x")).unwrap().file_type().is_symlink());
    }

    #[test]
    fn nothing_is_written_for_malformed_input() {
        let (_directory, output, manifest) = output(&[file("upper/a", 0o644, b"abc"), file("upper/../b", 0o644, b"abc")], "[]\n");
        assert!(write(&output, &manifest, profiles::get("default").unwrap()).is_err());
        let mut names: Vec<_> = fs::read_dir(&output).unwrap().map(|item| item.unwrap().file_name()).collect();
        names.sort();
        assert_eq!(names, ["upper.tar"]);
    }
}
