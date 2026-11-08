//! Run a command in a crosvm guest built from a base image.
//!
//! The guest boots the base image read-only and writes every change into an
//! overlay whose upper layer lives on a per-run disk. When the command ends, the
//! guest writes a tar with the run's metadata and the upper layer to the output
//! disk, which is read back here without trusting its content.

use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::{CString, OsString};
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use tar::{EntryType, Header};

use crate::image::{self, at};
use crate::{audit, network, profiles};

/// The run's init, which /usr/lib/qim/boot starts from the input disk.
const INIT: &[u8] = include_bytes!("../guest/init");
/// The audit reader's file name; it is installed next to the qim executable.
const READER: &str = "qim-audit-reader";

// The overlay's upper layer and the output disk are sparse; these are limits, not allocations.
const UPPER_DISK_SIZE: u64 = 64 << 30;
const OUTPUT_DISK_SIZE: u64 = UPPER_DISK_SIZE + (8 << 30);
const META_FILES: &[&str] = &["meta/exit_code", "meta/command.log", "meta/audit_status", "meta/audit_reader_exit"];

/// shlex.quote: a word that the guest's shell reads back as `value`.
fn shell_quote(value: &str) -> String {
    let safe = |character: char| character.is_ascii_alphanumeric() || "_@%+=:,./-".contains(character);
    if value.is_empty() {
        "''".to_string()
    } else if value.chars().all(safe) {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }
}

/// The input disk: the guest's init and audit reader, the run's configuration
/// and its NUL-separated argv.
pub fn input_tar(argv: &[OsString], user: Option<&str>, timeout: u64, reader: &[u8]) -> Vec<u8> {
    let timeout = timeout.to_string();
    let config: String = [
        ("QIM_USER", user.unwrap_or("")),
        ("QIM_ADDRESS", network::GUEST_ADDRESS),
        ("QIM_GATEWAY", network::GATEWAY),
        ("QIM_TIMEOUT", timeout.as_str()),
    ]
    .iter()
    .map(|(key, value)| format!("{key}={}\n", shell_quote(value)))
    .collect();
    let argv: Vec<u8> = argv.iter().flat_map(|argument| argument.as_bytes().iter().copied().chain([0])).collect();
    let mut archive = TarWriter::new(Vec::new());
    for (name, data, mode) in [
        ("init", INIT, 0o755),
        ("audit-reader", reader, 0o755),
        ("config", config.as_bytes(), 0o644),
        ("argv", argv.as_slice(), 0o644),
    ] {
        let mut header = ustar_header(EntryType::Regular, mode, data.len() as u64);
        header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
        archive.append(header, &[], data).expect("writing to memory");
    }
    archive.finish().expect("writing to memory")
}

/// Split the guest's output tar into meta files and upper.tar.
///
/// The guest controls this stream, so nothing is extracted onto the host
/// filesystem except the known meta files, as regular files.
pub fn read_output(raw: &Path, output_dir: &Path) -> Result<(), String> {
    let meta_dir = output_dir.join("meta");
    fs::create_dir(&meta_dir).map_err(at(&meta_dir))?;
    let upper_path = output_dir.join("upper.tar");
    let upper_file = File::create(&upper_path).map_err(at(&upper_path))?;
    let mut upper = TarWriter::new(BufWriter::with_capacity(1 << 20, upper_file));
    let source = File::open(raw).map_err(at(raw))?;
    let mut source = tar::Archive::new(BufReader::with_capacity(1 << 20, source));
    let failed = |error: io::Error| format!("cannot read the guest output: {error}");
    for entry in source.entries().map_err(failed)? {
        image::check_signal()?;
        let mut entry = entry.map_err(failed)?;
        let name = entry.path_bytes().into_owned();
        let meta = META_FILES.iter().find(|meta| meta.as_bytes() == name.as_slice());
        if let Some(meta) = meta
            && is_regular(entry.header().entry_type())
        {
            let target = meta_dir.join(&meta["meta/".len()..]);
            let mut file = File::create(&target).map_err(at(&target))?;
            io::copy(&mut entry, &mut file).map_err(failed)?;
        } else if name == b"upper" || name.starts_with(b"upper/") {
            copy_member(&mut upper, &mut entry).map_err(failed)?;
        }
    }
    upper.finish().map_err(at(&upper_path))?;
    Ok(())
}

/// tarfile's REGULAR_TYPES: the members whose data is file content.
fn is_regular(kind: EntryType) -> bool {
    matches!(kind, EntryType::Regular | EntryType::Continuous | EntryType::GNUSparse)
}

/// Copy a member of the guest's upper layer into upper.tar, keeping what
/// tarfile keeps: the name, metadata, link target, device numbers, the pax
/// records (which carry the xattrs) and, for regular files, the content.
fn copy_member<R: Read, W: Write>(upper: &mut TarWriter<W>, entry: &mut tar::Entry<R>) -> io::Result<()> {
    let source = entry.header().clone();
    let regular = is_regular(source.entry_type());
    // The content of a sparse member is read back expanded.
    let kind = if source.entry_type().is_gnu_sparse() { EntryType::Regular } else { source.entry_type() };
    let mut name = entry.path_bytes().into_owned();
    if kind.is_dir() && !name.ends_with(b"/") {
        name.push(b'/');
    }
    let link_name = entry.link_name_bytes().map(Cow::into_owned);
    let mut records: PaxRecords = match entry.pax_extensions()? {
        Some(extensions) => extensions
            .map(|record| record.map(|record| (record.key_bytes().to_vec(), record.value_bytes().to_vec())))
            .collect::<io::Result<_>>()?,
        None => Vec::new(),
    };
    // Only regular members have data, whatever the guest claims in the size field.
    let size = if regular { entry.size() } else { 0 };
    let mut header = ustar_header(kind, source.mode()? & 0o7777, size);
    header.set_uid(source.uid()?);
    header.set_gid(source.gid()?);
    header.set_mtime(source.mtime()?);
    set_field(&mut header.as_old_mut().name, &name, b"path", &mut records);
    if let Some(link_name) = &link_name {
        set_field(&mut header.as_old_mut().linkname, link_name, b"linkpath", &mut records);
    }
    let ustar = header.as_ustar_mut().expect("a ustar header");
    set_field(&mut ustar.uname, source.username_bytes().unwrap_or_default(), b"uname", &mut records);
    set_field(&mut ustar.gname, source.groupname_bytes().unwrap_or_default(), b"gname", &mut records);
    if matches!(kind, EntryType::Char | EntryType::Block) {
        header.set_device_major(source.device_major()?.unwrap_or(0))?;
        header.set_device_minor(source.device_minor()?.unwrap_or(0))?;
    }
    upper.append(header, &records, entry)
}

// --- Writing tar streams as Python's tarfile writes them (PAX_FORMAT) ---------------

const BLOCK_SIZE: u64 = 512;
/// tarfile pads an archive to a whole number of records.
const RECORD_SIZE: u64 = 20 * BLOCK_SIZE;
const PAX_HEADER_NAME: &[u8] = b"././@PaxHeader";

type PaxRecords = Vec<(Vec<u8>, Vec<u8>)>;

/// A ustar header with every numeric field written, as tarfile writes them.
fn ustar_header(kind: EntryType, mode: u32, size: u64) -> Header {
    let mut header = Header::new_ustar();
    header.set_entry_type(kind);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(size);
    header
}

/// Put `value` into a fixed-size header field, and into a pax record under
/// `key` when it does not fit or is not ASCII, as tarfile does.
fn set_field(field: &mut [u8], value: &[u8], key: &[u8], records: &mut PaxRecords) {
    let length = value.len().min(field.len());
    field[..length].copy_from_slice(&value[..length]);
    let representable = value.len() <= field.len() && value.is_ascii();
    if !representable && !records.iter().any(|(existing, _)| existing == key) {
        records.push((key.to_vec(), value.to_vec()));
    }
}

/// The payload of a pax extended header. Like tarfile, it declares values
/// that are not UTF-8 with hdrcharset=BINARY.
fn pax_payload(records: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let binary = records.iter().any(|(_, value)| std::str::from_utf8(value).is_err())
        && !records.iter().any(|(key, _)| key == b"hdrcharset");
    let declaration = binary.then(|| (b"hdrcharset".to_vec(), b"BINARY".to_vec()));
    let mut payload = Vec::new();
    for (key, value) in declaration.iter().chain(records) {
        // "<length> <key>=<value>\n", where the length counts its own digits.
        let rest = key.len() + value.len() + 3;
        let mut length = rest;
        while rest + length.to_string().len() != length {
            length = rest + length.to_string().len();
        }
        payload.extend_from_slice(format!("{length} ").as_bytes());
        payload.extend_from_slice(key);
        payload.push(b'=');
        payload.extend_from_slice(value);
        payload.push(b'\n');
    }
    payload
}

struct TarWriter<W: Write> {
    out: W,
    offset: u64,
}

impl<W: Write> TarWriter<W> {
    fn new(out: W) -> Self {
        TarWriter { out, offset: 0 }
    }

    /// Append a member, preceded by a pax header when there are records.
    /// `data` must hold at least the size given in the header.
    fn append(&mut self, header: Header, records: &[(Vec<u8>, Vec<u8>)], data: impl Read) -> io::Result<()> {
        if !records.is_empty() {
            let payload = pax_payload(records);
            let mut pax = ustar_header(EntryType::XHeader, 0, payload.len() as u64);
            pax.as_old_mut().name[..PAX_HEADER_NAME.len()].copy_from_slice(PAX_HEADER_NAME);
            self.entry(pax, payload.as_slice())?;
        }
        self.entry(header, data)
    }

    fn entry(&mut self, mut header: Header, data: impl Read) -> io::Result<()> {
        header.set_cksum();
        let size = header.entry_size()?;
        self.write(header.as_bytes())?;
        let copied = io::copy(&mut data.take(size), &mut self.out)?;
        self.offset += copied;
        if copied < size {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected end of data"));
        }
        self.pad(BLOCK_SIZE)
    }

    fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.out.write_all(bytes)?;
        self.offset += bytes.len() as u64;
        Ok(())
    }

    fn pad(&mut self, unit: u64) -> io::Result<()> {
        let padding = self.offset.next_multiple_of(unit) - self.offset;
        self.write(&vec![0; padding as usize])
    }

    /// End the archive as tarfile does: two zero blocks, then zeros up to a whole record.
    fn finish(mut self) -> io::Result<W> {
        self.write(&[0; 2 * BLOCK_SIZE as usize])?;
        self.pad(RECORD_SIZE)?;
        self.out.flush()?;
        Ok(self.out)
    }
}

// --- Running ---------------------------------------------------------------------

/// A directory with a unique name, removed with its content when dropped.
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new(parent: &Path) -> Result<TempDir, String> {
        let template = CString::new(parent.join("tmpXXXXXX").into_os_string().into_vec())
            .map_err(|_| format!("{}: contains a NUL byte", parent.display()))?;
        let mut template = template.into_bytes_with_nul();
        // SAFETY: the template is a writable NUL-terminated buffer.
        if unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) }.is_null() {
            return Err(format!("cannot create a directory in {}: {}", parent.display(), io::Error::last_os_error()));
        }
        template.pop();
        Ok(TempDir(PathBuf::from(OsString::from_vec(template))))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn sparse_file(path: &Path, size: u64) -> Result<(), String> {
    File::create(path).and_then(|file| file.set_len(size)).map_err(at(path))
}

/// The audit reader binary, installed next to the running qim executable.
fn reader_path() -> Result<PathBuf, String> {
    let executable = std::env::current_exe().map_err(|error| format!("cannot locate the qim executable: {error}"))?;
    Ok(executable.with_file_name(READER))
}

fn crosvm_args(base: &Path, work: &Path, output_dir: &Path, memory_mib: u64, cpus: u32) -> Vec<OsString> {
    let option = |prefix: &str, path: PathBuf, suffix: &str| {
        let mut option = OsString::from(prefix);
        option.push(path);
        option.push(suffix);
        option
    };
    vec![
        "run".into(),
        "--disable-sandbox".into(),
        "--mem".into(),
        memory_mib.to_string().into(),
        "--cpus".into(),
        cpus.to_string().into(),
        "--block".into(),
        option("path=", base.join("root.img"), ",ro,root"),
        "--block".into(),
        option("path=", work.join("upper.img"), ""),
        "--block".into(),
        option("path=", work.join("input.tar"), ",ro"),
        "--block".into(),
        option("path=", work.join("output.raw"), ""),
        "--net".into(),
        format!("tap-name={}", network::TAP).into(),
        "--serial".into(),
        option("type=file,path=", output_dir.join("console.log"), ",hardware=serial,console"),
        // The guest streams audit records to this file while the command runs (/dev/hvc0).
        "--serial".into(),
        option("type=file,path=", output_dir.join("audit.log"), ",hardware=virtio-console,num=1"),
        "-p".into(),
        "init=/usr/lib/qim/boot quiet audit=1".into(),
        base.join("vmlinuz").into(),
    ]
}

pub fn run(
    image_name: &str,
    argv: &[OsString],
    output_dir: &Path,
    timeout: u64,
    memory_mib: u64,
    cpus: u32,
) -> Result<u8, String> {
    let base = image::images_dir()?.join(image_name);
    let info_path = base.join("image.json");
    let info = fs::read(&info_path).map_err(at(&info_path))?;
    let info: serde_json::Value =
        serde_json::from_slice(&info).map_err(|error| format!("{}: {error}", info_path.display()))?;
    let profile_name = info["profile"].as_str().ok_or_else(|| format!("{}: no profile", info_path.display()))?;
    let profile = profiles::get(profile_name)?;
    let reader_path = reader_path()?;
    let reader = fs::read(&reader_path).map_err(at(&reader_path))?;
    // Like mkdir(parents=True): the output directory itself must not exist.
    if let Some(parent) = output_dir.parent() {
        fs::create_dir_all(parent).map_err(at(parent))?;
    }
    fs::create_dir(output_dir).map_err(at(output_dir))?;
    {
        let work_dir = TempDir::new(&image::home()?)?;
        let work = work_dir.path();
        let input = work.join("input.tar");
        fs::write(&input, input_tar(argv, profile.user, timeout, &reader)).map_err(at(&input))?;
        sparse_file(&work.join("upper.img"), UPPER_DISK_SIZE)?;
        image::run(Command::new("mkfs.ext4").args(["-q", "-L", "qim-upper"]).arg(work.join("upper.img")))?;
        sparse_file(&work.join("output.raw"), OUTPUT_DISK_SIZE)?;
        let mut command = Command::new("crosvm");
        command.args(crosvm_args(&base, work, output_dir, memory_mib, cpus));
        {
            let network = network::guest_network(output_dir)?;
            let log_path = output_dir.join("crosvm.log");
            let log = File::create(&log_path).map_err(at(&log_path))?;
            let log_for_stderr = log.try_clone().map_err(at(&log_path))?;
            let mut child = image::spawn(command.stdout(log).stderr(log_for_stderr))?;
            image::wait(&command, &mut child, Some(Duration::from_secs(timeout + 300)))?;
            for problem in network.finish() {
                eprintln!("qim: warning: the network record may be incomplete: {problem}");
            }
        }
        read_output(&work.join("output.raw"), output_dir)?;
    }
    write_events(output_dir);
    let exit_code_path = output_dir.join("meta/exit_code");
    let exit_code = match fs::read(&exit_code_path) {
        Ok(exit_code) => exit_code,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let console = output_dir.join("console.log");
            return Err(format!("the guest did not report a result; see {}", console.display()));
        }
        Err(error) => return Err(at(&exit_code_path)(error)),
    };
    for problem in recording_problems(&output_dir.join("meta")) {
        eprintln!("qim: warning: the audit record may be incomplete: {problem}");
    }
    let exit_code = String::from_utf8_lossy(&exit_code);
    let code: i32 = exit_code
        .trim()
        .parse()
        .map_err(|_| format!("{}: not an exit status: {exit_code:?}", exit_code_path.display()))?;
    // As a process exit status, only the low 8 bits count.
    Ok(code as u8)
}

/// A host-side network record of the run; None if it is missing.
fn network_record(path: &Path) -> Result<Option<BufReader<File>>, String> {
    match File::open(path) {
        Ok(file) => Ok(Some(BufReader::with_capacity(1 << 20, file))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(at(path)(error)),
    }
}

/// Derive events.json from audit.log, dns.log and packets.log; logs that
/// cannot be converted only warn.
fn write_events(output_dir: &Path) {
    let log = output_dir.join("audit.log");
    if !log.exists() {
        return;
    }
    let events = output_dir.join("events.json");
    let result = File::open(&log)
        .map_err(at(&log))
        .and_then(|file| {
            let dns = network_record(&output_dir.join("dns.log"))?;
            let packets = network_record(&output_dir.join("packets.log"))?;
            audit::convert(BufReader::with_capacity(1 << 20, file), dns, packets)
        })
        .and_then(|doc| fs::write(&events, audit::dump(&doc)).map_err(at(&events)));
    if let Err(error) = result {
        eprintln!("qim: warning: cannot write events.json: {error}");
    }
}

/// Reasons to doubt that audit.log holds every record.
///
/// The kernel's lost counter alone is not enough: records produced while no
/// reader is registered go to the kernel log instead, without being counted.
pub fn recording_problems(meta_dir: &Path) -> Vec<String> {
    let read = |name: &str| {
        let path = meta_dir.join(name);
        fs::read(&path).map(|bytes| String::from_utf8_lossy(&bytes).into_owned()).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                format!("{} is missing", path.display())
            } else {
                format!("{}: {error}", path.display())
            }
        })
    };
    let (status, reader_exit) = match (read("audit_status"), read("audit_reader_exit")) {
        (Ok(status), Ok(reader_exit)) => (status, reader_exit),
        (Err(problem), _) | (_, Err(problem)) => return vec![problem],
    };
    let status: HashMap<&str, &str> = status
        .lines()
        .filter(|line| line.contains(' '))
        .filter_map(|line| line.trim_start().split_once(char::is_whitespace))
        .map(|(key, value)| (key, value.trim()))
        .collect();
    let mut problems = Vec::new();
    let lost = status.get("lost").copied();
    if lost != Some("0") {
        problems.push(format!("the kernel lost {} records", lost.unwrap_or("?")));
    }
    if status.get("pid").copied().unwrap_or("0") == "0" {
        problems.push("the reader was no longer registered when the command ended".to_string());
    }
    let reader_exit = reader_exit.trim();
    if reader_exit != "0" {
        problems.push(format!("the reader exited with status {reader_exit}"));
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct Member {
        kind: EntryType,
        mode: u32,
        data: Vec<u8>,
        records: PaxRecords,
        link_name: Option<Vec<u8>>,
        device: Option<(u32, u32)>,
    }

    /// The members of a tar, by name as tarfile reports it (directories without the trailing slash).
    fn members(data: &[u8]) -> BTreeMap<String, Member> {
        let mut archive = tar::Archive::new(data);
        let mut members = BTreeMap::new();
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let name = String::from_utf8(entry.path_bytes().into_owned()).unwrap();
            let header = entry.header().clone();
            let records = match entry.pax_extensions().unwrap() {
                Some(records) => records
                    .map(|record| record.map(|record| (record.key_bytes().to_vec(), record.value_bytes().to_vec())))
                    .collect::<io::Result<_>>()
                    .unwrap(),
                None => Vec::new(),
            };
            let link_name = entry.link_name_bytes().map(Cow::into_owned);
            let mut content = Vec::new();
            entry.read_to_end(&mut content).unwrap();
            let device = match header.entry_type() {
                EntryType::Char | EntryType::Block => {
                    Some((header.device_major().unwrap().unwrap(), header.device_minor().unwrap().unwrap()))
                }
                _ => None,
            };
            let member = Member { kind: header.entry_type(), mode: header.mode().unwrap(), data: content, records, link_name, device };
            members.insert(name.trim_end_matches('/').to_string(), member);
        }
        members
    }

    /// A tar of (name, type, data, link name, pax records).
    fn tar_bytes(entries: &[(&str, EntryType, &[u8], &str, PaxRecords)]) -> Vec<u8> {
        let mut archive = TarWriter::new(Vec::new());
        for (name, kind, data, link_name, records) in entries {
            let mut records = records.clone();
            let mut header = ustar_header(*kind, 0o644, data.len() as u64);
            set_field(&mut header.as_old_mut().name, name.as_bytes(), b"path", &mut records);
            set_field(&mut header.as_old_mut().linkname, link_name.as_bytes(), b"linkpath", &mut records);
            if *kind == EntryType::Char {
                header.set_device_major(0).unwrap();
                header.set_device_minor(0).unwrap();
            }
            archive.append(header, &records, *data).unwrap();
        }
        archive.finish().unwrap()
    }

    fn file<'a>(name: &'a str, data: &'static [u8]) -> (&'a str, EntryType, &'static [u8], &'static str, PaxRecords) {
        (name, EntryType::Regular, data, "", Vec::new())
    }

    fn special<'a>(name: &'a str, kind: EntryType, link_name: &'static str) -> (&'a str, EntryType, &'static [u8], &'static str, PaxRecords) {
        (name, kind, b"", link_name, Vec::new())
    }

    #[test]
    fn input_tar_contains_the_guest_programs_config_and_nul_separated_argv() {
        let argv = ["sh", "-c", "echo 'a b'"].map(OsString::from);
        let data = input_tar(&argv, Some("qim"), 60, b"reader binary");
        let members = members(&data);
        assert_eq!(members.keys().map(String::as_str).collect::<Vec<_>>(), ["argv", "audit-reader", "config", "init"]);
        assert_eq!(members["argv"].data, b"sh\0-c\0echo 'a b'\0");
        let config = String::from_utf8(members["config"].data.clone()).unwrap();
        assert!(config.contains("QIM_USER=qim\n"));
        assert!(config.contains("QIM_TIMEOUT=60\n"));
        assert_eq!(members["init"].mode, 0o755);
        assert_eq!(members["audit-reader"].mode, 0o755);
        assert_eq!(members["init"].data, INIT);
        assert_eq!(members["audit-reader"].data, b"reader binary");
        assert_eq!(data.len() as u64 % RECORD_SIZE, 0);
    }

    #[test]
    fn root_user_is_an_empty_value() {
        let data = input_tar(&[OsString::from("true")], None, 60, b"");
        assert!(String::from_utf8(members(&data)["config"].data.clone()).unwrap().contains("QIM_USER=''\n"));
    }

    #[test]
    fn config_values_are_quoted_as_shlex_quote_does() {
        assert_eq!(shell_quote("192.168.100.2/24"), "192.168.100.2/24");
        assert_eq!(shell_quote("x@%+=:,./-_"), "x@%+=:,./-_");
        assert_eq!(shell_quote("a b'c"), "'a b'\"'\"'c'");
    }

    fn read(entries: &[(&str, EntryType, &[u8], &str, PaxRecords)]) -> (TempDir, PathBuf) {
        let directory = TempDir::new(&std::env::temp_dir()).unwrap();
        let raw = directory.path().join("raw");
        let mut bytes = tar_bytes(entries);
        bytes.extend([0; 4096]);
        fs::write(&raw, bytes).unwrap();
        let output = directory.path().join("out");
        fs::create_dir(&output).unwrap();
        read_output(&raw, &output).unwrap();
        (directory, output)
    }

    #[test]
    fn known_meta_files_are_extracted_and_upper_is_kept_as_a_tar() {
        let (_directory, output) = read(&[
            special("meta/", EntryType::Directory, ""),
            file("meta/exit_code", b"3\n"),
            file("meta/command.log", b"hello\n"),
            special("upper/", EntryType::Directory, ""),
            file("upper/etc/new", b"x"),
            special("upper/etc/gone", EntryType::Char, ""),
        ]);
        assert_eq!(fs::read(output.join("meta/exit_code")).unwrap(), b"3\n");
        assert_eq!(fs::read(output.join("meta/command.log")).unwrap(), b"hello\n");
        let members = members(&fs::read(output.join("upper.tar")).unwrap());
        assert_eq!(members["upper/etc/new"].data, b"x");
        assert_eq!(members.keys().map(String::as_str).collect::<Vec<_>>(), ["upper", "upper/etc/gone", "upper/etc/new"]);
        assert_eq!(members["upper/etc/gone"].kind, EntryType::Char);
        assert_eq!(members["upper/etc/gone"].device, Some((0, 0)));
    }

    /// The names of every path below `root`, sorted, like rglob("*").
    fn tree(root: &Path) -> Vec<String> {
        let mut names = Vec::new();
        for item in fs::read_dir(root).unwrap() {
            let path = item.unwrap().path();
            names.push(path.file_name().unwrap().to_str().unwrap().to_string());
            if fs::symlink_metadata(&path).unwrap().is_dir() {
                names.extend(tree(&path));
            }
        }
        names.sort();
        names
    }

    #[test]
    fn nothing_else_reaches_the_host_filesystem() {
        let (_directory, output) = read(&[
            special("meta/exit_code", EntryType::Symlink, "/etc/passwd"),
            file("meta/other", b"x"),
            file("../escape", b"x"),
            file("/abs", b"x"),
            file("upperfoo/x", b"x"),
        ]);
        assert_eq!(tree(&output), ["meta", "upper.tar"]);
        assert!(members(&fs::read(output.join("upper.tar")).unwrap()).is_empty());
    }

    #[test]
    fn upper_members_keep_long_names_link_targets_and_xattrs() {
        let long_name = format!("upper/{}", "n".repeat(150));
        let xattr = (b"SCHILY.xattr.security.capability".to_vec(), b"\x01\x00\x00\x02\xff".to_vec());
        let (_directory, output) = read(&[
            (long_name.as_str(), EntryType::Regular, &b"content"[..], "", vec![xattr.clone()]),
            special("upper/link", EntryType::Symlink, "../target"),
        ]);
        let members = members(&fs::read(output.join("upper.tar")).unwrap());
        let long = &members[&long_name];
        assert_eq!(long.data, b"content");
        assert!(long.records.contains(&xattr));
        assert!(long.records.contains(&(b"hdrcharset".to_vec(), b"BINARY".to_vec())));
        assert_eq!(members["upper/link"].link_name.as_deref(), Some(&b"../target"[..]));
    }

    #[test]
    fn pax_record_lengths_count_their_own_digits() {
        // 97 bytes without the length fit a two-digit length: "99 ...".
        let record = (b"k".to_vec(), vec![b'v'; 93]);
        assert!(pax_payload(&[record]).starts_with(b"99 k=v"));
        let record = (b"k".to_vec(), vec![b'v'; 94]);
        assert!(pax_payload(&[record]).starts_with(b"101 k=v"));
    }

    const STATUS: &str = "enabled 1\nfailure 1\npid {pid}\nrate_limit 0\nbacklog_limit 0\nlost {lost}\nbacklog 0\n";

    fn problems(pid: &str, lost: &str, reader_exit: &str) -> Vec<String> {
        let directory = TempDir::new(&std::env::temp_dir()).unwrap();
        let meta = directory.path();
        fs::write(meta.join("audit_status"), STATUS.replace("{pid}", pid).replace("{lost}", lost)).unwrap();
        fs::write(meta.join("audit_reader_exit"), format!("{reader_exit}\n")).unwrap();
        recording_problems(meta)
    }

    #[test]
    fn complete_record() {
        assert_eq!(problems("117", "0", "0"), Vec::<String>::new());
    }

    #[test]
    fn each_reason_is_reported() {
        assert_eq!(problems("117", "3", "0"), ["the kernel lost 3 records"]);
        assert_eq!(problems("0", "0", "0"), ["the reader was no longer registered when the command ended"]);
        assert_eq!(problems("117", "0", "2"), ["the reader exited with status 2"]);
    }

    #[test]
    fn missing_status_is_a_problem() {
        let directory = TempDir::new(&std::env::temp_dir()).unwrap();
        assert_eq!(recording_problems(directory.path()).len(), 1);
    }

    #[test]
    fn an_unconvertible_audit_log_leaves_no_events_file() {
        let directory = TempDir::new(&std::env::temp_dir()).unwrap();
        fs::write(directory.path().join("audit.log"), "not an audit record\n").unwrap();
        write_events(directory.path());
        assert!(!directory.path().join("events.json").exists());
    }
}
