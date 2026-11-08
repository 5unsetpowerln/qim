//! Build a base guest image from a dated Arch Linux Archive snapshot.
//!
//! The packages come from https://archive.archlinux.org/repos/<date>/, so the
//! image content and the repository packages the guest installs later are both
//! fixed by the date. The image is built with pacman --root under bind mounts,
//! because pacstrap needs a devtmpfs mount that rootless containers refuse.
//!
//! This module also holds the helpers for running external commands, which
//! turn a caught SIGINT or SIGTERM into an error so that every mount, network
//! device and temporary directory is released on the way out.

use std::cmp::Ordering;
use std::ffi::CString;
use std::fmt::{self, Write as _};
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{self, AtomicI32};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::network;
use crate::profiles::{self, Profile};

/// Installed in the base image as /usr/lib/qim/boot.
pub const BOOT: &[u8] = include_bytes!("../guest/boot");

const ARCHIVE_SERVER: &str = "https://archive.archlinux.org/repos/{date}/$repo/os/$arch";
const REPOSITORIES: &[&str] = &["core", "extra"];

pub fn home() -> Result<PathBuf, String> {
    match std::env::var_os("QIM_HOME") {
        Some(home) if !home.is_empty() => Ok(PathBuf::from(home)),
        _ => std::env::home_dir()
            .map(|home| home.join(".cache/qim"))
            .ok_or_else(|| "cannot determine the home directory".to_string()),
    }
}

pub fn images_dir() -> Result<PathBuf, String> {
    Ok(home()?.join("images"))
}

/// A calendar date, which names an archive snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Date {
    year: u32,
    month: u32,
    day: u32,
}

impl Date {
    pub fn new(year: u32, month: u32, day: u32) -> Option<Date> {
        let valid = (1..=9999).contains(&year)
            && (1..=12).contains(&month)
            && (1..=days_in_month(year, month)).contains(&day);
        valid.then_some(Date { year, month, day })
    }

    /// Parse YYYY-MM-DD.
    pub fn parse(text: &str) -> Result<Date, String> {
        let number = |range: std::ops::Range<usize>| {
            text.get(range)
                .filter(|digits| digits.bytes().all(|byte| byte.is_ascii_digit()))
                .and_then(|digits| digits.parse().ok())
        };
        let bytes = text.as_bytes();
        let shaped = bytes.len() == 10 && bytes[4] == b'-' && bytes[7] == b'-';
        shaped
            .then(|| Date::new(number(0..4)?, number(5..7)?, number(8..10)?))
            .flatten()
            .ok_or_else(|| format!("invalid date: {text} (expected YYYY-MM-DD)"))
    }

    /// Today in UTC.
    pub fn today() -> Date {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("the clock is set after 1970");
        Date::from_days(now.as_secs() / 86_400)
    }

    /// The date `days` days after 1970-01-01 (the civil_from_days algorithm by Howard Hinnant).
    fn from_days(days: u64) -> Date {
        let shifted = days + 719_468;
        let era = shifted / 146_097;
        let day_of_era = shifted % 146_097;
        let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let month_from_march = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
        let month = if month_from_march < 10 { month_from_march + 3 } else { month_from_march - 9 };
        let year = era * 400 + year_of_era + u64::from(month <= 2);
        Date { year: year as u32, month: month as u32, day: day as u32 }
    }

    pub fn previous(self) -> Date {
        match self {
            Date { day: 2.., .. } => Date { day: self.day - 1, ..self },
            Date { month: 2.., .. } => Date { month: self.month - 1, day: days_in_month(self.year, self.month - 1), ..self },
            _ => Date { year: self.year - 1, month: 12, day: 31 },
        }
    }

    fn compact(self) -> String {
        format!("{:04}{:02}{:02}", self.year, self.month, self.day)
    }
}

/// ISO 8601 (YYYY-MM-DD).
impl fmt::Display for Date {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// The previous day (UTC): the archive for the current day may still be incomplete.
pub fn default_date(today: Date) -> Date {
    today.previous()
}

/// A pacman.conf for the snapshot of `date`.
///
/// It deliberately has no NoExtract lines: container images commonly exclude
/// etc/pacman.conf, the mirrorlist, man pages and locales, and those
/// exclusions must not leak into the guest. The archive is a single, slow
/// server that sometimes stalls, and there is no other server to fall back
/// to, so pacman's low-speed abort is disabled; the run's timeout bounds the
/// time instead.
pub fn pacman_conf(date: Date, cache_dir: Option<&str>) -> String {
    let server = ARCHIVE_SERVER.replace("{date}", &format!("{:04}/{:02}/{:02}", date.year, date.month, date.day));
    let mut lines: Vec<String> = [
        "[options]",
        "Architecture = auto",
        "SigLevel = Required DatabaseOptional",
        "LocalFileSigLevel = Optional",
        "ParallelDownloads = 5",
        "DisableDownloadTimeout",
    ]
    .map(String::from)
    .into();
    if let Some(cache_dir) = cache_dir {
        lines.push(format!("CacheDir = {cache_dir}"));
    }
    for repository in REPOSITORIES {
        lines.extend([String::new(), format!("[{repository}]"), format!("Server = {server}")]);
    }
    lines.join("\n") + "\n"
}

// --- External commands and signals -------------------------------------------

static CAUGHT_SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_signal(signal: libc::c_int) {
    CAUGHT_SIGNAL.store(signal, atomic::Ordering::SeqCst);
}

/// Turn SIGINT and SIGTERM into an error at the next command or check, so that
/// the code unwinding from it releases what it set up.
pub fn catch_signals() {
    for signal in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: the handler only stores to an atomic, which is async-signal-safe.
        unsafe { libc::signal(signal, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t) };
    }
}

pub fn caught_signal() -> Option<i32> {
    match CAUGHT_SIGNAL.load(atomic::Ordering::SeqCst) {
        0 => None,
        signal => Some(signal),
    }
}

pub(crate) fn check_signal() -> Result<(), String> {
    caught_signal().map_or(Ok(()), |signal| Err(format!("interrupted by signal {signal}")))
}

const POLL_INTERVAL: Duration = Duration::from_millis(10);
/// How long Python's subprocess lets a child that got the same SIGINT exit by itself.
const SIGNAL_GRACE: Duration = Duration::from_millis(250);

pub(crate) fn spawn(command: &mut Command) -> Result<Child, String> {
    check_signal()?;
    command.spawn().map_err(|error| format!("cannot run {command:?}: {error}"))
}

/// Wait for `child`, killing it when a signal is caught or `timeout` passes.
pub(crate) fn wait(command: &Command, child: &mut Child, timeout: Option<Duration>) -> Result<ExitStatus, String> {
    let deadline = timeout.map(|timeout| Instant::now() + timeout);
    let reap = |child: &mut Child| child.try_wait().map_err(|error| format!("{command:?}: {error}"));
    let failure = loop {
        if let Some(status) = reap(child)? {
            return Ok(status);
        }
        if let Some(signal) = caught_signal() {
            let grace_end = Instant::now() + SIGNAL_GRACE;
            while Instant::now() < grace_end && reap(child)?.is_none() {
                sleep(POLL_INTERVAL);
            }
            break format!("{command:?}: interrupted by signal {signal}");
        }
        if let (Some(deadline), Some(timeout)) = (deadline, timeout)
            && Instant::now() >= deadline
        {
            break format!("{command:?} timed out after {} seconds", timeout.as_secs());
        }
        sleep(POLL_INTERVAL);
    };
    let _ = child.kill();
    let _ = child.wait();
    Err(failure)
}

pub(crate) fn check(command: &Command, status: ExitStatus) -> Result<(), String> {
    if status.success() { Ok(()) } else { Err(format!("{command:?} failed: {status}")) }
}

/// Run a command to completion and require success.
pub(crate) fn run(command: &mut Command) -> Result<(), String> {
    let mut child = spawn(command)?;
    let status = wait(command, &mut child, None)?;
    check(command, status)
}

/// Run a command and return its standard output; its standard error is discarded.
fn output(command: &mut Command) -> Result<Vec<u8>, String> {
    let mut child = spawn(command.stdout(Stdio::piped()).stderr(Stdio::null()))?;
    let mut stdout = Vec::new();
    let read = child.stdout.take().expect("stdout is piped").read_to_end(&mut stdout);
    let status = wait(command, &mut child, None)?;
    read.map_err(|error| format!("{command:?}: {error}"))?;
    check(command, status)?;
    Ok(stdout)
}

pub(crate) fn at(path: &Path) -> impl FnOnce(io::Error) -> String + '_ {
    move |error| format!("{}: {error}", path.display())
}

fn write(path: &Path, contents: impl AsRef<[u8]>) -> Result<(), String> {
    fs::write(path, contents).map_err(at(path))
}

fn chmod(path: &Path, mode: u32) -> Result<(), String> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(at(path))
}

/// The entries of a directory; none if it does not exist, as with a glob.
fn list_dir(directory: &Path) -> Result<Vec<PathBuf>, String> {
    match fs::read_dir(directory) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        result => result
            .and_then(|items| items.map(|item| item.map(|item| item.path())).collect())
            .map_err(at(directory)),
    }
}

// --- Building ------------------------------------------------------------------

/// Mounts made for the build; dropping this unmounts them in reverse order.
struct Mounts {
    umount_options: &'static [&'static str],
    targets: Vec<PathBuf>,
}

impl Mounts {
    fn new(umount_options: &'static [&'static str]) -> Mounts {
        Mounts { umount_options, targets: Vec::new() }
    }

    fn mount(&mut self, options: &[&str], source: &str, target: PathBuf) -> Result<(), String> {
        run(Command::new("mount").args(options).arg(source).arg(&target))?;
        self.targets.push(target);
        Ok(())
    }
}

impl Drop for Mounts {
    fn drop(&mut self) {
        for target in self.targets.iter().rev() {
            let _ = Command::new("umount").args(self.umount_options).arg(target).status();
        }
    }
}

/// Provide /dev, /proc and /sys inside `root` for package scriptlets and chroot.
fn chroot_mounts(root: &Path) -> Result<Mounts, String> {
    let mut mounts = Mounts::new(&["-R", "-l"]);
    for (options, source, target) in [
        (&["--rbind"][..], "/dev", "dev"),
        (&["-t", "proc"], "proc", "proc"),
        (&["--rbind"], "/sys", "sys"),
    ] {
        let path = root.join(target);
        fs::create_dir_all(&path).map_err(at(&path))?;
        mounts.mount(options, source, path)?;
    }
    Ok(mounts)
}

/// A scratch /tmp and the host's resolver for the profile's setup script.
fn setup_mounts(root: &Path) -> Result<Mounts, String> {
    let mut mounts = Mounts::new(&[]);
    mounts.mount(&["-t", "tmpfs"], "tmp", root.join("tmp"))?;
    mounts.mount(&["--bind"], "/etc/resolv.conf", root.join("etc/resolv.conf"))?;
    Ok(mounts)
}

fn chroot(root: &Path) -> Command {
    let mut command = Command::new("chroot");
    command.arg(root);
    command
}

fn run_setup(root: &Path, profile: &Profile) -> Result<(), String> {
    let user = profile.user.unwrap_or("root");
    let home = profile.user.map_or_else(|| "/root".to_string(), |user| format!("/home/{user}"));
    let _mounts = setup_mounts(root)?;
    run(Command::new("chroot")
        .arg(format!("--userspec={user}:{user}"))
        .arg(root)
        .args(["env", "-i", &format!("HOME={home}"), &format!("USER={user}")])
        .args(["PATH=/usr/local/bin:/usr/bin", "LANG=C.UTF-8"])
        .args(["bash", "-c", &format!("cd ~ && {}", profile.setup)]))
}

fn configure(root: &Path, profile: &Profile) -> Result<(), String> {
    write(&root.join("etc/hostname"), "qim-guest\n")?;
    let boot = root.join("usr/lib/qim/boot");
    let boot_dir = boot.parent().expect("a path below root");
    fs::create_dir_all(boot_dir).map_err(at(boot_dir))?;
    write(&boot, BOOT)?;
    chmod(&boot, 0o755)?;
    // The gateway answers DNS (network::guest_network), so the guest never needs to change this file.
    let resolv = root.join("etc/resolv.conf");
    if fs::symlink_metadata(&resolv).is_ok() {
        fs::remove_file(&resolv).map_err(at(&resolv))?;
    }
    write(&resolv, format!("nameserver {}\n", network::GATEWAY))?;
    let Some(user) = profile.user else {
        return Ok(());
    };
    run(chroot(root).args(["useradd", "--create-home", user]))?;
    if !profile.sudo_commands.is_empty() {
        let sudoers = root.join("etc/sudoers.d/qim");
        write(&sudoers, format!("{user} ALL=(root) NOPASSWD: {}\n", profile.sudo_commands.join(", ")))?;
        chmod(&sudoers, 0o440)?;
    }
    Ok(())
}

/// Add the profile's files and directories. This comes after the setup script
/// so that they do not affect it: with the aur profile's PKGDEST, the package
/// built for paru would otherwise stay in the image.
fn add_profile_files(root: &Path, profile: &Profile) -> Result<(), String> {
    for (path, contents) in profile.files {
        let target = root.join(path.trim_start_matches('/'));
        let parent = target.parent().expect("a path below root");
        fs::create_dir_all(parent).map_err(at(parent))?;
        write(&target, contents)?;
    }
    let user = profile.user.unwrap_or("root");
    for directory in profile.user_dirs {
        run(chroot(root).args(["install", "-d", "-m", "0755", "-o", user, "-g", user, directory]))?;
    }
    Ok(())
}

/// root/usr/lib/modules/*/vmlinuz, sorted.
fn kernels(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut kernels: Vec<PathBuf> = list_dir(&root.join("usr/lib/modules"))?
        .into_iter()
        .map(|directory| directory.join("vmlinuz"))
        .filter(|kernel| fs::symlink_metadata(kernel).is_ok())
        .collect();
    kernels.sort_by(|a, b| python_order(a.as_os_str().as_bytes(), b.as_os_str().as_bytes()));
    Ok(kernels)
}

/// Copy the content only, as shutil.copyfile does.
fn copy_contents(source: &Path, target: &Path) -> Result<(), String> {
    let mut reader = File::open(source).map_err(at(source))?;
    let mut writer = File::create(target).map_err(at(target))?;
    io::copy(&mut reader, &mut writer).map_err(at(target))?;
    Ok(())
}

pub fn build(profile_name: &str, date: Date, name: Option<&str>) -> Result<PathBuf, String> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err("qim image build must run as root (it bind-mounts /dev, /proc and /sys)".to_string());
    }
    let profile = profiles::get(profile_name)?;
    let name = name.map_or_else(|| format!("{}-{}", profile.name, date.compact()), str::to_string);
    let base = images_dir()?.join(&name);
    if base.exists() {
        return Err(format!("image {name} already exists: {}", base.display()));
    }
    let root = base.join("root");
    let pacman_db = root.join("var/lib/pacman");
    fs::create_dir_all(&pacman_db).map_err(at(&pacman_db))?;
    let cache_dir = home()?.join("pkg");
    fs::create_dir_all(&cache_dir).map_err(at(&cache_dir))?;
    let cache_dir_text = cache_dir.to_str().ok_or_else(|| format!("{}: not valid UTF-8", cache_dir.display()))?;
    let build_conf = base.join("pacman.conf");
    write(&build_conf, pacman_conf(date, Some(cache_dir_text)))?;

    {
        let _mounts = chroot_mounts(&root)?;
        run(Command::new("pacman")
            .arg("--config")
            .arg(&build_conf)
            .arg("--root")
            .arg(&root)
            .args(["-Sy", "--noconfirm"])
            .args(profile.packages()))?;
        write(&root.join("etc/pacman.conf"), pacman_conf(date, None))?;
        run(chroot(&root).args(["pacman-key", "--init"]))?;
        run(chroot(&root).args(["pacman-key", "--populate", "archlinux"]))?;
        // pacman-key starts gpg-agent; stop it so that its sockets do not end up in the image.
        run(chroot(&root).args(["gpgconf", "--homedir", "/etc/pacman.d/gnupg", "--kill", "all"]))?;
        for leftover in list_dir(&root.join("etc/pacman.d/gnupg"))? {
            if leftover.file_name().is_some_and(|name| name.as_bytes().starts_with(b"S.")) {
                fs::remove_file(&leftover).map_err(at(&leftover))?;
            }
        }
        configure(&root, profile)?;
        if !profile.setup.is_empty() {
            run_setup(&root, profile)?;
        }
        add_profile_files(&root, profile)?;
    }

    let kernels = kernels(&root)?;
    let [kernel] = kernels.as_slice() else {
        return Err(format!("expected one kernel in the image, found {}", kernels.len()));
    };
    copy_contents(kernel, &base.join("vmlinuz"))?;

    let entries = manifest(&root)?;
    let manifest_json = json_file(&Json::List(entries.iter().map(Entry::to_json).collect()), 1);
    write(&base.join("manifest.json"), &manifest_json)?;
    let packages = output(Command::new("pacman").arg("--root").arg(&root).arg("-Q"))?;
    let packages = String::from_utf8(packages).map_err(|_| "pacman -Q printed invalid UTF-8".to_string())?;
    let content_bytes: u64 = entries
        .iter()
        .map(|entry| match entry.kind {
            Kind::File { size, .. } => size,
            _ => 0,
        })
        .sum();
    let size_mib = content_bytes * 2 / (1 << 20) + 2048;
    run(Command::new("mkfs.ext4")
        .args(["-q", "-L", "qim-base", "-d"])
        .arg(&root)
        .arg(base.join("root.img"))
        .arg(format!("{size_mib}M")))?;
    let kernel_version = kernel.parent().and_then(Path::file_name).expect("a kernel below a directory");
    let info = object(vec![
        ("name", text(name.as_str())),
        ("profile", text(profile.name)),
        ("date", text(date.to_string())),
        ("kernel", text(kernel_version.as_bytes())),
        ("packages", Json::List(packages.lines().map(text).collect())),
        ("manifest_sha256", text(hex(&Sha256::digest(manifest_json.as_bytes())))),
    ]);
    write(&base.join("image.json"), json_file(&info, 2))?;
    Ok(base)
}

// --- Manifest --------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    Dir,
    File { size: u64, sha256: String },
    Symlink { target: Vec<u8> },
    Other,
}

/// One path below the image root, as manifest.json lists it.
#[derive(Debug, PartialEq)]
pub struct Entry {
    /// "/" followed by the path relative to the root.
    pub path: Vec<u8>,
    pub kind: Kind,
    /// Permission bits only (S_IMODE).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// Extended attributes sorted by name; symlinks have none.
    pub xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Entry {
    fn to_json(&self) -> Json {
        let mut fields = vec![
            ("path", text(self.path.as_slice())),
            ("mode", text(format!("{:04o}", self.mode))),
            ("uid", Json::Int(self.uid.into())),
            ("gid", Json::Int(self.gid.into())),
        ];
        match &self.kind {
            Kind::Dir => fields.push(("type", text("dir"))),
            Kind::File { size, sha256 } => {
                fields.extend([("type", text("file")), ("size", Json::Int(*size)), ("sha256", text(sha256.as_str()))])
            }
            Kind::Symlink { target } => fields.extend([("type", text("symlink")), ("target", text(target.as_slice()))]),
            Kind::Other => fields.push(("type", text("other"))),
        }
        if !self.xattrs.is_empty() {
            let xattrs = self.xattrs.iter().map(|(name, value)| (name.clone(), text(hex(value))));
            fields.push(("xattrs", Json::Object(xattrs.collect())));
        }
        object(fields)
    }

    fn from_json(json: &Json) -> Result<Entry, String> {
        let Json::Object(fields) = json else {
            return Err("an entry is not an object".to_string());
        };
        let field = |key: &str| {
            let found = fields.iter().find(|(name, _)| name == key.as_bytes());
            found.map(|(_, value)| value).ok_or_else(|| format!("an entry has no {key}"))
        };
        let string = |key: &str| match field(key)? {
            Json::Str(value) => Ok(value.as_slice()),
            _ => Err(format!("{key} is not a string")),
        };
        let number = |key: &str| match field(key)? {
            Json::Int(value) => Ok(*value),
            _ => Err(format!("{key} is not a number")),
        };
        let id = |key: &str| number(key).and_then(|value| u32::try_from(value).map_err(|_| format!("{key} is too large")));
        let kind = match string("type")? {
            b"dir" => Kind::Dir,
            b"file" => {
                let sha256 = String::from_utf8(string("sha256")?.to_vec()).map_err(|_| "sha256 is not hexadecimal")?;
                Kind::File { size: number("size")?, sha256 }
            }
            b"symlink" => Kind::Symlink { target: string("target")?.to_vec() },
            b"other" => Kind::Other,
            other => return Err(format!("unknown type {:?}", String::from_utf8_lossy(other))),
        };
        let mode = std::str::from_utf8(string("mode")?).ok().and_then(|mode| u32::from_str_radix(mode, 8).ok());
        let xattrs = match fields.iter().find(|(name, _)| name == b"xattrs") {
            None => Vec::new(),
            Some((_, Json::Object(xattrs))) => xattrs
                .iter()
                .map(|(name, value)| match value {
                    Json::Str(value) => unhex(value).map(|value| (name.clone(), value)),
                    _ => None,
                })
                .collect::<Option<_>>()
                .ok_or("an xattr value is not hexadecimal")?,
            Some(_) => return Err("xattrs is not an object".to_string()),
        };
        Ok(Entry {
            path: string("path")?.to_vec(),
            kind,
            mode: mode.ok_or("mode is not octal")?,
            uid: id("uid")?,
            gid: id("gid")?,
            xattrs,
        })
    }
}

/// Read a manifest.json written by `build`.
pub fn read_manifest(path: &Path) -> Result<Vec<Entry>, String> {
    let invalid = |problem: String| format!("{}: {problem}", path.display());
    let Json::List(items) = parse_json(&fs::read(path).map_err(at(path))?).map_err(invalid)? else {
        return Err(invalid("not a list".to_string()));
    };
    let entry = |(index, item)| Entry::from_json(item).map_err(|problem| invalid(format!("entry {index}: {problem}")));
    items.iter().enumerate().map(entry).collect()
}

/// Every path under `root` with its type, metadata and content hash, sorted by path.
pub fn manifest(root: &Path) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::new();
    let mut buffer = vec![0; 1 << 20];
    let mut directories = vec![root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        for path in list_dir(&directory)? {
            check_signal()?;
            let info = fs::symlink_metadata(&path).map_err(at(&path))?;
            let file_type = info.file_type();
            let kind = if file_type.is_symlink() {
                Kind::Symlink { target: fs::read_link(&path).map_err(at(&path))?.into_os_string().into_vec() }
            } else if file_type.is_dir() {
                directories.push(path.clone());
                Kind::Dir
            } else if file_type.is_file() {
                Kind::File { size: info.len(), sha256: file_sha256(&path, &mut buffer)? }
            } else {
                Kind::Other
            };
            let xattrs = if file_type.is_symlink() { Vec::new() } else { xattrs(&path).map_err(at(&path))? };
            let relative = path.strip_prefix(root).expect("a path below root");
            entries.push(Entry {
                path: [b"/", relative.as_os_str().as_bytes()].concat(),
                kind,
                mode: info.mode() & 0o7777,
                uid: info.uid(),
                gid: info.gid(),
                xattrs,
            });
        }
    }
    entries.sort_by(|a, b| python_order(&a.path, &b.path));
    Ok(entries)
}

fn file_sha256(path: &Path, buffer: &mut [u8]) -> Result<String, String> {
    let mut file = File::open(path).map_err(at(path))?;
    let mut digest = Sha256::new();
    loop {
        match file.read(buffer) {
            Ok(0) => return Ok(hex(&digest.finalize())),
            Ok(length) => digest.update(&buffer[..length]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(at(path)(error)),
        }
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn unhex(text: &[u8]) -> Option<Vec<u8>> {
    let digit = |byte: u8| char::from(byte).to_digit(16);
    let pairs = text.chunks(2).map(|pair| match pair {
        &[high, low] => Some((digit(high)? << 4 | digit(low)?) as u8),
        _ => None,
    });
    pairs.collect()
}

/// The extended attributes of `path` (following a final symlink), sorted by name.
fn xattrs(path: &Path) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: `sized` passes a buffer valid for `size` bytes, or null with size 0.
    let names = sized(|buffer, size| unsafe { libc::listxattr(path.as_ptr(), buffer.cast(), size) })?;
    let mut attributes = Vec::new();
    for name in names.split(|&byte| byte == 0).filter(|name| !name.is_empty()) {
        let name = CString::new(name)?;
        // SAFETY: as above.
        let value = sized(|buffer, size| unsafe { libc::getxattr(path.as_ptr(), name.as_ptr(), buffer.cast(), size) })?;
        attributes.push((name.into_bytes(), value));
    }
    attributes.sort_by(|a, b| python_order(&a.0, &b.0));
    Ok(attributes)
}

/// Call a listxattr-style function, which reports the size it needs when given no buffer.
fn sized(call: impl Fn(*mut u8, usize) -> isize) -> io::Result<Vec<u8>> {
    loop {
        let size = call(std::ptr::null_mut(), 0);
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = vec![0; size as usize];
        let filled = call(buffer.as_mut_ptr(), buffer.len());
        if filled >= 0 {
            buffer.truncate(filled as usize);
            return Ok(buffer);
        }
        let error = io::Error::last_os_error();
        // The value grew between the two calls.
        if error.raw_os_error() != Some(libc::ERANGE) {
            return Err(error);
        }
    }
}

// --- JSON as Python's json module writes it ----------------------------------------
//
// json_file writes it and parse_json reads it back, with the strings as the
// bytes they were decoded from.

/// The characters Python decodes a file name to: UTF-8, with each undecodable
/// byte mapped to U+DC80..U+DCFF (surrogateescape).
fn python_chars(bytes: &[u8]) -> impl Iterator<Item = u32> + '_ {
    bytes.utf8_chunks().flat_map(|chunk| {
        let invalid = chunk.invalid().iter().map(|&byte| 0xDC00 | u32::from(byte));
        chunk.valid().chars().map(u32::from).chain(invalid)
    })
}

/// Order byte strings as Python orders the strings it decodes them to.
fn python_order(a: &[u8], b: &[u8]) -> Ordering {
    python_chars(a).cmp(python_chars(b))
}

/// A JSON value whose strings are bytes, decoded as Python decodes file names.
#[derive(Debug)]
enum Json {
    Int(u64),
    Str(Vec<u8>),
    List(Vec<Json>),
    Object(Vec<(Vec<u8>, Json)>),
}

fn text(value: impl Into<Vec<u8>>) -> Json {
    Json::Str(value.into())
}

fn object(fields: Vec<(&str, Json)>) -> Json {
    Json::Object(fields.into_iter().map(|(key, value)| (key.into(), value)).collect())
}

/// json.dumps(value, sort_keys=True, indent=indent) + "\n".
fn json_file(value: &Json, indent: usize) -> String {
    let mut out = String::new();
    write_json(&mut out, value, indent, 0);
    out.push('\n');
    out
}

fn write_json(out: &mut String, value: &Json, indent: usize, depth: usize) {
    let items: Vec<(Option<&[u8]>, &Json)> = match value {
        Json::Int(number) => return write!(out, "{number}").expect("writing to a String"),
        Json::Str(bytes) => return write_json_string(out, bytes),
        Json::List(items) => items.iter().map(|item| (None, item)).collect(),
        Json::Object(fields) => {
            let mut fields: Vec<_> = fields.iter().map(|(key, value)| (Some(key.as_slice()), value)).collect();
            fields.sort_by(|a, b| python_order(a.0.unwrap_or_default(), b.0.unwrap_or_default()));
            fields
        }
    };
    let (open, close) = if matches!(value, Json::List(_)) { ('[', ']') } else { ('{', '}') };
    out.push(open);
    let newline = |out: &mut String, depth: usize| {
        out.push('\n');
        out.extend(std::iter::repeat_n(' ', indent * depth));
    };
    for (position, (key, item)) in items.iter().enumerate() {
        if position > 0 {
            out.push(',');
        }
        newline(out, depth + 1);
        if let Some(key) = key {
            write_json_string(out, key);
            out.push_str(": ");
        }
        write_json(out, item, indent, depth + 1);
    }
    if !items.is_empty() {
        newline(out, depth);
    }
    out.push(close);
}

/// Parse a document as json_file writes it (objects, lists, strings and
/// non-negative integers), decoding each string back to its bytes: the
/// inverse of python_chars, so a lone U+DC80..U+DCFF is the byte 0x80..0xFF.
fn parse_json(input: &[u8]) -> Result<Json, String> {
    let mut parser = JsonParser { input, position: 0 };
    let value = parser.value()?;
    parser.skip_whitespace();
    if parser.position < input.len() {
        return Err(parser.error("trailing data"));
    }
    Ok(value)
}

struct JsonParser<'a> {
    input: &'a [u8],
    position: usize,
}

impl JsonParser<'_> {
    fn error(&self, problem: &str) -> String {
        format!("invalid JSON at byte {}: {problem}", self.position)
    }

    fn skip_whitespace(&mut self) {
        while self.input.get(self.position).is_some_and(|byte| b" \t\n\r".contains(byte)) {
            self.position += 1;
        }
    }

    fn next_byte(&mut self) -> Option<u8> {
        let byte = self.input.get(self.position).copied();
        self.position += usize::from(byte.is_some());
        byte
    }

    fn next_token(&mut self) -> Option<u8> {
        self.skip_whitespace();
        self.next_byte()
    }

    fn value(&mut self) -> Result<Json, String> {
        match self.next_token() {
            Some(b'[') => self.items(b']', Self::value).map(Json::List),
            Some(b'{') => self.items(b'}', Self::field).map(Json::Object),
            Some(b'"') => self.string().map(Json::Str),
            Some(digit @ b'0'..=b'9') => {
                let mut number = u64::from(digit - b'0');
                while let Some(&digit @ b'0'..=b'9') = self.input.get(self.position) {
                    let next = number.checked_mul(10).and_then(|number| number.checked_add(u64::from(digit - b'0')));
                    number = next.ok_or_else(|| self.error("number out of range"))?;
                    self.position += 1;
                }
                Ok(Json::Int(number))
            }
            _ => Err(self.error("expected a value")),
        }
    }

    fn field(&mut self) -> Result<(Vec<u8>, Json), String> {
        if self.next_token() != Some(b'"') {
            return Err(self.error("expected a key"));
        }
        let key = self.string()?;
        if self.next_token() != Some(b':') {
            return Err(self.error("expected ':'"));
        }
        Ok((key, self.value()?))
    }

    /// The items of a list or object, after its opening bracket.
    fn items<T>(&mut self, close: u8, item: impl Fn(&mut Self) -> Result<T, String>) -> Result<Vec<T>, String> {
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.input.get(self.position) == Some(&close) {
            self.position += 1;
            return Ok(items);
        }
        loop {
            items.push(item(self)?);
            match self.next_token() {
                Some(b',') => {}
                Some(byte) if byte == close => return Ok(items),
                _ => return Err(self.error("expected ',' or the closing bracket")),
            }
        }
    }

    /// The rest of a string, after its opening quote.
    fn string(&mut self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        loop {
            let unescaped = match self.next_byte().ok_or_else(|| self.error("unterminated string"))? {
                b'"' => return Ok(bytes),
                b'\\' => match self.next_byte() {
                    Some(b'u') => {
                        self.unicode_escape(&mut bytes)?;
                        continue;
                    }
                    Some(b'b') => 0x08,
                    Some(b'f') => 0x0C,
                    Some(b'n') => b'\n',
                    Some(b'r') => b'\r',
                    Some(b't') => b'\t',
                    Some(byte @ (b'"' | b'\\' | b'/')) => byte,
                    _ => return Err(self.error("invalid escape")),
                },
                byte => byte,
            };
            bytes.push(unescaped);
        }
    }

    fn hex_unit(&mut self) -> Result<u32, String> {
        let digits = self.input.get(self.position..self.position + 4);
        let unit = digits.and_then(|digits| {
            digits.iter().try_fold(0, |unit, &byte| Some(unit << 4 | char::from(byte).to_digit(16)?))
        });
        let unit = unit.ok_or_else(|| self.error("invalid \\u escape"))?;
        self.position += 4;
        Ok(unit)
    }

    /// A \u escape, after the "\u": a character, a surrogate pair, or a lone
    /// U+DC80..U+DCFF standing for an undecodable byte.
    fn unicode_escape(&mut self, bytes: &mut Vec<u8>) -> Result<(), String> {
        let unit = self.hex_unit()?;
        let code = match unit {
            0xD800..=0xDBFF if self.input[self.position..].starts_with(b"\\u") => {
                self.position += 2;
                let low = self.hex_unit()?;
                if !(0xDC00..=0xDFFF).contains(&low) {
                    return Err(self.error("unpaired surrogate"));
                }
                0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)
            }
            0xDC80..=0xDCFF => {
                bytes.push((unit - 0xDC00) as u8);
                return Ok(());
            }
            unit => unit,
        };
        let character = char::from_u32(code).ok_or_else(|| self.error("unpaired surrogate"))?;
        bytes.extend_from_slice(character.encode_utf8(&mut [0; 4]).as_bytes());
        Ok(())
    }
}

/// A JSON string with ensure_ascii, escaped exactly as Python's json module does.
fn write_json_string(out: &mut String, bytes: &[u8]) {
    out.push('"');
    for character in python_chars(bytes) {
        let _ = match character {
            0x22 => out.write_str("\\\""),
            0x5C => out.write_str("\\\\"),
            0x0A => out.write_str("\\n"),
            0x0D => out.write_str("\\r"),
            0x09 => out.write_str("\\t"),
            0x08 => out.write_str("\\b"),
            0x0C => out.write_str("\\f"),
            0x20..=0x7E => out.write_char(char::from(character as u8)),
            0x10000.. => {
                let offset = character - 0x10000;
                write!(out, "\\u{:04x}\\u{:04x}", 0xD800 | (offset >> 10), 0xDC00 | (offset & 0x3FF))
            }
            _ => write!(out, "\\u{character:04x}"),
        };
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::TempDir;

    fn date(year: u32, month: u32, day: u32) -> Date {
        Date::new(year, month, day).unwrap()
    }

    #[test]
    fn servers_point_to_the_archive_of_the_date() {
        let conf = pacman_conf(date(2026, 11, 8), None);
        let server = "Server = https://archive.archlinux.org/repos/2026/11/08/$repo/os/$arch";
        assert!(conf.contains(&format!("[core]\n{server}\n")));
        assert!(conf.contains(&format!("[extra]\n{server}\n")));
    }

    #[test]
    fn stalls_of_the_archive_do_not_abort_downloads() {
        assert!(pacman_conf(date(2026, 11, 8), None).contains("[options]\nArchitecture = auto\nSigLevel = Required DatabaseOptional\nLocalFileSigLevel = Optional\nParallelDownloads = 5\nDisableDownloadTimeout\n"));
    }

    #[test]
    fn has_no_extraction_exclusions() {
        assert!(!pacman_conf(date(2026, 11, 8), None).contains("NoExtract"));
    }

    #[test]
    fn cache_dir_only_when_given() {
        assert!(!pacman_conf(date(2026, 11, 8), None).contains("CacheDir"));
        assert!(pacman_conf(date(2026, 11, 8), Some("/var/cache/qim")).contains("CacheDir = /var/cache/qim\n"));
    }

    #[test]
    fn default_date_is_the_previous_day() {
        assert_eq!(default_date(date(2026, 11, 9)), date(2026, 11, 8));
        assert_eq!(default_date(date(2026, 3, 1)), date(2026, 2, 28));
        assert_eq!(default_date(date(2024, 3, 1)), date(2024, 2, 29));
        assert_eq!(default_date(date(2026, 1, 1)), date(2025, 12, 31));
    }

    #[test]
    fn days_since_the_epoch_become_dates() {
        assert_eq!(Date::from_days(0), date(1970, 1, 1));
        assert_eq!(Date::from_days(11016), date(2000, 2, 29));
        assert_eq!(Date::from_days(20766), date(2026, 11, 9));
    }

    #[test]
    fn dates_are_iso_formatted_and_parsed() {
        assert_eq!(Date::parse("2026-11-08"), Ok(date(2026, 11, 8)));
        assert_eq!(date(2026, 11, 8).to_string(), "2026-11-08");
        for invalid in ["2026-02-29", "2026-13-01", "2026-1-08", "20261108", "2026-11-08 ", "\u{ff12}026-11-08"] {
            assert!(Date::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn manifest_lists_files_directories_and_symlinks_sorted_by_path() {
        let directory = TempDir::new(&std::env::temp_dir()).unwrap();
        let root = directory.path();
        fs::create_dir(root.join("d")).unwrap();
        chmod(&root.join("d"), 0o755).unwrap();
        fs::write(root.join("d/f"), b"hello\n").unwrap();
        chmod(&root.join("d/f"), 0o644).unwrap();
        std::os::unix::fs::symlink("d/f", root.join("l")).unwrap();
        let entries = manifest(root).unwrap();
        // SAFETY: getuid and getgid have no preconditions.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let entry = |path: &str, kind, mode| Entry { path: path.into(), kind, mode, uid, gid, xattrs: Vec::new() };
        assert_eq!(entries, [
            entry("/d", Kind::Dir, 0o755),
            entry("/d/f", Kind::File {
                size: 6,
                sha256: "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03".into(),
            }, 0o644),
            entry("/l", Kind::Symlink { target: b"d/f".to_vec() }, 0o777),
        ]);
    }

    #[test]
    fn manifest_json_reads_back_to_the_entries_it_was_written_from() {
        let entries = vec![
            Entry {
                path: b"/caf\xc3\xa9 \"q\" \\ \x7f \x01\n\t\xf0\x90\x82\x80\xf0\x9f\x98\x80 \xff \xed\xa0\x80".to_vec(),
                kind: Kind::File { size: 3, sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into() },
                mode: 0o4755,
                uid: 1000,
                gid: 4_000_000_000,
                xattrs: vec![(b"security.capability".to_vec(), vec![1, 0, 0, 2, 0xff])],
            },
            Entry { path: b"/d".to_vec(), kind: Kind::Dir, mode: 0o1777, uid: 0, gid: 0, xattrs: Vec::new() },
            Entry { path: b"/l".to_vec(), kind: Kind::Symlink { target: b"\xfe/x".to_vec() }, mode: 0o777, uid: 0, gid: 0, xattrs: Vec::new() },
            Entry { path: b"/o".to_vec(), kind: Kind::Other, mode: 0o600, uid: 0, gid: 0, xattrs: Vec::new() },
        ];
        let directory = TempDir::new(&std::env::temp_dir()).unwrap();
        let path = directory.path().join("manifest.json");
        fs::write(&path, json_file(&Json::List(entries.iter().map(Entry::to_json).collect()), 1)).unwrap();
        assert_eq!(read_manifest(&path).unwrap(), entries);
    }

    #[test]
    fn manifest_strings_decode_escapes_to_bytes() {
        // A lone U+DC80..U+DCFF is an undecodable byte; a surrogate pair is one character.
        let document = "[{\"gid\": 0, \"mode\": \"0755\", \"path\": \"/a\\udcff\\ud83d\\ude00\\u00e9\\n\\/\", \"type\": \"dir\", \"uid\": 0}]";
        let Json::List(items) = parse_json(document.as_bytes()).unwrap() else { panic!("not a list") };
        let entry = Entry::from_json(&items[0]).unwrap();
        assert_eq!(entry.path, b"/a\xff\xf0\x9f\x98\x80\xc3\xa9\n/");
    }

    #[test]
    fn invalid_manifest_json_is_rejected() {
        for document in [
            "[{\"path\": \"/a\\ud83d\"}]",
            "[{\"path\": \"/a\\udc00\"}]",
            "[{\"path\": \"/a\\u12\"}]",
            "[{\"path\": \"/a\"}] x",
            "[{\"path\": \"/a\"},]",
            "[{\"path\" \"/a\"}]",
            "[-1]",
            "[18446744073709551616]",
            "[\"unterminated]",
        ] {
            assert!(parse_json(document.as_bytes()).is_err(), "{document}");
        }
        let entry = |fields: &str| parse_json(format!("{{{fields}}}").as_bytes()).map(|json| Entry::from_json(&json));
        assert!(entry("\"gid\": 0, \"mode\": \"0755\", \"path\": \"/a\", \"type\": \"dir\", \"uid\": 0").unwrap().is_ok());
        assert!(entry("\"gid\": 0, \"mode\": \"0758\", \"path\": \"/a\", \"type\": \"dir\", \"uid\": 0").unwrap().is_err());
        assert!(entry("\"gid\": 0, \"mode\": \"0755\", \"path\": \"/a\", \"type\": \"file\", \"uid\": 0").unwrap().is_err());
        assert!(entry("\"gid\": 0, \"mode\": \"0755\", \"path\": \"/a\", \"type\": \"dir\", \"uid\": 4294967296").unwrap().is_err());
    }

    #[test]
    fn paths_are_ordered_as_python_orders_decoded_names() {
        let mut paths: Vec<&[u8]> = vec![&b"/a\xef\xbf\xbd"[..], b"/a\xff", b"/a/x", b"/a-b"];
        paths.sort_by(|a, b| python_order(a, b));
        assert_eq!(paths, [&b"/a-b"[..], b"/a/x", b"/a\xff", b"/a\xef\xbf\xbd"]);
    }

    #[test]
    fn json_is_written_as_python_json_dumps_writes_it() {
        // Expected output of json.dumps(doc, sort_keys=True, indent=1) + "\n" with the
        // path decoded by os.fsdecode.
        let path = b"/caf\xc3\xa9 \"q\" \\ \x7f \x01\n\t\xf0\x9f\x98\x80 \xff";
        let doc = Json::List(vec![
            object(vec![
                ("path", text(&path[..])),
                ("mode", text("0755")),
                ("uid", Json::Int(0)),
                ("xattrs", object(vec![("user.b", text("01")), ("security.capability", text("ff"))])),
                ("empty", Json::List(Vec::new())),
                ("obj", Json::Object(Vec::new())),
            ]),
            text("x"),
        ]);
        assert_eq!(
            json_file(&doc, 1),
            "[\n {\n  \"empty\": [],\n  \"mode\": \"0755\",\n  \"obj\": {},\n  \"path\": \"/caf\\u00e9 \\\"q\\\" \\\\ \\u007f \
             \\u0001\\n\\t\\ud83d\\ude00 \\udcff\",\n  \"uid\": 0,\n  \"xattrs\": {\n   \"security.capability\": \"ff\",\n   \
             \"user.b\": \"01\"\n  }\n },\n \"x\"\n]\n"
        );
    }
}
