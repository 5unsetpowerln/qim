//! Tests of the audit log conversion (docs/events.md). The expected values are
//! derived by hand from the spec and are the same as in tests/test_audit.py.

use qim::audit::{convert, dump};
use serde_json::{Value, json};

/// Convert an audit log without host-side network records.
fn audit_only(input: &[u8]) -> Result<Value, String> {
    convert(input, None::<&[u8]>, None)
}

const AT_FDCWD: &str = "ffffff9c";
const W: u64 = 10000;

const WORKED_EXAMPLE_INPUT: &str = r#"type=SYSCALL msg=audit(1.000:10): arch=c000003e syscall=59 success=yes exit=0 a0=0 a1=0 a2=0 a3=0 items=1 ppid=1 pid=100 comm="sh" exe="/usr/bin/sh"
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
"#;

const WORKED_EXAMPLE_OUTPUT: &str = r#"{
  "counts": {
    "ignored_records": 1,
    "syscall_events": 8,
    "unresolved_paths": 1
  },
  "dns": [],
  "files": [
    {
      "errno": null,
      "ok": true,
      "op": "read",
      "path": "/etc",
      "processes": [
        2
      ]
    },
    {
      "errno": null,
      "ok": true,
      "op": "create",
      "path": "/etc/out",
      "processes": [
        2
      ]
    },
    {
      "errno": null,
      "ok": true,
      "op": "truncate",
      "path": "/etc/out",
      "processes": [
        2
      ]
    },
    {
      "errno": null,
      "ok": true,
      "op": "write",
      "path": "/etc/out",
      "processes": [
        2
      ]
    },
    {
      "errno": null,
      "ok": true,
      "op": "read",
      "path": "/root/a.txt",
      "processes": [
        2
      ]
    },
    {
      "errno": null,
      "ok": true,
      "op": "exec",
      "path": "/usr/bin/cat",
      "processes": [
        2
      ]
    },
    {
      "errno": null,
      "ok": true,
      "op": "exec",
      "path": "/usr/bin/sh",
      "processes": [
        1
      ]
    },
    {
      "errno": "ENOENT",
      "ok": false,
      "op": "delete",
      "path": null,
      "processes": [
        2
      ],
      "unresolved": {
        "dirfd": 7,
        "name": "zz"
      }
    }
  ],
  "network": [
    {
      "address": "169.254.1.1",
      "errno": null,
      "family": "inet",
      "ok": true,
      "port": 53,
      "processes": [
        2
      ],
      "syscall": "connect"
    }
  ],
  "processes": [
    {
      "argv": [
        "sh",
        "-c",
        "x"
      ],
      "cwd": "/root",
      "exe": "/usr/bin/sh",
      "id": 1,
      "parent": null
    },
    {
      "argv": [
        "cat",
        "a.txt"
      ],
      "cwd": "/root",
      "exe": "/usr/bin/cat",
      "id": 2,
      "parent": 1
    }
  ],
  "schema_version": 1,
  "wire": []
}
"#;

fn record(rtype: &str, serial: impl std::fmt::Display, body: &str) -> String {
    format!("type={rtype} msg=audit(1.000:{serial}): {body}")
}

/// One syscall event. exe, cwd, names and EXECVE bodies are raw tokens.
#[derive(Clone)]
struct Ev {
    serial: u64,
    nr: u32,
    ok: bool,
    exit: String,
    a: [String; 4],
    pid: String,
    ppid: String,
    exe: String,
    cwd: Option<String>,
    paths: Vec<(String, String)>,
    execve: Vec<String>,
    saddr: Option<String>,
    proctitle: bool,
}

fn ev(serial: u64, nr: u32) -> Ev {
    Ev {
        serial,
        nr,
        ok: true,
        exit: "0".into(),
        a: ["0".into(), "0".into(), "0".into(), "0".into()],
        pid: "100".into(),
        ppid: "1".into(),
        exe: r#""/usr/bin/x""#.into(),
        cwd: Some(r#""/w""#.into()),
        paths: Vec::new(),
        execve: Vec::new(),
        saddr: None,
        proctitle: true,
    }
}

impl Ev {
    fn exit(mut self, exit: impl ToString) -> Self {
        self.exit = exit.to_string();
        self
    }
    fn failed(mut self, exit: i64) -> Self {
        self.ok = false;
        self.exit = exit.to_string();
        self
    }
    fn a0(mut self, v: &str) -> Self {
        self.a[0] = v.into();
        self
    }
    fn a1(mut self, v: &str) -> Self {
        self.a[1] = v.into();
        self
    }
    fn a2(mut self, v: &str) -> Self {
        self.a[2] = v.into();
        self
    }
    fn pid(mut self, pid: impl ToString) -> Self {
        self.pid = pid.to_string();
        self
    }
    fn ppid(mut self, ppid: impl ToString) -> Self {
        self.ppid = ppid.to_string();
        self
    }
    fn exe(mut self, token: &str) -> Self {
        self.exe = token.into();
        self
    }
    fn cwd(mut self, token: Option<&str>) -> Self {
        self.cwd = token.map(str::to_string);
        self
    }
    fn paths(mut self, paths: &[(&str, &str)]) -> Self {
        self.paths = paths.iter().map(|&(n, t)| (n.to_string(), t.to_string())).collect();
        self
    }
    fn execve(mut self, bodies: &[&str]) -> Self {
        self.execve = bodies.iter().map(|b| b.to_string()).collect();
        self
    }
    fn saddr(mut self, saddr: &str) -> Self {
        self.saddr = Some(saddr.into());
        self
    }
    fn no_proctitle(mut self) -> Self {
        self.proctitle = false;
        self
    }
    fn lines(&self) -> Vec<String> {
        let s = self.serial;
        let success = if self.ok { "yes" } else { "no" };
        let mut lines = vec![record(
            "SYSCALL",
            s,
            &format!(
                "arch=c000003e syscall={} success={success} exit={} a0={} a1={} a2={} a3={} items={} ppid={} pid={} comm=\"x\" exe={}",
                self.nr, self.exit, self.a[0], self.a[1], self.a[2], self.a[3], self.paths.len(), self.ppid,
                self.pid, self.exe
            ),
        )];
        lines.extend(self.execve.iter().map(|b| record("EXECVE", s, b)));
        if let Some(cwd) = &self.cwd {
            lines.push(record("CWD", s, &format!("cwd={cwd}")));
        }
        for (item, (name, nametype)) in self.paths.iter().enumerate() {
            lines.push(record("PATH", s, &format!("item={item} name={name} nametype={nametype}")));
        }
        if let Some(saddr) = &self.saddr {
            lines.push(record("SOCKADDR", s, &format!("saddr={saddr}")));
        }
        if self.proctitle {
            lines.push(record("PROCTITLE", s, "proctitle=78"));
        }
        lines
    }
}

/// A successful execve of path whose argv is [basename].
fn exec_ev(serial: u64, path: &str, pid: i64, ppid: i64) -> Ev {
    let quoted = format!("\"{path}\"");
    let base = path.rsplit('/').next().unwrap();
    ev(serial, 59)
        .pid(pid)
        .ppid(ppid)
        .exe(&quoted)
        .paths(&[(&quoted, "NORMAL")])
        .execve(&[&format!("argc=1 a0=\"{base}\"")])
}

fn lines_of(events: &[Ev]) -> Vec<String> {
    events.iter().flat_map(Ev::lines).collect()
}

fn try_lines(lines: &[String]) -> Result<Value, String> {
    audit_only(lines.join("\n").as_bytes())
}

fn run(events: &[Ev]) -> Value {
    try_lines(&lines_of(events)).unwrap()
}

fn entry(path: &str, op: &str) -> Value {
    json!({"path": path, "op": op, "ok": true, "errno": null, "processes": []})
}

fn unresolved(dirfd: i64, name: &str, op: &str) -> Value {
    json!({"path": null, "op": op, "ok": true, "errno": null, "processes": [],
           "unresolved": {"dirfd": dirfd, "name": name}})
}

fn image(id: u64, exe: &str, parent: Option<u64>) -> Value {
    json!({"id": id, "exe": exe, "parent": parent, "cwd": "/w",
           "argv": [exe.rsplit('/').next().unwrap()]})
}

trait With {
    fn set(self, key: &str, value: Value) -> Value;
    fn procs(self, processes: &[u64]) -> Value;
    fn failed(self, errno: &str) -> Value;
}

impl With for Value {
    fn set(mut self, key: &str, value: Value) -> Value {
        self[key] = value;
        self
    }
    fn procs(self, processes: &[u64]) -> Value {
        self.set("processes", json!(processes))
    }
    fn failed(self, errno: &str) -> Value {
        self.set("ok", json!(false)).set("errno", json!(errno))
    }
}

fn paths_of(doc: &Value) -> Vec<&str> {
    doc["files"].as_array().unwrap().iter().map(|e| e["path"].as_str().unwrap()).collect()
}

fn exes_of(doc: &Value) -> Vec<&str> {
    doc["processes"].as_array().unwrap().iter().map(|p| p["exe"].as_str().unwrap()).collect()
}

// Worked example

#[test]
fn worked_example_output_matches_the_spec() {
    let doc = audit_only(WORKED_EXAMPLE_INPUT.as_bytes()).unwrap();
    assert_eq!(dump(&doc), WORKED_EXAMPLE_OUTPUT);
}

#[test]
fn worked_example_serialization_is_byte_identical_across_runs() {
    let first = dump(&audit_only(WORKED_EXAMPLE_INPUT.as_bytes()).unwrap());
    let second = dump(&audit_only(WORKED_EXAMPLE_INPUT.as_bytes()).unwrap());
    assert_eq!(first.as_bytes(), second.as_bytes());
}

// Serialization

#[test]
fn dump_matches_python_json_dumps() {
    // json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False) + "\n" of this
    // document, as printed by Python 3.14.
    let doc = json!({
        "s": "\u{0}\u{1f}\"\\\n\r\t\u{8}\u{c}\u{7f}\u{2028}\u{2029}\u{e9}\\xff",
        "e": [], "o": {}, "n": [1, -2, {"z": null, "a": true}],
    });
    let expected = "{\n  \"e\": [],\n  \"n\": [\n    1,\n    -2,\n    {\n      \"a\": true,\n      \"z\": null\n    }\n  ],\n  \"o\": {},\n  \"s\": \"\\u0000\\u001f\\\"\\\\\\n\\r\\t\\b\\f\u{7f}\u{2028}\u{2029}\u{e9}\\\\xff\"\n}\n";
    assert_eq!(dump(&doc), expected);
}

// EXECVE

#[test]
fn execve_chunked_and_hex_arguments() {
    // a1: quoted chunks; a2: hex "hi there"; a3: hex chunks that split the UTF-8
    // sequence C3 A9 (e-acute), so they must be joined before decoding; a4: hex
    // that is not valid UTF-8.
    let doc = run(&[ev(1, 59).exe(r#""/usr/bin/prog""#).paths(&[(r#""/usr/bin/prog""#, "NORMAL")]).execve(&[
        r#"argc=5 a0="prog" a1_len=10 a1[0]="hello" a1[1]="world" a2=6869207468657265 a3_len=4 a3[0]=41C3 a3[1]=A942 a4=FF41"#,
    ])]);
    assert_eq!(
        doc["processes"],
        json!([image(1, "/usr/bin/prog", None)
            .set("argv", json!(["prog", "helloworld", "hi there", "A\u{e9}B", "\\xffA"]))])
    );
}

#[test]
fn multiple_execve_records_are_joined_in_order() {
    let doc = run(&[
        ev(1, 59).pid(100).paths(&[(r#""/usr/bin/x""#, "NORMAL")]).execve(&[r#"argc=4 a0="a" a1="b""#, r#"a2="c" a3="d""#]),
        // a chunked argument continued in the next record
        ev(2, 59)
            .pid(200)
            .paths(&[(r#""/usr/bin/x""#, "NORMAL")])
            .execve(&[r#"argc=3 a0="sh" a1="-c" a2_len=6 a2[0]=616263"#, "a2[1]=646566"]),
    ]);
    let argvs: Vec<&Value> = doc["processes"].as_array().unwrap().iter().map(|p| &p["argv"]).collect();
    assert_eq!(argvs, [&json!(["a", "b", "c", "d"]), &json!(["sh", "-c", "abcdef"])]);
}

#[test]
fn hex_exe_is_decoded() {
    // 2F7573722F62696E2F612062 is "/usr/bin/a b"
    let doc = run(&[ev(1, 59)
        .exe("2F7573722F62696E2F612062")
        .paths(&[("2F7573722F62696E2F612062", "NORMAL")])
        .execve(&[r#"argc=1 a0="a""#])]);
    assert_eq!(doc["processes"], json!([image(1, "/usr/bin/a b", None).set("argv", json!(["a"]))]));
    assert_eq!(doc["files"], json!([entry("/usr/bin/a b", "exec").procs(&[1])]));
}

// PATH names

#[test]
fn hex_names_that_are_not_utf8() {
    let doc = run(&[
        // "/tmp/\xffa", absolute
        ev(1, 257).exit(3).a0(AT_FDCWD).paths(&[("2F746D702FFF61", "NORMAL")]),
        // cwd "/w\xc3" and relative name "ab", both hex
        ev(2, 257).exit(4).a0(AT_FDCWD).cwd(Some("2F77C3")).paths(&[("6162", "NORMAL")]),
    ]);
    assert_eq!(doc["files"], json!([entry("/tmp/\\xffa", "read"), entry("/w\\xc3/ab", "read")]));
}

#[test]
fn null_names_are_skipped() {
    let doc = run(&[
        // the (null) record is not "the first non-PARENT record": fd 3 is /real
        ev(1, 257).exit(3).a0(AT_FDCWD).a2("10000").paths(&[("(null)", "CREATE"), (r#""/real""#, "NORMAL")]),
        ev(2, 257).exit(4).a0("3").paths(&[(r#""x""#, "NORMAL")]),
        ev(3, 87).paths(&[(r#""/w""#, "PARENT"), ("(null)", "DELETE")]),
    ]);
    assert_eq!(doc["files"], json!([entry("/real", "read"), entry("/real/x", "read")]));
}

#[test]
fn normalization() {
    let doc = run(&[
        ev(1, 257).exit(3).a0(AT_FDCWD).cwd(Some(r#""/""#)).paths(&[(r#"".""#, "NORMAL")]),
        ev(2, 257).exit(4).a0(AT_FDCWD).paths(&[(r#""./a//b/../c/.""#, "NORMAL")]),
        ev(3, 257).exit(5).a0(AT_FDCWD).paths(&[(r#""//x/./y""#, "NORMAL")]),
        // a trailing slash is removed, so this joins the entry of /x/y
        ev(4, 257).exit(6).a0(AT_FDCWD).paths(&[(r#""/x/y/""#, "NORMAL")]),
        ev(5, 257).exit(7).a0(AT_FDCWD).paths(&[(r#""d/""#, "NORMAL")]),
    ]);
    assert_eq!(paths_of(&doc), ["/", "/w/a/b/../c", "/w/d", "/x/y"]);
}

// Directory fds

#[test]
fn renameat2_resolves_source_against_a0_and_destination_against_a2() {
    let doc = run(&[
        ev(1, 257).exit(3).a0(AT_FDCWD).a2("90800").paths(&[(r#""/src""#, "NORMAL")]),
        ev(2, 257).exit(4).a0("ffffffffffffff9c").a2("10000").paths(&[(r#""/dst""#, "NORMAL")]),
        ev(3, 316).a0("3").a2("4").paths(&[
            (r#""/src""#, "PARENT"),
            (r#""/dst""#, "PARENT"),
            (r#""a""#, "DELETE"),
            (r#""b""#, "CREATE"),
        ]),
    ]);
    assert_eq!(
        doc["files"],
        json!([entry("/dst", "read"), entry("/dst/b", "rename_to"), entry("/src", "read"), entry("/src/a", "rename_from")])
    );
}

#[test]
fn overwriting_rename() {
    let doc = run(&[
        // the record shape of a rename over an existing file on overlayfs
        ev(1, 82).paths(&[
            (r#""/d/""#, "PARENT"),
            (r#""/d/""#, "PARENT"),
            (r#""/d/config.lock""#, "DELETE"),
            (r#""/d/config""#, "DELETE"),
            ("(null)", "PARENT"),
            ("(null)", "PARENT"),
            ("(null)", "PARENT"),
            ("(null)", "CREATE"),
            (r#""/d/config""#, "CREATE"),
        ]),
        ev(2, 257).exit(3).a0(AT_FDCWD).a2("10000").paths(&[(r#""/src""#, "NORMAL")]),
        ev(3, 257).exit(4).a0(AT_FDCWD).a2("10000").paths(&[(r#""/dst""#, "NORMAL")]),
        // the replaced destination "b" (DELETE) is resolved against a2 like the CREATE
        ev(4, 264).a0("3").a2("4").paths(&[
            (r#""/src""#, "PARENT"),
            (r#""/dst""#, "PARENT"),
            (r#""a""#, "DELETE"),
            (r#""b""#, "DELETE"),
            ("(null)", "CREATE"),
            (r#""b""#, "CREATE"),
        ]),
        // a failed rename: the later UNKNOWN record gets the destination op
        ev(5, 82).failed(-2).paths(&[(r#""x""#, "UNKNOWN"), (r#""y""#, "UNKNOWN")]),
    ]);
    assert_eq!(
        doc["files"],
        json!([
            entry("/d/config", "delete"),
            entry("/d/config", "rename_to"),
            entry("/d/config.lock", "rename_from"),
            entry("/dst", "read"),
            entry("/dst/b", "delete"),
            entry("/dst/b", "rename_to"),
            entry("/src", "read"),
            entry("/src/a", "rename_from"),
            entry("/w/x", "rename_from").failed("ENOENT"),
            entry("/w/y", "rename_to").failed("ENOENT"),
        ])
    );
}

#[test]
fn linkat_and_symlinkat() {
    let doc = run(&[
        ev(1, 257).exit(3).a0(AT_FDCWD).a2("10000").paths(&[(r#""/a""#, "NORMAL")]),
        ev(2, 257).exit(4).a0(AT_FDCWD).a2("10000").paths(&[(r#""/b""#, "NORMAL")]),
        ev(3, 265).a0("3").a2("4").paths(&[(r#""src""#, "NORMAL"), (r#""/b""#, "PARENT"), (r#""dst""#, "CREATE")]),
        // symlinkat(target, newdirfd, linkpath): the base is a1
        ev(4, 266).a0("7f0000001000").a1("4").paths(&[(r#""/b""#, "PARENT"), (r#""ln""#, "CREATE")]),
    ]);
    assert_eq!(
        doc["files"],
        json!([
            entry("/a", "read"),
            entry("/a/src", "link_source"),
            entry("/b", "read"),
            entry("/b/dst", "link"),
            entry("/b/ln", "symlink"),
        ])
    );
}

#[test]
fn unlinkat_with_at_removedir() {
    let doc = run(&[
        ev(1, 263).a0(AT_FDCWD).a2("200").paths(&[(r#""/w""#, "PARENT"), (r#""d""#, "DELETE")]),
        ev(2, 263).a0(AT_FDCWD).a2("0").paths(&[(r#""/w""#, "PARENT"), (r#""f""#, "DELETE")]),
        // ENOTEMPTY is 39
        ev(3, 263).failed(-39).a0(AT_FDCWD).a2("200").paths(&[(r#""/w""#, "PARENT"), (r#""e""#, "DELETE")]),
    ]);
    assert_eq!(
        doc["files"],
        json!([entry("/w/d", "rmdir"), entry("/w/e", "rmdir").failed("ENOTEMPTY"), entry("/w/f", "delete")])
    );
}

// The fd table

#[test]
fn dup_dup2_dup3_and_fcntl_dupfd_propagate_mappings() {
    let doc = run(&[
        ev(1, 257).exit(3).a0(AT_FDCWD).a2("10000").paths(&[(r#""/data""#, "NORMAL")]),
        ev(2, 33).exit(10).a0("3").a1("a"),            // dup2(3, 10)
        ev(3, 72).exit(20).a0("a").a1("0").a2("14"),   // fcntl(10, F_DUPFD, 20)
        ev(4, 72).exit(21).a0("3").a1("406"),          // fcntl(3, F_DUPFD_CLOEXEC, 0)
        ev(5, 32).exit(5).a0("3"),                     // dup(3)
        ev(6, 292).exit(30).a0("3").a1("1e").a2("80000"), // dup3(3, 30, O_CLOEXEC)
        ev(7, 72).exit(1).a0("3").a1("1"),             // fcntl(3, F_GETFD) maps nothing
        ev(8, 257).exit(40).a0("a").paths(&[(r#""x""#, "NORMAL")]),
        ev(9, 257).exit(41).a0("14").paths(&[(r#""y""#, "NORMAL")]),
        ev(10, 257).exit(42).a0("15").paths(&[(r#""z""#, "NORMAL")]),
        ev(11, 257).exit(43).a0("5").paths(&[(r#""w""#, "NORMAL")]),
        ev(12, 257).exit(44).a0("1e").paths(&[(r#""v""#, "NORMAL")]),
        ev(13, 257).exit(45).a0("1").paths(&[(r#""n""#, "NORMAL")]),
    ]);
    assert_eq!(
        doc["files"],
        json!([
            entry("/data", "read"),
            entry("/data/v", "read"),
            entry("/data/w", "read"),
            entry("/data/x", "read"),
            entry("/data/y", "read"),
            entry("/data/z", "read"),
            unresolved(1, "n", "read"),
        ])
    );
    assert_eq!(doc["counts"]["unresolved_paths"], json!(1));
}

#[test]
fn close_removes_the_mapping() {
    let doc = run(&[
        ev(1, 257).exit(3).a0(AT_FDCWD).a2("10000").paths(&[(r#""/data""#, "NORMAL")]),
        ev(2, 3).a0("3"),
        // EBADF is 9
        ev(3, 257).failed(-9).a0("3").paths(&[(r#""x""#, "UNKNOWN")]),
    ]);
    assert_eq!(doc["files"], json!([entry("/data", "read"), unresolved(3, "x", "read").failed("EBADF")]));
}

#[test]
fn close_range_removes_every_fd_in_the_range() {
    let doc = run(&[
        ev(1, 257).exit(4).a0(AT_FDCWD).a2("10000").paths(&[(r#""/a""#, "NORMAL")]),
        ev(2, 257).exit(5).a0(AT_FDCWD).a2("10000").paths(&[(r#""/b""#, "NORMAL")]),
        ev(3, 257).exit(7).a0(AT_FDCWD).a2("10000").paths(&[(r#""/c""#, "NORMAL")]),
        ev(4, 436).a0("5").a1("ffffffff"), // close_range(5, ~0U, 0)
        ev(5, 257).exit(8).a0("4").paths(&[(r#""k""#, "NORMAL")]),
        ev(6, 257).exit(9).a0("5").paths(&[(r#""l""#, "NORMAL")]),
        ev(7, 257).exit(10).a0("7").paths(&[(r#""m""#, "NORMAL")]),
    ]);
    assert_eq!(
        doc["files"],
        json!([
            entry("/a", "read"),
            entry("/a/k", "read"),
            entry("/b", "read"),
            entry("/c", "read"),
            unresolved(5, "l", "read"),
            unresolved(7, "m", "read"),
        ])
    );
}

#[test]
fn close_range_with_cloexec_closes_nothing() {
    let doc = run(&[
        ev(1, 257).exit(5).a0(AT_FDCWD).a2("10000").paths(&[(r#""/b""#, "NORMAL")]),
        ev(2, 436).a0("3").a1("ffffffff").a2("4"), // CLOSE_RANGE_CLOEXEC
        ev(3, 257).exit(6).a0("5").paths(&[(r#""l""#, "NORMAL")]),
    ]);
    assert_eq!(doc["files"], json!([entry("/b", "read"), entry("/b/l", "read")]));
}

#[test]
fn fork_copies_the_fd_table_to_the_child() {
    let doc = run(&[
        ev(1, 257).pid(100).exit(3).a0(AT_FDCWD).a2("10000").paths(&[(r#""/data""#, "NORMAL")]),
        ev(2, 56).pid(100).exit(101), // clone
        ev(3, 3).pid(100).a0("3"),    // the parent's close does not affect the copy
        ev(4, 257).pid(101).ppid(100).exit(4).a0("3").a2("10000").paths(&[(r#""x""#, "NORMAL")]),
        ev(5, 57).pid(101).ppid(100).exit(103), // fork copies fds 3 and 4
        ev(6, 257).pid(103).ppid(101).exit(5).a0("4").paths(&[(r#""q""#, "NORMAL")]),
        ev(7, 257).pid(100).failed(-9).a0("3").paths(&[(r#""y""#, "UNKNOWN")]),
        ev(8, 257).pid(102).exit(3).a0("3").paths(&[(r#""z""#, "NORMAL")]), // no table
    ]);
    assert_eq!(
        doc["files"],
        json!([
            entry("/data", "read"),
            entry("/data/x", "read"),
            entry("/data/x/q", "read"),
            unresolved(3, "y", "read").failed("EBADF"),
            unresolved(3, "z", "read"),
        ])
    );
}

// Clones and pid reuse

#[test]
fn child_that_ran_before_its_clone_was_logged_keeps_its_state() {
    // With CLONE_VFORK the child's events (13, 14) get smaller serials than the
    // parent's clone3 (15).
    let doc = run(&[
        exec_ev(10, "/usr/bin/paru", 100, 1),
        ev(11, 257).pid(100).exit(3).a0(AT_FDCWD).a2("10000").paths(&[(r#""/data""#, "NORMAL")]),
        ev(12, 257).pid(100).exit(4).a0(AT_FDCWD).a2("1").paths(&[(r#""/log""#, "NORMAL")]),
        // the child's first event: origin (100, 13); attributed via current[ppid]
        ev(13, 257).pid(101).ppid(100).exit(4).a0(AT_FDCWD).a2("10000").paths(&[(r#""/tmp""#, "NORMAL")]),
        exec_ev(14, "/usr/bin/makepkg", 101, 100),
        // 15 - 10000 < 13 < 15: kept; only the missing fd 3 is copied, fd 4 stays /tmp
        ev(15, 435).pid(100).exit(101),
        ev(16, 257).pid(101).ppid(100).exit(5).a0("3").paths(&[(r#""x""#, "NORMAL")]),
        ev(17, 257).pid(101).ppid(100).exit(6).a0("4").paths(&[(r#""y""#, "NORMAL")]),
        exec_ev(18, "/usr/bin/sh", 101, 100),
    ]);
    assert_eq!(
        doc["processes"],
        json!([image(1, "/usr/bin/paru", None), image(2, "/usr/bin/makepkg", Some(1)), image(3, "/usr/bin/sh", Some(2))])
    );
    assert_eq!(
        doc["files"],
        json!([
            entry("/data", "read").procs(&[1]),
            entry("/data/x", "read").procs(&[2]),
            entry("/log", "write").procs(&[1]),
            entry("/tmp", "read").procs(&[1]),
            entry("/tmp/y", "read").procs(&[2]),
            entry("/usr/bin/makepkg", "exec").procs(&[2]),
            entry("/usr/bin/paru", "exec").procs(&[1]),
            entry("/usr/bin/sh", "exec").procs(&[3]),
        ])
    );
}

#[test]
fn state_left_by_an_earlier_process_with_the_same_pid_is_reset() {
    let doc = run(&[
        exec_ev(20, "/old", 200, 100), // origin of pid 200: (100, 20)
        ev(21, 257).pid(200).ppid(100).exit(3).a0(AT_FDCWD).a2("10000").paths(&[(r#""/olddir""#, "NORMAL")]),
        exec_ev(10018, "/parent", 100, 1),
        ev(10019, 257).pid(100).exit(5).a0(AT_FDCWD).a2("10000").paths(&[(r#""/newdir""#, "NORMAL")]),
        // the origin ppid matches, but 10020 - 10000 < 20 does not hold: reset
        ev(10020, 56).pid(100).exit(200),
        ev(10021, 257).pid(200).ppid(100).exit(6).a0("3").paths(&[(r#""a""#, "NORMAL")]),
        ev(10022, 257).pid(200).ppid(100).exit(7).a0("5").paths(&[(r#""b""#, "NORMAL")]),
        exec_ev(10023, "/new", 200, 100),
    ]);
    assert_eq!(
        doc["processes"],
        json!([image(1, "/old", None), image(2, "/parent", None), image(3, "/new", Some(2))])
    );
    assert_eq!(
        doc["files"],
        json!([
            entry("/new", "exec").procs(&[3]),
            entry("/newdir", "read").procs(&[2]),
            entry("/newdir/b", "read").procs(&[2]),
            entry("/old", "exec").procs(&[1]),
            entry("/olddir", "read").procs(&[1]),
            entry("/parent", "exec").procs(&[2]),
            unresolved(3, "a", "read").procs(&[2]),
        ])
    );
}

#[test]
fn reused_pid_whose_exec_is_logged_before_the_clone() {
    let doc = run(&[
        exec_ev(20, "/old", 200, 100), // origin of pid 200: (100, 20)
        ev(21, 257).pid(200).ppid(100).exit(3).a0(AT_FDCWD).a2("10000").paths(&[(r#""/olddir""#, "NORMAL")]),
        exec_ev(10018, "/parent", 300, 1),
        ev(10019, 257).pid(300).exit(5).a0(AT_FDCWD).a2("10000").paths(&[(r#""/newdir""#, "NORMAL")]),
        // a new process reusing pid 200 execs before the parent's clone3 is logged:
        // ppid 300 differs from the origin's 100, so the state is reset as if 300
        // created it here (current 2, fds {5: /newdir}, origin (300, 10020)); the
        // image's parent is therefore 2
        exec_ev(10020, "/new", 200, 300),
        // 10021 - 10000 < 10020 < 10021 and ppid 300: the child is kept
        ev(10021, 435).pid(300).exit(200),
        ev(10022, 257).pid(200).ppid(300).exit(6).a0("5").paths(&[(r#""b""#, "NORMAL")]),
        ev(10023, 257).pid(200).ppid(300).exit(7).a0("3").paths(&[(r#""c""#, "NORMAL")]),
    ]);
    assert_eq!(
        doc["processes"],
        json!([image(1, "/old", None), image(2, "/parent", None), image(3, "/new", Some(2))])
    );
    assert_eq!(
        doc["files"],
        json!([
            entry("/new", "exec").procs(&[3]),
            entry("/newdir", "read").procs(&[2]),
            entry("/newdir/b", "read").procs(&[3]),
            entry("/old", "exec").procs(&[1]),
            entry("/olddir", "read").procs(&[1]),
            entry("/parent", "exec").procs(&[2]),
            unresolved(3, "c", "read").procs(&[3]),
        ])
    );
}

#[test]
fn exec_after_reparenting_to_pid_1_keeps_the_parent() {
    let doc = run(&[
        exec_ev(1, "/a", 100, 1),
        ev(2, 56).pid(100).exit(101), // current[101] = 1, origin (100, 2)
        // reparented to pid 1, but the origin is recent (2 > 3 - 10000): no reset
        exec_ev(3, "/b", 101, 1),
    ]);
    assert_eq!(doc["processes"], json!([image(1, "/a", None), image(2, "/b", Some(1))]));
}

#[test]
fn exec_with_another_ppid_and_an_old_origin_resets() {
    let doc = run(&[
        exec_ev(1, "/a", 100, 1),
        ev(2, 56).pid(100).exit(101), // current[101] = 1, origin (100, 2)
        // 2 <= 10002 - 10000 and ppid 1 differs: reset; pid 1 has no state, so
        // the image's parent is null
        exec_ev(10002, "/b", 101, 1),
    ]);
    assert_eq!(doc["processes"], json!([image(1, "/a", None), image(2, "/b", None)]));
}

// Open flags and errno

#[test]
fn ops_from_flags() {
    let doc = run(&[
        ev(1, 2).exit(3).a1("200000").paths(&[(r#""/p""#, "NORMAL")]), // O_PATH
        ev(2, 2).exit(4).a1("202").paths(&[(r#""/q""#, "NORMAL")]),    // O_RDWR|O_TRUNC
        ev(3, 85).exit(5).paths(&[(r#""/""#, "PARENT"), (r#""/r""#, "CREATE")]), // creat
        ev(4, 437).exit(6).a0(AT_FDCWD).paths(&[(r#""s""#, "CREATE")]),          // openat2
        // O_WRONLY|O_CREAT|O_TRUNC on an existing file: no create
        ev(5, 257).exit(7).a0(AT_FDCWD).a2("241").paths(&[(r#""/t""#, "NORMAL")]),
        ev(6, 2).exit(8).a1("3").paths(&[(r#""/v""#, "NORMAL")]), // access mode 3
    ]);
    assert_eq!(
        doc["files"],
        json!([
            entry("/p", "path"),
            entry("/q", "read"),
            entry("/q", "truncate"),
            entry("/q", "write"),
            entry("/r", "create"),
            entry("/r", "truncate"),
            entry("/r", "write"),
            entry("/t", "truncate"),
            entry("/t", "write"),
            entry("/v", "open"),
            entry("/w/s", "open"),
        ])
    );
}

#[test]
fn errno_names_are_the_kernel_primary_names() {
    let doc = run(&[
        ev(1, 257).failed(-95).a0(AT_FDCWD).paths(&[(r#""/e95""#, "UNKNOWN")]),
        ev(2, 257).failed(-11).a0(AT_FDCWD).paths(&[(r#""/e11""#, "UNKNOWN")]),
        ev(3, 257).failed(-35).a0(AT_FDCWD).paths(&[(r#""/e35""#, "UNKNOWN")]),
        // 512 (ERESTARTSYS) is not in the uapi headers
        ev(4, 257).failed(-512).a0(AT_FDCWD).paths(&[(r#""/e512""#, "UNKNOWN")]),
    ]);
    assert_eq!(
        doc["files"],
        json!([
            entry("/e11", "read").failed("EAGAIN"),
            entry("/e35", "read").failed("EDEADLK"),
            entry("/e512", "read").failed("512"),
            entry("/e95", "read").failed("EOPNOTSUPP"),
        ])
    );
}

// Processes

#[test]
fn parents_and_attribution() {
    let doc = run(&[
        exec_ev(1, "/a", 100, 1),
        // the same pid execs again: the parent is the replaced image
        exec_ev(2, "/b", 100, 1),
        // no clone seen for pid 300: the parent falls back to current[ppid]
        exec_ev(3, "/c", 300, 100),
        // a failed exec creates no image and is attributed to current[pid]
        ev(4, 59).pid(300).ppid(100).failed(-2).paths(&[(r#""/nope""#, "UNKNOWN")]),
        // no CWD record
        exec_ev(5, "/d", 400, 999).cwd(None),
    ]);
    assert_eq!(
        doc["processes"],
        json!([
            image(1, "/a", None),
            image(2, "/b", Some(1)),
            image(3, "/c", Some(2)),
            image(4, "/d", None).set("cwd", Value::Null),
        ])
    );
    assert_eq!(
        doc["files"],
        json!([
            entry("/a", "exec").procs(&[1]),
            entry("/b", "exec").procs(&[2]),
            entry("/c", "exec").procs(&[3]),
            entry("/d", "exec").procs(&[4]),
            entry("/nope", "exec").failed("ENOENT").procs(&[3]),
        ])
    );
}

#[test]
fn events_of_several_processes_form_one_entry() {
    let saddr = "02000050010203040000000000000000"; // 1.2.3.4:80
    let doc = run(&[
        exec_ev(1, "/a", 100, 1),
        exec_ev(2, "/b", 200, 1),
        ev(3, 257).pid(100).exit(3).a0(AT_FDCWD).paths(&[(r#""/f""#, "NORMAL")]),
        ev(4, 257).pid(200).exit(3).a0(AT_FDCWD).paths(&[(r#""/f""#, "NORMAL")]),
        // pid 300 has no image and neither has its ppid 1: adds nothing
        ev(5, 257).pid(300).exit(3).a0(AT_FDCWD).paths(&[(r#""/f""#, "NORMAL")]),
        // EACCES is 13: a different entry
        ev(6, 257).pid(200).failed(-13).a0(AT_FDCWD).paths(&[(r#""/f""#, "NORMAL")]),
        ev(7, 257).pid(300).exit(4).a0(AT_FDCWD).paths(&[(r#""/g""#, "NORMAL")]),
        ev(8, 42).pid(200).saddr(saddr),
        ev(9, 42).pid(100).saddr(saddr),
        ev(10, 42).pid(100).saddr(saddr),
    ]);
    assert_eq!(
        doc["files"],
        json!([
            entry("/a", "exec").procs(&[1]),
            entry("/b", "exec").procs(&[2]),
            entry("/f", "read").failed("EACCES").procs(&[2]),
            entry("/f", "read").procs(&[1, 2]),
            entry("/g", "read"),
        ])
    );
    assert_eq!(
        doc["network"],
        json!([{"syscall": "connect", "family": "inet", "address": "1.2.3.4", "port": 80,
                "ok": true, "errno": null, "processes": [1, 2]}])
    );
}

// Network

#[test]
fn socket_addresses() {
    let doc = run(&[
        ev(1, 42).saddr("0A0001BB000000002604CAC0A104000D000000000000000200000000"),
        // abstract unix: 00 "abc" 00 "d"
        ev(2, 44).saddr("0100006162630064"),
        ev(3, 42).saddr("01002F6465762F6C6F670000"),
        ev(4, 46).saddr("100000000000000000000000"),
        ev(5, 42).saddr("0000ABCD"),
        // EINPROGRESS is 115
        ev(6, 42).failed(-115).saddr("020001BBD17E234E0000000000000000"),
        ev(7, 307).saddr("02000035C0A864020000000000000000"),
        ev(8, 42), // no SOCKADDR
        ev(9, 49).saddr("02000035C0A864020000000000000000"), // bind is not listed
        // IPv4-mapped ::ffff:127.0.0.1, port 80
        ev(10, 42).saddr(concat!("0A00005000000000", "00000000000000000000FFFF7F000001", "00000000")),
    ]);
    let net = |syscall: &str, family: &str, address: Value, port: Value| {
        json!({"syscall": syscall, "family": family, "address": address, "port": port,
               "ok": true, "errno": null, "processes": []})
    };
    assert_eq!(
        doc["network"],
        json!([
            net("connect", "af0", json!("0000abcd"), Value::Null),
            net("sendmmsg", "inet", json!("192.168.100.2"), json!(53)),
            net("connect", "inet", json!("209.126.35.78"), json!(443)).failed("EINPROGRESS"),
            net("connect", "inet6", json!("2604:cac0:a104:d::2"), json!(443)),
            net("connect", "inet6", json!("::ffff:127.0.0.1"), json!(80)),
            net("sendmsg", "netlink", Value::Null, Value::Null),
            net("connect", "unix", json!("/dev/log"), Value::Null),
            net("sendto", "unix", json!("@abcd"), Value::Null),
        ])
    );
}

#[test]
fn ipv6_text_forms() {
    // RFC 5952 (first longest zero run, at least two groups) as Python's ipaddress
    // prints them, with only IPv4-mapped addresses in mixed notation.
    let cases = [
        ("00000000000000000000000000000000", "::"),
        ("00000000000000000000000000000001", "::1"),
        ("20010db8000000000001000000000001", "2001:db8::1:0:0:1"),
        ("20010db8000100000001000100010001", "2001:db8:1:0:1:1:1:1"),
        ("00000000000000000000ffff00000000", "::ffff:0.0.0.0"),
        ("000000000000000000000000c0000201", "::c000:201"),
        ("0000000000000000ffff000001020304", "::ffff:0:102:304"),
        ("fe800000000000000000000000000000", "fe80::"),
        ("00010000000000000000000000000000", "1::"),
        ("20010db800000000000000000000ffff", "2001:db8::ffff"),
    ];
    for (serial, (hex, text)) in (1..).zip(cases) {
        let doc = run(&[ev(serial, 42).saddr(&format!("0A000000{}{hex}00000000", "00000000"))]);
        assert_eq!(doc["network"][0]["address"], json!(text), "{hex}");
    }
}

// Streaming

#[test]
fn interleaved_records_of_two_events() {
    let lines = vec![
        record("SYSCALL", 20, r#"arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=0 a2=0 a3=0 items=1 ppid=1 pid=100 comm="x" exe="/x""#),
        record("SYSCALL", 21, r#"arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=0 a2=1 a3=0 items=1 ppid=1 pid=200 comm="x" exe="/x""#),
        record("CWD", 21, r#"cwd="/b""#),
        record("CWD", 20, r#"cwd="/a""#),
        record("PATH", 20, r#"item=0 name="f" nametype=NORMAL"#),
        record("PATH", 21, r#"item=0 name="g" nametype=NORMAL"#),
        record("PROCTITLE", 21, "proctitle=78"),
        record("PROCTITLE", 20, "proctitle=78"),
    ];
    let doc = try_lines(&lines).unwrap();
    assert_eq!(doc["files"], json!([entry("/a/f", "read"), entry("/b/g", "write")]));
    assert_eq!(doc["counts"]["syscall_events"], json!(2));
}

#[test]
fn records_of_other_types_are_counted_not_grouped() {
    let mut lines = vec![record("CONFIG_CHANGE", 3, "op=set audit_failure=1 old=1 res=1")];
    lines.extend(ev(3, 257).exit(3).a0(AT_FDCWD).paths(&[(r#""/f""#, "NORMAL")]).lines());
    lines.push(record("UNKNOWN[1409]", 3, "foo=bar"));
    let doc = try_lines(&lines).unwrap();
    assert_eq!(doc["files"], json!([entry("/f", "read")]));
    assert_eq!(doc["counts"], json!({"syscall_events": 1, "ignored_records": 2, "unresolved_paths": 0}));
}

#[test]
fn events_are_processed_in_serial_order() {
    let doc = run(&[
        exec_ev(31, "/b", 200, 1),
        exec_ev(30, "/a", 100, 1),
        // in serial order the close (40) precedes the open (41)
        ev(41, 257).pid(1).exit(3).a0(AT_FDCWD).a2("10000").paths(&[(r#""/d""#, "NORMAL")]),
        ev(40, 3).pid(1).a0("3"),
        ev(42, 257).pid(1).exit(4).a0("3").paths(&[(r#""x""#, "NORMAL")]),
    ]);
    assert_eq!(exes_of(&doc), ["/a", "/b"]);
    assert!(doc["files"].as_array().unwrap().contains(&entry("/d/x", "read")));
}

#[test]
fn a_record_just_inside_the_reorder_window_is_accepted() {
    let doc = run(&[exec_ev(4 + W, "/b", 200, 1), exec_ev(5, "/a", 100, 1)]);
    assert_eq!(exes_of(&doc), ["/a", "/b"]);
}

#[test]
fn a_record_at_the_reorder_window_is_rejected() {
    assert!(try_lines(&lines_of(&[ev(5 + W, 3).a0("3"), ev(5, 3).a0("3")])).is_err());
}

#[test]
fn records_of_other_types_take_no_part_in_the_reorder_window() {
    let mut lines = ev(5 + W, 3).a0("3").lines();
    lines.push(record("DAEMON_START", 5, "op=start"));
    let doc = try_lines(&lines).unwrap();
    assert_eq!(doc["counts"], json!({"syscall_events": 1, "ignored_records": 1, "unresolved_paths": 0}));
}

#[test]
fn events_without_proctitle_are_processed_at_the_end() {
    let doc = run(&[exec_ev(51, "/b", 200, 1).no_proctitle(), exec_ev(50, "/a", 100, 1).no_proctitle()]);
    assert_eq!(exes_of(&doc), ["/a", "/b"]);
    assert_eq!(doc["counts"]["syscall_events"], json!(2));
}

#[test]
fn malformed_line_is_rejected() {
    assert!(audit_only("not an audit record\n".as_bytes()).is_err());
}

// Number syntax

#[test]
fn numbers_are_plain_ascii_64_bit_values() {
    let bad: [(&str, Vec<String>); 6] = [
        ("hex with 0x", ev(1, 3).a0("0x3").lines()),
        ("decimal with a plus", ev(1, 3).pid("+100").lines()),
        ("decimal with an underscore", ev(1, 3).exit("1_0").lines()),
        ("hex of 2**64", ev(1, 257).exit(3).a0(AT_FDCWD).a2("10000000000000000").paths(&[(r#""/f""#, "NORMAL")]).lines()),
        ("decimal of 2**63", ev(1, 3).pid("9223372036854775808").lines()),
        ("non-ASCII digit in the serial", vec![record("SYSCALL", "\u{661}", "syscall=3 success=yes")]),
    ];
    for (name, lines) in bad {
        assert!(try_lines(&lines).is_err(), "{name}");
    }
    // upper-case hex and a negative exit are fine
    let doc = run(&[ev(2, 257).failed(-2).a0("FFFFFF9C").paths(&[(r#""f""#, "UNKNOWN")])]);
    assert_eq!(doc["files"], json!([entry("/w/f", "read").failed("ENOENT")]));
}

// Reading bytes

#[test]
fn reads_bytes_and_replaces_invalid_utf8() {
    let mut data = ev(1, 257).exit(3).a0(AT_FDCWD).paths(&[("\"/tmp/@\"", "NORMAL")]).lines().join("\n").into_bytes();
    let at = data.iter().position(|&b| b == b'@').unwrap();
    data[at] = 0xff;
    let doc = audit_only(&data[..]).unwrap();
    assert_eq!(doc["files"], json!([entry("/tmp/\u{fffd}", "read")]));
}

#[test]
fn ill_formed_utf8() {
    // E2 82 | A | F0 | 80 | 80 | ED | A0 | 80 | F4 | 90 | 80 | 80 | B | C3: every
    // maximal ill-formed subpart becomes one U+FFFD in a line, while every byte
    // outside a valid character becomes \xNN in a hex value.
    let raw: &[u8] = b"\xe2\x82A\xf0\x80\x80\xed\xa0\x80\xf4\x90\x80\x80B\xc3";
    let mut data = ev(1, 257).exit(3).a0(AT_FDCWD).paths(&[("\"/q@\"", "NORMAL")]).lines().join("\n").into_bytes();
    let at = data.iter().position(|&b| b == b'@').unwrap();
    data.splice(at..at + 1, raw.iter().copied());
    data.push(b'\n');
    let hex_name = concat!("2F68", "E282", "41", "F08080", "EDA080", "F4908080", "42", "C3");
    data.extend(ev(2, 257).exit(4).a0(AT_FDCWD).paths(&[(hex_name, "NORMAL")]).lines().join("\n").into_bytes());
    let doc = audit_only(&data[..]).unwrap();
    let replaced = format!("/q\u{fffd}A{}B\u{fffd}", "\u{fffd}".repeat(10));
    assert_eq!(
        doc["files"],
        json!([
            entry("/h\\xe2\\x82A\\xf0\\x80\\x80\\xed\\xa0\\x80\\xf4\\x90\\x80\\x80B\\xc3", "read"),
            entry(&replaced, "read"),
        ])
    );
}

// Host-side network records

fn with_records(dns: &str, packets: &str) -> Result<Value, String> {
    convert(WORKED_EXAMPLE_INPUT.as_bytes(), Some(dns.as_bytes()), Some(packets.as_bytes()))
}

#[test]
fn dns_entries_are_distinct_with_sorted_answers() {
    let dns = r#"{"name": "b.example", "type": "A", "rcode": "NOERROR", "answers": ["192.0.2.2", "192.0.2.1", "192.0.2.2"]}
{"name": "a.example", "type": "AAAA", "rcode": "NOERROR", "answers": []}
{"name": "a.example", "type": "A", "rcode": null, "answers": []}
{"name": "a.example", "type": "A", "rcode": "NOERROR", "answers": ["192.0.2.9"]}
{"name": "b.example", "type": "A", "rcode": "NOERROR", "answers": ["192.0.2.1", "192.0.2.2"]}
"#;
    // By (name, type, canonical JSON): for a.example A, '"' sorts before ']'
    // in {"answers":["... versus {"answers":[]...
    assert_eq!(
        with_records(dns, "").unwrap()["dns"],
        json!([
            {"name": "a.example", "type": "A", "rcode": "NOERROR", "answers": ["192.0.2.9"]},
            {"name": "a.example", "type": "A", "rcode": null, "answers": []},
            {"name": "a.example", "type": "AAAA", "rcode": "NOERROR", "answers": []},
            {"name": "b.example", "type": "A", "rcode": "NOERROR", "answers": ["192.0.2.1", "192.0.2.2"]},
        ])
    );
}

#[test]
fn wire_entries_are_distinct_and_ordered_by_destination() {
    let packets = r#"{"protocol": "udp", "family": "inet", "address": "192.0.2.1", "port": 53}
{"protocol": "tcp", "family": "inet", "address": "192.0.2.1", "port": 443}
{"protocol": "icmp", "family": "inet", "address": "192.0.2.1", "port": null}
{"protocol": "tcp", "family": "inet6", "address": "2001:db8::1", "port": 443}
{"protocol": "udp", "family": "inet", "address": "192.0.2.1", "port": 53}
{"protocol": "tcp", "family": "inet", "address": "10.0.0.1", "port": 80}
{"protocol": "udp", "family": "inet", "address": "192.0.2.1", "port": 443}"#;
    assert_eq!(
        with_records("", packets).unwrap()["wire"],
        json!([
            {"protocol": "tcp", "family": "inet", "address": "10.0.0.1", "port": 80},
            {"protocol": "icmp", "family": "inet", "address": "192.0.2.1", "port": null},
            {"protocol": "udp", "family": "inet", "address": "192.0.2.1", "port": 53},
            {"protocol": "tcp", "family": "inet", "address": "192.0.2.1", "port": 443},
            {"protocol": "udp", "family": "inet", "address": "192.0.2.1", "port": 443},
            {"protocol": "tcp", "family": "inet6", "address": "2001:db8::1", "port": 443},
        ])
    );
}

#[test]
fn missing_or_empty_records_are_empty_lists() {
    let missing = audit_only(WORKED_EXAMPLE_INPUT.as_bytes()).unwrap();
    let empty = with_records("", "").unwrap();
    for doc in [missing, empty] {
        assert_eq!(doc["dns"], json!([]));
        assert_eq!(doc["wire"], json!([]));
    }
}

#[test]
fn records_with_other_keys_or_value_types_are_rejected() {
    let valid_dns = r#"{"name": "a", "type": "A", "rcode": null, "answers": []}"#;
    let valid_packet = r#"{"protocol": "udp", "family": "inet", "address": "192.0.2.1", "port": 53}"#;
    assert!(with_records(valid_dns, valid_packet).is_ok());
    let bad_dns = [
        "not json",
        "[]",
        "\"a\"",
        "",
        r#"{"name": "a", "type": "A", "rcode": null}"#,
        r#"{"name": "a", "type": "A", "rcode": null, "answers": [], "extra": 1}"#,
        r#"{"name": null, "type": "A", "rcode": null, "answers": []}"#,
        r#"{"name": "a", "type": 1, "rcode": null, "answers": []}"#,
        r#"{"name": "a", "type": "A", "rcode": 0, "answers": []}"#,
        r#"{"name": "a", "type": "A", "rcode": null, "answers": "192.0.2.1"}"#,
        r#"{"name": "a", "type": "A", "rcode": null, "answers": [1]}"#,
    ];
    for bad in bad_dns {
        assert!(with_records(&format!("{valid_dns}\n{bad}\n{valid_dns}\n"), "").is_err(), "{bad}");
    }
    let bad_packets = [
        "{}",
        r#"{"protocol": "udp", "family": "inet", "address": "192.0.2.1"}"#,
        r#"{"protocol": "udp", "family": "inet", "address": "192.0.2.1", "port": 53, "x": null}"#,
        r#"{"protocol": 17, "family": "inet", "address": "192.0.2.1", "port": 53}"#,
        r#"{"protocol": "udp", "family": null, "address": "192.0.2.1", "port": 53}"#,
        r#"{"protocol": "udp", "family": "inet", "address": [], "port": 53}"#,
        r#"{"protocol": "udp", "family": "inet", "address": "192.0.2.1", "port": "53"}"#,
        r#"{"protocol": "udp", "family": "inet", "address": "192.0.2.1", "port": 53.5}"#,
    ];
    for bad in bad_packets {
        assert!(with_records("", &format!("{valid_packet}\n{bad}\n")).is_err(), "{bad}");
    }
    // Lines must be UTF-8.
    let mut not_utf8 = valid_packet.as_bytes().to_vec();
    not_utf8[42] = 0xff;
    assert!(convert(WORKED_EXAMPLE_INPUT.as_bytes(), None, Some(&not_utf8[..])).is_err());
}
