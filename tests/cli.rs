//! The command line of spec section 7, driven through the real binary.
use assert_cmd::Command;

fn bin() -> Command {
    Command::cargo_bin("smtp-proxy").unwrap()
}

#[path = "common/certs.rs"]
mod generated_certs;

/// The flags a started proxy needs, minus whatever the test wants to vary.
fn certs() -> std::path::PathBuf {
    generated_certs::dir().to_path_buf()
}

/// The upstream probe is spawned, not awaited (spec 6: it must not block
/// accepting connections), so its log line arrives some time after the
/// proxy has announced itself on stdout. Both tests below wait for it.
const PROBE_WARNING: &str = "Could not ask 127.0.0.1:1 which extensions it offers";

/// Ten seconds against a connect-refused that takes microseconds: four
/// orders of magnitude of margin, so this waits for an event rather than
/// tuning a timing window. Expiry is a failure, never a skipped assertion.
const DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// Polls `text` every 50 ms until it contains `needle`, and returns it.
/// Panics when the deadline expires, so a probe that never runs or a
/// wording that has drifted makes the test red rather than passing quietly.
fn wait_for(what: &str, needle: &str, text: impl Fn() -> String) -> String {
    let start = std::time::Instant::now();
    loop {
        let current = text();
        if current.contains(needle) {
            return current;
        }
        assert!(
            start.elapsed() < DEADLINE,
            "waited {DEADLINE:?} for {needle:?} in {what}, which held:\n{current}"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// A spawned proxy that is reaped whatever happens to the test.
///
/// `std::process::Child` does not kill on drop, so every panic between a
/// spawn and its `kill()` used to leave a real daemon listening on an
/// ephemeral port with nobody to reap it. The likeliest such panic is
/// `wait_for`'s deadline above -- which is precisely what a genuine
/// regression in this code trips, so the failure mode paired a red test
/// with a leaked process. Six of those were once found still alive after
/// two days and nineteen hours, holding a binary from a deleted worktree.
///
/// `Deref`/`DerefMut` keep `child.kill()`, `child.wait()`, `child.id()`,
/// `child.try_wait()` and `child.stdout.take()` reading as before, so the
/// tests say what they always said and the reaping is the only addition.
struct Proxy(std::process::Child);

impl Proxy {
    fn spawn(command: &mut std::process::Command) -> Self {
        Self(command.spawn().unwrap())
    }
}

impl std::ops::Deref for Proxy {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Proxy {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        // Both results are dropped on purpose. On the success path the test
        // has already killed and reaped the child, so `kill` answers "no
        // such process" and `wait` "no child processes" -- and this runs
        // during unwinding as well, where a panic would abort the test
        // binary instead of reporting the failure that got us here.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn version_flag() {
    bin()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_lists_the_perl_flags() {
    let out = bin()
        .arg("--help")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    for flag in [
        "--listen",
        "--user",
        "--tohost",
        "--toport",
        "--tls_cert",
        "--tls_key",
        "--api",
        "--logpath",
        "--loglevel",
        "--smtplog",
        "--credentials",
        "--max_header_size",
        "--man",
    ] {
        assert!(text.contains(flag), "missing {flag} in\n{text}");
    }
}

/// The greeting deadline's default is an operator-visible contract -- it is
/// what a deployment gets without asking -- and nothing else pins it. A flag
/// that silently lost its `default_value_t` would still parse, still run, and
/// quietly hand every fresh connection the ten-minute budget again.
#[test]
fn greeting_timeout_is_offered_with_its_30_second_default() {
    let out = bin()
        .arg("--help")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    let flag = text
        .split("--greeting_timeout")
        .nth(1)
        .unwrap_or_else(|| panic!("--greeting_timeout is not offered:\n{text}"));
    assert!(
        flag.contains("[default: 30]"),
        "--greeting_timeout lost its default:\n{flag}"
    );
}

#[test]
fn missing_mandatory_flag_exits_1_with_usage() {
    bin()
        .args(["--listen", "127.0.0.1:0"])
        .assert()
        .code(1)
        .stderr(predicates::str::contains("--tohost"));
}

/// Every mandatory flag but the one under test, so that a usage error is
/// the only thing that can go wrong.
fn complete_args() -> Vec<String> {
    let certs = certs();
    [
        "--listen",
        "127.0.0.1:0",
        "--tohost",
        "127.0.0.1",
        "--toport",
        "1",
        "--api",
        "http://127.0.0.1:1/check",
    ]
    .iter()
    .map(|s| s.to_string())
    .chain([
        "--tls_cert".to_string(),
        certs.join("server.crt").display().to_string(),
        "--tls_key".to_string(),
        certs.join("server.key").display().to_string(),
    ])
    .collect()
}

/// Runs the binary to completion and returns (exit code, stdout, stderr).
///
/// The one helper for "drive the binary and read what it said", and it
/// cannot hang. There used to be two -- this one without a deadline, and a
/// `run_bounded` with one -- which is a trap rather than a choice: `run` is
/// the name the next person reaches for, and reading a plain
/// `std::process::Command::output()` does not announce that it waits for the
/// child to close its pipes. A proxy that *starts* never closes them and
/// never exits, so such a call blocks for ever: cargo does not time a test
/// out, so the whole `cli` binary sits there until CI's wall clock kills the
/// job, with no failing assertion and no captured output to read, and on a
/// developer's machine it leaves a live daemon on an ephemeral port that no
/// `Proxy` guard covers. So the deadline belongs on the obvious name, and
/// there is nothing else to reach for.
///
/// The exit code is an `Option` for the same reason: `None` is a process
/// that did not exit on its own and had to be killed at `DEADLINE`, which is
/// a distinct outcome from any code it could have returned, and a caller
/// comparing against `Some(1)` reports it as a failure instead of hanging.
/// `DEADLINE` is the same ten seconds the pollers above use, four orders of
/// magnitude above a clap error, so a loaded host cannot make this flaky.
fn run(args: &[String]) -> (Option<i32>, String, String) {
    let out = bin().args(args).timeout(DEADLINE).output().unwrap();
    (
        out.status.code(),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

/// Each bad command line exits 1, complains on stderr, and says nothing on
/// stdout. The `Usage:` count is the point: it must never be more than one.
/// Passing a clap error through `usage_exit` used to print a second,
/// differently worded usage block after clap's own.
///
/// The expected count is per case because clap is not uniform about it: an
/// unknown argument renders a `Usage:` block, while a bad *value* for a
/// known flag renders only the complaint and the `--help` hint. Both are
/// clap's own output and neither is the defect this test pins shut.
#[test]
fn usage_errors_exit_1_with_at_most_one_usage_block() {
    for (name, args, expected, usage_blocks) in [
        (
            "unknown flag",
            vec!["--bogus".to_string()],
            "unexpected argument '--bogus'",
            1,
        ),
        (
            "unparseable port",
            {
                let mut a = complete_args();
                let i = a.iter().position(|x| x == "--toport").unwrap();
                a[i + 1] = "notanumber".to_string();
                a
            },
            "invalid value 'notanumber' for '--toport <TOPORT>'",
            0,
        ),
        (
            "malformed listen address",
            {
                let mut a = complete_args();
                let i = a.iter().position(|x| x == "--listen").unwrap();
                a[i + 1] = "nonsense".to_string();
                a
            },
            "Could not parse nonsense",
            1,
        ),
        (
            "missing mandatory flag",
            vec!["--listen".to_string(), "127.0.0.1:0".to_string()],
            "--tohost is required",
            1,
        ),
    ] {
        let (code, stdout, stderr) = run(&args);
        assert_eq!(code, Some(1), "{name}: exit code\nstderr:\n{stderr}");
        assert_eq!(stdout, "", "{name}: nothing belongs on stdout");
        assert!(
            stderr.contains(expected),
            "{name}: expected {expected:?} in stderr:\n{stderr}"
        );
        assert_eq!(
            stderr.matches("Usage:").count(),
            usage_blocks,
            "{name}: wrong number of Usage: blocks in stderr:\n{stderr}"
        );
    }
}

/// `--max_header_size 0` used to be accepted, and then refused every message
/// carrying any header at all with 552 -- the opposite of the "0 means
/// unlimited" its four sibling limits document. Unlimited is not an option
/// here, because the header block is the one part of a message this proxy
/// holds in memory, so the value has to be refused at startup.
#[test]
fn max_header_size_zero_is_refused_at_startup() {
    let mut args = complete_args();
    args.push("--max_header_size".to_string());
    args.push("0".to_string());
    let (code, stdout, stderr) = run(&args);
    assert_eq!(
        code,
        Some(1),
        "--max_header_size 0 must exit 1 rather than start\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(stdout, "", "nothing belongs on stdout");
    assert!(
        stderr.contains("--max_header_size"),
        "the complaint must name the flag:\n{stderr}"
    );
    assert!(
        stderr.contains("unlimited"),
        "the complaint must say 0 is not unlimited:\n{stderr}"
    );
}

/// The help text is where an operator meets the rule, so it has to carry it.
#[test]
fn help_says_max_header_size_has_no_unlimited() {
    let out = bin()
        .arg("--help")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    let flag = text
        .split("--max_header_size <MAX_HEADER_SIZE>")
        .nth(1)
        .unwrap_or_else(|| panic!("--max_header_size is not offered:\n{text}"));
    let help = flag.split("--upstream_tls").next().unwrap();
    assert!(
        help.contains("unlimited"),
        "--max_header_size help does not mention that 0 is not unlimited:\n{help}"
    );
}

/// What `--man` must print: `docs/manual.md` without its YAML front matter.
/// Derived here rather than by calling `config::manual`, so a stripping
/// defect in the binary cannot pass by being shared with its test.
fn manual_body() -> &'static str {
    let source = include_str!("../docs/manual.md");
    let rest = source
        .strip_prefix("---\n")
        .expect("docs/manual.md opens with front matter");
    let close = rest.find("\n---\n").expect("the front matter is closed");
    rest[close + "\n---\n".len()..].trim_start_matches('\n')
}

/// `--man` prints the manual, byte for byte, and nothing else.
#[test]
fn man_prints_the_manual() {
    let (code, stdout, stderr) = run(&["--man".to_string()]);
    assert_eq!(code, Some(0), "stderr:\n{stderr}");
    assert_eq!(stderr, "", "nothing belongs on stderr");
    let want = manual_body();
    assert!(
        want.starts_with("# NAME\n"),
        "the test's own stripping is off"
    );
    if stdout != want {
        let at = stdout
            .bytes()
            .zip(want.bytes())
            .position(|(a, b)| a != b)
            .unwrap_or(stdout.len().min(want.len()));
        let lo = at.saturating_sub(80);
        let hi = (at + 80).min(stdout.len());
        panic!(
            "--man printed {} bytes, the manual body is {}; first difference at byte {at}:\n{}",
            stdout.len(),
            want.len(),
            String::from_utf8_lossy(&stdout.as_bytes()[lo..hi])
        );
    }
}

/// `--man` answers before any other check: a command line that would be
/// refused still gets the manual, as `--help` does.
#[test]
fn man_is_printed_whatever_else_the_command_line_holds() {
    let args = ["--max_header_size", "0", "--man"].map(String::from);
    let (code, stdout, stderr) = run(&args);
    assert_eq!(code, Some(0), "stderr:\n{stderr}");
    assert_eq!(stderr, "", "nothing belongs on stderr");
    assert!(stdout.starts_with("# NAME\n"), "{stdout}");
}

/// `smtp-proxy --man | head` at its most abrupt: the only read end is closed
/// before the child writes, so the write fails with EPIPE. That is the
/// reader's choice and not an error: exit 0, and no panic on stderr.
#[test]
fn man_into_a_closed_pipe_exits_0() {
    use std::io::Read;
    use std::process::Stdio;
    let mut child = Proxy::spawn(
        std::process::Command::new(assert_cmd::cargo::cargo_bin("smtp-proxy"))
            .arg("--man")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    drop(child.stdout.take());
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            start.elapsed() < DEADLINE,
            "--man did not exit within {DEADLINE:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert_eq!(status.code(), Some(0), "stderr:\n{stderr}");
    assert_eq!(stderr, "", "a closed pipe is not worth a message");
}

/// With `--man` a plain switch, clap's hint names the help flag.
#[test]
fn a_clap_error_points_to_help() {
    let (code, _stdout, stderr) = run(&["--bogus".to_string()]);
    assert_eq!(code, Some(1), "stderr:\n{stderr}");
    assert!(
        stderr.contains("For more information, try '--help'."),
        "{stderr}"
    );
}

#[test]
fn starts_binds_and_announces() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    let certs = certs();
    let mut child = Proxy::spawn(
        std::process::Command::new(assert_cmd::cargo::cargo_bin("smtp-proxy"))
            .args([
                "--listen",
                "127.0.0.1:0",
                "--tohost",
                "127.0.0.1",
                "--toport",
                "1",
                "--api",
                "http://127.0.0.1:1/check",
                "--loglevel",
                "info",
            ])
            .arg("--tls_cert")
            .arg(certs.join("server.crt"))
            .arg("--tls_key")
            .arg(certs.join("server.key"))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    assert!(
        line.starts_with("Waiting for connections on 127.0.0.1:"),
        "{line}"
    );
    line.clear();
    stdout.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "Will forward mails to 127.0.0.1:1");

    // Read stderr on a thread, because the probe's line arrives on its own
    // schedule and a blocking read to EOF would need the child dead first.
    let collected = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let sink = collected.clone();
    let pipe = child.stderr.take().unwrap();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(pipe).lines() {
            let Ok(line) = line else { return };
            sink.lock().unwrap().push_str(&line);
            sink.lock().unwrap().push('\n');
        }
    });
    let stderr = wait_for("stderr", &format!("[warn] {PROBE_WARNING}"), || {
        collected.lock().unwrap().clone()
    });
    assert!(stderr.lines().next().unwrap().starts_with('['), "{stderr}");
    child.kill().unwrap();
    child.wait().unwrap();
    reader.join().unwrap();
}

/// `--logpath` names a file rather than the default `/dev/stderr`, so the
/// log must land in that file, in the spec 8.1 layout, and not on stderr.
#[test]
fn logpath_writes_the_log_to_a_file() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    let dir = tempfile::tempdir().unwrap();
    let logfile = dir.path().join("proxy.log");
    let certs = certs();
    let mut child = Proxy::spawn(
        std::process::Command::new(assert_cmd::cargo::cargo_bin("smtp-proxy"))
            .args([
                "--listen",
                "127.0.0.1:0",
                "--tohost",
                "127.0.0.1",
                "--toport",
                "1",
                "--api",
                "http://127.0.0.1:1/check",
                "--loglevel",
                "debug",
            ])
            .arg("--tls_cert")
            .arg(certs.join("server.crt"))
            .arg("--tls_key")
            .arg(certs.join("server.key"))
            .arg("--logpath")
            .arg(&logfile)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    let pid = child.id();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    assert!(
        line.starts_with("Waiting for connections on 127.0.0.1:"),
        "{line}"
    );
    line.clear();
    stdout.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "Will forward mails to 127.0.0.1:1");
    // The probe is spawned, so wait for its line to reach the file rather
    // than assume the announcement implies it.
    let text = wait_for("the log file", PROBE_WARNING, || {
        std::fs::read_to_string(&logfile).unwrap_or_default()
    });
    child.kill().unwrap();
    let stderr = {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut s).unwrap();
        s
    };
    assert_eq!(stderr, "", "nothing should reach stderr with --logpath set");
    child.wait().unwrap();

    let warn = text
        .lines()
        .find(|l| l.contains(PROBE_WARNING))
        .unwrap_or_else(|| panic!("no probe warning in {}:\n{text}", logfile.display()));
    // Spec 8.1: `[<ts>] [<pid>] [<level>] <message>`, no connection id on a
    // message that belongs to no connection.
    let rest = warn
        .strip_prefix('[')
        .and_then(|r| r.split_once("] "))
        .unwrap_or_else(|| panic!("no timestamp bracket on: {warn}"));
    assert_eq!(rest.0.len(), "2026-09-11 14:13:51.12345".len(), "{warn}");
    assert!(
        rest.1
            .starts_with(&format!("[{pid}] [warn] {PROBE_WARNING}")),
        "{warn}"
    );
}

/// Spec 9.1, through the real binary: SIGTERM has to drain and exit 0,
/// rather than leave the runtime to be torn down under the sessions.
#[test]
fn sigterm_drains_and_exits_cleanly() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    let dir = tempfile::tempdir().unwrap();
    let logfile = dir.path().join("proxy.log");
    let certs = certs();
    let mut child = Proxy::spawn(
        std::process::Command::new(assert_cmd::cargo::cargo_bin("smtp-proxy"))
            .args([
                "--listen",
                "127.0.0.1:0",
                "--tohost",
                "127.0.0.1",
                "--toport",
                "1",
                "--api",
                "http://127.0.0.1:1/check",
                "--loglevel",
                "info",
            ])
            .arg("--tls_cert")
            .arg(certs.join("server.crt"))
            .arg("--tls_key")
            .arg(certs.join("server.key"))
            .arg("--logpath")
            .arg(&logfile)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    assert!(
        line.starts_with("Waiting for connections on 127.0.0.1:"),
        "{line}"
    );

    assert!(
        std::process::Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );

    // No connections are open, so the drain has nothing to wait for and
    // the timeout never comes into it.
    wait_for(
        "the log file",
        "Shutting down; draining 0 connection(s)",
        || std::fs::read_to_string(&logfile).unwrap_or_default(),
    );
    // Polled rather than a blocking `wait`, so that a shutdown that hangs
    // fails this test instead of hanging it.
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            start.elapsed() < DEADLINE,
            "the proxy did not exit within {DEADLINE:?} of SIGTERM"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    assert!(status.success(), "{status}");
}
