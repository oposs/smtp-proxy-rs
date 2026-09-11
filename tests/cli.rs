//! The command line of spec section 7, driven through the real binary.
use assert_cmd::Command;

fn bin() -> Command {
    Command::cargo_bin("smtp-proxy").unwrap()
}

/// The flags a started proxy needs, minus whatever the test wants to vary.
fn certs() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/certs")
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
        "--max_message_size",
        "--man",
    ] {
        assert!(text.contains(flag), "missing {flag} in\n{text}");
    }
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

/// Runs the binary and returns (exit code, stdout, stderr).
fn run(args: &[String]) -> (i32, String, String) {
    let out = std::process::Command::new(assert_cmd::cargo::cargo_bin("smtp-proxy"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
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
/// known flag renders only the complaint and the `--man` hint. Both are
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
        assert_eq!(code, 1, "{name}: exit code\nstderr:\n{stderr}");
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

/// `--man` is a help action, so it succeeds and prints the long about to
/// stdout. Grouped here because it is the one flag of this family that
/// must *not* look like a usage error.
#[test]
fn man_exits_0_with_the_long_description() {
    let (code, stdout, stderr) = run(&["--man".to_string()]);
    assert_eq!(code, 0, "stderr:\n{stderr}");
    assert_eq!(stderr, "", "nothing belongs on stderr");
    assert!(
        stdout.contains("Starts an SMTP server on the listen host and port."),
        "{stdout}"
    );
    assert!(stdout.contains("--max_message_size"), "{stdout}");
}

#[test]
fn starts_binds_and_announces() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    let certs = certs();
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("smtp-proxy"))
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
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
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
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("smtp-proxy"))
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
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
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
