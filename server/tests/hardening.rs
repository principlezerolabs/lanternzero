//! Memory hygiene (spec §6.2) in the real binary: what `doctor` reports and
//! what `serve` does at start must agree, on whatever system the tests run
//! (swap is on and memlock limited on most CI runners; macOS encrypts swap).
//! Also checks that `doctor` prints nothing identifying.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_lz-server");
const HOST: &str = "lz-doctor.example";
/// Nothing listens here (the discard port), so the chain check fails fast.
const LWD: &str = "http://127.0.0.1:9";

fn temp_dir() -> PathBuf {
    let mut raw = [0u8; 8];
    rand::fill(&mut raw);
    let name: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let d = std::env::temp_dir().join(format!("lz-hardening-{name}"));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_config(dir: &Path, allow_swap: bool) -> PathBuf {
    let path = dir.join("config.toml");
    let text = format!(
        r#"listen = "127.0.0.1:0"
public_host = "{HOST}"
network = "main"
data_dir = "{}"
vapid_contact = "mailto:ops@{HOST}"

[chain]
lightwalletd = "{LWD}"

[hardening]
allow_swap = {allow_swap}
"#,
        dir.join("data").display()
    );
    std::fs::write(&path, text).unwrap();
    path
}

fn doctor(config: &Path) -> String {
    let out = Command::new(BIN)
        .arg(config)
        .arg("doctor")
        .env("RUST_LOG", "warn")
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap()
}

/// Starts `serve` and returns the first start-up decision it logs.
fn start(config: &Path) -> (String, bool) {
    let mut child = Command::new(BIN)
        .arg(config)
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let decision = loop {
        let line = rx
            .recv_timeout(Duration::from_secs(60))
            .expect("serve logged no start-up decision");
        if line.contains("memory hygiene ok")
            || line.contains("swap may hold")
            || line.contains("refusing to start")
        {
            break line;
        }
    };
    // Still running a moment later?
    std::thread::sleep(Duration::from_millis(500));
    let running = child.try_wait().unwrap().is_none();
    let _ = child.kill();
    let _ = child.wait();
    (decision, running)
}

#[test]
fn doctor_and_startup_agree_and_doctor_output_is_safe_to_share() {
    let dir = temp_dir();
    let strict = write_config(&dir, false);
    let report = doctor(&strict);
    let memory = report
        .lines()
        .find(|l| l.contains("  memory  "))
        .unwrap_or_else(|| panic!("no memory check in:\n{report}"))
        .to_owned();

    for name in ["data-dir", "core-dumps", "memory", "chain"] {
        assert!(
            report.contains(&format!("  {name}")),
            "{name} missing:\n{report}"
        );
    }
    #[cfg(unix)]
    assert!(report.contains("pass  core-dumps"), "{report}");
    assert!(
        report.contains("FAIL  chain"),
        "unreachable chain source:\n{report}"
    );
    for secret in [HOST, "127.0.0.1:9", dir.to_str().unwrap()] {
        assert!(
            !report.contains(secret),
            "doctor printed {secret}:\n{report}"
        );
    }

    let (decision, running) = start(&strict);
    if memory.starts_with("FAIL") {
        assert!(decision.contains("refusing to start"), "{decision}");
        assert!(!running, "a refused server kept running");
        // The operator says swap is encrypted: it starts, with a warning.
        let allowed = write_config(&dir, true);
        assert!(doctor(&allowed).contains("warn  memory"));
        let (decision, running) = start(&allowed);
        assert!(decision.contains("swap may hold"), "{decision}");
        assert!(running);
    } else {
        assert!(memory.starts_with("pass"), "{memory}");
        assert!(decision.contains("memory hygiene ok"), "{decision}");
        assert!(running, "the server didn't stay up");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
