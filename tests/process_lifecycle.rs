#![cfg(feature = "test-fixtures")]
use std::{
    fs,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use unbolt::{command, process, recovery};
fn fixture(mode: &str) -> (std::path::PathBuf, command::UninstallCommand) {
    let root =
        std::env::temp_dir().join(format!("unbolt-process-fixture-{}", recovery::unique_id()));
    fs::create_dir_all(&root).unwrap();
    let exe = env!("CARGO_BIN_EXE_unbolt-test-fixture");
    let command = command::parse(&format!(
        "{} {} {}",
        command::quote_argument(exe),
        mode,
        command::quote_argument(&root.join("complete.txt").display().to_string())
    ))
    .unwrap();
    (root, command)
}
#[test]
fn waits_for_detached_child_and_grandchild() {
    let (root, cmd) = fixture("root");
    let start = Instant::now();
    let result = process::run_at(
        &cmd,
        "fixture-app",
        &AtomicBool::new(false),
        &root.join("sessions"),
    )
    .unwrap();
    assert!(result.safe_to_scan);
    assert_eq!(result.session.exit_code, Some(0));
    assert!(result.session.total_processes >= 3);
    assert!(start.elapsed() >= Duration::from_millis(650));
    assert_eq!(
        fs::read(root.join("complete.txt")).unwrap(),
        b"grandchild finished"
    );
    assert!(root.starts_with(std::env::temp_dir()));
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn cancellation_does_not_kill_installer() {
    let (root, cmd) = fixture("delayed");
    let cancel = Arc::new(AtomicBool::new(false));
    let flag = cancel.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(150));
        flag.store(true, Ordering::Relaxed);
    });
    let result = process::run_at(&cmd, "fixture-app", &cancel, &root.join("sessions")).unwrap();
    assert!(result.cancelled);
    assert!(!result.safe_to_scan);
    assert!(process::assert_cleanup_ready_at(&root.join("sessions"), "fixture-app").is_err());
    let duplicate = process::run_at(
        &cmd,
        "fixture-app",
        &AtomicBool::new(false),
        &root.join("sessions"),
    )
    .unwrap_err();
    assert!(duplicate.contains("already has a running"));
    let deadline = Instant::now() + Duration::from_secs(5);
    while !root.join("complete.txt").exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    let session_path = root
        .join("sessions")
        .join(format!("{}.json", result.session.id));
    while Instant::now() < deadline {
        let session: process::Session =
            serde_json::from_slice(&fs::read(&session_path).unwrap()).unwrap();
        if session.state == "completed" {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let session: process::Session =
        serde_json::from_slice(&fs::read(session_path).unwrap()).unwrap();
    assert_eq!(session.state, "completed");
    assert_eq!(
        fs::read(root.join("complete.txt")).unwrap(),
        b"installer finished"
    );
    process::assert_cleanup_ready_at(&root.join("sessions"), "fixture-app").unwrap();
    assert!(root.starts_with(std::env::temp_dir()));
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn preserves_reboot_exit_status() {
    let (root, cmd) = fixture("reboot");
    let result = process::run_at(
        &cmd,
        "fixture-app",
        &AtomicBool::new(false),
        &root.join("sessions"),
    )
    .unwrap();
    assert_eq!(result.session.exit_code, Some(3010));
    assert!(!result.safe_to_scan);
    assert!(process::assert_cleanup_ready_at(&root.join("sessions"), "fixture-app").is_err());
    assert!(root.starts_with(std::env::temp_dir()));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cancellation_before_launch_has_no_side_effects() {
    let (root, cmd) = fixture("delayed");
    assert!(
        process::run_at(
            &cmd,
            "fixture-app",
            &AtomicBool::new(true),
            &root.join("sessions")
        )
        .is_err()
    );
    assert!(!root.join("sessions").exists());
    assert!(!root.join("complete.txt").exists());
    assert!(root.starts_with(std::env::temp_dir()));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn successful_tracked_retry_supersedes_completed_failure() {
    let (root, mut cmd) = fixture("reboot");
    let storage = root.join("sessions");
    process::run_at(&cmd, "fixture-app", &AtomicBool::new(false), &storage).unwrap();
    assert!(process::assert_cleanup_ready_at(&storage, "fixture-app").is_err());
    cmd.arguments[0] = "root".into();
    let success = process::run_at(&cmd, "fixture-app", &AtomicBool::new(false), &storage).unwrap();
    assert!(success.safe_to_scan);
    process::assert_cleanup_ready_at(&storage, "fixture-app").unwrap();
    assert!(root.starts_with(std::env::temp_dir()));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_launch_preserves_complex_and_empty_arguments() {
    let (root, mut cmd) = fixture("arguments");
    let expected = [
        "",
        "/qn",
        "with spaces",
        "a\"b",
        r"C:\ends with slash\",
        "日本語",
        "a\tb",
    ];
    cmd.arguments.extend(expected.map(str::to_owned));
    let result = process::run_at(
        &cmd,
        "fixture-arguments",
        &AtomicBool::new(false),
        &root.join("sessions"),
    )
    .unwrap();
    assert_eq!(result.session.exit_code, Some(0));
    let received: Vec<String> =
        serde_json::from_slice(&fs::read(root.join("complete.txt")).unwrap()).unwrap();
    assert_eq!(received, expected);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn windows_installer_accepts_switches_and_reports_only_missing_owned_package() {
    let (root, _) = fixture("root");
    let missing = root.join("never created package.msi");
    assert!(!missing.exists());
    let cmd = command::parse(&format!(
        "{} /x {} /qn /norestart",
        command::quote_argument(&command::system_msiexec().unwrap()),
        command::quote_argument(&missing.display().to_string())
    ))
    .unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let flag = cancel.clone();
    let (stop, timer) = std::sync::mpsc::channel();
    let timeout = thread::spawn(move || {
        if timer.recv_timeout(Duration::from_secs(15)).is_err() {
            flag.store(true, Ordering::Relaxed);
        }
    });
    // This package does not exist: Windows Installer cannot remove any product.
    // Error 1619 proves it parsed the switches and tried opening that exact file.
    let result = process::run_at(&cmd, "fixture-missing-msi", &cancel, &root.join("sessions"));
    let _ = stop.send(());
    timeout.join().unwrap();
    let result = result.unwrap();
    assert!(!result.cancelled);
    assert_eq!(result.session.state, "completed");
    assert_eq!(result.session.exit_code, Some(1619));
    assert!(!result.safe_to_scan);
    assert!(!missing.exists());
    fs::remove_dir_all(root).unwrap();
}
