#![cfg(feature = "test-fixtures")]
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use unbolt::{inventory, model::RegistrySource, process, recovery};
use winreg::{RegKey, enums::HKEY_CURRENT_USER};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("unbolt-helper-fixture-{}", recovery::unique_id())))
    }
    fn command(&self, mode: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_unbolt-cli"));
        command.args(["helper-fixture", &self.0.display().to_string(), mode]);
        command
    }
    fn run(&self, mode: &str) -> Value {
        let output = self.command(mode).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // This private registration is written before launch, so it can also be
        // cleaned when the test deliberately disconnects the fixture caller.
        if let Ok(bytes) = fs::read(self.0.join("registration.json"))
            && let Ok(source) = serde_json::from_slice::<RegistrySource>(&bytes)
            && source.hive == "HKCU"
            && source.key.starts_with(&format!(
                "{}\\UnboltHelperFixture",
                inventory::UNINSTALL_ROOT
            ))
        {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(source.key);
        }
        assert!(self.0.starts_with(std::env::temp_dir()));
        assert!(
            self.0
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("unbolt-helper-fixture-")
        );
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn wait_for(predicate: impl Fn() -> bool) {
    let until = Instant::now() + Duration::from_secs(12);
    while !predicate() && Instant::now() < until {
        thread::sleep(Duration::from_millis(25));
    }
    assert!(
        predicate(),
        "helper fixture did not reach the expected state"
    );
}
fn session(root: &Path) -> Option<process::Session> {
    let path = fs::read_dir(root.join(recovery::DATA_DIRECTORY).join("process-sessions"))
        .ok()?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "json"))?;
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}
fn registration_exists(root: &Path) -> bool {
    let source: RegistrySource =
        serde_json::from_slice(&fs::read(root.join("registration.json")).unwrap()).unwrap();
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(&source.key)
        .is_ok()
}

#[test]
fn helper_removes_only_reviewed_fixture_and_preserves_restorable_backups() {
    let fixture = Fixture::new();
    let result = fixture.run("force");
    assert!(result.get("error").is_none(), "{result}");
    assert_eq!(result["folder_exists"], false);
    assert_eq!(result["registered"], false);
    assert!(!registration_exists(&fixture.0));
    let items = result["reply"]["data"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    for item in items {
        assert_eq!(item["state"], "Removed");
        let backup = PathBuf::from(item["backup"].as_str().unwrap());
        assert!(backup.is_file());
        if item["kind"] == "Files" {
            assert_eq!(
                fs::read(backup.parent().unwrap().join("payload/owned.txt")).unwrap(),
                b"owned helper fixture"
            );
        }
    }
}
#[test]
fn helper_rejects_changed_files_wrong_application_and_changed_binary() {
    for mode in ["changed", "wrong-target", "binary-changed"] {
        let fixture = Fixture::new();
        let result = fixture.run(mode);
        assert!(result.get("error").is_some(), "{mode}: {result}");
        assert_eq!(result["folder_exists"], true);
        assert_eq!(result["registered"], true);
        assert!(fixture.0.join("App/owned.txt").is_file());
        assert!(session(&fixture.0).is_none());
    }
}
#[test]
fn helper_keeps_monitoring_after_queue_cancellation_and_caller_exit() {
    let fixture = Fixture::new();
    let result = fixture.run("uninstall");
    assert!(result.get("error").is_none(), "{result}");
    assert_eq!(result["reply"]["data"]["safe_to_scan"], false);
    assert!(
        result["status"]
            .as_str()
            .unwrap()
            .contains("still monitored")
    );
    assert_eq!(
        session(&fixture.0).unwrap().state,
        "monitoring-after-queue-stop"
    );
    fs::write(fixture.0.join("release.txt"), b"release").unwrap();
    wait_for(|| session(&fixture.0).is_some_and(|s| s.state == "completed"));
    let saved = session(&fixture.0).unwrap();
    assert_eq!(saved.exit_code, Some(0));
    assert_eq!(saved.scope, "job-contained descendants");
    assert!(saved.error.is_none());
}
#[test]
fn pipe_disconnect_stops_queue_and_retains_running_monitor() {
    let fixture = Fixture::new();
    let mut caller = fixture
        .command("disconnect")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_for(|| fixture.0.join("ready.txt").is_file());
    // Kill only this test-owned caller after its test-owned installer started.
    caller.kill().unwrap();
    caller.wait().unwrap();
    wait_for(|| session(&fixture.0).is_some_and(|s| s.state == "monitoring-after-queue-stop"));
    assert!(fixture.0.join("App/fixture.exe").is_file());
    fs::write(fixture.0.join("release.txt"), b"release").unwrap();
    wait_for(|| session(&fixture.0).is_some_and(|s| s.state == "completed"));
    assert_eq!(session(&fixture.0).unwrap().exit_code, Some(0));
}
#[test]
fn startup_helper_restores_raw_owned_value_and_rejects_stale_review() {
    let fixture = Fixture::new();
    let result = fixture.run("startup");
    assert_eq!(result["raw_type_preserved"], true);
    assert_eq!(result["raw_bytes_preserved"], true);
    assert_eq!(result["disabled"]["state"], "Disabled by Unbolt");
    assert_eq!(result["restored"]["data"]["state"], "Configured");
    assert!(std::path::Path::new(result["disabled"]["backup"].as_str().unwrap()).is_file());
    let stale = Fixture::new();
    let result = stale.run("startup-stale");
    assert!(
        result["error"]
            .as_str()
            .unwrap()
            .contains("changed since review")
    );
    assert_eq!(result["value"], "changed after review");
}
