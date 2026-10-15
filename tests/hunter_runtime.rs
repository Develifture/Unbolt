#![cfg(feature = "test-fixtures")]
use std::{
    fs,
    os::windows::process::CommandExt,
    path::PathBuf,
    process::{Child, Command},
    sync::atomic::AtomicBool,
    thread,
    time::{Duration, Instant},
};
use unbolt::{command, hunter, inventory, recovery, startup};
use winreg::{RegKey, enums::*};
struct Fixture {
    root: PathBuf,
    child: Child,
    key: String,
    startup_names: Vec<String>,
}
impl Fixture {
    fn new() -> Self {
        let name = format!("UnboltHunterFixture{}", recovery::unique_id());
        let root =
            std::env::temp_dir().join(format!("unbolt-hunter-fixture-{}", recovery::unique_id()));
        let folder = root.join("App");
        fs::create_dir_all(&folder).unwrap();
        let executable = folder.join("fixture.exe");
        fs::copy(env!("CARGO_BIN_EXE_unbolt-test-fixture"), &executable).unwrap();
        let key = format!("{}\\{name}", inventory::UNINSTALL_ROOT);
        let (registry, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(&key)
            .unwrap();
        registry.set_value("DisplayName", &name).unwrap();
        registry
            .set_value("InstallLocation", &folder.display().to_string())
            .unwrap();
        drop(registry);
        let child = Command::new(&executable)
            .args(["window", &root.join("ready.json").display().to_string()])
            .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
            .spawn()
            .unwrap();
        let run = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(startup::RUN, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY)
            .unwrap();
        let startup_names = vec![
            format!("{name}StartA"),
            format!("{name}StartB"),
            format!("{name}Other"),
        ];
        for entry in &startup_names[..2] {
            run.set_value(
                entry,
                &format!(
                    "{} --fixture-noop",
                    command::quote_argument(&executable.to_string_lossy())
                ),
            )
            .unwrap();
        }
        let other = folder.join("same-name-other.exe");
        fs::copy(&executable, &other).unwrap();
        run.set_value(
            &startup_names[2],
            &format!(
                "{} --fixture-noop",
                command::quote_argument(&other.to_string_lossy())
            ),
        )
        .unwrap();
        Self {
            root,
            child,
            key,
            startup_names,
        }
    }
    fn window(&self) -> usize {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(bytes) = fs::read(self.root.join("ready.json"))
                && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes)
            {
                return value["window"].as_u64().unwrap() as usize;
            }
            assert!(Instant::now() < until);
            thread::sleep(Duration::from_millis(25));
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::write(self.root.join("release.txt"), b"release");
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.key);
        if let Ok(run) = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(startup::RUN, KEY_WRITE | KEY_WOW64_64KEY)
        {
            for name in &self.startup_names {
                let _ = run.delete_value(name);
            }
        }
        assert!(self.root.starts_with(std::env::temp_dir()));
        assert!(
            self.root
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("unbolt-hunter-fixture-")
        );
        let _ = fs::remove_dir_all(&self.root);
    }
}
#[test]
fn real_window_attribution_and_reviewed_process_stop_are_identity_bound() {
    let mut fixture = Fixture::new();
    let window = fixture.window();
    assert!(
        hunter::open_windows()
            .iter()
            .any(|w| w.window == window && w.pid == fixture.child.id())
    );
    let mut bounds: windows_sys::Win32::Foundation::RECT = unsafe { std::mem::zeroed() };
    unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::GetWindowRect(window as _, &mut bounds);
    }
    // A real unobscured part of this test-owned window, without input injection.
    assert_eq!(
        hunter::window_at_point(bounds.right - 30, bounds.top + 80),
        Some((window, fixture.child.id()))
    );
    let cancel = AtomicBool::new(false);
    assert!(hunter::inspect_window(window, fixture.child.id() + 1, &cancel).is_err());
    let report = hunter::inspect_window(window, fixture.child.id(), &cancel).unwrap();
    assert_eq!(report.peer.pid, fixture.child.id());
    assert!(
        report
            .window_title
            .starts_with("Unbolt Hunter verification")
    );
    assert!(report.inventory_errors.is_empty());
    assert!(
        report
            .unique_application()
            .unwrap()
            .name
            .starts_with("UnboltHunterFixture")
    );
    let entries = startup::collect(&cancel);
    let matching = entries
        .records
        .iter()
        .filter(|e| e.launches(&report.peer.image))
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), 2);
    assert!(
        matching
            .iter()
            .all(|e| fixture.startup_names[..2].contains(&e.name().to_string()))
    );
    assert_ne!(matching[0].source.slot(), matching[1].source.slot());
    let run = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(startup::RUN, KEY_READ | KEY_WOW64_64KEY)
        .unwrap();
    assert!(
        fixture
            .startup_names
            .iter()
            .all(|n| run.get_raw_value(n).is_ok())
    );
    let mut stale = report.peer.clone();
    stale.created += 1;
    assert!(hunter::stop(&stale).is_err());
    assert!(fixture.child.try_wait().unwrap().is_none());
    hunter::stop(&report.peer).unwrap();
    assert!(!fixture.child.wait().unwrap().success());
    assert!(fixture.root.join("App/fixture.exe").is_file());
    assert!(
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(&fixture.key)
            .is_ok()
    );
    assert!(hunter::inspect_window(window, fixture.child.id(), &cancel).is_err());
}
