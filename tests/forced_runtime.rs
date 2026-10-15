#![cfg(feature = "test-fixtures")]
use std::{
    fs,
    process::{Child, Command},
    sync::atomic::AtomicBool,
    thread,
    time::{Duration, Instant},
};
use unbolt::{activity, forced, model::Confidence, recovery};
struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
fn running_fixture_blocks_forced_removal_and_closed_fixture_can_be_quarantined() {
    let root =
        std::env::temp_dir().join(format!("unbolt-process-fixture-{}", recovery::unique_id()));
    let folder = root.join("App");
    fs::create_dir_all(&folder).unwrap();
    let exe = folder.join("fixture.exe");
    fs::copy(env!("CARGO_BIN_EXE_unbolt-test-fixture"), &exe).unwrap();
    let marker = root.join("ready.txt");
    let mut child = OwnedChild(
        Command::new(&exe)
            .args(["held", &marker.display().to_string()])
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while fs::read(&marker).ok().as_deref() != Some(b"fixture started".as_slice())
        && Instant::now() < deadline
    {
        thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(fs::read(&marker).unwrap(), b"fixture started");
    let flag = AtomicBool::new(false);
    let blockers = activity::blockers(&folder, &flag).unwrap();
    assert!(
        blockers.iter().any(|p| p.pid == child.0.id()),
        "{blockers:?}"
    );
    let target = forced::folder_target("Unbolt runtime verification", &folder).unwrap();
    let blocked = forced::preview(&target, &flag).unwrap();
    assert_eq!(blocked.report.candidates[0].confidence, Confidence::Blocked);
    assert!(
        forced::execute_at(
            &blocked,
            &forced::Selection {
                files: vec![0],
                registry: vec![]
            },
            &flag,
            &root.join("Recovery")
        )
        .is_err()
    );
    assert!(folder.is_dir());
    fs::write(root.join("release.txt"), b"release").unwrap();
    child.0.wait().unwrap();
    let ready = forced::preview(&target, &flag).unwrap();
    assert_eq!(ready.report.candidates[0].confidence, Confidence::High);
    let result = forced::execute_at(
        &ready,
        &forced::Selection {
            files: vec![0],
            registry: vec![],
        },
        &flag,
        &root.join("Recovery"),
    )
    .unwrap();
    assert_eq!(result.items[0].state, "Removed");
    assert!(!folder.exists());
    assert!(
        result.items[0]
            .backup
            .as_ref()
            .unwrap()
            .parent()
            .unwrap()
            .join("payload/fixture.exe")
            .is_file()
    );
    drop(child);
    assert!(root.starts_with(std::env::temp_dir()));
    assert!(
        root.file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("unbolt-process-fixture-")
    );
    fs::remove_dir_all(root).unwrap();
}
