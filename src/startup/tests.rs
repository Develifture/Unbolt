use super::*;
use crate::context::{CallerScope, with_scope};
use winreg::RegKey;
fn fixture() -> (PathBuf, Policy) {
    let root =
        std::env::temp_dir().join(format!("unbolt-startup-fixture-{}", recovery::unique_id()));
    let user = root.join("UserStartup");
    fs::create_dir_all(&user).unwrap();
    (
        root,
        Policy {
            user: Some(user),
            common: None,
        },
    )
}
fn scoped(root: &Path, call: impl FnOnce()) {
    with_scope(
        CallerScope {
            data: root.join(recovery::DATA_DIRECTORY),
            ..Default::default()
        },
        call,
    );
}
#[test]
fn file_disable_restore_conflict_stale_and_interrupted_backup_are_reversible() {
    let (root, policy) = fixture();
    scoped(&root, || {
        let file = policy
            .user
            .as_ref()
            .unwrap()
            .join("UnboltStartupFixture.lnk");
        fs::write(&file, b"owned startup fixture").unwrap();
        let source = Source::Folder {
            all_users: false,
            name: "UnboltStartupFixture.lnk".into(),
        };
        let store = root.join("Backups");
        let flag = AtomicBool::new(false);
        let old = fresh(&policy, &store, &source, None, &flag).unwrap();
        fs::write(&file, b"changed content").unwrap();
        assert!(change_at(&policy, &store, &old, Change::Disable, &flag).is_err());
        assert!(file.is_file());
        fs::write(&file, b"owned startup fixture").unwrap();
        let entry = fresh(&policy, &store, &source, None, &flag).unwrap();
        let out = change_at(&policy, &store, &entry, Change::Disable, &flag).unwrap();
        assert!(!file.exists());
        let id = out
            .backup
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        let mut manifest = load(&out.backup).unwrap();
        manifest.state = "prepared".into();
        persist(&out.backup, &manifest).unwrap();
        let disabled = fresh(&policy, &store, &source, Some(id), &flag).unwrap();
        assert_eq!(disabled.state, "Needs recovery review");
        assert!(disabled.mutable());
        fs::write(&file, b"new occupant").unwrap();
        assert!(change_at(&policy, &store, &disabled, Change::Restore, &flag).is_err());
        assert_eq!(fs::read(&file).unwrap(), b"new occupant");
        fs::remove_file(&file).unwrap();
        let disabled = fresh(&policy, &store, &source, Some(id), &flag).unwrap();
        change_at(&policy, &store, &disabled, Change::Restore, &flag).unwrap();
        assert_eq!(fs::read(&file).unwrap(), b"owned startup fixture");
        assert_eq!(load(&out.backup).unwrap().state, "restored");
    });
    assert!(root.starts_with(std::env::temp_dir()));
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn cancellation_backup_failure_and_payload_change_do_not_change_source() {
    let (root, policy) = fixture();
    scoped(&root, || {
        let file = policy
            .user
            .as_ref()
            .unwrap()
            .join("UnboltStartupFixture.lnk");
        fs::write(&file, b"fixture").unwrap();
        let source = Source::Folder {
            all_users: false,
            name: "UnboltStartupFixture.lnk".into(),
        };
        let store = root.join("Backups");
        let flag = AtomicBool::new(false);
        let entry = fresh(&policy, &store, &source, None, &flag).unwrap();
        assert!(
            change_at(
                &policy,
                &store,
                &entry,
                Change::Disable,
                &AtomicBool::new(true)
            )
            .is_err()
        );
        fs::write(&store, b"occupied backup path").unwrap();
        assert!(change_at(&policy, &store, &entry, Change::Disable, &flag).is_err());
        assert_eq!(fs::read(&file).unwrap(), b"fixture");
        fs::remove_file(&store).unwrap();
        let out = change_at(&policy, &store, &entry, Change::Disable, &flag).unwrap();
        fs::write(out.backup.parent().unwrap().join("payload"), b"tampered").unwrap();
        let id = out
            .backup
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        assert!(fresh(&policy, &store, &source, Some(id), &flag).is_err());
        assert!(!file.exists());
    });
    assert!(root.starts_with(std::env::temp_dir()));
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn run_value_transactions_preserve_raw_type_and_other_values() {
    let (root, policy) = fixture();
    let name = format!("UnboltStartupFixture{}", recovery::unique_id());
    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(RUN, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY)
        .unwrap();
    struct Cleanup<'a>(&'a RegKey, String, String);
    impl Drop for Cleanup<'_> {
        fn drop(&mut self) {
            let _ = self.0.delete_value(&self.1);
            let _ = self.0.delete_value(&self.2);
        }
    }
    let other = format!("{name}Other");
    let _cleanup = Cleanup(&key, name.clone(), other.clone());
    let bytes = command::wide("%USERPROFILE%\\UnboltStartupFixtureMissing.exe --fixture")
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let value = RegValue {
        vtype: REG_EXPAND_SZ,
        bytes: bytes.clone().into(),
    };
    key.set_raw_value(&name, &value).unwrap();
    key.set_value(&other, &"fixture sentinel").unwrap();
    scoped(&root, || {
        let source = Source::Registry {
            location: RegistrySource {
                hive: "HKCU".into(),
                view: KEY_WOW64_64KEY,
                key: RUN.into(),
            },
            name: name.clone(),
        };
        let store = root.join("Backups");
        let flag = AtomicBool::new(false);
        let entry = fresh(&policy, &store, &source, None, &flag).unwrap();
        let out = change_at(&policy, &store, &entry, Change::Disable, &flag).unwrap();
        assert!(key.get_raw_value(&name).is_err());
        assert_eq!(
            key.get_value::<String, _>(&other).unwrap(),
            "fixture sentinel"
        );
        let id = out
            .backup
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        let disabled = fresh(&policy, &store, &source, Some(id), &flag).unwrap();
        key.set_value(&name, &"new occupant").unwrap();
        assert!(change_at(&policy, &store, &disabled, Change::Restore, &flag).is_err());
        assert_eq!(key.get_value::<String, _>(&name).unwrap(), "new occupant");
        key.delete_value(&name).unwrap();
        let disabled = fresh(&policy, &store, &source, Some(id), &flag).unwrap();
        change_at(&policy, &store, &disabled, Change::Restore, &flag).unwrap();
        let restored = key.get_raw_value(&name).unwrap();
        assert_eq!(restored.vtype, REG_EXPAND_SZ);
        assert_eq!(restored.bytes.as_ref(), bytes);
    });
    assert!(root.starts_with(std::env::temp_dir()));
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn unsupported_registry_and_folder_sources_are_rejected() {
    let (root, policy) = fixture();
    assert!(
        validate_registry(
            &RegistrySource {
                hive: "HKLM".into(),
                view: KEY_WOW64_64KEY,
                key: "SOFTWARE\\Classes".into()
            },
            "test"
        )
        .is_err()
    );
    for name in ["../file", "folder\\file", "file:stream", "desktop.ini", "."] {
        assert!(policy.file(false, name).is_err());
    }
    assert!(manifest_path(&root, "../elsewhere").is_err());
    assert!(root.starts_with(std::env::temp_dir()));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn redirected_folder_cannot_reuse_an_identical_file_review() {
    let (root, policy) = fixture();
    scoped(&root, || {
        let name = "UnboltStartupFixture.lnk";
        let original = policy.user.as_ref().unwrap().join(name);
        fs::write(&original, b"owned fixture").unwrap();
        let other = root.join("RedirectedStartup");
        fs::create_dir(&other).unwrap();
        fs::hard_link(&original, other.join(name)).unwrap();
        let redirected = Policy {
            user: Some(other.clone()),
            common: None,
        };
        let source = Source::Folder {
            all_users: false,
            name: name.into(),
        };
        let store = root.join("Backups");
        let cancel = AtomicBool::new(false);
        let reviewed = fresh(&policy, &store, &source, None, &cancel).unwrap();
        let changed = fresh(&redirected, &store, &source, None, &cancel).unwrap();
        assert_eq!(reviewed.snapshot, changed.snapshot);
        assert_ne!(
            reviewed.fingerprint().unwrap(),
            changed.fingerprint().unwrap()
        );
        assert!(change_at(&redirected, &store, &reviewed, Change::Disable, &cancel).is_err());
        assert!(original.is_file());
        assert!(other.join(name).is_file());
        let disabled = change_at(&policy, &store, &reviewed, Change::Disable, &cancel).unwrap();
        let id = disabled
            .backup
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        assert!(fresh(&redirected, &store, &source, Some(id), &cancel).is_err());
        let restore = fresh(&policy, &store, &source, Some(id), &cancel).unwrap();
        change_at(&policy, &store, &restore, Change::Restore, &cancel).unwrap();
        assert_eq!(fs::read(&original).unwrap(), b"owned fixture");
    });
    assert!(root.starts_with(std::env::temp_dir()));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn shortcut_targets_remain_identifiable_after_disable_and_share_no_name_based_attribution() {
    let (root, policy) = fixture();
    scoped(&root, || {
        let executable = root.join("Owned Ω.exe");
        let unrelated = root.join("Owned Ω helper.exe");
        fs::write(&executable, b"inert owned target").unwrap();
        fs::write(&unrelated, b"inert other target").unwrap();
        let file = policy
            .user
            .as_ref()
            .unwrap()
            .join("Different friendly name.lnk");
        crate::shell_link::write_fixture(&file, &executable, "--owned \"Ω argument\"", &root);
        let before = fs::read(&file).unwrap();
        let source = Source::Folder {
            all_users: false,
            name: "Different friendly name.lnk".into(),
        };
        let store = root.join("Backups");
        let cancel = AtomicBool::new(false);
        let entry = fresh(&policy, &store, &source, None, &cancel).unwrap();
        assert!(entry.launch_note.is_none());
        assert!(entry.launches(&executable));
        assert!(!entry.launches(&unrelated));
        assert!(entry.matches("owned Ω.exe"));
        assert!(entry.display_command().contains("--owned"));
        let out = change_at(&policy, &store, &entry, Change::Disable, &cancel).unwrap();
        let id = out
            .backup
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        let disabled = fresh(&policy, &store, &source, Some(id), &cancel).unwrap();
        assert!(disabled.launches(&executable));
        change_at(&policy, &store, &disabled, Change::Restore, &cancel).unwrap();
        assert_eq!(fs::read(&file).unwrap(), before);
        assert_eq!(fs::read(&executable).unwrap(), b"inert owned target");
        assert_eq!(fs::read(&unrelated).unwrap(), b"inert other target");
        fs::write(&file, b"not a shortcut").unwrap();
        let unreadable = fresh(&policy, &store, &source, None, &cancel).unwrap();
        assert!(unreadable.mutable());
        assert!(unreadable.launch_note.is_some());
        assert!(!unreadable.launches(&executable));
    });
    assert!(root.starts_with(std::env::temp_dir()));
    fs::remove_dir_all(root).unwrap();
}
