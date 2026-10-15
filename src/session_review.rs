//! Explicit, non-destructive recovery of deferred uninstall sessions.
use crate::{
    UnboltResult, activity, backup_delete, inventory,
    model::*,
    process::{self, RestartReview, Session},
    recovery, scanner,
};
use std::{
    fs,
    path::{Path, PathBuf},
    ptr::null_mut,
    sync::atomic::AtomicBool,
};
use windows_sys::Win32::{
    Foundation::*,
    System::{JobObjects::*, SystemServices::JOB_OBJECT_QUERY, Threading::*},
};

pub(crate) fn boot_id() -> UnboltResult<u32> {
    // Microsoft documents this successful-boot counter at:
    // https://learn.microsoft.com/windows-hardware/design/device-experiences/oem-hvci-enablement
    use winreg::{RegKey, enums::*};
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters", KEY_READ | KEY_WOW64_64KEY)
        .and_then(|key| key.get_value("BootId"))
        .map_err(|e| format!("Cannot verify the Windows boot counter; uninstall remains pending: {e}"))
}

pub struct Review {
    manifest: PathBuf,
    app: Application,
    session: Session,
    bytes: Vec<u8>,
    boot: u32,
    baseline: Option<u32>,
}

fn read_session(id: &str) -> UnboltResult<(Session, Vec<u8>)> {
    let parts = id.split('-').collect::<Vec<_>>();
    if parts.len() != 3
        || parts
            .iter()
            .any(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err("Invalid uninstall session identifier".into());
    }
    let path = recovery::data_dir()
        .join("process-sessions")
        .join(format!("{id}.json"));
    for ancestor in path.ancestors() {
        scanner::snapshot(ancestor)?;
    }
    if fs::metadata(&path).map_err(|e| e.to_string())?.len() > 1024 * 1024 {
        return Err("Session record is too large".into());
    }
    let bytes = fs::read(&path).map_err(|e| e.to_string())?;
    if bytes.len() > 1024 * 1024 {
        return Err("Session record is too large".into());
    }
    let session: Session = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if session.id != id {
        return Err("Session identifier changed".into());
    }
    Ok((session, bytes))
}

fn eligible(session: &Session) -> UnboltResult<()> {
    if session.error.is_some()
        || !matches!(session.exit_code, Some(0 | 3010 | 1641))
        || !(session.state == "completed-needs-review"
            || (session.state == "completed" && matches!(session.exit_code, Some(3010 | 1641))))
    {
        return Err("This session is running, failed, already resolved, or requires a different recovery review".into());
    }
    Ok(())
}

fn check_processes(session: &Session) -> UnboltResult<()> {
    unsafe {
        if session.root.pid == 0 || session.root.created == 0 {
            return Err("Installer process identity is missing".into());
        }
        let handle = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            session.root.pid,
        );
        if handle.is_null() {
            if GetLastError() != ERROR_INVALID_PARAMETER {
                return Err("Cannot verify whether the original installer has stopped".into());
            }
        } else {
            let mut created: FILETIME = std::mem::zeroed();
            let mut exited = created;
            let mut kernel = created;
            let mut user = created;
            let valid =
                GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) != 0;
            let same = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
            let stopped = WaitForSingleObject(handle, 0);
            CloseHandle(handle);
            if !valid || (same == session.root.created && stopped != WAIT_OBJECT_0) {
                return Err(
                    "The original installer is still running or could not be verified".into(),
                );
            }
        }
        if let Some(name) = &session.job_name {
            let job = OpenJobObjectW(JOB_OBJECT_QUERY, 0, crate::command::wide(name).as_ptr());
            if job.is_null() {
                if GetLastError() != ERROR_FILE_NOT_FOUND {
                    return Err("Cannot verify the installer process group".into());
                }
            } else {
                let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = std::mem::zeroed();
                let ok = QueryInformationJobObject(
                    job,
                    JobObjectBasicAccountingInformation,
                    &mut info as *mut _ as *mut _,
                    std::mem::size_of_val(&info) as u32,
                    null_mut(),
                );
                CloseHandle(job);
                if ok == 0 || info.ActiveProcesses != 0 {
                    return Err(
                        "An installer process group is still active or could not be verified"
                            .into(),
                    );
                }
            }
        }
    }
    Ok(())
}

fn check_application(app: &Application, cancel: &AtomicBool) -> UnboltResult<()> {
    if cancelled(cancel) {
        return Err("Uninstall review cancelled".into());
    }
    if app.sources.is_empty() || inventory::registered(app)? {
        return Err(
            "The saved application has no verifiable registration history or is still registered"
                .into(),
        );
    }
    let current = inventory::collect(cancel);
    if current.cancelled || !current.errors.is_empty() {
        return Err("Current application inventory could not be verified".into());
    }
    if current.apps.iter().any(|a| {
        a.id == app.id
                || a.sources.iter().any(|s| app.sources.contains(s))
                // A replacement registration can have a new key and version.
                // Ambiguous product identity must keep recovery blocked even
                // when no saved installation folder remains to inspect.
                || (!app.name.trim().is_empty()
                    && a.name.trim().eq_ignore_ascii_case(app.name.trim())
                    && a.publisher.trim().eq_ignore_ascii_case(app.publisher.trim()))
                || (!app.uninstall.trim().is_empty()
                    && a.uninstall.trim().eq_ignore_ascii_case(app.uninstall.trim()))
    }) {
        return Err("The application has been registered again; refresh before continuing".into());
    }
    if let Some(path) = &app.location {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                let policy = scanner::PathPolicy::explicit_target(path)?;
                let location = policy.validate(path, &current.apps)?;
                if !activity::blockers(&location, cancel)?.is_empty() {
                    return Err("Application files are still in use; close the application before reviewing again".into());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("Cannot inspect the saved application folder: {e}")),
        }
    }
    Ok(())
}

pub fn prepare(manifest: &Path, session_id: &str, cancel: &AtomicBool) -> UnboltResult<Review> {
    prepare_at_boot(manifest, session_id, cancel, boot_id()?)
}
fn prepare_at_boot(
    manifest: &Path,
    session_id: &str,
    cancel: &AtomicBool,
    boot: u32,
) -> UnboltResult<Review> {
    let app = backup_delete::saved_application(manifest)?;
    let storage = recovery::data_dir().join("process-sessions");
    let _lease = process::reserve_application(&storage, &app.id)?;
    let (session, bytes) = read_session(session_id)?;
    if session.application_id != app.id {
        return Err("The session does not belong to this saved application".into());
    }
    eligible(&session)?;
    let baseline = session
        .boot_id
        .or_else(|| session.restart_review.as_ref().map(|r| r.baseline_boot));
    if baseline.is_some_and(|old| boot <= old) {
        return Err("Restart Windows, then select this uninstall result and review again. The boot counter has not advanced.".into());
    }
    check_processes(&session)?;
    check_application(&app, cancel)?;
    Ok(Review {
        manifest: manifest.to_path_buf(),
        app,
        session,
        bytes,
        boot,
        baseline,
    })
}

impl Review {
    pub fn description(&self) -> String {
        if self.baseline.is_none() {
            format!(
                "{}\r\n\r\nThis older uninstall record has no boot reference. Record the current Windows boot as a reference, then restart Windows and review this result again?\r\n\r\nThe uninstall remains pending. No application files or registry entries will be removed.",
                self.app.name
            )
        } else {
            format!(
                "{}\r\n\r\nA later Windows boot was verified. The saved registration is absent, the recorded installer/process group has stopped, and supported folder checks passed.\r\n\r\nResolve session {} for a fresh leftover review? Other pending or failed sessions still block cleanup. This does not clean any files or restore the application.",
                self.app.name, self.session.id
            )
        }
    }
    pub fn execute(self, cancel: &AtomicBool) -> UnboltResult<String> {
        self.execute_at_boot(cancel, boot_id()?)
    }
    fn execute_at_boot(self, cancel: &AtomicBool, boot: u32) -> UnboltResult<String> {
        let storage = recovery::data_dir().join("process-sessions");
        let _lease = process::reserve_application(&storage, &self.app.id)?;
        if boot != self.boot
            || read_session(&self.session.id)?.1 != self.bytes
            || backup_delete::saved_application(&self.manifest)? != self.app
        {
            return Err("The uninstall review changed; review the current record again".into());
        }
        eligible(&self.session)?;
        check_processes(&self.session)?;
        check_application(&self.app, cancel)?;
        if cancelled(cancel) {
            return Err("Uninstall review cancelled".into());
        }
        let mut session = self.session;
        session.restart_review = Some(RestartReview {
            baseline_boot: self.baseline.unwrap_or(boot),
            resolved_boot: self.baseline.map(|_| boot),
        });
        if self.baseline.is_some() {
            session.state = "resolved-after-restart".into();
        }
        process::save(&storage, &session)?;
        let text = if self.baseline.is_some() {
            "Uninstall session resolved after a verified restart. Use Backups → Review leftovers for a fresh scan. Other unresolved sessions and ownership protections still apply."
        } else {
            "Boot reference recorded. Restart Windows, then review this uninstall result again. Cleanup remains blocked."
        };
        if let Err(error) = recovery::history(
            "uninstall-session-review",
            &self.app.name,
            &format!("Session {}: {text}", session.id),
        ) {
            return Ok(format!(
                "{text}\r\nThe session was saved, but operation history could not be written: {error}"
            ));
        }
        Ok(text.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        command,
        context::{self, CallerScope},
    };

    fn fixture(state: &str, code: i32, boot: Option<u32>, test: impl FnOnce(&Path, &Session)) {
        let root = std::env::temp_dir().join(format!(
            "unbolt-session-review-fixture-{}",
            recovery::unique_id()
        ));
        fs::create_dir_all(root.join("App")).unwrap();
        struct OwnedRoot(PathBuf);
        impl Drop for OwnedRoot {
            fn drop(&mut self) {
                assert!(self.0.starts_with(std::env::temp_dir()));
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _owned = OwnedRoot(root.clone());
        context::with_scope(
            CallerScope {
                data: root.clone(),
                ..Default::default()
            },
            || {
                let source = RegistrySource {
                    hive: "HKCU".into(),
                    view: winreg::enums::KEY_WOW64_64KEY,
                    key: format!(
                        "{}\\UnboltSessionReviewFixture{}",
                        inventory::UNINSTALL_ROOT,
                        recovery::unique_id()
                    ),
                };
                let app = Application {
                    id: inventory::source_id(&source),
                    name: format!("Unbolt owned session fixture {}", recovery::unique_id()),
                    publisher: String::new(),
                    version: "1".into(),
                    location: Some(root.join("App")),
                    uninstall: String::new(),
                    quiet_uninstall: String::new(),
                    size_kib: None,
                    system_component: false,
                    sources: vec![source],
                };
                let directory = root.join("registry-backups").join(recovery::unique_id());
                fs::create_dir_all(&directory).unwrap();
                let manifest = directory.join("application.json");
                fs::write(&manifest, serde_json::to_vec(&app).unwrap()).unwrap();
                let cmd = command::parse(&format!(
                    "{} --list",
                    command::quote_argument(
                        &std::env::current_exe().unwrap().display().to_string()
                    )
                ))
                .unwrap();
                let mut session = process::run_at(
                    &cmd,
                    &app.id,
                    &AtomicBool::new(false),
                    &root.join("process-sessions"),
                )
                .unwrap()
                .session;
                session.state = state.into();
                session.exit_code = Some(code);
                session.boot_id = boot;
                process::save(&root.join("process-sessions"), &session).unwrap();
                test(&manifest, &session);
            },
        );
    }
    fn check(manifest: &Path, session: &Session, boot: u32) -> UnboltResult<Review> {
        prepare_at_boot(manifest, &session.id, &AtomicBool::new(false), boot)
    }

    #[test]
    fn restart_resolution_preserves_exit_result_and_releases_cleanup_and_forced_gates() {
        for (state, code) in [
            ("completed", 3010),
            ("completed", 1641),
            ("completed-needs-review", 0),
        ] {
            fixture(state, code, Some(100), |manifest, session| {
                let flag = AtomicBool::new(false);
                assert!(process::assert_cleanup_ready(&session.application_id).is_err());
                assert!(process::assert_forced_ready(&session.application_id).is_err());
                assert!(check(manifest, session, 100).is_err());
                assert!(check(manifest, session, 99).is_err());
                check(manifest, session, 101)
                    .unwrap()
                    .execute_at_boot(&flag, 101)
                    .unwrap();
                let resolved = read_session(&session.id).unwrap().0;
                assert!(resolved.restart_resolved());
                assert_eq!(resolved.exit_code, Some(code));
                assert_eq!(resolved.scope, session.scope);
                process::assert_cleanup_ready(&session.application_id).unwrap();
                process::assert_forced_ready(&session.application_id).unwrap();
                assert!(manifest.is_file());
            });
        }
    }
    #[test]
    fn legacy_session_requires_reference_boot_then_a_later_boot() {
        fixture("completed-needs-review", 0, None, |manifest, session| {
            let path = recovery::data_dir()
                .join("process-sessions")
                .join(format!("{}.json", session.id));
            let mut old: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            old.as_object_mut().unwrap().remove("boot_id");
            old.as_object_mut().unwrap().remove("restart_review");
            fs::write(path, serde_json::to_vec(&old).unwrap()).unwrap();
            let flag = AtomicBool::new(false);
            check(manifest, session, 100)
                .unwrap()
                .execute_at_boot(&flag, 100)
                .unwrap();
            assert!(process::assert_cleanup_ready(&session.application_id).is_err());
            assert!(check(manifest, session, 100).is_err());
            check(manifest, session, 101)
                .unwrap()
                .execute_at_boot(&flag, 101)
                .unwrap();
            process::assert_cleanup_ready(&session.application_id).unwrap();
        });
    }
    #[test]
    fn cancelled_changed_and_cross_boot_reviews_do_not_resolve() {
        fixture("completed", 3010, Some(100), |manifest, session| {
            let flag = AtomicBool::new(false);
            assert!(prepare_at_boot(manifest, &session.id, &AtomicBool::new(true), 101).is_err());
            assert!(
                check(manifest, session, 101)
                    .unwrap()
                    .execute_at_boot(&AtomicBool::new(true), 101)
                    .is_err()
            );
            assert!(
                check(manifest, session, 101)
                    .unwrap()
                    .execute_at_boot(&flag, 102)
                    .is_err()
            );
            let plan = check(manifest, session, 101).unwrap();
            let mut changed = session.clone();
            changed.scope.push_str(" changed");
            process::save(&recovery::data_dir().join("process-sessions"), &changed).unwrap();
            assert!(plan.execute_at_boot(&flag, 101).is_err());
            assert!(process::assert_cleanup_ready(&session.application_id).is_err());
        });
    }
    #[test]
    fn wrong_application_failed_and_running_sessions_stay_blocked() {
        fixture(
            "completed-needs-review",
            0,
            Some(100),
            |manifest, session| {
                let storage = recovery::data_dir().join("process-sessions");
                for (state, exit, error) in [
                    ("running", Some(0), None),
                    ("completed", Some(1603), None),
                    (
                        "completed-needs-review",
                        Some(0),
                        Some("tracking error".into()),
                    ),
                    ("completed-needs-review", None, None),
                ] {
                    let mut invalid = session.clone();
                    invalid.state = state.into();
                    invalid.exit_code = exit;
                    invalid.error = error;
                    process::save(&storage, &invalid).unwrap();
                    assert!(check(manifest, session, 101).is_err());
                }
                let mut wrong = session.clone();
                wrong.application_id.push_str("-other");
                process::save(&storage, &wrong).unwrap();
                assert!(check(manifest, session, 101).is_err());
                assert!(
                    prepare_at_boot(manifest, "../outside", &AtomicBool::new(false), 101).is_err()
                );
            },
        );
    }
    #[test]
    fn live_root_and_active_operation_cannot_be_resolved() {
        fixture(
            "completed-needs-review",
            0,
            Some(100),
            |manifest, session| {
                let storage = recovery::data_dir().join("process-sessions");
                let mut live = session.clone();
                let peer = crate::broker::identity::process(std::process::id()).unwrap();
                live.root = process::ProcessIdentity {
                    pid: peer.pid,
                    created: peer.created,
                };
                process::save(&storage, &live).unwrap();
                assert!(check(manifest, session, 101).is_err());
                process::save(&storage, session).unwrap();
                let _lease =
                    process::reserve_application(&storage, &session.application_id).unwrap();
                assert!(check(manifest, session, 101).is_err());
            },
        );
    }
    #[test]
    fn reappearing_registration_invalidates_confirmed_review() {
        fixture("completed", 3010, Some(100), |manifest, session| {
            use winreg::{RegKey, enums::*};
            let plan = check(manifest, session, 101).unwrap();
            let source = plan.app.sources[0].clone();
            let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(&source.key)
                .unwrap();
            let result = plan.execute_at_boot(&AtomicBool::new(false), 101);
            drop(key);
            RegKey::predef(HKEY_CURRENT_USER)
                .delete_subkey_all(&source.key)
                .unwrap();
            assert!(result.is_err());
            assert!(process::assert_cleanup_ready(&session.application_id).is_err());
        });
    }
    #[test]
    fn replacement_registration_with_new_source_invalidates_review_without_a_folder() {
        for missing_folder in [false, true] {
            fixture("completed", 3010, Some(100), |manifest, session| {
                use winreg::{RegKey, enums::*};
                let mut app = backup_delete::saved_application(manifest).unwrap();
                if missing_folder {
                    app.location = Some(recovery::data_dir().join("absent-folder"));
                } else {
                    app.location = None;
                }
                fs::write(manifest, serde_json::to_vec(&app).unwrap()).unwrap();
                let plan = check(manifest, session, 101).unwrap();
                let key_path = format!(
                    "{}\\UnboltReplacement{}",
                    inventory::UNINSTALL_ROOT,
                    recovery::unique_id()
                );
                struct OwnedKey(String);
                impl Drop for OwnedKey {
                    fn drop(&mut self) {
                        let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.0);
                    }
                }
                let _owned = OwnedKey(key_path.clone());
                let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
                    .create_subkey(&key_path)
                    .unwrap();
                key.set_value("DisplayName", &app.name).unwrap();
                key.set_value("Publisher", &app.publisher).unwrap();
                key.set_value("DisplayVersion", &app.version).unwrap();
                key.set_value("UninstallString", &app.uninstall).unwrap();
                if let Some(path) = &app.location {
                    key.set_value("InstallLocation", &path.display().to_string())
                        .unwrap();
                }
                let replacement_id = inventory::source_id(&RegistrySource {
                    hive: "HKCU".into(),
                    view: KEY_WOW64_64KEY,
                    key: key_path,
                });
                assert_ne!(app.id, replacement_id);
                let _active = process::reserve_application(
                    &recovery::data_dir().join("process-sessions"),
                    &replacement_id,
                )
                .unwrap();
                assert!(check(manifest, session, 101).is_err());
                assert!(plan.execute_at_boot(&AtomicBool::new(false), 101).is_err());
                assert!(!read_session(&session.id).unwrap().0.restart_resolved());
            });
        }
    }
    #[test]
    fn pending_sessions_keep_exports_until_resolution_and_recheck_after_confirmation() {
        for (state, code) in [("completed-needs-review", 0), ("completed", 3010)] {
            fixture(state, code, Some(100), |manifest, session| {
                let app = backup_delete::saved_application(manifest).unwrap();
                let record = crate::records::BackupRecord {
                    id: manifest
                        .parent()
                        .unwrap()
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .into(),
                    kind: "Registration export".into(),
                    application: app.name,
                    state: "Exported".into(),
                    original: String::new(),
                    manifest: manifest.into(),
                    recoverable: false,
                };
                let flag = AtomicBool::new(false);
                assert!(backup_delete::prepare(std::slice::from_ref(&record), &flag).is_err());
                check(manifest, session, 101)
                    .unwrap()
                    .execute_at_boot(&flag, 101)
                    .unwrap();
                let plan = backup_delete::prepare(std::slice::from_ref(&record), &flag).unwrap();
                // A new pending session after confirmation must retain the export.
                process::save(&recovery::data_dir().join("process-sessions"), session).unwrap();
                assert!(plan.execute(&flag).is_err());
                assert!(manifest.exists());
                check(manifest, session, 101)
                    .unwrap()
                    .execute_at_boot(&flag, 101)
                    .unwrap();
                let plan = backup_delete::prepare(std::slice::from_ref(&record), &flag).unwrap();
                let active = process::reserve_application(
                    &recovery::data_dir().join("process-sessions"),
                    &session.application_id,
                )
                .unwrap();
                assert!(plan.execute(&flag).is_err());
                assert!(manifest.exists());
                drop(active);
                backup_delete::prepare(&[record], &flag)
                    .unwrap()
                    .execute(&flag)
                    .unwrap();
                assert!(!manifest.exists());
            });
        }
    }
    #[test]
    fn resolving_one_record_does_not_clear_other_pending_sessions() {
        fixture(
            "completed-needs-review",
            0,
            Some(100),
            |manifest, session| {
                let mut other = session.clone();
                other.id = recovery::unique_id();
                process::save(&recovery::data_dir().join("process-sessions"), &other).unwrap();
                check(manifest, session, 101)
                    .unwrap()
                    .execute_at_boot(&AtomicBool::new(false), 101)
                    .unwrap();
                assert!(process::assert_cleanup_ready(&session.application_id).is_err());
                assert!(!read_session(&other.id).unwrap().0.restart_resolved());
            },
        );
    }
    #[test]
    fn changed_backup_and_directory_replacement_are_rejected() {
        fixture("completed", 3010, Some(100), |manifest, session| {
            let plan = check(manifest, session, 101).unwrap();
            let mut app = plan.app.clone();
            app.location = None;
            fs::write(manifest, serde_json::to_vec(&app).unwrap()).unwrap();
            assert!(plan.execute_at_boot(&AtomicBool::new(false), 101).is_err());
            assert!(process::assert_cleanup_ready(&session.application_id).is_err());
            // A directory in place of a session is never treated as a record.
            let path = recovery::data_dir()
                .join("process-sessions")
                .join(format!("{}.json", session.id));
            fs::remove_file(&path).unwrap();
            fs::create_dir(path).unwrap();
            assert!(check(manifest, session, 101).is_err());
        });
    }
    #[test]
    fn session_directory_junction_cannot_redirect_review_writes() {
        fixture("completed", 3010, Some(100), |manifest, session| {
            let root = recovery::data_dir();
            let store = root.join("process-sessions");
            let external = root.join("external-sessions");
            let original = fs::read(store.join(format!("{}.json", session.id))).unwrap();
            fs::rename(&store, &external).unwrap();
            let result = std::process::Command::new("cmd.exe")
                .args(["/c", "mklink", "/J"])
                .arg(&store)
                .arg(&external)
                .output()
                .unwrap();
            assert!(result.status.success());
            let rejected = check(manifest, session, 101).is_err();
            let unchanged =
                fs::read(external.join(format!("{}.json", session.id))).unwrap() == original;
            fs::remove_dir(&store).unwrap();
            fs::rename(&external, &store).unwrap();
            assert!(rejected && unchanged);
        });
    }
}
