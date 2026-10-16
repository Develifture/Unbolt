use crate::{
    UnboltResult,
    command::{self, UninstallCommand},
    inventory,
    model::*,
    process, recovery,
};
use serde::{Deserialize, Serialize};
use std::sync::atomic::AtomicBool;

#[derive(Clone, Copy, Serialize, Deserialize)]
pub enum Mode {
    Normal,
    Quiet,
    ForcedMsi { quiet: bool },
}

fn product_code(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    if bytes.len() != 38 || bytes[0] != b'{' || bytes[37] != b'}' {
        return None;
    }
    for (i, b) in bytes.iter().enumerate().take(37).skip(1) {
        if [9, 14, 19, 24].contains(&i) {
            if *b != b'-' {
                return None;
            }
        } else if !b.is_ascii_hexdigit() {
            return None;
        }
    }
    Some(value.to_ascii_uppercase())
}

fn command_product(cmd: &UninstallCommand, system: &str) -> UnboltResult<Option<String>> {
    let expected = std::fs::canonicalize(system).map_err(|e| e.to_string())?;
    if std::fs::canonicalize(&cmd.executable).map_err(|e| e.to_string())? != expected {
        return Ok(None);
    }
    let mut codes = Vec::new();
    let mut args = cmd.arguments.iter();
    while let Some(arg) = args.next() {
        let lower = arg.to_ascii_lowercase();
        if lower == "/i" || lower == "/x" {
            let code = args
                .next()
                .and_then(|v| product_code(v))
                .ok_or("MSI command has no valid product GUID")?;
            codes.push(code);
        } else if lower.starts_with("/i{") || lower.starts_with("/x{") {
            codes.push(product_code(&arg[2..]).ok_or("Malformed MSI product GUID")?);
        }
    }
    codes.sort();
    codes.dedup();
    if codes.len() > 1 {
        return Err("MSI command names more than one product".into());
    }
    Ok(codes.pop())
}

pub fn prepare_mode(app: &Application, mode: Mode) -> UnboltResult<UninstallCommand> {
    let Mode::ForcedMsi { quiet } = mode else {
        return prepare(app, matches!(mode, Mode::Quiet));
    };
    if app.system_component {
        return Err("System components are excluded from forced MSI removal".into());
    }
    let system = command::system_msiexec()?;
    let mut codes = Vec::new();
    if let Ok(cmd) = command::parse(&app.uninstall)
        && let Some(code) = command_product(&cmd, &system)?
    {
        codes.push(code);
    }
    for source in &app.sources {
        if let Some(code) = source.key.rsplit('\\').next().and_then(product_code)
            && let Ok(key) = inventory::hive(&source.hive)?
                .open_subkey_with_flags(&source.key, winreg::enums::KEY_READ | source.view)
            && key.get_value::<u32, _>("WindowsInstaller").ok() == Some(1)
        {
            codes.push(code);
        }
    }
    codes.sort();
    codes.dedup();
    if codes.len() != 1 {
        return Err("Forced MSI needs one verified Windows Installer product GUID".into());
    }
    command::parse(&format!(
        "{} /x {} /norestart{}",
        command::quote_argument(&system),
        codes[0],
        if quiet { " /qn" } else { "" }
    ))
}

pub fn prepare(app: &Application, quiet: bool) -> UnboltResult<UninstallCommand> {
    if app.system_component {
        return Err("System-component uninstall is excluded in this release.".into());
    }
    if quiet {
        if app.quiet_uninstall.is_empty() {
            return Err("No registered quiet command. Use normal uninstall.".into());
        }
        command::parse(&app.quiet_uninstall)
    } else {
        command::parse(&app.uninstall)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UninstallOutcome {
    pub application: String,
    pub status: String,
    pub exit_code: Option<i32>,
    pub backup: String,
    pub elapsed_ms: u128,
    pub process_session: String,
    pub tracking_scope: String,
    pub tracked_processes: u32,
    pub safe_to_scan: bool,
}

fn completion_status(cancelled: bool, exit_code: Option<i32>, safe_to_scan: bool) -> &'static str {
    if cancelled {
        "Queue stopped; the running uninstaller is still monitored. Cleanup is deferred."
    } else if matches!(exit_code, Some(3010 | 1641)) {
        "Restart required before cleanup can be reviewed."
    } else if exit_code == Some(1639) {
        "Uninstaller rejected the command line (1639); cleanup is deferred."
    } else if exit_code.is_some_and(|code| code != 0) {
        "Uninstaller reported an error or an unrecognized status; cleanup is deferred."
    } else if !safe_to_scan {
        "Process tracking needs review; cleanup is deferred."
    } else {
        "Uninstaller and tracked children finished; review remaining locations."
    }
}

pub fn run(app: &Application, quiet: bool, cancel: &AtomicBool) -> UnboltResult<UninstallOutcome> {
    run_mode(app, if quiet { Mode::Quiet } else { Mode::Normal }, cancel)
}

pub fn run_mode(
    app: &Application,
    mode: Mode,
    cancel: &AtomicBool,
) -> UnboltResult<UninstallOutcome> {
    if cancelled(cancel) {
        return Err("Cancelled before uninstall.".into());
    }
    process::assert_idle(&app.id)?;
    if !inventory::registered(app)? {
        return Err("Application registration changed; refresh the list.".into());
    }
    let cmd = prepare_mode(app, mode)?;
    let current = inventory::collect(cancel);
    if current.cancelled || !current.errors.is_empty() {
        return Err("Current inventory could not be verified; refresh before uninstall.".into());
    }
    let current_app = current
        .apps
        .iter()
        .find(|a| a.sources.iter().any(|s| app.sources.contains(s)))
        .ok_or("Application registration changed; refresh before uninstall.")?;
    if current_app != app {
        return Err(
            "Application details changed since review; refresh and review before uninstall.".into(),
        );
    }
    let current_command = prepare_mode(current_app, mode)?;
    if current_command.executable != cmd.executable || current_command.arguments != cmd.arguments {
        return Err("Uninstall command changed since review; refresh before uninstall.".into());
    }
    // Hold the same lease from export creation through installer monitoring,
    // so backup disposal cannot remove recovery evidence before launch.
    let storage = recovery::data_dir().join("process-sessions");
    let lease = process::reserve_application(&storage, &app.id)?;
    process::assert_idle(&app.id)?;
    let backup = recovery::backup_registration(current_app)?;
    recovery::history("uninstall-start", &app.name, &cmd.original)?;
    let result = match process::run_reserved(
        &cmd,
        &app.id,
        cancel,
        &storage,
        lease,
        Some(&backup.join("application.json")),
    ) {
        Ok(result) => result,
        Err(e) => {
            let _ = recovery::history("uninstall-launch-failed", &app.name, &e);
            return Err(e);
        }
    };
    let status = completion_status(
        result.cancelled,
        result.session.exit_code,
        result.safe_to_scan,
    );
    let outcome = UninstallOutcome {
        application: app.name.clone(),
        status: status.into(),
        exit_code: result.session.exit_code,
        backup: backup.display().to_string(),
        elapsed_ms: result.elapsed_ms,
        process_session: result.session.id,
        tracking_scope: result.session.scope,
        tracked_processes: result.session.total_processes,
        safe_to_scan: result.safe_to_scan && result.session.exit_code == Some(0),
    };
    Ok(record_outcome(outcome))
}

fn record_outcome(mut outcome: UninstallOutcome) -> UninstallOutcome {
    let recorded = serde_json::to_string(&outcome)
        .map_err(|e| e.to_string())
        .and_then(|detail| recovery::history("uninstall-result", &outcome.application, &detail));
    if let Err(error) = recorded {
        // The installer already ran. Preserve its result and preview eligibility
        // while reporting the audit failure separately from a launch rejection.
        outcome
            .status
            .push_str(&format!(" Operation history could not be written: {error}"));
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    const GUID: &str = "{01234567-89AB-CDEF-0123-456789ABCDEF}";
    #[test]
    fn completed_process_keeps_preview_eligibility_when_final_history_write_fails() {
        let root = std::env::temp_dir().join(format!(
            "unbolt-outcome-log-fixture-{}",
            recovery::unique_id()
        ));
        fs::create_dir_all(root.join("history.jsonl")).unwrap();
        let result = crate::context::with_scope(
            crate::context::CallerScope {
                data: root.clone(),
                ..Default::default()
            },
            || {
                let cmd = command::parse(&format!(
                    "{} --list",
                    command::quote_argument(
                        &std::env::current_exe().unwrap().display().to_string()
                    )
                ))
                .unwrap();
                let result =
                    process::run(&cmd, "owned-log-failure-fixture", &AtomicBool::new(false))
                        .unwrap();
                assert_eq!(result.session.exit_code, Some(0));
                assert!(result.safe_to_scan);
                let id = result.session.id.clone();
                let outcome = record_outcome(UninstallOutcome {
                    application: "Owned logging fixture".into(),
                    status: completion_status(false, result.session.exit_code, result.safe_to_scan)
                        .into(),
                    exit_code: result.session.exit_code,
                    backup: root.join("owned-export").display().to_string(),
                    elapsed_ms: result.elapsed_ms,
                    process_session: id.clone(),
                    tracking_scope: result.session.scope,
                    tracked_processes: result.session.total_processes,
                    safe_to_scan: result.safe_to_scan,
                });
                assert!(outcome.safe_to_scan);
                assert_eq!(outcome.process_session, id);
                assert_eq!(outcome.exit_code, Some(0));
                assert!(outcome.status.contains("tracked children finished"));
                assert!(
                    outcome
                        .status
                        .contains("Operation history could not be written")
                );
                assert!(
                    process::sessions()
                        .unwrap()
                        .iter()
                        .any(|s| s.id == id && s.state == "completed")
                );
                outcome
            },
        );
        assert!(result.safe_to_scan);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn changed_location_with_unchanged_command_is_rejected_before_backup_or_launch() {
        use winreg::{RegKey, enums::*};
        let name = format!("UnboltStaleReviewFixture{}", recovery::unique_id());
        let key_path = format!("{}\\{name}", inventory::UNINSTALL_ROOT);
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
        key.set_value("DisplayName", &name).unwrap();
        key.set_value(
            "UninstallString",
            &format!(
                "{} --list",
                command::quote_argument(&std::env::current_exe().unwrap().display().to_string())
            ),
        )
        .unwrap();
        let root =
            std::env::temp_dir().join(format!("unbolt-stale-review-{}", recovery::unique_id()));
        std::fs::create_dir_all(&root).unwrap();
        key.set_value("InstallLocation", &root.join("old").display().to_string())
            .unwrap();
        let flag = AtomicBool::new(false);
        let before = inventory::collect(&flag);
        assert!(before.errors.is_empty());
        let app = before.apps.into_iter().find(|a| a.name == name).unwrap();
        key.set_value("InstallLocation", &root.join("new").display().to_string())
            .unwrap();
        let result = crate::context::with_scope(
            crate::context::CallerScope {
                data: root.clone(),
                ..Default::default()
            },
            || run_mode(&app, Mode::Normal, &flag),
        );
        let no_side_effects =
            !root.join("registry-backups").exists() && !root.join("process-sessions").exists();
        std::fs::remove_dir_all(root).unwrap();
        assert!(result.is_err(), "stale review accepted: {result:?}");
        assert!(
            no_side_effects,
            "stale review created backup or launched a process"
        );
    }
    #[test]
    fn failed_installer_is_reported_as_an_error_rather_than_a_tracking_problem() {
        assert!(completion_status(false, Some(1639), false).contains("command line (1639)"));
        assert!(completion_status(false, Some(1603), false).contains("reported an error"));
        assert!(completion_status(false, Some(3010), false).contains("Restart required"));
        assert!(completion_status(false, Some(0), false).contains("tracking needs review"));
        assert!(completion_status(false, Some(0), true).contains("tracked children finished"));
        assert!(completion_status(true, Some(1639), false).contains("Queue stopped"));
    }
    #[test]
    fn newly_merged_registry_source_is_rejected_before_backup_or_launch() {
        use winreg::{RegKey, enums::*};
        let name = format!("UnboltMergedReviewFixture{}", recovery::unique_id());
        let paths = [
            format!("{}\\{name}-a", inventory::UNINSTALL_ROOT),
            format!("{}\\{name}-b", inventory::UNINSTALL_ROOT),
        ];
        struct OwnedKeys([String; 2]);
        impl Drop for OwnedKeys {
            fn drop(&mut self) {
                for path in &self.0 {
                    let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(path);
                }
            }
        }
        let _owned = OwnedKeys(paths.clone());
        let command = format!(
            "{} --list",
            command::quote_argument(&std::env::current_exe().unwrap().display().to_string())
        );
        let populate = |path: &str| {
            let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(path)
                .unwrap();
            key.set_value("DisplayName", &name).unwrap();
            key.set_value("UninstallString", &command).unwrap();
        };
        populate(&paths[0]);
        let flag = AtomicBool::new(false);
        let before = inventory::collect(&flag);
        assert!(before.errors.is_empty());
        let app = before.apps.into_iter().find(|a| a.name == name).unwrap();
        populate(&paths[1]);
        let current = inventory::collect(&flag);
        assert!(current.errors.is_empty());
        assert!(
            current
                .apps
                .iter()
                .find(|a| a.name == name)
                .unwrap()
                .sources
                .len()
                > app.sources.len()
        );
        let root =
            std::env::temp_dir().join(format!("unbolt-merged-review-{}", recovery::unique_id()));
        let result = crate::context::with_scope(
            crate::context::CallerScope {
                data: root.clone(),
                ..Default::default()
            },
            || run_mode(&app, Mode::Normal, &flag),
        );
        assert!(result.unwrap_err().contains("Application details changed"));
        assert!(!root.exists());
    }
    #[test]
    fn rejects_injected_or_ambiguous_msi_product_identifiers() {
        assert_eq!(
            product_code(&GUID.to_ascii_lowercase()).as_deref(),
            Some(GUID)
        );
        for invalid in [
            format!("{GUID} /qn"),
            GUID.replace('A', "Z"),
            GUID.replace('-', " "),
            GUID.trim_matches(['{', '}']).into(),
        ] {
            assert!(product_code(&invalid).is_none());
        }
        let system = command::system_msiexec().unwrap();
        let cmd = command::parse(&format!(
            "{} /I{} /X{{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}}",
            command::quote_argument(&system),
            GUID
        ))
        .unwrap();
        assert!(command_product(&cmd, &system).is_err());
    }
    #[test]
    fn verifies_system_installer_and_supports_joined_or_separate_switches() {
        let system = command::system_msiexec().unwrap();
        for switch in [format!("/I{GUID}"), format!("/x {GUID}")] {
            let cmd =
                command::parse(&format!("{} {switch}", command::quote_argument(&system))).unwrap();
            assert_eq!(
                command_product(&cmd, &system).unwrap().as_deref(),
                Some(GUID)
            );
        }
        let own_exe = std::env::current_exe().unwrap();
        let cmd = command::parse(&format!(
            "{} /x {GUID}",
            command::quote_argument(&own_exe.display().to_string())
        ))
        .unwrap();
        assert!(command_product(&cmd, &system).unwrap().is_none());
    }
}
