//! Explicit, selective removal without invoking a broken third-party uninstaller.
use crate::{
    UnboltResult, activity, inventory,
    model::*,
    process, recovery, registration, registry_cleanup,
    scanner::{self, PathPolicy},
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::Instant,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Plan {
    pub report: ScanReport,
    pub registration_start: usize,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Selection {
    pub files: Vec<usize>,
    pub registry: Vec<usize>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ItemResult {
    pub kind: String,
    pub label: String,
    pub state: String,
    pub message: String,
    pub backup: Option<PathBuf>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Outcome {
    pub id: String,
    pub application: String,
    pub status: String,
    pub items: Vec<ItemResult>,
    pub cancelled: bool,
}

pub fn folder_target(name: &str, folder: &Path) -> UnboltResult<Application> {
    let name = name.trim();
    if name.chars().count() < 3
        || name.chars().count() > 200
        || name.contains(['\0', '\r', '\n', '\\', '/'])
    {
        return Err("Supply a product name between 3 and 200 characters".into());
    }
    if !folder.is_dir() {
        return Err("Choose an existing application directory".into());
    }
    Ok(Application {
        id: format!("manual:{}", scanner::normalize(folder)),
        name: name.into(),
        publisher: String::new(),
        version: String::new(),
        location: Some(folder.into()),
        uninstall: String::new(),
        quiet_uninstall: String::new(),
        size_kib: None,
        system_component: false,
        sources: vec![],
    })
}
fn validate_target(app: &Application, current: &Inventory) -> UnboltResult<Vec<Application>> {
    if current.cancelled || !current.errors.is_empty() {
        return Err(
            "Complete current application inventory is required before forced removal".into(),
        );
    }
    if app.system_component {
        return Err("System components cannot be forcibly removed".into());
    }
    if app.sources.is_empty() {
        let location = app
            .location
            .as_deref()
            .ok_or("A manual target needs its exact directory")?;
        // The folder can disappear after quarantine; validate the declared identity without requiring existence.
        if app.id != format!("manual:{}", scanner::normalize(location))
            || app.name.trim() != app.name
            || app.name.chars().count() < 3
            || app.name.chars().count() > 200
            || app.name.contains(['\0', '\r', '\n', '\\', '/'])
            || !app.uninstall.is_empty()
            || !app.quiet_uninstall.is_empty()
        {
            return Err("Inconsistent manual folder target".into());
        }
    } else if !current.apps.iter().any(|a| a == app) {
        return Err(
            "The selected application's registration changed; refresh and review again".into(),
        );
    }
    Ok(current
        .apps
        .iter()
        .filter(|a| a.id != app.id)
        .cloned()
        .collect())
}
pub fn preview(app: &Application, cancel: &AtomicBool) -> UnboltResult<Plan> {
    let start = Instant::now();
    process::assert_forced_ready(&app.id)?;
    let current = inventory::collect(cancel);
    let others = validate_target(app, &current)?;
    let mut report = ScanReport {
        app: app.clone(),
        candidates: vec![],
        registry_candidates: vec![],
        errors: vec![],
        elapsed_ms: 0,
        cancelled: false,
        app_registered: inventory::registered(app)?,
    };
    let mut activity_error = None;
    if let Some(path) = app.location.as_deref()
        && path.exists()
    {
        let policy = PathPolicy::explicit_target(path)?;
        let validated = policy
            .validate(path, &others)
            .and_then(|_| scanner::tree_signature(path, cancel));
        let (confidence,evidence,signature)=match validated {
            Ok(signature)=>match activity::blockers(path,cancel) {
                Ok(p) if p.is_empty()=>(Confidence::High,"Exact reviewed application directory; files in use checked with Windows Restart Manager.".into(),Some(signature)),
                Ok(p)=>{let text=format!("Close these processes and review again: {}",p.iter().map(|p|format!("{} (PID {})",p.name,p.pid)).collect::<Vec<_>>().join(", ")); activity_error=Some(text.clone());(Confidence::Blocked,text,Some(signature))},
                Err(e)=>{activity_error=Some(e.clone());(Confidence::Blocked,e,Some(signature))},
            },
            Err(e)=>(Confidence::Blocked,e,None),
        };
        report.candidates.push(Candidate {
            path: path.into(),
            confidence,
            evidence,
            snapshot: scanner::snapshot(path)?,
            tree_signature: signature,
        });
    }
    report.registry_candidates =
        registry_cleanup::scan(app, &current.apps, false, cancel, &mut report.errors);
    let registration_start = report.registry_candidates.len();
    report
        .registry_candidates
        .extend(registration::candidates(app, cancel)?);
    if let Some(error) = activity_error {
        report.errors.push(error.clone());
        for candidate in &mut report.registry_candidates {
            candidate.confidence = Confidence::Blocked;
            candidate.evidence = error.clone();
        }
    }
    report.elapsed_ms = start.elapsed().as_millis();
    report.cancelled = cancelled(cancel);
    Ok(Plan {
        report,
        registration_start,
    })
}

pub fn execute(plan: &Plan, selection: &Selection, cancel: &AtomicBool) -> UnboltResult<Outcome> {
    execute_at(plan, selection, cancel, &recovery::data_dir())
}
fn persist(path: &Path, result: &Outcome) -> UnboltResult<()> {
    let pending = path.with_extension("pending");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&pending)
        .map_err(|e| e.to_string())?;
    use std::io::Write;
    file.write_all(&serde_json::to_vec_pretty(result).map_err(|e| e.to_string())?)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    fs::rename(pending, path).map_err(|e| e.to_string())
}
fn selected_indices(indices: &[usize], length: usize) -> UnboltResult<Vec<usize>> {
    let mut result = indices.to_vec();
    result.sort_unstable();
    result.dedup();
    if result.iter().any(|&i| i >= length) {
        return Err("Selection is outside the reviewed plan".into());
    }
    Ok(result)
}
pub fn execute_at(
    plan: &Plan,
    selection: &Selection,
    cancel: &AtomicBool,
    storage: &Path,
) -> UnboltResult<Outcome> {
    if cancelled(cancel) || plan.report.cancelled {
        return Err("Cancelled before forced removal".into());
    }
    let app = &plan.report.app;
    let _lease = process::reserve_application(&storage.join("process-sessions"), &app.id)?;
    process::assert_forced_ready(&app.id)?;
    let others = validate_target(app, &inventory::collect(cancel))?;
    let files = selected_indices(&selection.files, plan.report.candidates.len())?;
    let registry = selected_indices(&selection.registry, plan.report.registry_candidates.len())?;
    if files.is_empty() && registry.is_empty() {
        return Err("Check one or more reviewed removal items".into());
    }
    if plan.registration_start > plan.report.registry_candidates.len() {
        return Err("Invalid registration boundary".into());
    }
    for &i in &files {
        let c = &plan.report.candidates[i];
        if c.confidence != Confidence::High || app.location.as_ref() != Some(&c.path) {
            return Err("File selection lacks exact ownership evidence".into());
        }
        PathPolicy::explicit_target(&c.path)?.validate(&c.path, &others)?;
        if scanner::snapshot(&c.path)? != c.snapshot
            || Some(scanner::tree_signature(&c.path, cancel)?) != c.tree_signature
        {
            return Err("Directory changed since review; preview again".into());
        }
    }
    // Check use again just before any selected resources change, even for an entry-only selection.
    if let Some(path) = app.location.as_deref()
        && path.exists()
        && !activity::blockers(path, cancel)?.is_empty()
    {
        return Err(
            "Application files are now in use; close the application and review again".into(),
        );
    }
    let fresh_product_keys = registry_cleanup::scan(
        app,
        &inventory::collect(cancel).apps,
        false,
        cancel,
        &mut vec![],
    );
    for &i in &registry {
        if plan.report.registry_candidates[i].confidence != Confidence::High {
            return Err("Registry selection requires ownership review".into());
        }
        let candidate = &plan.report.registry_candidates[i];
        if i < plan.registration_start
            && !fresh_product_keys.iter().any(|c| {
                c.source == candidate.source
                    && c.snapshot == candidate.snapshot
                    && c.confidence == Confidence::High
            })
        {
            return Err(
                "Product settings changed or their ownership cannot be verified; review again"
                    .into(),
            );
        }
    }
    let id = recovery::unique_id();
    let journal_directory = storage.join("forced-removal");
    fs::create_dir_all(&journal_directory).map_err(|e| e.to_string())?;
    let journal = journal_directory.join(format!("{id}.json"));
    let mut outcome = Outcome {
        id,
        application: app.name.clone(),
        status: "Preparing reviewed removal".into(),
        items: vec![],
        cancelled: false,
    };
    persist(&journal, &outcome)?;
    let mut registration_backups = Vec::new();
    for &i in registry.iter().filter(|&&i| i >= plan.registration_start) {
        let candidate = &plan.report.registry_candidates[i];
        let backup = registration::prepare_backup(
            app,
            candidate,
            cancel,
            &storage.join("registration-cleanup"),
        )?;
        registration_backups.push((i, backup));
    }
    let mut failed = false;
    for &i in &files {
        let c = &plan.report.candidates[i];
        let label = c.path.display().to_string();
        let result = if cancelled(cancel) {
            Err("Queue stopped before this item".into())
        } else {
            validate_target(app, &inventory::collect(cancel)).and_then(|others| {
                recovery::quarantine_with_policy(
                    app,
                    c,
                    &PathPolicy::explicit_target(&c.path)?,
                    &others,
                    &storage.join("quarantine"),
                    cancel,
                )
            })
        };
        failed |= result.is_err();
        outcome.items.push(item("Files", label, result));
        persist(&journal, &outcome)?;
    }
    for &i in registry.iter().filter(|&&i| i < plan.registration_start) {
        let c = &plan.report.registry_candidates[i];
        let result = if cancelled(cancel) {
            Err("Queue stopped before this item".into())
        } else {
            validate_target(app, &inventory::collect(cancel)).and_then(|_| {
                registry_cleanup::cleanup_at(app, c, cancel, &storage.join("registry-cleanup"))
            })
        };
        failed |= result.is_err();
        outcome
            .items
            .push(item("Product settings", c.label(), result));
        persist(&journal, &outcome)?;
    }
    for (i, backup) in registration_backups {
        let c = &plan.report.registry_candidates[i];
        if failed || cancelled(cancel) {
            outcome.items.push(ItemResult {
                kind: "App-list entry".into(),
                label: c.label(),
                state: "Retained".into(),
                message: "Selected cleanup did not finish; the app-list entry was retained.".into(),
                backup: Some(backup),
            });
        } else {
            let result =
                registration::remove_prepared(app, c, &backup, cancel).map(|_| backup.clone());
            failed |= result.is_err();
            let mut result_item = item("App-list entry", c.label(), result);
            result_item.backup = Some(backup);
            outcome.items.push(result_item);
        }
        persist(&journal, &outcome)?;
    }
    outcome.cancelled = cancelled(cancel);
    outcome.status = if outcome.cancelled {
        "Removal stopped; review each item's result"
    } else if failed {
        "Removal needs review; inspect each selected item's result"
    } else {
        "Selected resources removed; backups are available"
    }
    .into();
    persist(&journal, &outcome)?;
    if storage == recovery::data_dir() {
        let _ = recovery::history(
            "forced-removal-result",
            &app.name,
            &serde_json::to_string(&outcome).map_err(|e| e.to_string())?,
        );
    }
    Ok(outcome)
}
fn item(kind: &str, label: String, result: UnboltResult<PathBuf>) -> ItemResult {
    match result {
        Ok(backup) => ItemResult {
            kind: kind.into(),
            label,
            state: "Removed".into(),
            message: "Backup saved before removal".into(),
            backup: Some(backup),
        },
        Err(message) => ItemResult {
            kind: kind.into(),
            label,
            state: "Needs review".into(),
            message,
            backup: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use winreg::{RegKey, enums::*};
    struct Fixture {
        root: PathBuf,
        name: String,
        source: RegistrySource,
    }
    impl Fixture {
        fn new() -> Self {
            let id = recovery::unique_id().replace('-', "X");
            let name = format!("UnboltForceFixtureX{id}");
            let root = std::env::temp_dir().join(format!("unbolt-force-fixture-{id}"));
            let app = root.join("App");
            fs::create_dir_all(&app).unwrap();
            fs::write(app.join("owned.txt"), b"original fixture content").unwrap();
            let source = RegistrySource {
                hive: "HKCU".into(),
                view: KEY_WOW64_64KEY,
                key: format!("{}\\{name}", inventory::UNINSTALL_ROOT),
            };
            let hkcu = RegKey::predef(HKEY_CURRENT_USER);
            let (registration, _) = hkcu.create_subkey(&source.key).unwrap();
            registration.set_value("DisplayName", &name).unwrap();
            registration
                .set_value("InstallLocation", &app.display().to_string())
                .unwrap();
            registration
                .set_value("DisplayVersion", &"fixture")
                .unwrap();
            let (product, _) = hkcu.create_subkey(format!("Software\\{name}")).unwrap();
            product
                .set_value("Path", &app.display().to_string())
                .unwrap();
            product.set_value("Number", &123u32).unwrap();
            Self { root, name, source }
        }
        fn app(&self) -> Application {
            inventory::collect(&AtomicBool::new(false))
                .apps
                .into_iter()
                .find(|a| a.name == self.name)
                .unwrap()
        }
        fn plan(&self) -> Plan {
            preview(&self.app(), &AtomicBool::new(false)).unwrap()
        }
        fn storage(&self) -> PathBuf {
            self.root.join("Recovery")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let hkcu = RegKey::predef(HKEY_CURRENT_USER);
            let _ = hkcu.delete_subkey_all(&self.source.key);
            let _ = hkcu.delete_subkey_all(format!("Software\\{}", self.name));
            assert!(self.root.starts_with(std::env::temp_dir()));
            assert!(
                self.root
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("unbolt-force-fixture-")
            );
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    #[test]
    fn reviewed_registered_removal_and_each_backup_restore_are_reversible() {
        let fixture = Fixture::new();
        let plan = fixture.plan();
        let flag = AtomicBool::new(false);
        assert!(plan.report.app_registered);
        assert_eq!(plan.report.candidates[0].confidence, Confidence::High);
        assert_eq!(plan.registration_start, 1);
        assert_eq!(plan.report.registry_candidates.len(), 2);
        let selected = Selection {
            files: vec![0],
            registry: vec![0, 1],
        };
        let result = execute_at(&plan, &selected, &flag, &fixture.storage()).unwrap();
        assert!(
            result.items.iter().all(|r| r.state == "Removed"),
            "{result:?}"
        );
        assert!(!fixture.root.join("App").exists());
        assert!(!inventory::registered(&plan.report.app).unwrap());
        recovery::restore_at(
            result.items[0].backup.as_deref().unwrap(),
            &fixture.storage().join("quarantine"),
        )
        .unwrap();
        registry_cleanup::restore_at(
            result.items[1].backup.as_deref().unwrap(),
            &fixture.storage().join("registry-cleanup"),
        )
        .unwrap();
        let entry_backup = result.items[2].backup.as_deref().unwrap();
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (occupied, _) = hkcu.create_subkey(&fixture.source.key).unwrap();
        occupied.set_value("DisplayName", &"new entry").unwrap();
        drop(occupied);
        assert!(
            registration::restore_at(
                entry_backup,
                &fixture.storage().join("registration-cleanup")
            )
            .is_err()
        );
        assert_eq!(
            hkcu.open_subkey(&fixture.source.key)
                .unwrap()
                .get_value::<String, _>("DisplayName")
                .unwrap(),
            "new entry"
        );
        hkcu.delete_subkey_all(&fixture.source.key).unwrap();
        registration::restore_at(
            entry_backup,
            &fixture.storage().join("registration-cleanup"),
        )
        .unwrap();
        assert_eq!(fixture.app(), plan.report.app);
        assert_eq!(
            fs::read(fixture.root.join("App/owned.txt")).unwrap(),
            b"original fixture content"
        );
        assert_eq!(
            hkcu.open_subkey(format!("Software\\{}", fixture.name))
                .unwrap()
                .get_value::<u32, _>("Number")
                .unwrap(),
            123
        );
    }
    #[test]
    fn stale_file_or_registration_review_prevents_any_removal() {
        let fixture = Fixture::new();
        let plan = fixture.plan();
        let flag = AtomicBool::new(false);
        fs::write(
            fixture.root.join("App/owned.txt"),
            b"changed fixture content",
        )
        .unwrap();
        assert!(
            execute_at(
                &plan,
                &Selection {
                    files: vec![0],
                    registry: vec![1]
                },
                &flag,
                &fixture.storage()
            )
            .is_err()
        );
        assert!(fixture.root.join("App").exists());
        assert!(inventory::registered(&plan.report.app).unwrap());
        let plan = fixture.plan();
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(&fixture.source.key, KEY_WRITE)
            .unwrap()
            .set_value("DisplayVersion", &"changed")
            .unwrap();
        assert!(
            execute_at(
                &plan,
                &Selection {
                    files: vec![0],
                    registry: vec![1]
                },
                &flag,
                &fixture.storage()
            )
            .is_err()
        );
        assert!(fixture.root.join("App").exists());
        assert!(inventory::registered(&plan.report.app).unwrap());
    }
    #[test]
    fn cleanup_failure_retains_selected_app_list_entry() {
        let fixture = Fixture::new();
        let plan = fixture.plan();
        let flag = AtomicBool::new(false);
        fs::create_dir_all(fixture.storage()).unwrap();
        fs::write(fixture.storage().join("quarantine"), b"storage unavailable").unwrap();
        let result = execute_at(
            &plan,
            &Selection {
                files: vec![0],
                registry: vec![1],
            },
            &flag,
            &fixture.storage(),
        )
        .unwrap();
        assert_eq!(result.items[0].state, "Needs review");
        assert_eq!(result.items.last().unwrap().state, "Retained");
        assert!(fixture.root.join("App").exists());
        assert!(inventory::registered(&plan.report.app).unwrap());
        assert!(
            result
                .items
                .last()
                .unwrap()
                .backup
                .as_ref()
                .unwrap()
                .is_file()
        );
    }
    #[test]
    fn registration_only_and_invalid_selections_keep_unselected_files_intact() {
        let fixture = Fixture::new();
        let plan = fixture.plan();
        let flag = AtomicBool::new(false);
        assert!(
            execute_at(
                &plan,
                &Selection {
                    files: vec![99],
                    registry: vec![]
                },
                &flag,
                &fixture.storage()
            )
            .is_err()
        );
        assert!(
            execute_at(
                &plan,
                &Selection {
                    files: vec![0],
                    registry: vec![]
                },
                &AtomicBool::new(true),
                &fixture.storage()
            )
            .is_err()
        );
        let result = execute_at(
            &plan,
            &Selection {
                files: vec![],
                registry: vec![1],
            },
            &flag,
            &fixture.storage(),
        )
        .unwrap();
        assert_eq!(result.items.len(), 1);
        assert_eq!(result.items[0].state, "Removed");
        assert_eq!(
            fs::read(fixture.root.join("App/owned.txt")).unwrap(),
            b"original fixture content"
        );
        assert!(!inventory::registered(&plan.report.app).unwrap());
    }
    #[test]
    fn manual_folder_cannot_bypass_a_registered_apps_shared_location() {
        let fixture = Fixture::new();
        let target =
            folder_target("Manual ownership declaration", &fixture.root.join("App")).unwrap();
        let plan = preview(&target, &AtomicBool::new(false)).unwrap();
        assert_eq!(plan.report.candidates[0].confidence, Confidence::Blocked);
        assert!(
            execute_at(
                &plan,
                &Selection {
                    files: vec![0],
                    registry: vec![]
                },
                &AtomicBool::new(false),
                &fixture.storage()
            )
            .is_err()
        );
        assert_eq!(
            fs::read(fixture.root.join("App/owned.txt")).unwrap(),
            b"original fixture content"
        );
        assert!(inventory::registered(&fixture.app()).unwrap());
    }
}
