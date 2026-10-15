use crate::{
    UnboltResult, inventory,
    model::*,
    scanner::{self, PathPolicy},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
static HISTORY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// Caller-local storage for settings, history, operation sessions, and recovery copies.
pub const DATA_DIRECTORY: &str = "Unbolt";

pub fn data_dir() -> PathBuf {
    if let Some(data) = crate::context::data() {
        return data;
    }
    PathBuf::from(
        std::env::var_os("LOCALAPPDATA").unwrap_or_else(|| std::env::temp_dir().into_os_string()),
    )
    .join(DATA_DIRECTORY)
}
pub fn unique_id() -> String {
    format!(
        "{}-{}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

pub fn history(kind: &str, app: &str, detail: &str) -> UnboltResult<()> {
    let _guard = HISTORY_LOCK
        .lock()
        .map_err(|_| "History writer is unavailable")?;
    fs::create_dir_all(data_dir()).map_err(|e| e.to_string())?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(data_dir().join("history.jsonl"))
        .map_err(|e| e.to_string())?;
    let event = serde_json::json!({"id":unique_id(),"kind":kind,"application":app,"detail":detail});
    file.write_all(format!("{event}\n").as_bytes())
        .map_err(|e| e.to_string())
}
pub fn read_history() -> UnboltResult<String> {
    let p = data_dir().join("history.jsonl");
    if !p.exists() {
        return Ok("No operations recorded yet.".into());
    }
    let text = fs::read_to_string(p).map_err(|e| e.to_string())?;
    let lines = text.lines().collect::<Vec<_>>();
    Ok(lines[lines.len().saturating_sub(200)..].join("\r\n"))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QuarantineManifest {
    pub schema: u32,
    pub application: String,
    pub original: PathBuf,
    pub stored: PathBuf,
    pub snapshot: FileSnapshot,
    pub state: String,
}

fn write_manifest(path: &Path, manifest: &QuarantineManifest) -> UnboltResult<()> {
    let data = serde_json::to_vec_pretty(manifest).map_err(|e| e.to_string())?;
    let pending = path.with_extension("pending");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)
        .map_err(|e| e.to_string())?;
    file.write_all(&data)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    // On Windows rename replaces an existing destination atomically on the same volume.
    fs::rename(&pending, path).map_err(|e| e.to_string())
}

pub fn quarantine(
    app: &Application,
    candidate: &Candidate,
    cancel: &AtomicBool,
) -> UnboltResult<PathBuf> {
    crate::process::assert_cleanup_ready(&app.id)?;
    if inventory::registered(app)? {
        return Err("Application is still registered; uninstall it before cleanup.".into());
    }
    let fresh = inventory::collect(cancel);
    if fresh.cancelled || !fresh.errors.is_empty() {
        return Err("Full current inventory is required before cleanup.".into());
    }
    let others = fresh
        .apps
        .into_iter()
        .filter(|a| a.id != app.id)
        .collect::<Vec<_>>();
    let manifest = quarantine_with_policy(
        app,
        candidate,
        &PathPolicy::windows(),
        &others,
        &data_dir().join("quarantine"),
        cancel,
    )?;
    let _ = history(
        "quarantine",
        &app.name,
        &format!("{} -> {}", candidate.path.display(), manifest.display()),
    );
    Ok(manifest)
}

pub(crate) fn quarantine_with_policy(
    app: &Application,
    candidate: &Candidate,
    policy: &PathPolicy,
    others: &[Application],
    storage: &Path,
    cancel: &AtomicBool,
) -> UnboltResult<PathBuf> {
    if candidate.confidence != Confidence::High {
        return Err("Only high-confidence exact installation paths support cleanup.".into());
    }
    let original = policy.validate(&candidate.path, others)?;
    if app
        .location
        .as_ref()
        .and_then(|p| fs::canonicalize(p).ok())
        .as_ref()
        .map(|p| scanner::normalize(p))
        != Some(scanner::normalize(&original))
    {
        return Err("Candidate does not match the recorded installation location.".into());
    }
    if Some(scanner::tree_signature(&original, cancel)?) != candidate.tree_signature {
        return Err("Directory contents changed since preview; rescan first.".into());
    }
    if scanner::snapshot(&original)? != candidate.snapshot {
        return Err("Candidate changed since preview; rescan first.".into());
    }
    if cancelled(cancel) {
        return Err("Cancelled; no cleanup performed.".into());
    }
    let dir = storage.join(unique_id());
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let dir = fs::canonicalize(&dir).map_err(|e| e.to_string())?;
    let manifest_path = dir.join("manifest.json");
    let mut manifest = QuarantineManifest {
        schema: 1,
        application: app.name.clone(),
        original,
        stored: dir.join("payload"),
        snapshot: candidate.snapshot.clone(),
        state: "prepared".into(),
    };
    write_manifest(&manifest_path, &manifest)?;
    // Rename only: never recursively delete or fall back to a partial cross-volume copy.
    fs::rename(&manifest.original, &manifest.stored).map_err(|e| {
        format!(
            "Could not quarantine (same-volume writable storage required); original retained: {e}"
        )
    })?;
    manifest.state = "quarantined".into();
    if let Err(e) = write_manifest(&manifest_path, &manifest) {
        return Err(format!(
            "Files were moved. Recovery manifest is at {}: {e}",
            manifest_path.display()
        ));
    }
    Ok(manifest_path)
}

pub fn restore(path: &Path) -> UnboltResult<()> {
    if fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .is_some_and(|v| v["kind"] == "startup")
    {
        return crate::startup::restore(path);
    }
    if fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .is_some_and(|v| v["kind"] == "registration")
    {
        return crate::registration::restore(path);
    }
    if fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .is_some_and(|v| v["kind"] == "registry")
    {
        return crate::registry_cleanup::restore(path);
    }
    restore_at(path, &data_dir().join("quarantine"))?;
    if let Ok(bytes) = fs::read(path)
        && let Ok(manifest) = serde_json::from_slice::<QuarantineManifest>(&bytes)
    {
        let _ = history(
            "restore",
            &manifest.application,
            &manifest.original.display().to_string(),
        );
    }
    Ok(())
}

pub(crate) fn restore_at(path: &Path, storage: &Path) -> UnboltResult<()> {
    let resolved = fs::canonicalize(path).map_err(|e| e.to_string())?;
    let storage = fs::canonicalize(storage).map_err(|e| e.to_string())?;
    if !resolved.starts_with(&storage)
        || resolved.file_name().and_then(|s| s.to_str()) != Some("manifest.json")
    {
        return Err("Manifest must be inside Unbolt quarantine.".into());
    }
    let mut manifest: QuarantineManifest =
        serde_json::from_slice(&fs::read(&resolved).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let expected = resolved.parent().unwrap().join("payload");
    let stored = fs::canonicalize(&manifest.stored)
        .map_err(|e| format!("Quarantined payload is unavailable: {e}"))?;
    let expected_identity = fs::canonicalize(&expected).map_err(|e| e.to_string())?;
    if manifest.schema != 1 || stored != expected_identity {
        return Err("Unsupported or inconsistent manifest.".into());
    }
    if manifest.state == "restored" {
        return Err("Already restored.".into());
    }
    if manifest.original.exists() {
        return Err("Original path is occupied; restore will not overwrite it.".into());
    }
    scanner::validate_tree(&expected, &AtomicBool::new(false))?;
    let parent = manifest
        .original
        .parent()
        .ok_or("Invalid restore destination")?;
    if !parent.is_dir() {
        return Err("Original parent directory no longer exists.".into());
    }
    for ancestor in parent.ancestors() {
        scanner::snapshot(ancestor)?;
    }
    fs::rename(&expected, &manifest.original).map_err(|e| e.to_string())?;
    manifest.state = "restored".into();
    write_manifest(&resolved, &manifest)?;
    Ok(())
}

pub fn manifests() -> Vec<PathBuf> {
    let mut paths = fs::read_dir(data_dir().join("quarantine"))
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|e| e.path().join("manifest.json"))
        .filter(|p| p.is_file())
        .collect::<Vec<_>>();
    paths.extend(
        fs::read_dir(data_dir().join("registry-cleanup"))
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .map(|e| e.path().join("manifest.json"))
            .filter(|p| p.is_file()),
    );
    paths.extend(
        fs::read_dir(data_dir().join("registration-cleanup"))
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .map(|e| e.path().join("manifest.json"))
            .filter(|p| p.is_file()),
    );
    paths.sort();
    paths.reverse();
    paths
}

pub fn manifest_description(path: &Path) -> Option<String> {
    if let Some(description) = crate::startup::manifest_description(path) {
        return Some(description);
    }
    let bytes = fs::read(path).ok()?;
    if let Ok(m) = serde_json::from_slice::<crate::registry_cleanup::RegistryManifest>(&bytes) {
        return (m.state == "removed").then(|| {
            format!(
                "{}\r\n{}\\{} (registry)",
                m.application, m.source.hive, m.source.key
            )
        });
    }
    let m = serde_json::from_slice::<QuarantineManifest>(&bytes).ok()?;
    (m.state != "restored" && m.stored.exists())
        .then(|| format!("{}\r\n{}", m.application, m.original.display()))
}

pub fn backup_registration(app: &Application) -> UnboltResult<PathBuf> {
    let dir = data_dir().join("registry-backups").join(unique_id());
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    for (index, source) in app.sources.iter().enumerate() {
        let root = inventory::hive(&source.hive)?;
        let key = root
            .open_subkey_with_flags(&source.key, winreg::enums::KEY_READ | source.view)
            .map_err(|e| e.to_string())?;
        let hive = if source.hive == "HKLM" {
            "HKEY_LOCAL_MACHINE"
        } else {
            "HKEY_CURRENT_USER"
        };
        // .reg files preserve the physical 32-bit path for correct import without a view switch.
        let physical = if source.view == winreg::enums::KEY_WOW64_32KEY && source.hive == "HKLM" {
            source
                .key
                .replacen("SOFTWARE\\", "SOFTWARE\\WOW6432Node\\", 1)
        } else {
            source.key.clone()
        };
        let mut text = String::from("Windows Registry Editor Version 5.00\r\n\r\n");
        let mut budget = 10_000;
        export_key(&key, &format!("{hive}\\{physical}"), &mut text, &mut budget)?;
        let bytes = std::iter::once(0xfeffu16)
            .chain(text.encode_utf16())
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        fs::write(dir.join(format!("registration-{index}.reg")), bytes)
            .map_err(|e| e.to_string())?;
    }
    fs::write(
        dir.join("application.json"),
        serde_json::to_vec_pretty(app).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(dir)
}

fn export_key(
    key: &winreg::RegKey,
    path: &str,
    text: &mut String,
    budget: &mut usize,
) -> UnboltResult<()> {
    if *budget == 0 {
        return Err("Registry backup exceeds bounded export limit".into());
    }
    *budget -= 1;
    text.push_str(&format!("[{path}]\r\n"));
    for value in key.enum_values() {
        let (name, value) = value.map_err(|e| e.to_string())?;
        let escaped = name.replace('\\', "\\\\").replace('"', "\\\"");
        let name = if name.is_empty() {
            "@".into()
        } else {
            format!("\"{escaped}\"")
        };
        let hex = value
            .bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(",");
        text.push_str(&format!("{name}=hex({:x}):{hex}\r\n", value.vtype as u32));
    }
    text.push_str("\r\n");
    for name in key.enum_keys() {
        let name = name.map_err(|e| e.to_string())?;
        let child = key.open_subkey(&name).map_err(|e| e.to_string())?;
        export_key(&child, &format!("{path}\\{name}"), text, budget)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quarantine_restore_and_conflict_are_reversible() {
        let root = std::env::temp_dir().join(format!("unbolt-recovery-{}", unique_id()));
        fs::create_dir_all(&root).unwrap();
        let appdir = root.join("Example");
        fs::create_dir(&appdir).unwrap();
        fs::write(appdir.join("settings.txt"), b"valuable fixture").unwrap();
        let app = Application {
            id: "fixture".into(),
            name: "Example".into(),
            publisher: String::new(),
            version: String::new(),
            location: Some(appdir.clone()),
            uninstall: String::new(),
            quiet_uninstall: String::new(),
            size_kib: None,
            system_component: false,
            sources: vec![],
        };
        let candidate = Candidate {
            path: appdir.clone(),
            confidence: Confidence::High,
            evidence: "fixture".into(),
            snapshot: scanner::snapshot(&appdir).unwrap(),
            tree_signature: Some(
                scanner::tree_signature(&appdir, &AtomicBool::new(false)).unwrap(),
            ),
        };
        let policy = PathPolicy {
            roots: vec![root.clone()],
            protected: vec![root.clone()],
        };
        let storage = root.join("quarantine");
        let manifest = quarantine_with_policy(
            &app,
            &candidate,
            &policy,
            &[],
            &storage,
            &AtomicBool::new(false),
        )
        .unwrap();
        // Older manifests stored logical/aliased paths. Resolve identity rather
        // than comparing spelling, including Windows packaged-app redirection.
        let mut aliased: QuarantineManifest =
            serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
        aliased.stored = manifest.parent().unwrap().join(".").join("payload");
        write_manifest(&manifest, &aliased).unwrap();
        assert!(!appdir.exists());
        fs::create_dir(&appdir).unwrap();
        assert!(
            restore_at(&manifest, &storage)
                .unwrap_err()
                .contains("occupied")
        );
        fs::remove_dir(&appdir).unwrap();
        restore_at(&manifest, &storage).unwrap();
        assert_eq!(
            fs::read(appdir.join("settings.txt")).unwrap(),
            b"valuable fixture"
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn review_candidates_cannot_be_moved() {
        let candidate = Candidate {
            path: "missing".into(),
            confidence: Confidence::Review,
            evidence: String::new(),
            snapshot: FileSnapshot {
                is_dir: false,
                len: 0,
                modified_ns: 0,
                created_ticks: 0,
            },
            tree_signature: None,
        };
        let app = Application {
            id: String::new(),
            name: String::new(),
            publisher: String::new(),
            version: String::new(),
            location: None,
            uninstall: String::new(),
            quiet_uninstall: String::new(),
            size_kib: None,
            system_component: false,
            sources: vec![],
        };
        assert!(
            quarantine_with_policy(
                &app,
                &candidate,
                &PathPolicy {
                    roots: vec![],
                    protected: vec![]
                },
                &[],
                Path::new("missing"),
                &AtomicBool::new(false)
            )
            .is_err()
        );
    }

    #[test]
    fn changed_contents_and_backup_failure_leave_original_intact() {
        let root = std::env::temp_dir().join(format!("unbolt-failure-{}", unique_id()));
        fs::create_dir_all(&root).unwrap();
        let appdir = root.join("Example");
        fs::create_dir(&appdir).unwrap();
        let file = appdir.join("settings.txt");
        fs::write(&file, b"original").unwrap();
        let app = Application {
            id: "fixture".into(),
            name: "Example".into(),
            publisher: String::new(),
            version: String::new(),
            location: Some(appdir.clone()),
            uninstall: String::new(),
            quiet_uninstall: String::new(),
            size_kib: None,
            system_component: false,
            sources: vec![],
        };
        let flag = AtomicBool::new(false);
        let policy = PathPolicy {
            roots: vec![root.clone()],
            protected: vec![root.clone()],
        };
        let mut candidate = Candidate {
            path: appdir.clone(),
            confidence: Confidence::High,
            evidence: String::new(),
            snapshot: scanner::snapshot(&appdir).unwrap(),
            tree_signature: Some(scanner::tree_signature(&appdir, &flag).unwrap()),
        };
        fs::write(&file, b"changed after preview").unwrap();
        assert!(
            quarantine_with_policy(
                &app,
                &candidate,
                &policy,
                &[],
                &root.join("quarantine"),
                &flag
            )
            .unwrap_err()
            .contains("changed")
        );
        candidate.snapshot = scanner::snapshot(&appdir).unwrap();
        candidate.tree_signature = Some(scanner::tree_signature(&appdir, &flag).unwrap());
        let blocked_storage = root.join("blocked");
        fs::write(&blocked_storage, b"file not a directory").unwrap();
        assert!(
            quarantine_with_policy(&app, &candidate, &policy, &[], &blocked_storage, &flag)
                .is_err()
        );
        assert_eq!(fs::read(&file).unwrap(), b"changed after preview");
        assert!(
            quarantine_with_policy(
                &app,
                &candidate,
                &policy,
                &[],
                &root.join("quarantine"),
                &AtomicBool::new(true)
            )
            .unwrap_err()
            .contains("Cancelled")
        );
        assert!(appdir.exists());
        fs::remove_dir_all(root).unwrap();
    }
}
