//! Exact app-list entries; kept separate from product settings and Windows keys.
use crate::{
    UnboltResult, inventory,
    model::*,
    recovery,
    registry_cleanup::{self, RegistryCandidate, RegistryManifest, RegistryTree},
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};
use winreg::enums::*;
pub(crate) fn validate_source(source: &RegistrySource) -> UnboltResult<()> {
    let (parent, name) = source
        .key
        .rsplit_once('\\')
        .ok_or("Invalid registration source")?;
    if !matches!(source.hive.as_str(), "HKCU" | "HKLM")
        || !matches!(source.view, KEY_WOW64_32KEY | KEY_WOW64_64KEY)
        || !parent.eq_ignore_ascii_case(inventory::UNINSTALL_ROOT)
        || name.is_empty()
        || name.contains(['\\', '/', '\0', '\r', '\n'])
        || matches!(name, "." | "..")
    {
        return Err("Only an exact Windows application-list entry is supported".into());
    }
    Ok(())
}
fn text(tree: &RegistryTree, name: &str) -> Option<String> {
    let value = tree.values.get(name)?;
    if !matches!(value.value_type, 1 | 2) || value.bytes.len() % 2 != 0 {
        return None;
    }
    let units = value
        .bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .take_while(|&c| c != 0)
        .collect::<Vec<_>>();
    Some(String::from_utf16_lossy(&units).trim().to_string())
}
pub fn candidates(app: &Application, cancel: &AtomicBool) -> UnboltResult<Vec<RegistryCandidate>> {
    let mut result: Vec<RegistryCandidate> = Vec::new();
    for source in &app.sources {
        validate_source(source)?;
        let snapshot = registry_cleanup::capture_source(source, cancel)?;
        if text(&snapshot, "DisplayName").as_deref() != Some(&app.name) {
            return Err("Registration name changed; refresh first".into());
        }
        if snapshot
            .values
            .get("SystemComponent")
            .is_some_and(|v| v.value_type == 4 && v.bytes == 1u32.to_le_bytes())
        {
            return Err("System components cannot be forcibly removed".into());
        }
        if result.iter().any(|c| {
            source.hive == "HKCU"
                && c.source.hive == source.hive
                && c.source.key.eq_ignore_ascii_case(&source.key)
                && c.snapshot == snapshot
        }) {
            continue;
        }
        result.push(RegistryCandidate {source:source.clone(),confidence:Confidence::High,
            evidence:"Exact Windows app-list entry. Its removal hides the app from the installed list; it does not run an uninstaller.".into(),snapshot});
    }
    Ok(result)
}
pub(crate) fn prepare_backup(
    app: &Application,
    c: &RegistryCandidate,
    cancel: &AtomicBool,
    storage: &Path,
) -> UnboltResult<PathBuf> {
    validate_source(&c.source)?;
    if !app.sources.contains(&c.source) || c.confidence != Confidence::High {
        return Err("Registration is outside the selected application's sources".into());
    }
    if registry_cleanup::capture_source(&c.source, cancel)? != c.snapshot {
        return Err("App-list entry changed since review".into());
    }
    let directory = storage.join(recovery::unique_id());
    fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
    let path = directory.join("manifest.json");
    registry_cleanup::persist(
        &path,
        &RegistryManifest {
            kind: "registration".into(),
            application: app.name.clone(),
            source: c.source.clone(),
            snapshot: c.snapshot.clone(),
            state: "prepared".into(),
        },
    )?;
    Ok(path)
}
pub(crate) fn remove_prepared(
    app: &Application,
    c: &RegistryCandidate,
    backup: &Path,
    cancel: &AtomicBool,
) -> UnboltResult<()> {
    validate_source(&c.source)?;
    if !app.sources.contains(&c.source) || cancelled(cancel) {
        return Err("Registration removal cancelled or outside target".into());
    }
    let mut manifest: RegistryManifest =
        serde_json::from_slice(&fs::read(backup).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    if manifest.kind != "registration"
        || manifest.state != "prepared"
        || manifest.source != c.source
        || manifest.snapshot != c.snapshot
    {
        return Err("Registration backup is inconsistent".into());
    }
    if registry_cleanup::capture_source(&c.source, cancel)? != c.snapshot {
        return Err("App-list entry changed during removal; it was retained".into());
    }
    let (parent, name) = c.source.key.rsplit_once('\\').unwrap();
    let key = registry_cleanup::open_no_links(
        &RegistrySource {
            key: parent.into(),
            ..c.source.clone()
        },
        KEY_READ | KEY_WRITE,
    )?;
    if let Err(e) = key.delete_subkey_all(name) {
        manifest.state = "deletion-failed-review-required".into();
        let _ = registry_cleanup::persist(backup, &manifest);
        return Err(format!(
            "App-list entry could not be removed; backup retained: {e}"
        ));
    }
    manifest.state = "removed".into();
    registry_cleanup::persist(backup, &manifest)
}
pub fn restore(path: &Path) -> UnboltResult<()> {
    restore_at(path, &recovery::data_dir().join("registration-cleanup"))?;
    let _ = recovery::history(
        "registration-restore",
        "App-list entry",
        &path.display().to_string(),
    );
    Ok(())
}
pub(crate) fn restore_at(path: &Path, storage: &Path) -> UnboltResult<()> {
    registry_cleanup::restore_snapshot_manifest(path, storage, "registration", validate_source)
}
