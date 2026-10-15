//! Explicit disposal of selected local backups. Manifest payload paths are
//! descriptive only: deletion is restricted to the selected owned directory.
use crate::{UnboltResult, model::*, records::BackupRecord, recovery, scanner};
use std::{
    fs,
    path::{Component, Path, PathBuf},
    sync::atomic::AtomicBool,
};

const STORES: [&str; 5] = [
    "quarantine",
    "registry-cleanup",
    "registration-cleanup",
    "registry-backups",
    "startup-backups",
];
struct Node {
    path: PathBuf,
    snapshot: FileSnapshot,
}
struct Item {
    record: BackupRecord,
    directory: PathBuf,
    signature: u64,
    nodes: Vec<Node>,
}
pub struct Plan {
    root: PathBuf,
    items: Vec<Item>,
    bytes: u64,
}

fn checked_directory(root: &Path, manifest: &Path) -> UnboltResult<PathBuf> {
    if !manifest.is_absolute()
        || manifest
            .components()
            .any(|c| matches!(c, Component::ParentDir))
    {
        return Err("Backup paths must be absolute and cannot contain parent traversal".into());
    }
    for ancestor in manifest.ancestors().skip(1) {
        scanner::snapshot(ancestor)?;
    }
    let root = fs::canonicalize(root).map_err(|e| e.to_string())?;
    let directory = manifest.parent().ok_or("Backup has no directory")?;
    let directory = fs::canonicalize(directory).map_err(|e| e.to_string())?;
    let store = directory
        .parent()
        .ok_or("Backup has no storage directory")?;
    if store.parent() != Some(root.as_path())
        || !STORES
            .iter()
            .any(|s| store.file_name().is_some_and(|n| n == *s))
        || !directory.file_name().is_some_and(|n| {
            let id = n.to_string_lossy();
            let parts = id.split('-').collect::<Vec<_>>();
            parts.len() == 3
                && parts
                    .iter()
                    .all(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()))
        })
    {
        return Err("Only a selected Unbolt backup directory can be deleted".into());
    }
    let expected = if store.file_name().is_some_and(|n| n == "registry-backups") {
        "application.json"
    } else {
        "manifest.json"
    };
    if manifest.file_name().is_none_or(|n| n != expected) || scanner::snapshot(manifest)?.is_dir {
        return Err("Backup manifest is invalid".into());
    }
    let resolved = fs::canonicalize(manifest).map_err(|e| e.to_string())?;
    if resolved.parent() != Some(directory.as_path()) {
        return Err("Backup manifest escaped its directory".into());
    }
    Ok(directory)
}

pub fn saved_application(manifest: &Path) -> UnboltResult<Application> {
    checked_directory(&recovery::data_dir(), manifest)?;
    if manifest.file_name().is_none_or(|n| n != "application.json") {
        return Err("Choose an uninstall registration export to review leftovers".into());
    }
    if fs::metadata(manifest).map_err(|e| e.to_string())?.len() > 1024 * 1024 {
        return Err("Saved application record exceeds the supported size".into());
    }
    serde_json::from_slice(&fs::read(manifest).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

pub fn prepare(records: &[BackupRecord], cancel: &AtomicBool) -> UnboltResult<Plan> {
    prepare_at(&recovery::data_dir(), records, cancel)
}
fn prepare_at(root: &Path, records: &[BackupRecord], cancel: &AtomicBool) -> UnboltResult<Plan> {
    if records.is_empty() {
        return Err("Select at least one backup".into());
    }
    let root = fs::canonicalize(root).map_err(|e| e.to_string())?;
    let mut plan = Plan {
        root,
        items: vec![],
        bytes: 0,
    };
    for record in records {
        if cancelled(cancel) {
            return Err("Backup deletion cancelled; nothing was deleted".into());
        }
        if !matches!(
            record.state.as_str(),
            "quarantined" | "removed" | "restored" | "disabled" | "Exported"
        ) {
            return Err(
                "An unfinished backup needs recovery review before it can be deleted".into(),
            );
        }
        let directory = checked_directory(&plan.root, &record.manifest)?;
        if directory
            .file_name()
            .is_none_or(|id| id != record.id.as_str())
        {
            return Err("Selected backup identity changed; refresh and review again".into());
        }
        if fs::metadata(&record.manifest)
            .map_err(|e| e.to_string())?
            .len()
            > 1024 * 1024
        {
            return Err("Backup manifest exceeds the supported size".into());
        }
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(&record.manifest).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        let export = directory
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|n| n == "registry-backups");
        if (record.state == "Exported") != export
            || (!export && value["state"].as_str() != Some(record.state.as_str()))
        {
            return Err("Backup state changed; refresh and review again".into());
        }
        if plan.items.iter().any(|i| i.directory == directory) {
            continue;
        }
        let signature = scanner::tree_signature(&directory, cancel)?;
        let mut stack = vec![directory.clone()];
        let mut nodes = vec![];
        while let Some(path) = stack.pop() {
            if cancelled(cancel) {
                return Err("Backup deletion cancelled; nothing was deleted".into());
            }
            if nodes.len() >= 100_000 {
                return Err("Backup exceeds the supported deletion limit".into());
            }
            let snapshot = scanner::snapshot(&path)?;
            if snapshot.is_dir {
                for entry in fs::read_dir(&path).map_err(|e| e.to_string())? {
                    stack.push(entry.map_err(|e| e.to_string())?.path());
                }
            } else {
                plan.bytes = plan.bytes.saturating_add(snapshot.len);
            }
            nodes.push(Node { path, snapshot });
        }
        // Preserve the manifest on partial failure so this backup remains visible.
        let manifest = directory.join(record.manifest.file_name().unwrap());
        nodes.sort_by_key(|n| {
            (
                n.path == manifest,
                std::cmp::Reverse(n.path.components().count()),
            )
        });
        let root_index = nodes.iter().position(|n| n.path == directory).unwrap();
        let root_node = nodes.remove(root_index);
        nodes.push(root_node);
        plan.items.push(Item {
            record: record.clone(),
            directory,
            signature,
            nodes,
        });
    }
    Ok(plan)
}
impl Plan {
    pub fn description(&self) -> String {
        format!(
            "Permanently delete {} selected backup(s) ({:.1} MB)?\r\n\r\n{}\r\n\r\nThis deletes the stored recovery copies, not the original application files. These backups can no longer be restored. Disabled startup items stay disabled.\r\n\r\nThis cannot be undone.",
            self.items.len(),
            self.bytes as f64 / 1_048_576.,
            self.items
                .iter()
                .map(|i| format!(
                    "{} · {} · {}",
                    i.record.application, i.record.kind, i.record.id
                ))
                .collect::<Vec<_>>()
                .join("\r\n")
        )
    }
    pub fn execute(self, cancel: &AtomicBool) -> UnboltResult<String> {
        // Validate the complete selection before deleting any selected backup.
        for item in &self.items {
            if cancelled(cancel) {
                return Err("Backup deletion cancelled; nothing was deleted".into());
            }
            if checked_directory(&self.root, &item.record.manifest)? != item.directory
                || scanner::tree_signature(&item.directory, cancel)? != item.signature
            {
                return Err(
                    "A selected backup changed since review; refresh and review again".into(),
                );
            }
        }
        let mut results = vec![];
        for item in self.items {
            let result = (|| -> UnboltResult<()> {
                for node in &item.nodes {
                    if cancelled(cancel) {
                        return Err("Stopped; some backup contents may already be deleted".into());
                    }
                    // Recheck ancestry before each operation; never traverse a junction.
                    for ancestor in node.path.ancestors() {
                        scanner::snapshot(ancestor)?;
                    }
                    let resolved = fs::canonicalize(&node.path).map_err(|e| e.to_string())?;
                    if !resolved.starts_with(&item.directory)
                        || item.directory.parent().and_then(Path::parent)
                            != Some(self.root.as_path())
                    {
                        return Err("Backup path changed; deletion stopped".into());
                    }
                    let current = scanner::snapshot(&node.path)?;
                    if current.is_dir != node.snapshot.is_dir
                        || current.created_ticks != node.snapshot.created_ticks
                        || (!current.is_dir && current != node.snapshot)
                    {
                        return Err("Backup contents changed; deletion stopped".into());
                    }
                    if current.is_dir {
                        fs::remove_dir(&node.path)
                    } else {
                        fs::remove_file(&node.path)
                    }
                    .map_err(|e| e.to_string())?;
                }
                Ok(())
            })();
            let detail = match result {
                Ok(()) => format!(
                    "Deleted backup {} ({})",
                    item.record.id, item.record.application
                ),
                Err(e) => format!("Backup {}: {e}", item.record.id),
            };
            if fs::canonicalize(recovery::data_dir()).ok().as_ref() == Some(&self.root) {
                let _ = recovery::history("backup-delete", &item.record.application, &detail);
            }
            results.push(detail);
        }
        Ok(results.join("\r\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (PathBuf, BackupRecord) {
        let root =
            std::env::temp_dir().join(format!("unbolt-backup-delete-{}", recovery::unique_id()));
        let directory = root.join("quarantine").join(recovery::unique_id());
        fs::create_dir_all(directory.join("payload/nested")).unwrap();
        fs::write(directory.join("payload/nested/data"), b"recovery copy").unwrap();
        let manifest = directory.join("manifest.json");
        fs::write(&manifest, br#"{"state":"quarantined","original":"C:\\never-delete-original","stored":"C:\\never-follow-this"}"#).unwrap();
        let record = BackupRecord {
            id: directory.file_name().unwrap().to_string_lossy().into(),
            kind: "Files".into(),
            application: "Owned deletion fixture".into(),
            state: "quarantined".into(),
            original: "Unrelated original".into(),
            manifest,
            recoverable: true,
        };
        (root, record)
    }
    #[test]
    fn deletes_only_selected_backup_and_retains_original_and_sibling() {
        let (root, record) = fixture();
        let original = root.join("original");
        fs::write(&original, b"original retained").unwrap();
        let sibling = root.join("quarantine").join(recovery::unique_id());
        fs::create_dir(&sibling).unwrap();
        let plan = prepare_at(
            &root,
            std::slice::from_ref(&record),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(plan.description().contains("cannot be undone"));
        let result = plan.execute(&AtomicBool::new(false)).unwrap();
        assert!(result.contains("Deleted backup"));
        assert!(!record.manifest.parent().unwrap().exists());
        assert_eq!(fs::read(&original).unwrap(), b"original retained");
        assert!(sibling.exists());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn stale_cancelled_unfinished_and_foreign_backups_are_rejected() {
        let (root, mut record) = fixture();
        assert!(prepare_at(&root, std::slice::from_ref(&record), &AtomicBool::new(true)).is_err());
        let plan = prepare_at(
            &root,
            std::slice::from_ref(&record),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(plan.execute(&AtomicBool::new(true)).is_err());
        assert!(record.manifest.exists());
        let plan = prepare_at(
            &root,
            std::slice::from_ref(&record),
            &AtomicBool::new(false),
        )
        .unwrap();
        fs::write(
            record.manifest.parent().unwrap().join("payload/new"),
            b"new",
        )
        .unwrap();
        assert!(plan.execute(&AtomicBool::new(false)).is_err());
        assert!(record.manifest.exists());
        record.state = "prepared".into();
        assert!(
            prepare_at(
                &root,
                std::slice::from_ref(&record),
                &AtomicBool::new(false)
            )
            .is_err()
        );
        record.state = "restored".into();
        let foreign = root.join("foreign");
        fs::create_dir(&foreign).unwrap();
        record.manifest = foreign.join("manifest.json");
        fs::write(&record.manifest, b"{}").unwrap();
        assert!(prepare_at(&root, &[record], &AtomicBool::new(false)).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn refuses_a_reparse_payload_without_touching_its_target() {
        let (root, record) = fixture();
        let external = root.join("external");
        fs::create_dir(&external).unwrap();
        fs::write(external.join("keep"), b"keep").unwrap();
        // A junction fixture does not require Developer Mode or symlink privilege.
        let link = record
            .manifest
            .parent()
            .unwrap()
            .join("payload")
            .join("link");
        let status = std::process::Command::new("cmd.exe")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&external)
            .output()
            .unwrap();
        assert!(
            status.status.success(),
            "{}",
            String::from_utf8_lossy(&status.stderr)
        );
        assert!(prepare_at(&root, &[record], &AtomicBool::new(false)).is_err());
        assert_eq!(fs::read(external.join("keep")).unwrap(), b"keep");
        fs::remove_dir(&link).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn deletes_all_five_supported_backup_types_and_nested_manifests() {
        let root =
            std::env::temp_dir().join(format!("unbolt-backup-delete-{}", recovery::unique_id()));
        let mut records = vec![];
        for store in STORES {
            let directory = root.join(store).join(recovery::unique_id());
            fs::create_dir_all(directory.join("nested")).unwrap();
            fs::write(directory.join("nested/manifest.json"), b"nested content").unwrap();
            let state = if store == "registry-backups" {
                "Exported"
            } else if store == "startup-backups" {
                "disabled"
            } else {
                "restored"
            };
            let manifest = directory.join(if store == "registry-backups" {
                "application.json"
            } else {
                "manifest.json"
            });
            fs::write(&manifest, format!(r#"{{"state":"{state}"}}"#)).unwrap();
            records.push(BackupRecord {
                id: directory.file_name().unwrap().to_string_lossy().into(),
                kind: store.into(),
                application: "Owned type fixture".into(),
                state: state.into(),
                original: "Unchanged original".into(),
                manifest,
                recoverable: false,
            });
        }
        let result = prepare_at(&root, &records, &AtomicBool::new(false))
            .unwrap()
            .execute(&AtomicBool::new(false))
            .unwrap();
        assert_eq!(result.lines().count(), 5);
        assert!(
            records
                .iter()
                .all(|r| !r.manifest.parent().unwrap().exists())
        );
        fs::remove_dir_all(root).unwrap();
    }
}
