//! Structured local operation history and recovery inventory shared by GUI and CLI.
use crate::{UnboltResult, recovery};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryRecord {
    pub id: String,
    pub kind: String,
    pub application: String,
    pub detail: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackupRecord {
    pub id: String,
    pub kind: String,
    pub application: String,
    pub state: String,
    pub original: String,
    pub manifest: PathBuf,
    pub recoverable: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordPage<T> {
    pub records: Vec<T>,
    pub errors: Vec<String>,
}

pub fn history() -> UnboltResult<RecordPage<HistoryRecord>> {
    let mut page =
        history_at(&recovery::data_dir().join("history.jsonl")).unwrap_or_else(|error| {
            RecordPage {
                records: vec![],
                errors: vec![format!("Operation history could not be read: {error}")],
            }
        });
    match crate::session_review::pending_records() {
        Ok(mut pending) => {
            pending.records.append(&mut page.records);
            page.records = pending.records;
            page.errors.extend(pending.errors);
        }
        Err(error) => page.errors.push(format!(
            "Pending uninstall sessions could not be read: {error}"
        )),
    }
    Ok(page)
}
fn history_at(path: &Path) -> UnboltResult<RecordPage<HistoryRecord>> {
    if !path.exists() {
        return Ok(RecordPage {
            records: vec![],
            errors: vec![],
        });
    }
    let reader = BufReader::new(fs::File::open(path).map_err(|e| e.to_string())?);
    let mut records = VecDeque::new();
    let mut errors = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<HistoryRecord>(&line) {
            Ok(record) => {
                records.push_back(record);
                if records.len() > 10_000 {
                    records.pop_front();
                }
            }
            Err(e) => {
                if errors.len() < 100 {
                    errors.push(format!("History line {} could not be read: {e}", index + 1));
                }
            }
        }
    }
    let mut records = records.into_iter().collect::<Vec<_>>();
    records.sort_by(|a, b| {
        stamp(&b.id)
            .cmp(&stamp(&a.id))
            .then_with(|| b.id.cmp(&a.id))
    });
    Ok(RecordPage { records, errors })
}
pub fn stamp(id: &str) -> u64 {
    id.split('-')
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

pub fn recorded_time(id: &str) -> String {
    let seconds = stamp(id) / 1000;
    if seconds == 0 {
        return "Unknown".into();
    }
    let days = (seconds / 86400) as i64;
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        seconds % 86400 / 3600,
        seconds % 3600 / 60,
        seconds % 60
    )
}

pub fn backups() -> UnboltResult<RecordPage<BackupRecord>> {
    backups_at(&recovery::data_dir())
}
fn backups_at(root: &Path) -> UnboltResult<RecordPage<BackupRecord>> {
    let mut records = Vec::new();
    let mut errors = Vec::new();
    for (kind, directory) in [
        ("Files", "quarantine"),
        ("Registry", "registry-cleanup"),
        ("App-list entry", "registration-cleanup"),
        ("Registration export", "registry-backups"),
        ("Startup item", "startup-backups"),
    ] {
        let folder = root.join(directory);
        if !folder.exists() {
            continue;
        }
        for entry in fs::read_dir(&folder).map_err(|e| e.to_string())? {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    errors.push(e.to_string());
                    continue;
                }
            };
            if !entry.file_type().map_err(|e| e.to_string())?.is_dir() {
                continue;
            }
            let id = entry.file_name().to_string_lossy().into_owned();
            let manifest = entry.path().join(if directory == "registry-backups" {
                "application.json"
            } else {
                "manifest.json"
            });
            let result = (|| -> UnboltResult<BackupRecord> {
                let value: serde_json::Value =
                    serde_json::from_slice(&fs::read(&manifest).map_err(|e| e.to_string())?)
                        .map_err(|e| e.to_string())?;
                let application = if directory == "registry-backups" {
                    value["name"].as_str()
                } else {
                    value["application"].as_str()
                }
                .unwrap_or("Unknown application")
                .to_string();
                let state = value["state"].as_str().unwrap_or("Exported").to_string();
                let original = if directory == "startup-backups" {
                    value["original_location"]
                        .as_str()
                        .unwrap_or("Unknown startup source")
                        .into()
                } else if matches!(directory, "registry-cleanup" | "registration-cleanup") {
                    format!(
                        "{}\\{}",
                        value["source"]["hive"].as_str().unwrap_or("?"),
                        value["source"]["key"].as_str().unwrap_or("?")
                    )
                } else if directory == "quarantine" {
                    value["original"].as_str().unwrap_or("?").into()
                } else {
                    value["location"]
                        .as_str()
                        .unwrap_or("Uninstall registration")
                        .into()
                };
                let recoverable = directory != "registry-backups"
                    && recovery::manifest_description(&manifest).is_some();
                Ok(BackupRecord {
                    id,
                    kind: kind.into(),
                    application,
                    state,
                    original,
                    manifest: manifest.clone(),
                    recoverable,
                })
            })();
            match result {
                Ok(record) => records.push(record),
                Err(e) => errors.push(format!("{}: {e}", manifest.display())),
            }
        }
    }
    records.sort_by(|a, b| {
        stamp(&b.id)
            .cmp(&stamp(&a.id))
            .then_with(|| b.id.cmp(&a.id))
    });
    Ok(RecordPage { records, errors })
}
impl HistoryRecord {
    pub fn can_review_session(&self) -> bool {
        matches!(
            self.kind.as_str(),
            "uninstall-result" | "uninstall-session-pending"
        )
    }
    pub fn session_review_target(&self) -> UnboltResult<(PathBuf, String)> {
        if !self.can_review_session() {
            return Err("Choose a pending uninstall or uninstall result".into());
        }
        let value: serde_json::Value =
            serde_json::from_str(&self.detail).map_err(|e| e.to_string())?;
        let backup = value["backup"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or("Saved registration export is missing")?;
        let session = value["process_session"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or("Saved installer session is missing")?;
        Ok((
            PathBuf::from(backup).join("application.json"),
            session.to_owned(),
        ))
    }
    pub fn matches(&self, query: &str) -> bool {
        let query = query.to_lowercase();
        let operation = operation_label(&self.kind);
        let detail = detail_text(self);
        let date = recorded_time(&self.id);
        [
            &self.application,
            &self.kind,
            &self.detail,
            &self.id,
            &operation,
            &detail,
            &date,
        ]
        .iter()
        .any(|s| s.to_lowercase().contains(&query))
    }
}
impl BackupRecord {
    pub fn matches(&self, query: &str) -> bool {
        let query = query.to_lowercase();
        let state = state_label(&self.state).to_string();
        let date = recorded_time(&self.id);
        [
            &self.application,
            &self.kind,
            &self.original,
            &self.state,
            &self.id,
            &state,
            &date,
        ]
        .iter()
        .any(|s| s.to_lowercase().contains(&query))
    }
}

pub fn state_label(state: &str) -> &str {
    match state {
        "quarantined" => "In quarantine",
        "removed" => "Registry removed",
        "restored" => "Restored",
        "Exported" => "Export only",
        "prepared" => "Backup prepared",
        "disabled" => "Startup disabled",
        _ => "Needs review",
    }
}
pub fn operation_label(kind: &str) -> String {
    match kind {
        "uninstall-start" => "Uninstall started".into(),
        "uninstall-result" => "Uninstall result".into(),
        "uninstall-session-pending" => "Pending uninstall".into(),
        "uninstall-session-review" => "Uninstall session reviewed".into(),
        "uninstall-launch-failed" => "Uninstaller launch failed".into(),
        "quarantine" => "Files quarantined".into(),
        "restore" => "Files restored".into(),
        "registry-cleanup" => "Registry cleanup".into(),
        "registry-restore" => "Registry restored".into(),
        "registration-restore" => "App-list entry restored".into(),
        "forced-removal-result" => "Forced removal result".into(),
        "hunter-stop" => "Hunter process stopped".into(),
        "startup-change" => "Startup setting changed".into(),
        "backup-delete" => "Backup deletion".into(),
        _ => kind.replace('-', " "),
    }
}
pub fn display_path(path: &str) -> String {
    path.strip_prefix(r"\\?\").unwrap_or(path).to_string()
}
pub fn detail_text(record: &HistoryRecord) -> String {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&record.detail)
        && let Some(status) = value["status"].as_str()
    {
        let mut lines = vec![status.to_string()];
        if let Some(code) = value["exit_code"].as_i64() {
            lines.push(format!("Exit code: {code}"));
        }
        if let Some(scope) = value["tracking_scope"].as_str() {
            lines.push(format!("Process tracking: {scope}"));
        }
        if let Some(count) = value["tracked_processes"].as_u64() {
            lines.push(format!("Tracked processes: {count}"));
        }
        if let Some(backup) = value["backup"].as_str() {
            lines.push(format!("Backup folder: {}", display_path(backup)));
        }
        if let Some(items) = value["items"].as_array() {
            for item in items {
                lines.push(format!(
                    "{}: {} — {}",
                    item["label"].as_str().unwrap_or("Item"),
                    item["state"].as_str().unwrap_or("Unknown"),
                    item["message"].as_str().unwrap_or("")
                ));
                if let Some(backup) = item["backup"].as_str() {
                    lines.push(format!("Backup: {}", display_path(backup)));
                }
            }
        }
        if let Some(ms) = value["elapsed_ms"].as_u64() {
            lines.push(format!("Duration: {:.1} s", ms as f64 / 1000.));
        }
        return lines.join("\r\n");
    }
    record.detail.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recorded_time_formats_utc_calendar() {
        assert_eq!(recorded_time("1000-1-0"), "1970-01-01 00:00:01");
        assert_eq!(recorded_time("1709251200000-1-0"), "2024-03-01 00:00:00");
    }
    #[test]
    fn uninstall_result_is_presented_as_readable_details() {
        let record=HistoryRecord{id:"1000-1-0".into(),kind:"uninstall-result".into(),application:"Example".into(),detail:r#"{"status":"Reboot required","exit_code":3010,"backup":"C:\\Backup","elapsed_ms":1500}"#.into()};
        let text = detail_text(&record);
        assert!(text.contains("Reboot required"));
        assert!(text.contains("Exit code: 3010"));
        assert!(text.contains("Duration: 1.5 s"));
    }
    #[test]
    fn history_reports_corrupt_lines_and_keeps_structured_results() {
        let root = std::env::temp_dir().join(format!("unbolt-records-{}", recovery::unique_id()));
        fs::create_dir(&root).unwrap();
        let path = root.join("history.jsonl");
        let a = HistoryRecord {
            id: "1000-1-0".into(),
            kind: "cleanup".into(),
            application: "Example".into(),
            detail: "Saved backup".into(),
        };
        let b = HistoryRecord {
            id: "2000-1-0".into(),
            kind: "restore".into(),
            application: "Example".into(),
            detail: "Recovered settings".into(),
        };
        fs::write(
            &path,
            format!(
                "{}\ninvalid\n{}\n",
                serde_json::to_string(&a).unwrap(),
                serde_json::to_string(&b).unwrap()
            ),
        )
        .unwrap();
        let page = history_at(&path).unwrap();
        assert_eq!(page.records[0].kind, "restore");
        assert_eq!(page.errors.len(), 1);
        assert!(page.records[0].matches("settings"));
        assert!(!page.records[0].matches("unrelated"));
        assert!(root.starts_with(std::env::temp_dir()));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn backup_browser_does_not_mark_registration_exports_as_restorable() {
        let root = std::env::temp_dir().join(format!("unbolt-records-{}", recovery::unique_id()));
        let dir = root.join("registry-backups").join("1234-1-0");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("application.json"),
            r#"{"name":"Example","location":"C:\\Example"}"#,
        )
        .unwrap();
        let page = backups_at(&root).unwrap();
        assert_eq!(page.records.len(), 1);
        assert!(!page.records[0].recoverable);
        assert!(page.records[0].matches("example"));
        assert!(page.errors.is_empty());
        assert!(root.starts_with(std::env::temp_dir()));
        fs::remove_dir_all(root).unwrap();
    }
}
