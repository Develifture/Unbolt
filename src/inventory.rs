use crate::{UnboltResult, model::*};
use std::{collections::BTreeMap, path::PathBuf, sync::atomic::AtomicBool, time::Instant};
use winreg::{RegKey, enums::*};

pub const UNINSTALL_ROOT: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

pub fn hive(name: &str) -> UnboltResult<RegKey> {
    match name {
        "HKLM" => Ok(RegKey::predef(HKEY_LOCAL_MACHINE)),
        "HKCU" => {
            if let Some(sid) = crate::context::hive_sid() {
                RegKey::predef(HKEY_USERS)
                    .open_subkey_with_flags(sid, KEY_READ | KEY_WOW64_64KEY)
                    .map_err(|e| e.to_string())
            } else {
                Ok(RegKey::predef(HKEY_CURRENT_USER))
            }
        }
        _ => Err("Unsupported registry hive".into()),
    }
}

fn value(key: &RegKey, name: &str) -> String {
    key.get_value::<String, _>(name)
        .unwrap_or_default()
        .trim()
        .to_string()
}

pub fn source_id(s: &RegistrySource) -> String {
    format!("{}:{}:{}", s.hive, s.view, s.key.to_lowercase())
}

pub fn merge_records(records: Vec<Application>) -> Vec<Application> {
    let mut map: BTreeMap<String, Application> = BTreeMap::new();
    for app in records {
        // Never merge solely by display name: separate versions/users can coexist.
        let fingerprint = format!(
            "{}|{}|{}|{}|{}",
            app.name.to_lowercase(),
            app.version,
            app.uninstall,
            app.location
                .as_ref()
                .map(|p| p.to_string_lossy().to_lowercase())
                .unwrap_or_default(),
            app.sources
                .first()
                .map(|s| s.hive.as_str())
                .unwrap_or_default()
        );
        if let Some(existing) = map.get_mut(&fingerprint) {
            for s in app.sources {
                if !existing.sources.contains(&s) {
                    existing.sources.push(s);
                }
            }
            if existing.size_kib.is_none() {
                existing.size_kib = app.size_kib;
            }
        } else {
            map.insert(fingerprint, app);
        }
    }
    let mut apps: Vec<_> = map.into_values().collect();
    apps.sort_by_key(|a| a.name.to_lowercase());
    apps
}

pub fn collect(cancel: &AtomicBool) -> Inventory {
    let start = Instant::now();
    let mut records = Vec::new();
    let mut errors = Vec::new();
    for hive_name in ["HKLM", "HKCU"] {
        for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
            if cancelled(cancel) {
                break;
            }
            let root = hive(hive_name).unwrap();
            let parent = match root.open_subkey_with_flags(UNINSTALL_ROOT, KEY_READ | view) {
                Ok(k) => k,
                Err(e) if e.raw_os_error() == Some(2) => continue,
                Err(e) => {
                    errors.push(format!("{hive_name}/{view}: {e}"));
                    continue;
                }
            };
            for name in parent.enum_keys() {
                if cancelled(cancel) {
                    break;
                }
                let name = match name {
                    Ok(n) => n,
                    Err(e) => {
                        errors.push(e.to_string());
                        continue;
                    }
                };
                let key = match parent.open_subkey_with_flags(&name, KEY_READ | view) {
                    Ok(k) => k,
                    Err(e) => {
                        errors.push(format!("{name}: {e}"));
                        continue;
                    }
                };
                let display = value(&key, "DisplayName");
                if display.is_empty() {
                    continue;
                }
                let source = RegistrySource {
                    hive: hive_name.into(),
                    view,
                    key: format!("{UNINSTALL_ROOT}\\{name}"),
                };
                let location = crate::command::expand_environment(&value(&key, "InstallLocation"));
                records.push(Application {
                    id: source_id(&source),
                    name: display,
                    publisher: value(&key, "Publisher"),
                    version: value(&key, "DisplayVersion"),
                    location: if location.is_empty() {
                        None
                    } else {
                        Some(PathBuf::from(location.trim_matches('"')))
                    },
                    uninstall: value(&key, "UninstallString"),
                    quiet_uninstall: value(&key, "QuietUninstallString"),
                    size_kib: key.get_value("EstimatedSize").ok(),
                    system_component: key.get_value::<u32, _>("SystemComponent").unwrap_or(0) == 1,
                    sources: vec![source],
                });
            }
        }
    }
    Inventory {
        apps: merge_records(records),
        errors,
        elapsed_ms: start.elapsed().as_millis(),
        cancelled: cancelled(cancel),
    }
}

pub fn registered(app: &Application) -> UnboltResult<bool> {
    for source in &app.sources {
        match hive(&source.hive)?.open_subkey_with_flags(&source.key, KEY_READ | source.view) {
            Ok(_) => return Ok(true),
            Err(e) if e.raw_os_error() == Some(2) => {}
            Err(e) => return Err(format!("Cannot verify registration: {e}")),
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn app(view: u32, version: &str, hive: &str) -> Application {
        Application {
            id: view.to_string(),
            name: "Example".into(),
            publisher: String::new(),
            version: version.into(),
            location: None,
            uninstall: "uninstall.exe".into(),
            quiet_uninstall: String::new(),
            size_kib: None,
            system_component: false,
            sources: vec![RegistrySource {
                hive: hive.into(),
                view,
                key: "Software\\Example".into(),
            }],
        }
    }
    #[test]
    fn merge_views_but_preserve_versions_and_users() {
        let result = merge_records(vec![
            app(256, "1", "HKCU"),
            app(512, "1", "HKCU"),
            app(256, "2", "HKCU"),
            app(256, "1", "HKLM"),
        ]);
        assert_eq!(result.len(), 3);
        assert!(result.iter().any(|a| a.sources.len() == 2));
    }
    #[test]
    fn pre_cancel_returns_no_partial_success() {
        let result = collect(&AtomicBool::new(true));
        assert!(result.cancelled);
        assert!(result.apps.is_empty());
    }
}
