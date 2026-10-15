//! Owned software-key detection and typed, backed-up cleanup.
use crate::{UnboltResult, inventory, model::*, recovery, scanner};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};
use windows_sys::Win32::{
    Security::{
        DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, IsValidSecurityDescriptor,
        OWNER_SECURITY_INFORMATION,
    },
    System::Registry::{RegGetKeySecurity, RegSetKeySecurity},
};
use winreg::{RegKey, RegValue, enums::*};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawValue {
    pub value_type: u32,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryTree {
    pub security_descriptor: Vec<u8>,
    pub values: BTreeMap<String, RawValue>,
    pub children: BTreeMap<String, RegistryTree>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistryCandidate {
    pub source: RegistrySource,
    pub confidence: Confidence,
    pub evidence: String,
    pub snapshot: RegistryTree,
}
impl RegistryCandidate {
    pub fn label(&self) -> String {
        format!(
            "{}\\{} [{}-bit]",
            self.source.hive,
            self.source.key,
            if self.source.view == KEY_WOW64_64KEY {
                64
            } else {
                32
            }
        )
    }
}
#[derive(Serialize, Deserialize)]
pub struct RegistryManifest {
    pub kind: String,
    pub application: String,
    pub source: RegistrySource,
    pub snapshot: RegistryTree,
    pub state: String,
}

fn capture(
    key: &RegKey,
    cancel: &AtomicBool,
    budget: &mut usize,
    depth: usize,
) -> UnboltResult<RegistryTree> {
    if cancelled(cancel) {
        return Err("Registry scan cancelled".into());
    }
    if *budget == 0 || depth > 32 {
        return Err("Registry subtree exceeds bounded capture limit".into());
    }
    *budget -= 1;
    let mut values = BTreeMap::new();
    let mut children = BTreeMap::new();
    for entry in key.enum_values() {
        let (name, v) = entry.map_err(|e| e.to_string())?;
        if v.vtype == REG_LINK {
            return Err("Registry links are excluded".into());
        }
        if v.bytes.len() > 16 * 1024 * 1024 {
            return Err("Registry value exceeds capture limit".into());
        }
        values.insert(
            name,
            RawValue {
                value_type: v.vtype as u32,
                bytes: v.bytes.into_owned(),
            },
        );
    }
    for name in key.enum_keys() {
        let name = name.map_err(|e| e.to_string())?;
        let child = key
            .open_subkey_with_options_flags(&name, REG_OPTION_OPEN_LINK, KEY_READ)
            .map_err(|e| e.to_string())?;
        children.insert(name, capture(&child, cancel, budget, depth + 1)?);
    }
    let information =
        DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION;
    let mut length = 0;
    unsafe {
        RegGetKeySecurity(
            key.raw_handle().cast(),
            information,
            std::ptr::null_mut(),
            &mut length,
        );
    }
    if length == 0 || length > 1024 * 1024 {
        return Err("Cannot capture registry permissions".into());
    }
    let mut security_descriptor = vec![0u8; length as usize];
    let code = unsafe {
        RegGetKeySecurity(
            key.raw_handle().cast(),
            information,
            security_descriptor.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if code != 0 {
        return Err(format!("Cannot read registry security descriptor ({code})"));
    }
    security_descriptor.truncate(length as usize);
    Ok(RegistryTree {
        values,
        children,
        security_descriptor,
    })
}
pub fn snapshot(source: &RegistrySource, cancel: &AtomicBool) -> UnboltResult<RegistryTree> {
    validate_source(source)?;
    capture_source(source, cancel)
}
pub(crate) fn capture_source(
    source: &RegistrySource,
    cancel: &AtomicBool,
) -> UnboltResult<RegistryTree> {
    let key = open_no_links(source, KEY_READ)?;
    capture(&key, cancel, &mut 4096, 0)
}
pub(crate) fn open_no_links(source: &RegistrySource, permissions: u32) -> UnboltResult<RegKey> {
    let mut key = inventory::hive(&source.hive)?;
    let parts = source.key.split('\\').collect::<Vec<_>>();
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() || part.contains('\0') {
            return Err("Invalid registry path".into());
        }
        key = key
            .open_subkey_with_options_flags(
                part,
                REG_OPTION_OPEN_LINK,
                KEY_READ | source.view | if i + 1 == parts.len() { permissions } else { 0 },
            )
            .map_err(|e| e.to_string())?;
        for value in key.enum_values() {
            if value.map_err(|e| e.to_string())?.1.vtype == REG_LINK {
                return Err("Registry links are excluded".into());
            }
        }
    }
    Ok(key)
}
fn validate_source(s: &RegistrySource) -> UnboltResult<()> {
    if !matches!(s.hive.as_str(), "HKCU" | "HKLM")
        || !matches!(s.view, KEY_WOW64_32KEY | KEY_WOW64_64KEY)
    {
        return Err("Unsupported registry hive/view".into());
    }
    let parts = s.key.split('\\').collect::<Vec<_>>();
    if parts.len() < 2
        || !parts[0].eq_ignore_ascii_case("software")
        || parts
            .iter()
            .any(|p| p.is_empty() || p.contains(['\r', '\n', '[', ']']) || matches!(*p, "." | ".."))
    {
        return Err("Only bounded application Software subtrees are supported".into());
    }
    if matches!(
        parts[1].to_lowercase().as_str(),
        "microsoft" | "classes" | "policies" | "wow6432node" | "unbolt"
    ) {
        return Err("Protected registry namespace".into());
    }
    Ok(())
}
fn identifier(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}
fn product_names(app: &Application) -> Vec<String> {
    let short = app
        .name
        .split_whitespace()
        .take_while(|w| !w.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .collect::<Vec<_>>()
        .join(" ");
    vec![identifier(&app.name), identifier(&short)]
        .into_iter()
        .filter(|s| s.len() > 3)
        .collect()
}
fn contains_owned_path(tree: &RegistryTree, location: &Path) -> bool {
    let location = scanner::normalize(location);
    tree.values.values().any(|v| {
        if !matches!(v.value_type, 1 | 2 | 7) {
            return false;
        }
        let utf16 = v
            .bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect::<Vec<_>>();
        let text = String::from_utf16_lossy(&utf16)
            .replace('/', "\\")
            .to_lowercase();
        text.match_indices(&location).any(|(start, _)| {
            text[start + location.len()..]
                .chars()
                .next()
                .is_none_or(|c| matches!(c, '\\' | '"' | '\'' | '\0' | ' ' | ',' | ';'))
        })
    }) || tree
        .children
        .values()
        .any(|t| contains_owned_path(t, Path::new(&location)))
}
fn shared_product(app: &Application, all: &[Application]) -> bool {
    let names = product_names(app);
    all.iter()
        .any(|a| a.id != app.id && product_names(a).iter().any(|n| names.contains(n)))
}

pub fn scan(
    app: &Application,
    all: &[Application],
    registered: bool,
    cancel: &AtomicBool,
    errors: &mut Vec<String>,
) -> Vec<RegistryCandidate> {
    let mut results = Vec::new();
    let names = product_names(app);
    let publisher = identifier(app.publisher.split(',').next().unwrap_or_default());
    for hive in ["HKCU", "HKLM"] {
        for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
            if cancelled(cancel) {
                return results;
            }
            let root = match inventory::hive(hive).and_then(|r| {
                r.open_subkey_with_flags("Software", KEY_READ | view)
                    .map_err(|e| e.to_string())
            }) {
                Ok(k) => k,
                Err(e) => {
                    errors.push(e);
                    continue;
                }
            };
            for name in root.enum_keys() {
                if cancelled(cancel) {
                    return results;
                }
                let name = match name {
                    Ok(n) => n,
                    Err(e) => {
                        errors.push(e.to_string());
                        continue;
                    }
                };
                let normalized = identifier(&name);
                let is_product = names.contains(&normalized);
                let is_vendor = publisher.len() > 3
                    && (publisher == normalized
                        || publisher.strip_suffix("ltd") == Some(&normalized));
                if !is_product && !is_vendor {
                    continue;
                }
                let mut keys = Vec::new();
                if is_product {
                    keys.push(format!("Software\\{name}"));
                } else if let Ok(vendor) = root.open_subkey(&name) {
                    for child in vendor.enum_keys().flatten() {
                        if names.contains(&identifier(&child)) {
                            keys.push(format!("Software\\{name}\\{child}"));
                        }
                    }
                }
                for key in keys {
                    let source = RegistrySource {
                        hive: hive.into(),
                        view,
                        key,
                    };
                    let snapshot = match snapshot(&source, cancel) {
                        Ok(t) => t,
                        Err(e) => {
                            errors.push(format!("{}: {e}", source.key));
                            continue;
                        }
                    };
                    let explicit = app
                        .location
                        .as_ref()
                        .is_some_and(|p| contains_owned_path(&snapshot, p));
                    let (confidence, evidence) = if registered {
                        (
                            Confidence::Review,
                            "Application is still registered; settings may be active.",
                        )
                    } else if shared_product(app, all) {
                        (
                            Confidence::Blocked,
                            "Another installed version shares this product name.",
                        )
                    } else if explicit {
                        (
                            Confidence::High,
                            "Product-specific key contains a path to the recorded installation directory.",
                        )
                    } else {
                        (
                            Confidence::Review,
                            "Product name matches; exclusive ownership needs review.",
                        )
                    };
                    results.push(RegistryCandidate {
                        source,
                        confidence,
                        evidence: evidence.into(),
                        snapshot,
                    });
                }
            }
        }
    }
    // HKCU Software keys may be shared by both views. Preserve distinct views only when data differs.
    let mut unique: Vec<RegistryCandidate> = Vec::new();
    for c in results {
        if !unique.iter().any(|u| {
            u.source.hive == "HKCU"
                && c.source.hive == "HKCU"
                && u.source.key.eq_ignore_ascii_case(&c.source.key)
                && u.snapshot == c.snapshot
        }) {
            unique.push(c);
        }
    }
    unique
}

pub(crate) fn persist(path: &Path, m: &RegistryManifest) -> UnboltResult<()> {
    let bytes = serde_json::to_vec_pretty(m).map_err(|e| e.to_string())?;
    let pending = path.with_extension("pending");
    let mut f = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&pending)
        .map_err(|e| e.to_string())?;
    use std::io::Write;
    f.write_all(&bytes)
        .and_then(|_| f.sync_all())
        .map_err(|e| e.to_string())?;
    fs::rename(&pending, path).map_err(|e| e.to_string())
}

pub fn cleanup(
    app: &Application,
    c: &RegistryCandidate,
    cancel: &AtomicBool,
) -> UnboltResult<PathBuf> {
    crate::process::assert_cleanup_ready(&app.id)?;
    if inventory::registered(app)? {
        return Err("Uninstall the registered application before registry cleanup".into());
    }
    let current = inventory::collect(cancel);
    if current.cancelled || !current.errors.is_empty() || shared_product(app, &current.apps) {
        return Err("Registry ownership cannot be verified against current inventory".into());
    }
    let path = cleanup_at(
        app,
        c,
        cancel,
        &recovery::data_dir().join("registry-cleanup"),
    )?;
    let _ = recovery::history("registry-cleanup", &app.name, &c.label());
    Ok(path)
}
pub(crate) fn cleanup_at(
    app: &Application,
    c: &RegistryCandidate,
    cancel: &AtomicBool,
    storage: &Path,
) -> UnboltResult<PathBuf> {
    validate_source(&c.source)?;
    if c.confidence != Confidence::High
        || !app
            .location
            .as_ref()
            .is_some_and(|p| contains_owned_path(&c.snapshot, p))
    {
        return Err("Registry candidate lacks explicit ownership evidence".into());
    }
    if snapshot(&c.source, cancel)? != c.snapshot {
        return Err("Registry key changed since preview; rescan first".into());
    }
    let dir = storage.join(recovery::unique_id());
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join("manifest.json");
    let mut manifest = RegistryManifest {
        kind: "registry".into(),
        application: app.name.clone(),
        source: c.source.clone(),
        snapshot: c.snapshot.clone(),
        state: "prepared".into(),
    };
    persist(&path, &manifest)?;
    if cancelled(cancel) {
        return Err("Cancelled before registry deletion".into());
    }
    if snapshot(&c.source, cancel)? != c.snapshot {
        return Err("Registry key changed during backup; nothing deleted".into());
    }
    let (parent, name) = c
        .source
        .key
        .rsplit_once('\\')
        .ok_or("Invalid registry path")?;
    let key = open_no_links(
        &RegistrySource {
            key: parent.into(),
            ..c.source.clone()
        },
        KEY_READ | KEY_WRITE,
    )?;
    if let Err(e) = key.delete_subkey_all(name) {
        manifest.state = "deletion-failed-review-required".into();
        let _ = persist(&path, &manifest);
        return Err(format!(
            "Registry deletion failed; backup retained at {}: {e}",
            path.display()
        ));
    }
    manifest.state = "removed".into();
    persist(&path, &manifest)?;
    Ok(path)
}
fn value_type(t: u32) -> UnboltResult<RegType> {
    match t {
        0 => Ok(REG_NONE),
        1 => Ok(REG_SZ),
        2 => Ok(REG_EXPAND_SZ),
        3 => Ok(REG_BINARY),
        4 => Ok(REG_DWORD),
        5 => Ok(REG_DWORD_BIG_ENDIAN),
        7 => Ok(REG_MULTI_SZ),
        8 => Ok(REG_RESOURCE_LIST),
        9 => Ok(REG_FULL_RESOURCE_DESCRIPTOR),
        10 => Ok(REG_RESOURCE_REQUIREMENTS_LIST),
        11 => Ok(REG_QWORD),
        _ => Err("Unsupported registry type in backup".into()),
    }
}
fn restore_tree(key: &RegKey, tree: &RegistryTree) -> UnboltResult<()> {
    for (name, v) in &tree.values {
        key.set_raw_value(
            name,
            &RegValue {
                vtype: value_type(v.value_type)?,
                bytes: v.bytes.clone().into(),
            },
        )
        .map_err(|e| e.to_string())?;
    }
    for (name, child) in &tree.children {
        if name.contains('\\') {
            return Err("Invalid child name in backup".into());
        }
        let (k, _) = key
            .create_subkey_with_flags(name, KEY_READ | KEY_WRITE | 0x40000)
            .map_err(|e| e.to_string())?;
        restore_tree(&k, child)?;
    }
    if !descriptor_bounds_valid(&tree.security_descriptor)
        || unsafe { IsValidSecurityDescriptor(tree.security_descriptor.as_ptr() as *mut _) } == 0
    {
        return Err("Invalid registry permission backup".into());
    }
    // Owner/group are retained for full privileged recovery. Restore the DACL here;
    // assigning a different owner requires the future privileged recovery helper.
    let code = unsafe {
        RegSetKeySecurity(
            key.raw_handle().cast(),
            DACL_SECURITY_INFORMATION,
            tree.security_descriptor.as_ptr() as *mut _,
        )
    };
    if code != 0 {
        return Err(format!(
            "Cannot restore registry access permissions ({code})"
        ));
    }
    Ok(())
}

fn descriptor_bounds_valid(bytes: &[u8]) -> bool {
    if bytes.len() < 20 || u16::from_le_bytes([bytes[2], bytes[3]]) & 0x8000 == 0 {
        return false;
    }
    for position in [4, 8, 12, 16] {
        let offset = u32::from_le_bytes(bytes[position..position + 4].try_into().unwrap()) as usize;
        if offset == 0 {
            continue;
        }
        if offset < 20 || offset.checked_add(8).is_none_or(|end| end > bytes.len()) {
            return false;
        }
        let length = if position < 12 {
            8 + bytes[offset + 1] as usize * 4
        } else {
            u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize
        };
        if length < 8
            || offset
                .checked_add(length)
                .is_none_or(|end| end > bytes.len())
        {
            return false;
        }
    }
    true
}
pub fn restore(path: &Path) -> UnboltResult<()> {
    restore_at(path, &recovery::data_dir().join("registry-cleanup"))?;
    let _ = recovery::history(
        "registry-restore",
        "Registry backup",
        &path.display().to_string(),
    );
    Ok(())
}
pub(crate) fn restore_at(path: &Path, storage: &Path) -> UnboltResult<()> {
    restore_snapshot_manifest(path, storage, "registry", validate_source)
}
pub(crate) fn restore_snapshot_manifest(
    path: &Path,
    storage: &Path,
    kind: &str,
    validate: fn(&RegistrySource) -> UnboltResult<()>,
) -> UnboltResult<()> {
    let path = fs::canonicalize(path).map_err(|e| e.to_string())?;
    let storage = fs::canonicalize(storage).map_err(|e| e.to_string())?;
    if !path.starts_with(storage)
        || path.file_name().and_then(|s| s.to_str()) != Some("manifest.json")
    {
        return Err("Registry backup must be inside Unbolt storage".into());
    }
    let mut m: RegistryManifest =
        serde_json::from_slice(&fs::read(&path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    validate(&m.source)?;
    if m.kind != kind || m.state != "removed" {
        return Err("Backup is not a completed registry removal".into());
    }
    let (parent, name) = m
        .source
        .key
        .rsplit_once('\\')
        .ok_or("Invalid registry source")?;
    let parent = open_no_links(
        &RegistrySource {
            key: parent.into(),
            ..m.source.clone()
        },
        KEY_READ | KEY_WRITE,
    )?;
    let (key, disposition) = parent
        .create_subkey_with_flags(name, KEY_READ | KEY_WRITE | 0x40000 | m.source.view)
        .map_err(|e| e.to_string())?;
    if disposition != REG_CREATED_NEW_KEY {
        return Err("Registry destination already exists; nothing overwritten".into());
    }
    if let Err(e) = restore_tree(&key, &m.snapshot) {
        return Err(format!(
            "Restore incomplete; backup retained and destination needs review: {e}"
        ));
    }
    m.state = "restored".into();
    persist(&path, &m)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn link_typed_parent_is_rejected_before_child_capture() {
        let name = format!("UnboltLinkGuardX{}", recovery::unique_id());
        let path = format!("Software\\{name}");
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (parent, _) = hkcu.create_subkey(&path).unwrap();
        parent
            .set_raw_value(
                "SymbolicLinkValue",
                &RegValue {
                    vtype: REG_LINK,
                    bytes: "\\Registry\\Machine\\Software\\UnboltLinkGuardMissing\0"
                        .encode_utf16()
                        .flat_map(u16::to_le_bytes)
                        .collect::<Vec<_>>()
                        .into(),
                },
            )
            .unwrap();
        let (child, _) = parent.create_subkey("Child").unwrap();
        child.set_value("Owned", &123u32).unwrap();
        drop(child);
        drop(parent);
        let source = RegistrySource {
            hive: "HKCU".into(),
            view: KEY_WOW64_64KEY,
            key: format!("{path}\\Child"),
        };
        let result = snapshot(&source, &AtomicBool::new(false));
        assert!(result.unwrap_err().contains("links"));
        assert_eq!(
            hkcu.open_subkey(&source.key)
                .unwrap()
                .get_value::<u32, _>("Owned")
                .unwrap(),
            123
        );
        hkcu.delete_subkey_all(&path).unwrap();
    }
    #[test]
    fn malformed_security_descriptors_are_rejected_before_windows_calls() {
        assert!(!descriptor_bounds_valid(&[]));
        assert!(!descriptor_bounds_valid(&[0; 20]));
        let mut b = vec![0; 20];
        b[3] = 0x80;
        b[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(!descriptor_bounds_valid(&b));
    }
    #[test]
    fn path_reference_has_component_boundary() {
        let mut t = RegistryTree {
            security_descriptor: vec![],
            values: BTreeMap::new(),
            children: BTreeMap::new(),
        };
        t.values.insert(
            "Path".into(),
            RawValue {
                value_type: 1,
                bytes: "C:\\AppEvil\0"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            },
        );
        assert!(!contains_owned_path(&t, Path::new(r"C:\App")));
    }
    #[test]
    fn refuses_protected_registry_namespaces() {
        for key in [
            "Software",
            "Software\\Microsoft\\Example",
            "Software\\Classes\\Example",
            "Software\\Unbolt",
            "Software\\Unbolt",
            "Software\\Example\\..",
        ] {
            assert!(
                validate_source(&RegistrySource {
                    hive: "HKCU".into(),
                    view: KEY_WOW64_64KEY,
                    key: key.into()
                })
                .is_err()
            );
        }
    }
    #[test]
    fn registry_cleanup_and_restore_preserve_raw_types_and_conflicts() {
        let key_name = format!("UnboltFixture{}", recovery::unique_id());
        let source = RegistrySource {
            hive: "HKCU".into(),
            view: KEY_WOW64_64KEY,
            key: format!("Software\\{key_name}"),
        };
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (k, _) = hkcu.create_subkey(&source.key).unwrap();
        k.set_value("Path", &r"C:\UnboltFixtureApp").unwrap();
        k.set_value("Number", &123u32).unwrap();
        let (child, _) = k.create_subkey("Nested").unwrap();
        child
            .set_raw_value(
                "Binary",
                &RegValue {
                    vtype: REG_BINARY,
                    bytes: vec![0, 255, 7].into(),
                },
            )
            .unwrap();
        drop(child);
        drop(k);
        let cancel = AtomicBool::new(false);
        let before = snapshot(&source, &cancel).unwrap();
        let app = Application {
            id: "fixture".into(),
            name: key_name.clone(),
            publisher: String::new(),
            version: String::new(),
            location: Some(r"C:\UnboltFixtureApp".into()),
            uninstall: String::new(),
            quiet_uninstall: String::new(),
            size_kib: None,
            system_component: false,
            sources: vec![],
        };
        let c = RegistryCandidate {
            source: source.clone(),
            confidence: Confidence::High,
            evidence: "fixture".into(),
            snapshot: before.clone(),
        };
        let storage =
            std::env::temp_dir().join(format!("unbolt-registry-{}", recovery::unique_id()));
        let backup = cleanup_at(&app, &c, &cancel, &storage).unwrap();
        assert!(snapshot(&source, &cancel).is_err());
        let (occupied, _) = hkcu.create_subkey(&source.key).unwrap();
        drop(occupied);
        assert!(
            restore_at(&backup, &storage)
                .unwrap_err()
                .contains("exists")
        );
        hkcu.delete_subkey_all(&source.key).unwrap();
        restore_at(&backup, &storage).unwrap();
        assert_eq!(before, snapshot(&source, &cancel).unwrap());
        hkcu.delete_subkey_all(&source.key).unwrap();
        assert!(storage.starts_with(std::env::temp_dir()));
        fs::remove_dir_all(storage).unwrap();
    }
}
