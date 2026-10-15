use crate::{UnboltResult, inventory, model::*};
use std::{
    collections::HashSet,
    fs,
    hash::{DefaultHasher, Hash, Hasher},
    os::windows::fs::MetadataExt,
    path::{Component, Path, PathBuf, Prefix},
    sync::atomic::AtomicBool,
    time::{Instant, UNIX_EPOCH},
};

const REPARSE_POINT: u32 = 0x400;

pub fn snapshot(path: &Path) -> UnboltResult<FileSnapshot> {
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if m.file_attributes() & REPARSE_POINT != 0 {
        return Err("Reparse points and symbolic links are excluded".into());
    }
    Ok(FileSnapshot {
        is_dir: m.is_dir(),
        len: m.len(),
        modified_ns: m
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        created_ticks: m.creation_time(),
    })
}

pub fn normalize(path: &Path) -> String {
    path.to_string_lossy()
        .trim_start_matches(r"\\?\")
        .trim_end_matches(['\\', '/'])
        .replace('/', "\\")
        .to_lowercase()
}

pub(crate) fn same_or_under(path: &Path, ancestor: &Path) -> bool {
    let p = normalize(path);
    let a = normalize(ancestor);
    p == a || p.starts_with(&(a + "\\"))
}

#[derive(Clone)]
pub struct PathPolicy {
    pub roots: Vec<PathBuf>,
    pub protected: Vec<PathBuf>,
}

impl PathPolicy {
    pub fn explicit_target(path: &Path) -> UnboltResult<Self> {
        let mut policy = Self::windows();
        let parent = path
            .parent()
            .ok_or("A drive root cannot be a removal target")?;
        policy
            .roots
            .push(fs::canonicalize(parent).map_err(|e| e.to_string())?);
        Ok(policy)
    }
    pub fn windows() -> Self {
        let roots = [
            "ProgramFiles",
            "ProgramFiles(x86)",
            "LOCALAPPDATA",
            "APPDATA",
            "ProgramData",
        ]
        .iter()
        .filter_map(|n| crate::context::variable(n).map(PathBuf::from))
        .collect::<Vec<_>>();
        let mut protected = roots.clone();
        protected.push(crate::recovery::data_dir());
        protected.extend(crate::platform_paths::profile_containers());
        for n in ["SystemRoot", "USERPROFILE", "TEMP"] {
            if let Some(p) = crate::context::variable(n) {
                protected.push(p.into());
            }
        }
        if let Ok(exe) = std::env::current_exe()
            && let Some(p) = exe.parent()
        {
            protected.push(p.into());
        }
        if let Some(local) = crate::context::variable("LOCALAPPDATA") {
            protected.push(PathBuf::from(&local).join(crate::recovery::DATA_DIRECTORY));
            protected.push(PathBuf::from(local).join("Unbolt"));
        }
        if let Some(user) = crate::context::variable("USERPROFILE") {
            for name in [
                "Desktop",
                "Documents",
                "Downloads",
                "Pictures",
                "Music",
                "Videos",
                "OneDrive",
                "AppData",
            ] {
                protected.push(PathBuf::from(&user).join(name));
            }
        }
        if let Some(user) = std::env::var_os("USERPROFILE") {
            protected.push(PathBuf::from(user));
        }
        let roots = roots
            .into_iter()
            .map(|p| fs::canonicalize(&p).unwrap_or(p))
            .collect();
        let protected = protected
            .into_iter()
            .map(|p| fs::canonicalize(&p).unwrap_or(p))
            .collect();
        Self { roots, protected }
    }

    pub fn validate(&self, path: &Path, other_apps: &[Application]) -> UnboltResult<PathBuf> {
        if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err("Only absolute paths without parent traversal are supported".into());
        }
        // canonicalize() returns a verbatim local DOS path (\\?\C:\...).
        // Accept that exact prefix class, while retaining UNC/device exclusions.
        if !matches!(path.components().next(), Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
        {
            return Err("Network and device paths are excluded".into());
        }
        // Check every existing ancestor before canonicalizing: junctions must never silently change the target.
        let mut cursor = Some(path);
        while let Some(p) = cursor {
            if p.exists() {
                snapshot(p)?;
            }
            cursor = p.parent();
        }
        let canonical = fs::canonicalize(path).map_err(|e| e.to_string())?;
        let system = crate::platform_paths::windows();
        let executable = std::env::current_exe().ok();
        let packages = crate::platform_paths::machine()
            .into_iter()
            .find(|(name, _)| *name == "ProgramFiles")
            .map(|(_, p)| p.join("WindowsApps"));
        for tree in system
            .as_deref()
            .into_iter()
            .chain(executable.as_deref().and_then(Path::parent))
            .chain(packages.as_deref())
        {
            let tree = fs::canonicalize(tree).unwrap_or_else(|_| tree.to_path_buf());
            if same_or_under(&canonical, &tree) {
                return Err("Windows and Unbolt's executable storage are excluded".into());
            }
        }
        if !self
            .roots
            .iter()
            .any(|r| same_or_under(&canonical, r) && normalize(&canonical) != normalize(r))
        {
            return Err("Outside supported application storage locations".into());
        }
        for protected in &self.protected {
            if same_or_under(protected, &canonical)
                || (normalize(protected).ends_with("\\unbolt")
                    && same_or_under(&canonical, protected))
            {
                return Err("Protected location or an ancestor of a protected location".into());
            }
        }
        for app in other_apps {
            if let Some(location) = &app.location
                && {
                    let location = fs::canonicalize(location).unwrap_or_else(|_| location.clone());
                    same_or_under(&location, &canonical) || same_or_under(&canonical, &location)
                }
            {
                return Err(format!(
                    "Shared with another registered application: {}",
                    app.name
                ));
            }
        }
        Ok(canonical)
    }
}

pub fn validate_tree(path: &Path, cancel: &AtomicBool) -> UnboltResult<()> {
    tree_signature(path, cancel).map(|_| ())
}

pub fn tree_signature(path: &Path, cancel: &AtomicBool) -> UnboltResult<u64> {
    let mut stack = vec![path.to_path_buf()];
    let mut count = 0;
    let mut records = Vec::new();
    while let Some(p) = stack.pop() {
        if cancelled(cancel) {
            return Err("Cancelled; no cleanup started".into());
        }
        count += 1;
        if count > 100_000 {
            return Err("Tree is too large for bounded validation".into());
        }
        let m = snapshot(&p)?;
        records.push((
            normalize(
                p.strip_prefix(path)
                    .map_err(|_| "Tree enumeration escaped its root")?,
            ),
            m.len,
            m.modified_ns,
            m.created_ticks,
            m.is_dir,
        ));
        if m.is_dir {
            for child in fs::read_dir(&p).map_err(|e| e.to_string())? {
                stack.push(child.map_err(|e| e.to_string())?.path());
            }
        }
    }
    records.sort();
    let mut hash = DefaultHasher::new();
    records.hash(&mut hash);
    Ok(hash.finish())
}

pub fn scan(app: &Application, all: &[Application], cancel: &AtomicBool) -> ScanReport {
    let start = Instant::now();
    let mut errors = Vec::new();
    let mut candidates = Vec::new();
    let session_error = crate::process::assert_cleanup_ready(&app.id).err();
    if let Some(error) = &session_error {
        errors.push(error.clone());
    }
    let registered = match inventory::registered(app) {
        Ok(v) => v,
        Err(e) => {
            errors.push(e);
            true
        }
    };
    let policy = PathPolicy::windows();
    let others = all
        .iter()
        .filter(|a| a.id != app.id)
        .cloned()
        .collect::<Vec<_>>();
    let mut locations = Vec::new();
    if let Some(path) = &app.location {
        locations.push((path.clone(), true));
    }
    // Name-only discoveries are review-only and can never be quarantined automatically.
    if !app.name.contains(['\\', '/', ':']) && app.name.len() > 2 {
        for root in &policy.roots {
            locations.push((root.join(&app.name), false));
        }
    }
    let mut seen = HashSet::new();
    for (path, exact) in locations {
        if cancelled(cancel) {
            break;
        }
        if !path.exists() || !seen.insert(normalize(&path)) {
            continue;
        }
        let stamp = match snapshot(&path) {
            Ok(m) => m,
            Err(e) => {
                errors.push(format!("{}: {e}", path.display()));
                continue;
            }
        };
        let signature = policy
            .validate(&path, &others)
            .and_then(|_| tree_signature(&path, cancel));
        let tree_signature = signature.as_ref().ok().copied();
        let (confidence,evidence)=match signature {
            Err(e)=>(Confidence::Blocked,e),
            Ok(_) if registered=>(Confidence::Review,"Application is still registered. These may be active files, not leftovers.".into()),
            Ok(_) if exact=>(Confidence::High,"Exact recorded InstallLocation; registration removed; no shared installation path detected.".into()),
            Ok(_)=>(Confidence::Review,"Folder name matches display name only; ownership is not established.".into()),
        };
        candidates.push(Candidate {
            path,
            confidence,
            evidence,
            snapshot: stamp,
            tree_signature,
        });
    }
    let mut registry_candidates =
        crate::registry_cleanup::scan(app, all, registered, cancel, &mut errors);
    if let Some(error) = session_error {
        for candidate in &mut candidates {
            candidate.confidence = Confidence::Blocked;
            candidate.evidence = error.clone();
        }
        for candidate in &mut registry_candidates {
            candidate.confidence = Confidence::Blocked;
            candidate.evidence = error.clone();
        }
    }
    ScanReport {
        app: app.clone(),
        candidates,
        registry_candidates,
        errors,
        elapsed_ms: start.elapsed().as_millis(),
        cancelled: cancelled(cancel),
        app_registered: registered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub fn fixture(label: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "unbolt-test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }
    #[test]
    fn prevents_root_and_parent_traversal() {
        let root = fixture("paths");
        let child = root.join("App");
        fs::create_dir(&child).unwrap();
        let policy = PathPolicy {
            roots: vec![root.clone()],
            protected: vec![root.clone()],
        };
        assert!(policy.validate(&root, &[]).is_err());
        assert!(policy.validate(&child, &[]).is_ok());
        assert!(policy.validate(&child.join(".."), &[]).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn canonical_local_paths_are_allowed_but_network_and_device_prefixes_are_not() {
        let root = fixture("verbatim");
        let child = root.join("App");
        fs::create_dir(&child).unwrap();
        let policy = PathPolicy {
            roots: vec![fs::canonicalize(&root).unwrap()],
            protected: vec![],
        };
        let canonical = fs::canonicalize(&child).unwrap();
        assert!(policy.validate(&canonical, &[]).is_ok());
        for path in [
            r"\\server\share\App",
            r"\\?\UNC\server\share\App",
            r"\\.\C:\App",
            r"\\?\GLOBALROOT\Device\HarddiskVolume1\App",
        ] {
            assert!(policy.validate(Path::new(path), &[]).is_err(), "{path}");
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn removed_registration_leaves_a_visible_exact_location_for_review() {
        use winreg::{RegKey, enums::*};
        let root = fixture("post-uninstall");
        let directory = root.join("App");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("settings"), b"owned remaining data").unwrap();
        let source = RegistrySource {
            hive: "HKCU".into(),
            view: KEY_WOW64_64KEY,
            key: format!(
                "{}\\UnboltScanFixture-{}",
                inventory::UNINSTALL_ROOT,
                crate::recovery::unique_id()
            ),
        };
        let hive = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _) = hive.create_subkey(&source.key).unwrap();
        key.set_value("DisplayName", &"Unbolt scan fixture")
            .unwrap();
        drop(key);
        let app = Application {
            id: inventory::source_id(&source),
            name: "Unbolt scan fixture".into(),
            publisher: String::new(),
            version: String::new(),
            location: Some(directory.clone()),
            uninstall: String::new(),
            quiet_uninstall: String::new(),
            size_kib: None,
            system_component: false,
            sources: vec![source.clone()],
        };
        let before = scan(&app, std::slice::from_ref(&app), &AtomicBool::new(false));
        assert!(before.app_registered);
        assert_eq!(before.candidates[0].confidence, Confidence::Review);
        hive.delete_subkey(&source.key).unwrap();
        let after = scan(&app, &[], &AtomicBool::new(false));
        assert!(!after.app_registered);
        assert!(after.errors.is_empty(), "{:?}", after.errors);
        assert_eq!(after.candidates.len(), 1);
        assert_eq!(after.candidates[0].confidence, Confidence::High);
        assert_eq!(
            fs::read(directory.join("settings")).unwrap(),
            b"owned remaining data"
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn pre_cancel_tree_does_no_work() {
        assert!(
            validate_tree(Path::new("missing"), &AtomicBool::new(true))
                .unwrap_err()
                .contains("Cancelled")
        );
    }
    #[test]
    fn path_prefix_respects_boundaries() {
        assert!(!same_or_under(
            Path::new(r"C:\Apps2"),
            Path::new(r"C:\Apps")
        ));
    }

    #[test]
    fn nested_content_changes_invalidate_preview() {
        let root = fixture("signature");
        let child = root.join("nested");
        fs::create_dir(&child).unwrap();
        let file = child.join("config");
        fs::write(&file, b"old").unwrap();
        let flag = AtomicBool::new(false);
        let before = tree_signature(&root, &flag).unwrap();
        fs::write(&file, b"replacement content").unwrap();
        assert_ne!(before, tree_signature(&root, &flag).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn shared_locations_block_both_parent_and_child() {
        let root = fixture("shared");
        let parent = root.join("Vendor");
        let child = parent.join("Product");
        fs::create_dir_all(&child).unwrap();
        let app = Application {
            id: "other".into(),
            name: "Other product".into(),
            publisher: String::new(),
            version: String::new(),
            location: Some(child.clone()),
            uninstall: String::new(),
            quiet_uninstall: String::new(),
            size_kib: None,
            system_component: false,
            sources: vec![],
        };
        let policy = PathPolicy {
            roots: vec![root.clone()],
            protected: vec![root.clone()],
        };
        assert!(
            policy
                .validate(&parent, &[app])
                .unwrap_err()
                .contains("Shared")
        );
        fs::remove_dir_all(root).unwrap();
    }
}
