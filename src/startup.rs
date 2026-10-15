//! Purpose-specific Run/RunOnce values and Startup-folder files. No execution.
use crate::{
    UnboltResult,
    broker::identity,
    command, crypto, inventory,
    model::*,
    process,
    records::RecordPage,
    recovery,
    registry_cleanup::{self, RawValue},
    scanner,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};
use windows_sys::Win32::{
    Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW},
    System::Com::CoTaskMemFree,
    UI::Shell::{FOLDERID_CommonStartup, SHGetKnownFolderPath},
};
use winreg::{RegValue, enums::*};
pub const RUN: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
pub const RUN_ONCE: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum Source {
    Registry {
        location: RegistrySource,
        name: String,
    },
    Folder {
        all_users: bool,
        name: String,
    },
}
impl Source {
    pub fn name(&self) -> &str {
        match self {
            Self::Registry { name, .. } | Self::Folder { name, .. } => name,
        }
    }
    pub fn slot(&self) -> String {
        match self {
            Self::Registry { location, name } => format!(
                "registry:{}:{}:{}:{}",
                location.hive,
                location.view,
                location.key.to_lowercase(),
                name.to_lowercase()
            ),
            Self::Folder { all_users, name } => {
                format!("folder:{all_users}:{}", name.to_lowercase())
            }
        }
    }
    pub fn scope(&self) -> String {
        match self {
            Self::Registry { location, .. } => format!(
                "{} · {}-bit",
                if location.hive == "HKLM" {
                    "All users"
                } else {
                    "Current user"
                },
                if location.view == KEY_WOW64_64KEY {
                    64
                } else {
                    32
                }
            ),
            Self::Folder { all_users, .. } => if *all_users {
                "All users"
            } else {
                "Current user"
            }
            .into(),
        }
    }
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::Registry { location, .. } if location.key.eq_ignore_ascii_case(RUN_ONCE) => {
                "Registry: RunOnce"
            }
            Self::Registry { .. } => "Registry: Run",
            Self::Folder { .. } => "Startup folder",
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum Snapshot {
    Registry(RawValue),
    File {
        metadata: FileSnapshot,
        digest: [u8; 32],
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub source: Source,
    pub snapshot: Option<Snapshot>,
    pub backup: Option<String>,
    pub state: String,
    pub location: String,
    pub command: String,
    pub issue: Option<String>,
    #[serde(default)]
    pub launch: Option<crate::shell_link::SavedLink>,
    #[serde(default)]
    pub launch_note: Option<String>,
}
impl Entry {
    pub fn name(&self) -> &str {
        self.source.name()
    }
    pub fn mutable(&self) -> bool {
        self.snapshot.is_some()
            && self.issue.is_none()
            && matches!(
                self.state.as_str(),
                "Configured" | "Disabled by Unbolt" | "Needs recovery review"
            )
    }
    pub fn fingerprint(&self) -> UnboltResult<[u8; 32]> {
        crypto::fingerprint(&(
            &self.source,
            &self.snapshot,
            &self.backup,
            &self.state,
            scanner::normalize(Path::new(&self.location)),
        ))
    }
    pub fn matches(&self, query: &str) -> bool {
        let q = query.to_lowercase();
        format!(
            "{} {} {} {} {} {} {}",
            self.name(),
            self.source.scope(),
            self.location,
            self.command,
            self.state,
            self.source.kind_label(),
            self.display_command()
        )
        .to_lowercase()
        .contains(&q)
    }
    pub fn details(&self) -> String {
        let mut details = format!(
            "{} · {}\r\n{}\r\n{}\r\n{}{}\r\n\r\nConfigured means the startup source is present. Windows may separately block startup. This action does not start or stop an already-running program.",
            self.name(),
            self.source.scope(),
            self.state,
            self.location,
            self.command,
            self.issue
                .as_ref()
                .map(|s| format!("\r\n{s}"))
                .unwrap_or_default()
        );
        if let Some(launch) = &self.launch {
            details.push_str(&format!(
                "\r\n\r\nTarget: {}\r\nArguments: {}\r\nWorking folder: {}",
                launch.target, launch.arguments, launch.working_directory
            ));
        }
        if let Some(note) = &self.launch_note {
            details.push_str(&format!("\r\nTarget details: {note}"));
        }
        details
    }
    pub fn display_command(&self) -> String {
        if matches!(self.source, Source::Folder { .. }) {
            self.launch
                .as_ref()
                .map(|l| {
                    format!("{} {}", command::quote_argument(&l.target), l.arguments)
                        .trim_end()
                        .to_string()
                })
                .unwrap_or_else(|| self.location.clone())
        } else {
            self.command.clone()
        }
    }
    pub fn launches(&self, executable: &Path) -> bool {
        let Some(launch) = &self.launch else {
            return false;
        };
        let target = PathBuf::from(command::expand_environment(&launch.target));
        if !target.is_absolute() || target.to_string_lossy().starts_with(r"\\") {
            return false;
        }
        match (fs::canonicalize(target), fs::canonicalize(executable)) {
            (Ok(a), Ok(b)) => scanner::normalize(&a) == scanner::normalize(&b),
            _ => false,
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum Change {
    Disable,
    Restore,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Outcome {
    pub name: String,
    pub state: String,
    pub backup: PathBuf,
    pub message: String,
    pub registry_transaction: Option<bool>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u32,
    kind: String,
    application: String,
    source: Source,
    original_location: String,
    snapshot: Snapshot,
    state: String,
}
struct Policy {
    user: Option<PathBuf>,
    common: Option<PathBuf>,
}
impl Policy {
    fn windows() -> Self {
        let user = inventory::hive("HKCU")
            .ok()
            .and_then(|h| {
                h.open_subkey(
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
                )
                .ok()
            })
            .and_then(|k| k.get_value::<String, _>("Startup").ok())
            .map(|p| PathBuf::from(command::expand_environment(&p)))
            .or_else(|| {
                crate::context::variable("APPDATA")
                    .map(|p| PathBuf::from(p).join("Microsoft/Windows/Start Menu/Programs/Startup"))
            });
        let common = unsafe {
            let mut pointer = std::ptr::null_mut();
            if SHGetKnownFolderPath(
                &FOLDERID_CommonStartup,
                0,
                std::ptr::null_mut(),
                &mut pointer,
            ) < 0
            {
                None
            } else {
                let mut n = 0;
                while n < 32768 && *pointer.add(n) != 0 {
                    n += 1;
                }
                let value = (n < 32768).then(|| {
                    PathBuf::from(String::from_utf16_lossy(std::slice::from_raw_parts(
                        pointer, n,
                    )))
                });
                CoTaskMemFree(pointer.cast());
                value
            }
        };
        Self { user, common }
    }
    fn file(&self, all_users: bool, name: &str) -> UnboltResult<PathBuf> {
        if name.is_empty()
            || name.contains(['\\', '/', ':', '\0'])
            || name.ends_with(['.', ' '])
            || matches!(name, "." | "..")
            || name.eq_ignore_ascii_case("desktop.ini")
        {
            return Err("Only an exact Startup-folder file is supported".into());
        }
        let root = if all_users { &self.common } else { &self.user }
            .as_ref()
            .ok_or("Startup folder is unavailable")?;
        identity::check_chain(root, false)?;
        let plain = PathBuf::from(crate::records::display_path(&root.display().to_string()));
        let checked = scanner::PathPolicy::explicit_target(&plain)?.validate(&plain, &[])?;
        Ok(checked.join(name))
    }
    fn location(&self, source: &Source) -> UnboltResult<String> {
        match source {
            Source::Registry { location, name } => {
                validate_registry(location, name)?;
                Ok(format!("{}\\{} · {}", location.hive, location.key, name))
            }
            Source::Folder { all_users, name } => self
                .file(*all_users, name)
                .map(|p| crate::records::display_path(&p.display().to_string())),
        }
    }
}
fn validate_registry(source: &RegistrySource, name: &str) -> UnboltResult<()> {
    if !matches!(source.hive.as_str(), "HKCU" | "HKLM")
        || !matches!(source.view, KEY_WOW64_64KEY | KEY_WOW64_32KEY)
        || ![RUN, RUN_ONCE]
            .iter()
            .any(|p| p.eq_ignore_ascii_case(&source.key))
        || name.contains('\0')
        || name.encode_utf16().count() > 16383
    {
        return Err("Only an exact Run or RunOnce startup value is supported".into());
    }
    Ok(())
}
fn raw(value: RegValue) -> UnboltResult<RawValue> {
    if !matches!(value.vtype, REG_SZ | REG_EXPAND_SZ)
        || value.bytes.len() > 65536
        || !value.bytes.len().is_multiple_of(2)
    {
        return Err("This startup value has an unsupported type or size; it is read-only".into());
    }
    Ok(RawValue {
        value_type: value.vtype as u32,
        bytes: value.bytes.into_owned(),
    })
}
fn text(snapshot: &Snapshot) -> String {
    match snapshot {
        Snapshot::Registry(value) => {
            let units = value
                .bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| u16::from_le_bytes(*b))
                .take_while(|&u| u != 0)
                .collect::<Vec<_>>();
            String::from_utf16_lossy(&units)
        }
        Snapshot::File { .. } => {
            "Startup-folder launch file. Only the saved launch file is changed.".into()
        }
    }
}
fn launch_details(
    source: &Source,
    snapshot: &Snapshot,
    file: Option<&Path>,
    cancel: &AtomicBool,
) -> (Option<crate::shell_link::SavedLink>, Option<String>) {
    let result = (|| -> UnboltResult<crate::shell_link::SavedLink> {
        match source {
            Source::Registry { .. } => {
                let parsed = command::parse(&text(snapshot))?;
                Ok(crate::shell_link::SavedLink {
                    target: parsed.executable,
                    arguments: parsed
                        .arguments
                        .iter()
                        .map(|a| command::quote_argument(a))
                        .collect::<Vec<_>>()
                        .join(" "),
                    working_directory: String::new(),
                })
            }
            Source::Folder { name, .. } => {
                let path = file.ok_or("Startup file is unavailable")?;
                let Snapshot::File { metadata, digest } = snapshot else {
                    return Err("Startup-file snapshot is unavailable".into());
                };
                let info = if Path::new(name)
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("lnk"))
                {
                    crate::shell_link::read(path)?
                } else {
                    crate::shell_link::SavedLink {
                        target: crate::records::display_path(&path.display().to_string()),
                        arguments: String::new(),
                        working_directory: String::new(),
                    }
                };
                if scanner::snapshot(path)? != *metadata
                    || crypto::file_with_cancel(path, cancel)? != *digest
                {
                    return Err("Startup file changed while reading target details".into());
                }
                Ok(info)
            }
        }
    })();
    match result {
        Ok(info) => (Some(info), None),
        Err(error) => (None, Some(error)),
    }
}
fn capture(policy: &Policy, source: &Source, cancel: &AtomicBool) -> UnboltResult<Snapshot> {
    if cancelled(cancel) {
        return Err("Startup operation cancelled".into());
    }
    match source {
        Source::Registry { location, name } => {
            validate_registry(location, name)?;
            registry_cleanup::open_no_links(location, KEY_READ)?
                .get_raw_value(name)
                .map_err(|e| e.to_string())
                .and_then(raw)
                .map(Snapshot::Registry)
        }
        Source::Folder { all_users, name } => {
            let path = policy.file(*all_users, name)?;
            let metadata = scanner::snapshot(&path)?;
            if metadata.is_dir {
                return Err("Startup directories are not launch files".into());
            }
            let digest = crypto::file_with_cancel(&path, cancel)?;
            if scanner::snapshot(&path)? != metadata {
                return Err("Startup file changed while reading".into());
            }
            Ok(Snapshot::File { metadata, digest })
        }
    }
}
fn manifest_path(storage: &Path, id: &str) -> UnboltResult<PathBuf> {
    if id.is_empty() || id.len() > 128 || !id.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
        return Err("Invalid startup backup identity".into());
    }
    let path = storage.join(id).join("manifest.json");
    identity::check_chain(&path, false)?;
    Ok(path)
}
fn load(path: &Path) -> UnboltResult<Manifest> {
    if fs::metadata(path).map_err(|e| e.to_string())?.len() > 1024 * 1024 {
        return Err("Startup backup exceeds bounded size".into());
    }
    let m: Manifest = serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    if m.schema != 1 || m.kind != "startup" {
        return Err("Unsupported startup backup schema".into());
    }
    match (&m.source, &m.snapshot) {
        (Source::Registry { location, name }, Snapshot::Registry(value)) => {
            validate_registry(location, name)?;
            let vtype = match value.value_type {
                1 => REG_SZ,
                2 => REG_EXPAND_SZ,
                _ => return Err("Unsupported saved startup value type".into()),
            };
            raw(RegValue {
                vtype,
                bytes: value.bytes.clone().into(),
            })?;
        }
        (Source::Folder { .. }, Snapshot::File { metadata, .. }) if !metadata.is_dir => {}
        _ => return Err("Startup backup source and snapshot do not agree".into()),
    }
    Ok(m)
}
#[cfg(test)]
mod tests;

fn persist(path: &Path, m: &Manifest) -> UnboltResult<()> {
    use std::io::Write;
    let pending = path.with_extension("pending");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)
        .map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec_pretty(m).map_err(|e| e.to_string())?)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    fs::rename(pending, path).map_err(|e| e.to_string())
}
fn fresh(
    policy: &Policy,
    storage: &Path,
    source: &Source,
    backup: Option<&str>,
    cancel: &AtomicBool,
) -> UnboltResult<Entry> {
    let location = policy.location(source)?;
    if let Some(id) = backup {
        let path = manifest_path(storage, id)?;
        let m = load(&path)?;
        if scanner::normalize(Path::new(&m.original_location))
            != scanner::normalize(Path::new(&location))
        {
            return Err(
                "Startup source location changed since backup; restoration is blocked".into(),
            );
        }
        if m.source != *source
            || !matches!(m.state.as_str(), "disabled" | "prepared" | "disable-failed")
        {
            return Err("Startup backup is not a completed disable operation".into());
        }
        let issue = match source {
            Source::Registry { location, name } => {
                let key = registry_cleanup::open_no_links(location, KEY_READ)?;
                match key.get_raw_value(name) {
                    Ok(_) => Some(
                        "The original startup value is occupied; restoration will not overwrite it"
                            .into(),
                    ),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                    Err(e) => return Err(e.to_string()),
                }
            }
            Source::Folder { all_users, name } => {
                let original = policy.file(*all_users, name)?;
                let payload = path.parent().unwrap().join("payload");
                identity::check_chain(&payload, false)?;
                let Snapshot::File { metadata, digest } = &m.snapshot else {
                    return Err("Startup file backup has an inconsistent snapshot".into());
                };
                if scanner::snapshot(&payload)? != *metadata
                    || crypto::file_with_cancel(&payload, cancel)? != *digest
                {
                    return Err("Saved startup file changed; restoration is blocked".into());
                }
                match fs::symlink_metadata(original){Ok(_)=>Some("The original startup filename is occupied; restoration will not overwrite it".into()),Err(e)if e.kind()==std::io::ErrorKind::NotFound=>None,Err(e)=>return Err(e.to_string())}
            }
        };
        let payload = path.parent().unwrap().join("payload");
        let (mut launch, launch_note) = launch_details(source, &m.snapshot, Some(&payload), cancel);
        if matches!(source, Source::Folder { name, .. } if !Path::new(name).extension().is_some_and(|e|e.eq_ignore_ascii_case("lnk")))
            && let Some(info) = &mut launch
        {
            info.target = location.clone();
        }
        Ok(Entry {
            source: source.clone(),
            command: text(&m.snapshot),
            snapshot: Some(m.snapshot),
            backup: Some(id.into()),
            state: if m.state == "disabled" {
                "Disabled by Unbolt"
            } else {
                "Needs recovery review"
            }
            .into(),
            location,
            issue,
            launch,
            launch_note,
        })
    } else {
        let snapshot = capture(policy, source, cancel)?;
        let file = match source {
            Source::Folder { all_users, name } => Some(policy.file(*all_users, name)?),
            _ => None,
        };
        let (launch, launch_note) = launch_details(source, &snapshot, file.as_deref(), cancel);
        Ok(Entry {
            source: source.clone(),
            command: text(&snapshot),
            snapshot: Some(snapshot),
            backup: None,
            state: "Configured".into(),
            location,
            issue: None,
            launch,
            launch_note,
        })
    }
}
pub fn resolve(source: &Source, backup: Option<&str>, cancel: &AtomicBool) -> UnboltResult<Entry> {
    fresh(
        &Policy::windows(),
        &recovery::data_dir().join("startup-backups"),
        source,
        backup,
        cancel,
    )
}
pub fn collect(cancel: &AtomicBool) -> RecordPage<Entry> {
    collect_at(
        &Policy::windows(),
        &recovery::data_dir().join("startup-backups"),
        cancel,
    )
}
fn collect_at(policy: &Policy, storage: &Path, cancel: &AtomicBool) -> RecordPage<Entry> {
    let mut records: Vec<Entry> = Vec::new();
    let mut errors = Vec::new();
    for hive in ["HKCU", "HKLM"] {
        for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
            for key in [RUN, RUN_ONCE] {
                if cancelled(cancel) {
                    break;
                }
                let location = RegistrySource {
                    hive: hive.into(),
                    view,
                    key: key.into(),
                };
                let registry = match registry_cleanup::open_no_links(&location, KEY_READ) {
                    Ok(r) => r,
                    Err(e) => {
                        match inventory::hive(hive) {
                            Ok(h) => match h.open_subkey_with_flags(key, KEY_READ | view) {
                                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                                _ => errors.push(format!("{hive}\\{key}: {e}")),
                            },
                            Err(error) => errors.push(error),
                        }
                        continue;
                    }
                };
                for value in registry.enum_values().take(4096) {
                    if cancelled(cancel) {
                        break;
                    }
                    let (name, value) = match value {
                        Ok(v) => v,
                        Err(e) => {
                            errors.push(e.to_string());
                            continue;
                        }
                    };
                    let source = Source::Registry {
                        location: location.clone(),
                        name,
                    };
                    let result = raw(value);
                    let snapshot = result.as_ref().ok().cloned().map(Snapshot::Registry);
                    if hive=="HKCU"&&records.iter().any(|r|matches!(&r.source,Source::Registry{location:l,name}if l.hive==hive&&l.key.eq_ignore_ascii_case(key)&&name.eq_ignore_ascii_case(source.name()))&&r.snapshot==snapshot){continue;}
                    let (launch, launch_note) = snapshot
                        .as_ref()
                        .map(|s| launch_details(&source, s, None, cancel))
                        .unwrap_or_default();
                    records.push(Entry {
                        command: snapshot.as_ref().map(text).unwrap_or_default(),
                        snapshot,
                        location: policy.location(&source).unwrap_or_default(),
                        source,
                        backup: None,
                        state: "Configured".into(),
                        issue: result.err(),
                        launch,
                        launch_note,
                    });
                }
            }
        }
    }
    for all_users in [false, true] {
        let root = if all_users {
            &policy.common
        } else {
            &policy.user
        };
        let Some(root) = root else {
            errors.push("A Startup folder could not be located".into());
            continue;
        };
        if !root.exists() {
            continue;
        }
        if let Err(e) = identity::check_chain(root, false) {
            errors.push(e);
            continue;
        }
        match fs::read_dir(root) {
            Err(e) => errors.push(e.to_string()),
            Ok(entries) => {
                for item in entries.take(4096) {
                    if cancelled(cancel) {
                        break;
                    }
                    let item = match item {
                        Ok(v) => v,
                        Err(e) => {
                            errors.push(e.to_string());
                            continue;
                        }
                    };
                    let name = item.file_name().to_string_lossy().into_owned();
                    if name.eq_ignore_ascii_case("desktop.ini") {
                        continue;
                    }
                    let source = Source::Folder { all_users, name };
                    match fresh(policy, storage, &source, None, cancel) {
                        Ok(e) => records.push(e),
                        Err(e) => errors.push(format!("{}: {e}", source.name())),
                    }
                }
            }
        }
    }
    if storage.exists() {
        match fs::read_dir(storage) {
            Err(e) => errors.push(e.to_string()),
            Ok(entries) => {
                for entry in entries.take(10000) {
                    if cancelled(cancel) {
                        break;
                    }
                    let path = match entry {
                        Ok(e) => e.path(),
                        Err(e) => {
                            errors.push(e.to_string());
                            continue;
                        }
                    };
                    let Some(id) = path.file_name().and_then(|s| s.to_str()) else {
                        continue;
                    };
                    match manifest_path(storage, id).and_then(|p| load(&p)) {
                        Ok(m)
                            if matches!(
                                m.state.as_str(),
                                "disabled" | "prepared" | "disable-failed"
                            ) =>
                        {
                            match fresh(policy, storage, &m.source, Some(id), cancel) {
                                Ok(e) => records.push(e),
                                Err(e) => errors.push(e),
                            }
                        }
                        Ok(_) => {}
                        Err(e) => errors.push(e),
                    }
                }
            }
        }
    }
    records.sort_by_key(|e| (e.name().to_lowercase(), e.source.slot(), e.backup.clone()));
    if cancelled(cancel) {
        errors.push("Startup scan cancelled; coverage is incomplete".into());
    }
    RecordPage { records, errors }
}
fn move_no_replace(from: &Path, to: &Path) -> UnboltResult<()> {
    if unsafe {
        MoveFileExW(
            command::wide(&from.display().to_string()).as_ptr(),
            command::wide(&to.display().to_string()).as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(format!(
            "Startup file could not move; destination conflicts and cross-volume moves are refused ({})",
            unsafe { windows_sys::Win32::Foundation::GetLastError() }
        ));
    }
    Ok(())
}
fn writable_registry(
    source: &RegistrySource,
) -> UnboltResult<(winreg::RegKey, Option<winreg::transaction::Transaction>)> {
    let checked = registry_cleanup::open_no_links(source, KEY_READ | KEY_WRITE)?;
    let unsupported = |e: &std::io::Error| matches!(e.raw_os_error(), Some(50 | 120 | 6801 | 6805));
    let transaction = match winreg::transaction::Transaction::new() {
        Ok(t) => t,
        Err(e) if unsupported(&e) => return Ok((checked, None)),
        Err(e) => return Err(e.to_string()),
    };
    match checked.open_subkey_transacted_with_flags(
        "",
        &transaction,
        KEY_READ | KEY_WRITE | source.view,
    ) {
        Ok(key) => Ok((key, Some(transaction))),
        Err(e) if unsupported(&e) => Ok((checked, None)),
        Err(e) => Err(e.to_string()),
    }
}
pub fn change(entry: &Entry, operation: Change, cancel: &AtomicBool) -> UnboltResult<Outcome> {
    change_at(
        &Policy::windows(),
        &recovery::data_dir().join("startup-backups"),
        entry,
        operation,
        cancel,
    )
}
pub fn restore(path: &Path) -> UnboltResult<()> {
    let storage = fs::canonicalize(recovery::data_dir().join("startup-backups"))
        .map_err(|e| e.to_string())?;
    identity::check_chain(path, false)?;
    let path = fs::canonicalize(path).map_err(|e| e.to_string())?;
    if path.file_name().is_none_or(|n| n != "manifest.json")
        || path.parent().and_then(Path::parent) != Some(storage.as_path())
    {
        return Err("Startup backup must be an exact record in Unbolt's startup storage".into());
    }
    let m = load(&path)?;
    let id = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|s| s.to_str())
        .ok_or("Invalid startup backup path")?;
    let flag = AtomicBool::new(false);
    let entry = resolve(&m.source, Some(id), &flag)?;
    change(&entry, Change::Restore, &flag).map(|_| ())
}
pub fn manifest_description(path: &Path) -> Option<String> {
    let m = load(path).ok()?;
    matches!(m.state.as_str(),"disabled"|"prepared"|"disable-failed").then(||format!("{}\r\n{}\r\n{}\r\nRestoring this startup source may start the program at the next Windows sign-in.",m.application,Policy::windows().location(&m.source).unwrap_or_default(),text(&m.snapshot)))
}
fn change_at(
    policy: &Policy,
    storage: &Path,
    entry: &Entry,
    operation: Change,
    cancel: &AtomicBool,
) -> UnboltResult<Outcome> {
    if cancelled(cancel) || !entry.mutable() {
        return Err("Startup operation is cancelled or needs review".into());
    }
    identity::check_chain(storage, true)?;
    fs::create_dir_all(storage).map_err(|e| e.to_string())?;
    let _lease = process::reserve_application(storage, &entry.source.slot())?;
    let current = fresh(
        policy,
        storage,
        &entry.source,
        entry.backup.as_deref(),
        cancel,
    )?;
    if current.fingerprint()? != entry.fingerprint()? || !current.mutable() {
        return Err("Startup entry changed since review; refresh before changing it".into());
    }
    let (path, mut manifest) = match operation {
        Change::Disable => {
            if entry.backup.is_some() {
                return Err("Startup entry is already disabled".into());
            }
            let dir = storage.join(recovery::unique_id());
            fs::create_dir(&dir).map_err(|e| e.to_string())?;
            let path = dir.join("manifest.json");
            let m = Manifest {
                schema: 1,
                kind: "startup".into(),
                application: entry.name().into(),
                source: entry.source.clone(),
                original_location: current.location.clone(),
                snapshot: entry.snapshot.clone().ok_or("No startup snapshot")?,
                state: "prepared".into(),
            };
            persist(&path, &m)?;
            (path, m)
        }
        Change::Restore => {
            let path = manifest_path(
                storage,
                entry
                    .backup
                    .as_deref()
                    .ok_or("This entry has no disabled backup")?,
            )?;
            let m = load(&path)?;
            (path, m)
        }
    };
    if cancelled(cancel) {
        return Err(
            "Startup operation cancelled before change; any prepared backup was retained".into(),
        );
    }
    let mut registry_transaction = None;
    let result = (|| -> UnboltResult<()> {
        match (&entry.source, operation, &manifest.snapshot) {
            (Source::Registry { location, name }, Change::Disable, Snapshot::Registry(value)) => {
                let (key, transaction) = writable_registry(location)?;
                registry_transaction = Some(transaction.is_some());
                if raw(key.get_raw_value(name).map_err(|e| e.to_string())?)? != *value {
                    return Err("Startup value changed during backup; it was retained".into());
                }
                key.delete_value(name).map_err(|e| e.to_string())?;
                if let Some(transaction) = transaction {
                    transaction
                        .commit()
                        .map_err(|e| format!("Startup change did not commit: {e}"))
                } else {
                    Ok(())
                }
            }
            (Source::Registry { location, name }, Change::Restore, Snapshot::Registry(value)) => {
                let (key, transaction) = writable_registry(location)?;
                registry_transaction = Some(transaction.is_some());
                match key.get_raw_value(name) {
                    Ok(_) => {
                        return Err(
                            "Original startup value is occupied; no overwrite performed".into()
                        );
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.to_string()),
                }
                let vtype = match value.value_type {
                    1 => REG_SZ,
                    2 => REG_EXPAND_SZ,
                    _ => return Err("Unsupported saved startup value type".into()),
                };
                key.set_raw_value(
                    name,
                    &RegValue {
                        vtype,
                        bytes: value.bytes.clone().into(),
                    },
                )
                .map_err(|e| e.to_string())?;
                if let Some(transaction) = transaction {
                    transaction
                        .commit()
                        .map_err(|e| format!("Startup restoration did not commit: {e}"))
                } else {
                    Ok(())
                }
            }
            (Source::Folder { all_users, name }, Change::Disable, Snapshot::File { .. }) => {
                if capture(policy, &entry.source, cancel)? != manifest.snapshot {
                    return Err("Startup file changed during backup; it was retained".into());
                }
                move_no_replace(
                    &policy.file(*all_users, name)?,
                    &path.parent().unwrap().join("payload"),
                )
            }
            (
                Source::Folder { all_users, name },
                Change::Restore,
                Snapshot::File { metadata, digest },
            ) => {
                let payload = path.parent().unwrap().join("payload");
                identity::check_chain(&payload, false)?;
                if scanner::snapshot(&payload)? != *metadata
                    || crypto::file_with_cancel(&payload, cancel)? != *digest
                {
                    return Err("Saved startup file changed before restoration".into());
                }
                move_no_replace(&payload, &policy.file(*all_users, name)?)
            }
            _ => Err("Startup snapshot does not match its source".into()),
        }
    })();
    if let Err(error) = result {
        if matches!(operation, Change::Disable) {
            manifest.state = "disable-failed".into();
            let _ = persist(&path, &manifest);
        }
        return Err(format!("{error}\r\nBackup retained: {}", path.display()));
    }
    manifest.state = match operation {
        Change::Disable => "disabled",
        Change::Restore => "restored",
    }
    .into();
    persist(&path, &manifest).map_err(|e| {
        format!(
            "Startup source changed, but its backup state needs recovery review: {e}. Backup: {}",
            path.display()
        )
    })?;
    let mut out = Outcome {
        name: entry.name().into(),
        state: match operation {
            Change::Disable => "Disabled by Unbolt",
            Change::Restore => "Configured",
        }
        .into(),
        backup: path,
        registry_transaction,
        message:
            "Already-running processes are unchanged. Windows startup approval may still differ."
                .into(),
    };
    if registry_transaction == Some(false) {
        out.message.push_str(" Windows registry transactions were unavailable; a fresh value check was used. Independent changes to the same value cannot be excluded atomically.");
    }
    if let Err(error) = recovery::history(
        "startup-change",
        entry.name(),
        &serde_json::to_string(&out).map_err(|e| e.to_string())?,
    ) {
        return Err(format!(
            "Startup source changed, but history could not be saved: {error}. Backup: {}",
            out.backup.display()
        ));
    }
    Ok(out)
}
