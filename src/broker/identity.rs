use crate::{UnboltResult, context::CallerScope, records, scanner};
use std::{
    collections::BTreeMap,
    fs,
    mem::size_of,
    path::{Component, Path, PathBuf, Prefix},
    ptr::null_mut,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::ConvertSidToStringSidW, *},
    System::{RemoteDesktop::ProcessIdToSessionId, Threading::*},
};
use winreg::{RegKey, enums::*};
pub(crate) struct Handle(pub HANDLE);
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub pid: u32,
    pub created: u64,
    pub sid: String,
    pub image: PathBuf,
    pub session: u32,
}
fn token_information(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> UnboltResult<Vec<usize>> {
    unsafe {
        let mut needed = 0;
        GetTokenInformation(token, class, null_mut(), 0, &mut needed);
        if needed == 0 || needed > 65536 {
            return Err("Cannot read process token information".into());
        }
        let mut bytes = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
        if GetTokenInformation(token, class, bytes.as_mut_ptr().cast(), needed, &mut needed) == 0 {
            return Err(format!(
                "Token information unavailable ({})",
                GetLastError()
            ));
        }
        Ok(bytes)
    }
}
fn token(handle: HANDLE) -> UnboltResult<Handle> {
    unsafe {
        let mut token = null_mut();
        if OpenProcessToken(handle, TOKEN_QUERY, &mut token) == 0 {
            return Err(format!("Cannot read process identity ({})", GetLastError()));
        }
        Ok(Handle(token))
    }
}
pub fn current_sid() -> UnboltResult<String> {
    process(unsafe { GetCurrentProcessId() }).map(|p| p.sid)
}
pub fn process(pid: u32) -> UnboltResult<Peer> {
    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        );
        if handle.is_null() {
            return Err(format!("Peer process unavailable ({})", GetLastError()));
        }
        let handle = Handle(handle);
        if WaitForSingleObject(handle.0, 0) != WAIT_TIMEOUT {
            return Err("Peer process is no longer running".into());
        }
        let mut times = [FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        }; 4];
        let p = times.as_mut_ptr();
        if GetProcessTimes(handle.0, p, p.add(1), p.add(2), p.add(3)) == 0 {
            return Err("Cannot read peer creation time".into());
        }
        let mut image = vec![0u16; 32768];
        let mut length = image.len() as u32;
        if QueryFullProcessImageNameW(handle.0, 0, image.as_mut_ptr(), &mut length) == 0 {
            return Err("Cannot identify peer executable".into());
        }
        let token = token(handle.0)?;
        let buffer = token_information(token.0, TokenUser)?;
        let user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let mut sid = null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut sid) == 0 {
            return Err("Cannot format peer SID".into());
        }
        let mut n = 0;
        while *sid.add(n) != 0 && n < 256 {
            n += 1;
        }
        let string = String::from_utf16_lossy(std::slice::from_raw_parts(sid, n));
        LocalFree(sid.cast());
        if n == 256 {
            return Err("Invalid peer SID size".into());
        }
        let mut session = 0;
        if ProcessIdToSessionId(pid, &mut session) == 0 {
            return Err("Cannot identify peer session".into());
        }
        Ok(Peer {
            pid,
            created: ((times[0].dwHighDateTime as u64) << 32) | times[0].dwLowDateTime as u64,
            sid: string,
            image: fs::canonicalize(PathBuf::from(String::from_utf16_lossy(
                &image[..length as usize],
            )))
            .map_err(|e| e.to_string())?,
            session,
        })
    }
}
pub fn elevated() -> UnboltResult<bool> {
    unsafe {
        let token = token(GetCurrentProcess())?;
        let info = token_information(token.0, TokenElevation)?;
        Ok((*(info.as_ptr() as *const TOKEN_ELEVATION)).TokenIsElevated != 0)
    }
}
pub fn check_peer(actual: &Peer, expected: &Peer) -> UnboltResult<()> {
    if actual.pid != expected.pid
        || actual.sid != expected.sid
        || actual.created != expected.created
        || actual.image != expected.image
        || actual.session != expected.session
    {
        return Err("Helper connection belongs to a different process".into());
    }
    Ok(())
}
pub fn check_parent(peer: &Peer) -> UnboltResult<()> {
    let own = fs::canonicalize(std::env::current_exe().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    if peer.image.parent() != own.parent()
        || !peer
            .image
            .file_name()
            .and_then(|p| p.to_str())
            .is_some_and(|n| {
                [
                    "unbolt.exe",
                    "unbolt-cli.exe",
                    "Unbolt.exe",
                    "UnboltCLI.exe",
                ]
                .iter()
                .any(|s| n.eq_ignore_ascii_case(s))
            })
    {
        return Err("The helper must be launched by its adjacent Unbolt application".into());
    }
    Ok(())
}
pub fn profile(sid: &str) -> UnboltResult<PathBuf> {
    if !sid.starts_with("S-1-")
        || sid.len() > 256
        || sid
            .chars()
            .any(|c| !c.is_ascii_digit() && c != 'S' && c != '-')
    {
        return Err("Invalid caller SID".into());
    }
    let key = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(
            format!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{sid}"),
            KEY_READ | KEY_WOW64_64KEY,
        )
        .map_err(|e| format!("Caller profile unavailable: {e}"))?;
    let path: String = key
        .get_value("ProfileImagePath")
        .map_err(|e| e.to_string())?;
    let path = PathBuf::from(crate::command::expand_environment(&path));
    local_path(&path)?;
    fs::canonicalize(path).map_err(|e| e.to_string())
}
pub(crate) fn local_path(path: &Path) -> UnboltResult<()> {
    if !path.is_absolute() || path.components().any(|p| matches!(p, Component::ParentDir)) {
        return Err("Helper paths must be absolute local paths without traversal".into());
    }
    let disk = match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(d) | Prefix::VerbatimDisk(d) => d,
            _ => return Err("Network and device helper paths are excluded".into()),
        },
        _ => return Err("Invalid helper path prefix".into()),
    };
    let drive = format!("{}:\\", disk as char);
    let kind = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetDriveTypeW(
            crate::command::wide(&drive).as_ptr(),
        )
    };
    if !matches!(kind, 2 | 3 | 6) {
        return Err("Helper storage must be on a local writable drive".into());
    }
    for component in path.components() {
        if let Component::Normal(name) = component {
            let name = name.to_string_lossy();
            if name.contains(':') || name.ends_with(['.', ' ']) {
                return Err("Ambiguous Windows helper path".into());
            }
        }
    }
    Ok(())
}
pub(crate) fn check_chain(path: &Path, allow_missing: bool) -> UnboltResult<()> {
    local_path(path)?;
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        match scanner::snapshot(ancestor) {
            Ok(_) => {}
            Err(_error)
                if allow_missing
                    && fs::symlink_metadata(ancestor)
                        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
pub fn validate_storage_candidate(path: &Path) -> UnboltResult<()> {
    check_chain(path, true)
}
pub(crate) fn scope(peer: &Peer, data: &Path) -> UnboltResult<CallerScope> {
    let user_profile = profile(&peer.sid)?;
    let raw = records::display_path(&data.display().to_string());
    if raw.starts_with("\\\\")
        || !Path::new(&raw).is_absolute()
        || !data
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case(crate::recovery::DATA_DIRECTORY))
    {
        return Err("Helper data must be the caller's local Unbolt storage".into());
    }
    check_chain(data, false)?;
    let data = fs::canonicalize(data).map_err(|e| e.to_string())?;
    let user = records::display_path(&user_profile.display().to_string());
    let mut environment = BTreeMap::new();
    environment.insert("USERPROFILE".into(), user.clone());
    // Explorer stores redirected per-user AppData paths in this loaded user hive.
    let shell = RegKey::predef(HKEY_USERS)
        .open_subkey_with_flags(
            format!(
                "{}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
                peer.sid
            ),
            KEY_READ,
        )
        .ok();
    for (variable, value_name, fallback) in [
        (
            "LOCALAPPDATA",
            "Local AppData",
            format!("{user}\\AppData\\Local"),
        ),
        ("APPDATA", "AppData", format!("{user}\\AppData\\Roaming")),
    ] {
        let value = shell
            .as_ref()
            .and_then(|k| k.get_value::<String, _>(value_name).ok())
            .unwrap_or(fallback)
            .replace("%USERPROFILE%", &user)
            .replace("%userprofile%", &user);
        local_path(Path::new(&value))?;
        environment.insert(variable.into(), value);
    }
    let local = PathBuf::from(environment.get("LOCALAPPDATA").unwrap());
    let local = fs::canonicalize(&local).map_err(|e| e.to_string())?;
    if (!scanner::same_or_under(&data, &user_profile) && !scanner::same_or_under(&data, &local))
        || scanner::normalize(&data) == scanner::normalize(&user_profile)
    {
        return Err("Helper data is outside the caller's profile".into());
    }
    let system = crate::command::system_msiexec()?;
    let windows = Path::new(&system)
        .parent()
        .and_then(Path::parent)
        .ok_or("Invalid Windows directory")?;
    if scanner::same_or_under(&data, windows) {
        return Err("Windows directories cannot hold helper data".into());
    }
    environment.insert(
        "TEMP".into(),
        format!("{}\\Temp", environment.get("LOCALAPPDATA").unwrap()),
    );
    environment.insert("TMP".into(), environment.get("TEMP").unwrap().clone());
    // HKCU belongs to the desktop caller even when UAC uses another account.
    let hive_sid = (current_sid()? != peer.sid).then(|| peer.sid.clone());
    if let Some(windows) = crate::platform_paths::windows() {
        let windows = crate::records::display_path(&windows.display().to_string());
        environment.insert("SYSTEMROOT".into(), windows.clone());
        environment.insert("WINDIR".into(), windows);
    }
    for (name, path) in crate::platform_paths::machine() {
        environment.insert(
            name.to_ascii_uppercase(),
            crate::records::display_path(&path.display().to_string()),
        );
    }
    Ok(CallerScope {
        data,
        hive_sid,
        environment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn current_process_identity_rejects_pid_creation_sid_and_session_substitution() {
        let actual = process(unsafe { GetCurrentProcessId() }).unwrap();
        let mut changed = actual.clone();
        changed.created += 1;
        assert!(check_peer(&changed, &actual).is_err());
        changed = actual.clone();
        changed.sid = "S-1-5-18".into();
        assert!(check_peer(&changed, &actual).is_err());
        changed = actual.clone();
        changed.session += 1;
        assert!(check_peer(&changed, &actual).is_err());
    }
}
