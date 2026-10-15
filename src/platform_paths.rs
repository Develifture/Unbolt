use std::{path::PathBuf, ptr::null_mut};
use windows_sys::Win32::{
    System::Com::CoTaskMemFree,
    UI::Shell::{
        FOLDERID_ProgramData, FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86, SHGetKnownFolderPath,
    },
};
pub fn windows() -> Option<PathBuf> {
    crate::command::system_msiexec().ok().and_then(|s| {
        std::path::Path::new(&s)
            .parent()
            .and_then(std::path::Path::parent)
            .map(std::path::Path::to_path_buf)
    })
}
pub fn machine() -> Vec<(&'static str, PathBuf)> {
    [
        ("ProgramFiles", FOLDERID_ProgramFiles),
        ("ProgramFiles(x86)", FOLDERID_ProgramFilesX86),
        ("ProgramData", FOLDERID_ProgramData),
    ]
    .iter()
    .filter_map(|(name, id)| unsafe {
        let mut path = null_mut();
        if SHGetKnownFolderPath(id, 0, null_mut(), &mut path) < 0 {
            return None;
        }
        let mut count = 0;
        while *path.add(count) != 0 && count < 32768 {
            count += 1;
        }
        let result = (count < 32768).then(|| {
            PathBuf::from(String::from_utf16_lossy(std::slice::from_raw_parts(
                path, count,
            )))
        });
        CoTaskMemFree(path.cast());
        result.map(|p| (*name, p))
    })
    .collect()
}
pub fn profile_containers() -> Vec<PathBuf> {
    use winreg::{RegKey, enums::*};
    let Ok(root) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
        KEY_READ | KEY_WOW64_64KEY,
    ) else {
        return vec![];
    };
    root.enum_keys()
        .filter_map(Result::ok)
        .take(4096)
        .filter_map(|name| {
            root.open_subkey_with_flags(name, KEY_READ | KEY_WOW64_64KEY)
                .ok()?
                .get_value::<String, _>("ProfileImagePath")
                .ok()
        })
        .map(|p| PathBuf::from(crate::command::expand_environment(&p)))
        .filter(|p| p.is_absolute() && !p.to_string_lossy().starts_with("\\\\"))
        .collect()
}
