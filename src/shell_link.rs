//! Read saved Shell-link properties without resolving, saving, or launching them.
use crate::{UnboltResult, command, scanner};
use serde::{Deserialize, Serialize};
use std::path::Path;
use windows::{
    Win32::{
        Foundation::{PROPERTYKEY, RPC_E_CHANGED_MODE},
        Storage::EnhancedStorage::{PKEY_Link_Arguments, PKEY_Link_TargetParsingPath},
        System::Com::{
            CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
            CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, IPersistFile,
            STGM_READ,
            StructuredStorage::{PROPVARIANT, PropVariantClear, PropVariantToStringAlloc},
        },
        UI::Shell::{IShellLinkW, PropertiesSystem::IPropertyStore, SLGP_RAWPATH, ShellLink},
    },
    core::{Interface, PCWSTR, PWSTR},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SavedLink {
    pub target: String,
    pub arguments: String,
    pub working_directory: String,
}
struct Apartment(bool);
impl Apartment {
    fn enter() -> UnboltResult<Self> {
        let result =
            unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
        if result == RPC_E_CHANGED_MODE {
            Ok(Self(false))
        } else {
            result.ok().map_err(|e| e.to_string())?;
            Ok(Self(true))
        }
    }
}
impl Drop for Apartment {
    fn drop(&mut self) {
        if self.0 {
            unsafe { CoUninitialize() };
        }
    }
}
struct Value(PROPVARIANT);
impl Drop for Value {
    fn drop(&mut self) {
        let _ = unsafe { PropVariantClear(&mut self.0) };
    }
}
struct Text(PWSTR);
impl Drop for Text {
    fn drop(&mut self) {
        unsafe { CoTaskMemFree(Some(self.0.0.cast())) };
    }
}
fn property(store: &IPropertyStore, key: &PROPERTYKEY) -> UnboltResult<String> {
    let value = Value(unsafe { store.GetValue(key) }.map_err(|e| e.to_string())?);
    let text = Text(unsafe { PropVariantToStringAlloc(&value.0) }.map_err(|e| e.to_string())?);
    if text.0.is_null() {
        return Ok(String::new());
    }
    let mut length = 0;
    while length < 65536 && unsafe { *text.0.0.add(length) } != 0 {
        length += 1;
    }
    if length == 65536 {
        return Err("Saved shortcut property exceeds the supported length".into());
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(text.0.0, length) })
        .map_err(|_| "Saved shortcut property contains invalid Unicode".into())
}
fn buffered(call: impl FnOnce(&mut [u16]) -> windows::core::Result<()>) -> UnboltResult<String> {
    let mut buffer = vec![0u16; 32768];
    call(&mut buffer).map_err(|e| e.to_string())?;
    let length = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    if length >= buffer.len() - 1 {
        return Err("Saved shortcut field may be truncated; target needs review".into());
    }
    String::from_utf16(&buffer[..length])
        .map_err(|_| "Shortcut field contains invalid Unicode".into())
}
pub fn read(path: &Path) -> UnboltResult<SavedLink> {
    let snapshot = scanner::snapshot(path)?;
    if snapshot.is_dir || snapshot.len > 1024 * 1024 {
        return Err("Only regular Shell-link files up to 1 MiB can be inspected".into());
    }
    let _apartment = Apartment::enter()?;
    let link: IShellLinkW = unsafe { CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER) }
        .map_err(|e| e.to_string())?;
    let persist: IPersistFile = link.cast().map_err(|e| e.to_string())?;
    let filename = command::wide(&path.to_string_lossy());
    unsafe { persist.Load(PCWSTR(filename.as_ptr()), STGM_READ) }.map_err(|e| e.to_string())?;
    let store: IPropertyStore = link.cast().map_err(|e| e.to_string())?;
    let mut target = property(&store, &PKEY_Link_TargetParsingPath)?;
    if target.is_empty() {
        target =
            buffered(|b| unsafe { link.GetPath(b, std::ptr::null_mut(), SLGP_RAWPATH.0 as u32) })?;
    }
    let result = SavedLink {
        target,
        arguments: property(&store, &PKEY_Link_Arguments)?,
        working_directory: buffered(|b| unsafe { link.GetWorkingDirectory(b) })?,
    };
    if scanner::snapshot(path)? != snapshot {
        return Err("Shortcut file changed while reading its properties".into());
    }
    Ok(result)
}

#[cfg(test)]
pub(crate) fn write_fixture(path: &Path, target: &Path, arguments: &str, working: &Path) {
    let _apartment = Apartment::enter().unwrap();
    let link: IShellLinkW =
        unsafe { CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER) }.unwrap();
    unsafe {
        link.SetPath(PCWSTR(command::wide(&target.to_string_lossy()).as_ptr()))
            .unwrap();
        link.SetArguments(PCWSTR(command::wide(arguments).as_ptr()))
            .unwrap();
        link.SetWorkingDirectory(PCWSTR(command::wide(&working.to_string_lossy()).as_ptr()))
            .unwrap();
        let persist: IPersistFile = link.cast().unwrap();
        persist
            .Save(
                PCWSTR(command::wide(&path.to_string_lossy()).as_ptr()),
                true,
            )
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn reads_saved_unicode_and_long_arguments_without_changing_or_resolving_link() {
        let root = std::env::temp_dir().join(format!(
            "unbolt-link-fixture-{}",
            crate::recovery::unique_id()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("Owned.lnk");
        let missing = root.join("Missing Ω.exe");
        let arguments = format!("--owned \"Ω space\" {}", "x".repeat(4096));
        write_fixture(&path, &missing, &arguments, &root);
        let before = fs::read(&path).unwrap();
        let link = read(&path).unwrap();
        assert_eq!(
            scanner::normalize(Path::new(&link.target)),
            scanner::normalize(&missing)
        );
        assert_eq!(link.arguments, arguments);
        assert_eq!(
            scanner::normalize(Path::new(&link.working_directory)),
            scanner::normalize(&root)
        );
        assert!(!missing.exists());
        assert_eq!(fs::read(&path).unwrap(), before);
        fs::write(root.join("Invalid.lnk"), b"not a Shell link").unwrap();
        assert!(read(&root.join("Invalid.lnk")).is_err());
        assert!(root.starts_with(std::env::temp_dir()));
        fs::remove_dir_all(root).unwrap();
    }
}
