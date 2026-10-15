//! Application resource icons with per-application caching; no target code execution.
#![allow(unsafe_op_in_unsafe_fn)]
use std::{collections::HashMap, path::Path, ptr::null_mut};
use unbolt::{
    command::{expand_environment, wide},
    inventory,
    model::Application,
};
use windows_sys::Win32::UI::{
    Controls::*,
    Shell::SHDefExtractIconW,
    WindowsAndMessaging::{DestroyIcon, IDI_APPLICATION, LoadIconW},
};

pub struct AppIcons {
    pub handle: HIMAGELIST,
    cache: HashMap<String, i32>,
    size: i32,
}
fn icon_spec(value: &str) -> Option<(String, i32)> {
    let value = expand_environment(value.trim());
    let (path, index) = match value.rsplit_once(',') {
        Some((p, i)) if i.trim().parse::<i32>().is_ok() => (p, i.trim().parse().ok()?),
        _ => (value.as_str(), 0),
    };
    let path = path.trim().trim_matches('"').to_string();
    Path::new(&path).is_absolute().then_some((path, index))
}
impl AppIcons {
    pub unsafe fn new(size: i32) -> Self {
        let handle = ImageList_Create(size, size, ILC_COLOR32 | ILC_MASK, 32, 32);
        let icon = LoadIconW(null_mut(), IDI_APPLICATION);
        ImageList_ReplaceIcon(handle, -1, icon);
        Self {
            handle,
            cache: HashMap::new(),
            size,
        }
    }
    pub unsafe fn index(&mut self, app: &Application) -> i32 {
        if let Some(i) = self.cache.get(&app.id) {
            return *i;
        }
        let spec = app
            .sources
            .iter()
            .find_map(|s| {
                inventory::hive(&s.hive)
                    .ok()?
                    .open_subkey_with_flags(&s.key, winreg::enums::KEY_READ | s.view)
                    .ok()?
                    .get_value::<String, _>("DisplayIcon")
                    .ok()
            })
            .and_then(|v| icon_spec(&v));
        let mut result = 0;
        if let Some((path, index)) = spec
            && Path::new(&path).is_file()
        {
            let mut icon = null_mut();
            if SHDefExtractIconW(
                wide(&path).as_ptr(),
                index,
                0,
                &mut icon,
                null_mut(),
                self.size as u32,
            ) >= 0
                && !icon.is_null()
            {
                let slot = ImageList_ReplaceIcon(self.handle, -1, icon);
                if slot >= 0 {
                    result = slot;
                }
                DestroyIcon(icon);
            }
        }
        self.cache.insert(app.id.clone(), result);
        result
    }
}
impl Drop for AppIcons {
    fn drop(&mut self) {
        unsafe {
            ImageList_Destroy(self.handle);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_resource_index_and_quoted_paths() {
        assert_eq!(
            icon_spec(r#""C:\Program Files\Example\app.exe",-42"#),
            Some((r"C:\Program Files\Example\app.exe".into(), -42))
        );
        assert!(icon_spec("app.exe,2").is_none());
    }
}
