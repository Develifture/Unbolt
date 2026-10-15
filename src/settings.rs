use crate::{UnboltResult, recovery};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
#[derive(Default, Serialize, Deserialize)]
pub struct UiSettings {
    #[serde(default)]
    pub dark: bool,
}
pub fn load() -> UiSettings {
    fs::read(recovery::data_dir().join("settings.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}
pub fn save(settings: &UiSettings) -> UnboltResult<()> {
    save_at(&recovery::data_dir().join("settings.json"), settings)
}
fn save_at(path: &Path, settings: &UiSettings) -> UnboltResult<()> {
    fs::create_dir_all(path.parent().ok_or("Settings path has no parent")?)
        .map_err(|e| e.to_string())?;
    let pending = path.with_extension("pending");
    fs::write(
        &pending,
        serde_json::to_vec_pretty(settings).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    fs::rename(pending, path).map_err(|e| e.to_string())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn saves_and_reloads_theme_preference() {
        let root = std::env::temp_dir().join(format!("unbolt-settings-{}", recovery::unique_id()));
        let path = root.join("settings.json");
        save_at(&path, &UiSettings { dark: true }).unwrap();
        let value: UiSettings = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert!(value.dark);
        assert!(root.starts_with(std::env::temp_dir()));
        fs::remove_dir_all(root).unwrap();
    }
}
