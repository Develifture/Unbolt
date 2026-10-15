//! Read-only window attribution and identity-bound process stopping.
use crate::{
    UnboltResult,
    broker::identity::{self, Peer},
    command, inventory,
    model::*,
    scanner,
};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path, sync::atomic::AtomicBool};
use windows_sys::Win32::{Foundation::*, System::Threading::*, UI::WindowsAndMessaging::*};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Match {
    pub app: Application,
    pub confidence: Confidence,
    pub evidence: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub peer: Peer,
    pub window_title: String,
    pub matches: Vec<Match>,
    pub inventory_errors: Vec<String>,
    pub cancelled: bool,
}
#[derive(Clone, Debug)]
pub struct WindowChoice {
    pub window: usize,
    pub pid: u32,
    pub title: String,
}
pub fn open_windows() -> Vec<WindowChoice> {
    unsafe extern "system" fn collect(hwnd: HWND, data: LPARAM) -> BOOL {
        unsafe {
            let choices = &mut *(data as *mut Vec<WindowChoice>);
            if choices.len() >= 512 {
                return 0;
            }
            let mut pid = 0;
            GetWindowThreadProcessId(hwnd, &mut pid);
            if IsWindowVisible(hwnd) == 0 || pid == 0 || pid == GetCurrentProcessId() {
                return 1;
            }
            let mut title = [0u16; 1024];
            let length = GetWindowTextW(hwnd, title.as_mut_ptr(), title.len() as i32);
            if length > 0 {
                choices.push(WindowChoice {
                    window: hwnd as usize,
                    pid,
                    title: String::from_utf16_lossy(&title[..length as usize]),
                });
            }
            1
        }
    }
    let mut choices: Vec<WindowChoice> = Vec::new();
    unsafe {
        EnumWindows(
            Some(collect),
            &mut choices as *mut Vec<WindowChoice> as isize,
        );
    }
    choices.sort_by_key(|w| (w.title.to_lowercase(), w.pid));
    choices
}
impl Report {
    pub fn unique_application(&self) -> Option<&Application> {
        if self.cancelled || !self.inventory_errors.is_empty() || self.matches.len() != 1 {
            return None;
        }
        let found = &self.matches[0];
        (!found.app.system_component).then_some(&found.app)
    }
    pub fn details(&self) -> String {
        let matched = if self.matches.is_empty() {
            "No installed application could be attributed to this executable.\r\nUse an explicit folder review if you want to inspect an unregistered program.".into()
        } else {
            self.matches
                .iter()
                .map(|m| format!("{} ({:?})\r\n{}", m.app.name, m.confidence, m.evidence))
                .collect::<Vec<_>>()
                .join("\r\n\r\n")
        };
        format!(
            "Window: {}\r\nProcess: {}\r\nExecutable: {}\r\n\r\n{}{}\r\n\r\nIdentifying a window does not prove ownership of all files in its folder.",
            self.window_title,
            self.peer.pid,
            crate::records::display_path(&self.peer.image.display().to_string()),
            matched,
            if self.inventory_errors.is_empty() {
                String::new()
            } else {
                format!(
                    "\r\nInventory coverage is incomplete:\r\n{}",
                    self.inventory_errors.join("\r\n")
                )
            }
        )
    }
}
fn useful_directory(path: &Path, policy: &scanner::PathPolicy, windows: Option<&Path>) -> bool {
    let plain = crate::records::display_path(&path.display().to_string());
    let path = Path::new(&plain);
    if path.components().count() < 3 {
        return false;
    }
    if policy
        .protected
        .iter()
        .any(|p| scanner::normalize(p) == scanner::normalize(path))
    {
        return false;
    }
    windows.is_some_and(|windows| !scanner::same_or_under(path, windows))
}
pub fn match_executable(image: &Path, apps: &[Application]) -> Vec<Match> {
    let Ok(image) = fs::canonicalize(image) else {
        return vec![];
    };
    let mut result = Vec::new();
    let policy = scanner::PathPolicy::windows();
    let windows = crate::platform_paths::windows();
    for app in apps {
        let location = app
            .location
            .as_deref()
            .filter(|p| {
                p.is_absolute()
                    && !p
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
            })
            .and_then(|p| fs::canonicalize(p).ok());
        let registered = location.as_ref().is_some_and(|p| {
            p.is_dir()
                && useful_directory(p, &policy, windows.as_deref())
                && scanner::same_or_under(&image, p)
        });
        let command_directory = (!registered)
            .then(|| command::parse(&app.uninstall).ok())
            .flatten()
            .and_then(|c| fs::canonicalize(c.executable).ok())
            .and_then(|p| p.parent().map(Path::to_path_buf));
        let fallback = command_directory.as_ref().is_some_and(|p| {
            useful_directory(p, &policy, windows.as_deref()) && scanner::same_or_under(&image, p)
        });
        if registered || fallback {
            result.push(Match { app: app.clone(), confidence: if registered { Confidence::High } else { Confidence::Review },
                evidence: if registered { "Executable is inside the registered InstallLocation. Review shared paths and the selected application before acting." } else { "Executable is inside the registered uninstaller's folder. This is supporting evidence, not a verified installation location." }.into() });
        }
    }
    // Overlapping or shared registered roots remain multiple candidates; never
    // silently prefer the longest root or a display-name guess.
    result
}
pub fn window_at_point(x: i32, y: i32) -> Option<(usize, u32)> {
    unsafe {
        let under = WindowFromPoint(POINT { x, y });
        if under.is_null() {
            return None;
        }
        let root = GetAncestor(under, GA_ROOT);
        if root.is_null() {
            return None;
        }
        let mut pid = 0;
        GetWindowThreadProcessId(root, &mut pid);
        (pid != 0 && pid != GetCurrentProcessId()).then_some((root as usize, pid))
    }
}
pub fn inspect_window(hwnd: usize, expected_pid: u32, cancel: &AtomicBool) -> UnboltResult<Report> {
    let window = hwnd as HWND;
    let mut pid = 0;
    let mut title = [0u16; 1024];
    let mut class = [0u16; 128];
    unsafe {
        if IsWindow(window) == 0 || IsWindowVisible(window) == 0 {
            return Err("That window has closed; choose it again".into());
        }
        GetWindowThreadProcessId(window, &mut pid);
        GetWindowTextW(window, title.as_mut_ptr(), title.len() as i32);
        let n = GetClassNameW(window, class.as_mut_ptr(), class.len() as i32);
        let class = String::from_utf16_lossy(&class[..n.max(0) as usize]);
        if [
            "Progman",
            "WorkerW",
            "Shell_TrayWnd",
            "Shell_SecondaryTrayWnd",
        ]
        .contains(&class.as_str())
        {
            return Err(
                "Choose an application's open window. Desktop and tray items are not supported yet"
                    .into(),
            );
        }
        if pid == 0 || pid != expected_pid {
            return Err("The selected window changed; choose it again".into());
        }
        if pid == GetCurrentProcessId() {
            return Err("Choose another application's window".into());
        }
    }
    let peer = identity::process(pid)?;
    let current = inventory::collect(cancel);
    identity::check_peer(&identity::process(pid)?, &peer)?;
    let mut now = 0;
    unsafe {
        GetWindowThreadProcessId(window, &mut now);
    }
    if now != pid {
        return Err("The window changed while its application was identified".into());
    }
    let end = title.iter().position(|&c| c == 0).unwrap_or(title.len());
    Ok(Report {
        matches: match_executable(&peer.image, &current.apps),
        peer,
        window_title: String::from_utf16_lossy(&title[..end]),
        inventory_errors: current.errors,
        cancelled: current.cancelled,
    })
}
pub fn validate(peer: &Peer) -> UnboltResult<()> {
    identity::check_peer(&identity::process(peer.pid)?, peer)
}
pub fn stop(peer: &Peer) -> UnboltResult<()> {
    if peer.pid == unsafe { GetCurrentProcessId() } || peer.sid != identity::current_sid()? {
        return Err(
            "Only another process belonging to the current Windows user can be stopped".into(),
        );
    }
    let windows =
        crate::platform_paths::windows().ok_or("Windows directory could not be verified")?;
    if scanner::same_or_under(&peer.image, &windows) {
        return Err("Windows processes cannot be stopped through Hunter".into());
    }
    if let Some(own_folder) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        && scanner::same_or_under(&peer.image, &own_folder)
    {
        return Err("Unbolt's own processes cannot be stopped through Hunter".into());
    }
    validate(peer)?;
    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
            0,
            peer.pid,
        );
        if handle.is_null() {
            return Err(format!(
                "Windows did not allow this process to be stopped ({})",
                GetLastError()
            ));
        }
        let handle = identity::Handle(handle);
        // Bind the termination handle itself to the reviewed creation time.
        let (mut created, mut exited, mut kernel, mut user) = (
            std::mem::zeroed::<FILETIME>(),
            std::mem::zeroed::<FILETIME>(),
            std::mem::zeroed::<FILETIME>(),
            std::mem::zeroed::<FILETIME>(),
        );
        if GetProcessTimes(handle.0, &mut created, &mut exited, &mut kernel, &mut user) == 0
            || ((created.dwHighDateTime as u64) << 32 | created.dwLowDateTime as u64)
                != peer.created
        {
            return Err("Process identity changed since review".into());
        }
        let mut critical = 0;
        if IsProcessCritical(handle.0, &mut critical) == 0 || critical != 0 {
            return Err("Windows treats this process as essential or could not check its status. Stopping is blocked".into());
        }
        if TerminateProcess(handle.0, 1) == 0 {
            return Err(format!("Process could not be stopped ({})", GetLastError()));
        }
        if WaitForSingleObject(handle.0, 5000) != WAIT_OBJECT_0 {
            return Err("Stop requested; the process has not yet confirmed exit".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn app(id: &str, root: &Path) -> Application {
        Application {
            id: id.into(),
            name: id.into(),
            publisher: String::new(),
            version: String::new(),
            location: Some(root.into()),
            uninstall: String::new(),
            quiet_uninstall: String::new(),
            size_kib: None,
            system_component: false,
            sources: vec![],
        }
    }
    #[test]
    fn exact_location_matching_preserves_shared_and_overlapping_candidates() {
        let root = std::env::temp_dir().join(format!(
            "unbolt-hunter-fixture-{}",
            crate::recovery::unique_id()
        ));
        let folder = root.join("App/bin");
        fs::create_dir_all(&folder).unwrap();
        let exe = folder.join("target.exe");
        fs::write(&exe, b"owned matching fixture").unwrap();
        let apps = [
            app("parent", &root.join("App")),
            app("nested", &folder),
            app("same", &folder),
            app("other", &root.join("App2")),
        ];
        let matches = match_executable(&exe, &apps);
        assert_eq!(matches.len(), 3);
        assert!(matches.iter().all(|m| m.confidence == Confidence::High));
        assert!(matches.iter().all(|m| m.app.id != "other"));
        assert!(root.starts_with(std::env::temp_dir()));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn broad_roots_are_not_application_attribution() {
        let exe = std::env::current_exe().unwrap();
        let root = Path::new(exe.components().next().unwrap().as_os_str());
        assert!(
            match_executable(
                &exe,
                &[app("drive", root), app("temp", &std::env::temp_dir())]
            )
            .is_empty()
        );
    }
    #[test]
    fn own_process_cannot_be_stopped() {
        let peer = identity::process(unsafe { GetCurrentProcessId() }).unwrap();
        assert!(stop(&peer).unwrap_err().contains("another process"));
    }
}
