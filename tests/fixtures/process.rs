use std::{fs, path::Path, process::Command, thread, time::Duration};
// These Windows-only launchers intentionally exit before their children. The
// outer integration test owns the job and waits for every descendant to finish.
#[allow(clippy::zombie_processes)]
fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let mode = args.first().map(String::as_str).unwrap_or("");
    let marker = args.get(1).expect("fixture marker");
    let path = Path::new(marker);
    assert!(path.is_absolute());
    assert!(
        path.parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("unbolt-process-fixture-")
            || path
                .parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("unbolt-helper-fixture-")
            || path
                .parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("unbolt-hunter-fixture-")
    );
    match mode {
        "arguments" => fs::write(path, serde_json::to_vec(&args[2..]).unwrap()).unwrap(),
        "window" => window_fixture(
            path,
            args.get(2)
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(120)
                .clamp(1, 600),
        ),
        "root" => {
            Command::new(std::env::current_exe().unwrap())
                .args(["child", marker])
                .spawn()
                .unwrap();
        }
        "child" => {
            Command::new(std::env::current_exe().unwrap())
                .args(["grandchild", marker])
                .spawn()
                .unwrap();
        }
        "grandchild" => {
            thread::sleep(Duration::from_millis(700));
            fs::write(path, b"grandchild finished").unwrap();
        }
        "delayed" => {
            thread::sleep(Duration::from_millis(800));
            fs::write(path, b"installer finished").unwrap();
        }
        "reboot" => std::process::exit(3010),
        "held" => {
            fs::write(path, b"fixture started").unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(15);
            while !path.with_file_name("release.txt").exists()
                && std::time::Instant::now() < deadline
            {
                thread::sleep(Duration::from_millis(25));
            }
        }
        _ => panic!("Unknown fixture mode"),
    }
}

fn window_fixture(marker: &Path, lifetime: u64) {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::{
        Foundation::*, System::LibraryLoader::GetModuleHandleW, UI::WindowsAndMessaging::*,
    };
    unsafe extern "system" fn proc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
        if msg == WM_DESTROY {
            unsafe { PostQuitMessage(0) };
            return 0;
        }
        unsafe { DefWindowProcW(hwnd, msg, w, l) }
    }
    unsafe {
        let instance = GetModuleHandleW(null());
        let class = unbolt::command::wide("UnboltHunterOwnedFixture");
        let descriptor = WNDCLASSW {
            lpfnWndProc: Some(proc),
            hInstance: instance,
            lpszClassName: class.as_ptr(),
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            hbrBackground: (windows_sys::Win32::Graphics::Gdi::COLOR_WINDOW + 1) as _,
            ..std::mem::zeroed()
        };
        RegisterClassW(&descriptor);
        // Keep this owned test surface on screen and above unrelated desktop
        // windows so point-attribution checks do not depend on the user's focus.
        let hwnd = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
            class.as_ptr(),
            unbolt::command::wide("Unbolt Hunter verification — owned temporary app").as_ptr(),
            WS_OVERLAPPEDWINDOW,
            40,
            40,
            440,
            250,
            null_mut(),
            null_mut(),
            instance,
            null(),
        );
        assert!(!hwnd.is_null());
        ShowWindow(hwnd, SW_SHOW);
        // The test runner may start with a hidden console; display this owned
        // verification window after the initial STARTUPINFO show flag is used.
        ShowWindow(hwnd, SW_SHOWNORMAL);
        SetTimer(hwnd, 1, 50, None);
        fs::write(
            marker,
            serde_json::to_vec(
                &serde_json::json!({"pid":std::process::id(), "window":hwnd as usize}),
            )
            .unwrap(),
        )
        .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(lifetime);
        let mut message: MSG = std::mem::zeroed();
        while GetMessageW(&mut message, null_mut(), 0, 0) > 0 {
            if marker.with_file_name("release.txt").is_file()
                || std::time::Instant::now() > deadline
            {
                DestroyWindow(hwnd);
            } else {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    }
}
