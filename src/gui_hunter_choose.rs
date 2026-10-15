//! Keyboard-accessible native alternative to dragging the Hunter target.
#![allow(unsafe_op_in_unsafe_fn)]
use std::{
    mem::{size_of, zeroed},
    ptr::{null, null_mut},
};
use unbolt::{
    command::wide,
    hunter::{self, WindowChoice},
};
use windows_sys::Win32::{
    Foundation::*,
    Graphics::{Dwm::*, Gdi::*},
    System::LibraryLoader::GetModuleHandleW,
    UI::{
        HiDpi::{AdjustWindowRectExForDpi, GetDpiForWindow},
        Input::KeyboardAndMouse::{EnableWindow, SetFocus},
        WindowsAndMessaging::*,
    },
};
struct Form {
    choices: Vec<WindowChoice>,
    list: HWND,
    result: Option<(usize, u32)>,
    font: HFONT,
    background: HBRUSH,
    surface: HBRUSH,
    text: u32,
}
unsafe extern "system" fn proc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    if msg == WM_CREATE {
        let form = (*(l as *const CREATESTRUCTW)).lpCreateParams as *mut Form;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, form as isize);
        let dpi = GetDpiForWindow(hwnd).max(96) as i32;
        let scale = |n: i32| n * dpi / 96;
        let font = (*form).font;
        let child = |class: &str, text: &str, style: u32, id: usize, rect: [i32; 4]| {
            let [x, y, width, height] = rect;
            let h = CreateWindowExW(
                0,
                wide(class).as_ptr(),
                wide(text).as_ptr(),
                WS_CHILD | WS_VISIBLE | style,
                scale(x),
                scale(y),
                scale(width),
                scale(height),
                hwnd,
                id as HMENU,
                GetModuleHandleW(null()),
                null(),
            );
            SendMessageW(h, WM_SETFONT, font as usize, 1);
            h
        };
        child(
            "STATIC",
            "Choose an open window. Identification makes no changes.",
            0,
            10,
            [20, 18, 560, 26],
        );
        (*form).list = child(
            "LISTBOX",
            "Open application windows",
            WS_BORDER | WS_TABSTOP | WS_VSCROLL | LBS_NOTIFY as u32 | LBS_NOINTEGRALHEIGHT as u32,
            11,
            [20, 54, 560, 262],
        );
        for choice in &(*form).choices {
            let label = wide(&format!("{}  ·  process {}", choice.title, choice.pid));
            SendMessageW((*form).list, LB_ADDSTRING, 0, label.as_ptr() as isize);
        }
        child(
            "BUTTON",
            "Identify window",
            WS_TABSTOP | BS_DEFPUSHBUTTON as u32,
            IDOK as usize,
            [316, 334, 140, 34],
        );
        child(
            "BUTTON",
            "Cancel",
            WS_TABSTOP | BS_PUSHBUTTON as u32,
            IDCANCEL as usize,
            [466, 334, 114, 34],
        );
        return 0;
    }
    let form = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut Form;
    if form.is_null() {
        return DefWindowProcW(hwnd, msg, w, l);
    }
    match msg {
        WM_COMMAND => {
            let id = (w & 0xffff) as i32;
            let code = (w >> 16) & 0xffff;
            if id == IDCANCEL {
                DestroyWindow(hwnd);
            } else if id == IDOK || (id == 11 && code == LBN_DBLCLK as usize) {
                let index = SendMessageW((*form).list, LB_GETCURSEL, 0, 0);
                let chosen = {
                    let choices = &(*form).choices;
                    choices
                        .get(index as usize)
                        .map(|choice| (choice.window, choice.pid))
                };
                if let Some(chosen) = chosen {
                    (*form).result = Some(chosen);
                    DestroyWindow(hwnd);
                }
            }
            0
        }
        WM_CLOSE => {
            DestroyWindow(hwnd);
            0
        }
        WM_CTLCOLORSTATIC | WM_CTLCOLORLISTBOX => {
            let dc = w as HDC;
            SetTextColor(dc, (*form).text);
            SetBkMode(dc, TRANSPARENT as i32);
            let (background, surface, _, _) = crate::gui::dialog_palette();
            SetBkColor(
                dc,
                if msg == WM_CTLCOLORLISTBOX {
                    surface
                } else {
                    background
                },
            );
            if msg == WM_CTLCOLORLISTBOX {
                (*form).surface as isize
            } else {
                (*form).background as isize
            }
        }
        WM_ERASEBKGND => {
            let mut rect: RECT = zeroed();
            GetClientRect(hwnd, &mut rect);
            FillRect(w as HDC, &rect, (*form).background);
            1
        }
        WM_NCDESTROY => {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            DefWindowProcW(hwnd, msg, w, l)
        }
        _ => DefWindowProcW(hwnd, msg, w, l),
    }
}
pub unsafe fn choose(parent: HWND) -> Option<(usize, u32)> {
    let dpi = GetDpiForWindow(parent).max(96);
    let scale = |n: i32| n * dpi as i32 / 96;
    let (background, surface, text, dark) = crate::gui::dialog_palette();
    let mut form = Box::new(Form {
        choices: hunter::open_windows(),
        list: null_mut(),
        result: None,
        font: CreateFontW(
            -scale(16),
            0,
            0,
            0,
            400,
            0,
            0,
            0,
            DEFAULT_CHARSET as u32,
            OUT_DEFAULT_PRECIS as u32,
            CLIP_DEFAULT_PRECIS as u32,
            CLEARTYPE_QUALITY as u32,
            DEFAULT_PITCH as u32,
            wide("Segoe UI").as_ptr(),
        ),
        background: CreateSolidBrush(background),
        surface: CreateSolidBrush(surface),
        text,
    });
    let class = wide("UnboltHunterWindowChooser");
    let instance = GetModuleHandleW(null());
    RegisterClassW(&WNDCLASSW {
        lpfnWndProc: Some(proc),
        hInstance: instance,
        lpszClassName: class.as_ptr(),
        hCursor: LoadCursorW(null_mut(), IDC_ARROW),
        ..zeroed()
    });
    let mut parent_rect: RECT = zeroed();
    GetWindowRect(parent, &mut parent_rect);
    let mut bounds = RECT {
        left: 0,
        top: 0,
        right: scale(600),
        bottom: scale(386),
    };
    AdjustWindowRectExForDpi(
        &mut bounds,
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        0,
        WS_EX_DLGMODALFRAME,
        dpi,
    );
    let width = bounds.right - bounds.left;
    let height = bounds.bottom - bounds.top;
    let hwnd = CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        class.as_ptr(),
        wide("Hunter — choose an open window").as_ptr(),
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        parent_rect.left + (parent_rect.right - parent_rect.left - width) / 2,
        parent_rect.top + (parent_rect.bottom - parent_rect.top - height) / 2,
        width,
        height,
        parent,
        null_mut(),
        instance,
        (&mut *form as *mut Form).cast(),
    );
    if !hwnd.is_null() {
        let mode = dark as i32;
        DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE as u32,
            &mode as *const _ as _,
            size_of::<i32>() as u32,
        );
        EnableWindow(parent, 0);
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
        SetFocus(form.list);
        let mut msg: MSG = zeroed();
        while IsWindow(hwnd) != 0 {
            let result = GetMessageW(&mut msg, null_mut(), 0, 0);
            if result <= 0 {
                DestroyWindow(hwnd);
                if result == 0 {
                    PostQuitMessage(msg.wParam as i32);
                }
                break;
            }
            if IsDialogMessageW(hwnd, &msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        EnableWindow(parent, 1);
        SetForegroundWindow(parent);
    }
    DeleteObject(form.font);
    DeleteObject(form.background);
    DeleteObject(form.surface);
    form.result.take()
}
