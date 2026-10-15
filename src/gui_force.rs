//! Native modal input for an unregistered application's exact folder.
#![allow(unsafe_op_in_unsafe_fn)]
use std::{
    mem::{size_of, zeroed},
    path::Path,
    ptr::{null, null_mut},
};
use unbolt::{
    command::{expand_environment, wide},
    forced,
    model::Application,
};
use windows_sys::Win32::{
    Foundation::*,
    Graphics::{Dwm::*, Gdi::*},
    System::LibraryLoader::GetModuleHandleW,
    UI::{
        Controls::*,
        HiDpi::{AdjustWindowRectExForDpi, GetDpiForWindow},
        Input::KeyboardAndMouse::{EnableWindow, SetFocus},
        WindowsAndMessaging::*,
    },
};
struct Form {
    name: HWND,
    path: HWND,
    error: HWND,
    font: HFONT,
    background: HBRUSH,
    surface: HBRUSH,
    text: u32,
    result: Option<Application>,
}
unsafe fn text(hwnd: HWND) -> String {
    let len = GetWindowTextLengthW(hwnd);
    let mut value = vec![0u16; len as usize + 1];
    GetWindowTextW(hwnd, value.as_mut_ptr(), value.len() as i32);
    String::from_utf16_lossy(&value[..len as usize])
}
unsafe fn child(
    hwnd: HWND,
    class: &str,
    label: &str,
    id: usize,
    style: u32,
    rect: [i32; 4],
    dpi: u32,
) -> HWND {
    let [x, y, w, h] = rect;
    let scale = |n: i32| n * dpi as i32 / 96;
    CreateWindowExW(
        0,
        wide(class).as_ptr(),
        wide(label).as_ptr(),
        WS_CHILD | WS_VISIBLE | style,
        scale(x),
        scale(y),
        scale(w),
        scale(h),
        hwnd,
        id as HMENU,
        GetModuleHandleW(null()),
        null(),
    )
}
unsafe extern "system" fn proc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    if msg == WM_CREATE {
        let create = &*(l as *const CREATESTRUCTW);
        let form = &mut *(create.lpCreateParams as *mut Form);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, form as *mut _ as isize);
        let dpi = GetDpiForWindow(hwnd).max(96);
        let title = child(
            hwnd,
            "STATIC",
            "Review an unregistered application folder",
            200,
            0,
            [24, 20, 560, 26],
            dpi,
        );
        let help = child(
            hwnd,
            "STATIC",
            "Enter the product name and its exact folder. You will review individual items before removing anything.",
            201,
            0,
            [24, 56, 560, 44],
            dpi,
        );
        let name_label = child(
            hwnd,
            "STATIC",
            "Product name",
            202,
            0,
            [24, 114, 120, 24],
            dpi,
        );
        form.name = child(
            hwnd,
            "EDIT",
            "",
            101,
            WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL as u32,
            [158, 108, 426, 32],
            dpi,
        );
        let folder_label = child(
            hwnd,
            "STATIC",
            "Application folder",
            203,
            0,
            [24, 156, 132, 24],
            dpi,
        );
        form.path = child(
            hwnd,
            "EDIT",
            "",
            102,
            WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL as u32,
            [158, 150, 426, 32],
            dpi,
        );
        SendMessageW(
            form.name,
            EM_SETCUEBANNER,
            0,
            wide("e.g. Example Editor").as_ptr() as isize,
        );
        SendMessageW(
            form.path,
            EM_SETCUEBANNER,
            0,
            wide("Absolute folder path").as_ptr() as isize,
        );
        form.error = child(hwnd, "STATIC", "", 204, 0, [24, 194, 560, 44], dpi);
        let review = child(
            hwnd,
            "BUTTON",
            "Review items",
            1,
            WS_TABSTOP | BS_OWNERDRAW as u32,
            [318, 248, 128, 36],
            dpi,
        );
        let cancel = child(
            hwnd,
            "BUTTON",
            "Cancel",
            2,
            WS_TABSTOP | BS_OWNERDRAW as u32,
            [456, 248, 128, 36],
            dpi,
        );
        for control in [
            title,
            help,
            name_label,
            form.name,
            folder_label,
            form.path,
            form.error,
            review,
            cancel,
        ] {
            SendMessageW(control, WM_SETFONT, form.font as usize, 1);
        }
        SetFocus(form.name);
        return 0;
    }
    let raw = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut Form;
    if raw.is_null() {
        return DefWindowProcW(hwnd, msg, w, l);
    }
    match msg {
        WM_COMMAND => match w & 0xffff {
            1 => {
                let name = text((*raw).name);
                let path = expand_environment(text((*raw).path).trim().trim_matches('"'));
                match forced::folder_target(&name, Path::new(&path)) {
                    Ok(app) => {
                        (*raw).result = Some(app);
                        DestroyWindow(hwnd);
                    }
                    Err(error) => {
                        SetWindowTextW((*raw).error, wide(&error).as_ptr());
                    }
                }
                0
            }
            2 => {
                DestroyWindow(hwnd);
                0
            }
            _ => DefWindowProcW(hwnd, msg, w, l),
        },
        WM_CLOSE => {
            DestroyWindow(hwnd);
            0
        }
        WM_DRAWITEM => SendMessageW(GetParent(hwnd), msg, w, l),
        WM_ERASEBKGND => {
            let mut rect: RECT = zeroed();
            GetClientRect(hwnd, &mut rect);
            FillRect(w as HDC, &rect, (*raw).background);
            1
        }
        WM_CTLCOLORSTATIC | WM_CTLCOLOREDIT => {
            SetTextColor(w as HDC, (*raw).text);
            SetBkMode(w as HDC, TRANSPARENT as i32);
            if msg == WM_CTLCOLOREDIT {
                let (background, _, _, _) = crate::gui::dialog_palette();
                SetBkColor(w as HDC, background);
                (*raw).surface as isize
            } else {
                (*raw).background as isize
            }
        }
        WM_DESTROY => {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, w, l),
    }
}
pub unsafe fn choose_folder(parent: HWND) -> Option<Application> {
    let dpi = GetDpiForWindow(parent).max(96);
    let scale = |n: i32| n * dpi as i32 / 96;
    let (surface, background, text, dark) = crate::gui::dialog_palette();
    let mut form = Box::new(Form {
        name: null_mut(),
        path: null_mut(),
        error: null_mut(),
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
        result: None,
    });
    let class = wide("UnboltFolderReviewForm");
    let instance = GetModuleHandleW(null());
    let wc = WNDCLASSW {
        lpfnWndProc: Some(proc),
        hInstance: instance,
        lpszClassName: class.as_ptr(),
        hCursor: LoadCursorW(null_mut(), IDC_ARROW),
        ..zeroed()
    };
    RegisterClassW(&wc);
    let mut rect: RECT = zeroed();
    GetWindowRect(parent, &mut rect);
    let mut bounds = RECT {
        left: 0,
        top: 0,
        right: scale(608),
        bottom: scale(308),
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
        wide("Review application folder").as_ptr(),
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        rect.left + (rect.right - rect.left - width) / 2,
        rect.top + (rect.bottom - rect.top - height) / 2,
        width,
        height,
        parent,
        null_mut(),
        instance,
        (&mut *form as *mut Form).cast(),
    );
    if !hwnd.is_null() {
        let dark = dark as i32;
        DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE as u32,
            &dark as *const _ as *const _,
            size_of::<i32>() as u32,
        );
        EnableWindow(parent, 0);
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
        SetFocus(form.name);
        let mut msg: MSG = zeroed();
        while IsWindow(hwnd) != 0 {
            let code = GetMessageW(&mut msg, null_mut(), 0, 0);
            if code <= 0 {
                DestroyWindow(hwnd);
                if code == 0 {
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
