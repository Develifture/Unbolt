//! A floating native target. Releasing it identifies a window; no removal.
#![allow(unsafe_op_in_unsafe_fn)]
use std::{
    mem::zeroed,
    ptr::{null, null_mut},
};
use unbolt::{UnboltResult, command::wide};
use windows_sys::Win32::{
    Foundation::*,
    Graphics::Gdi::*,
    System::LibraryLoader::GetModuleHandleW,
    UI::{
        HiDpi::GetDpiForWindow,
        Input::KeyboardAndMouse::{ReleaseCapture, SetCapture},
        WindowsAndMessaging::*,
    },
};
pub const TARGET_CHOSEN: u32 = WM_APP + 41;
struct Tile {
    owner: HWND,
    offset: POINT,
    dragging: bool,
}
unsafe fn finish(hwnd: HWND, select: bool) {
    let raw = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut Tile;
    if raw.is_null() {
        return;
    }
    let owner = (*raw).owner;
    (*raw).dragging = false;
    ReleaseCapture();
    ShowWindow(hwnd, SW_HIDE);
    let mut point: POINT = zeroed();
    let (window, pid) = if select && GetCursorPos(&mut point) != 0 {
        unbolt::hunter::window_at_point(point.x, point.y)
            .map(|(hwnd, pid)| (hwnd as HWND, pid))
            .unwrap_or((null_mut(), 0))
    } else {
        (null_mut(), 0)
    };
    ShowWindow(owner, SW_RESTORE);
    SetForegroundWindow(owner);
    PostMessageW(owner, TARGET_CHOSEN, pid as usize, window as isize);
    DestroyWindow(hwnd);
}
unsafe extern "system" fn proc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    if msg == WM_NCCREATE {
        let create = &*(l as *const CREATESTRUCTW);
        let tile = Box::new(Tile {
            owner: create.lpCreateParams as HWND,
            offset: POINT { x: 0, y: 0 },
            dragging: false,
        });
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, Box::into_raw(tile) as isize);
        return 1;
    }
    let raw = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut Tile;
    if raw.is_null() {
        return DefWindowProcW(hwnd, msg, w, l);
    }
    match msg {
        WM_LBUTTONDOWN => {
            let mut point: POINT = zeroed();
            GetCursorPos(&mut point);
            let mut rect: RECT = zeroed();
            GetWindowRect(hwnd, &mut rect);
            (*raw).offset = POINT {
                x: point.x - rect.left,
                y: point.y - rect.top,
            };
            (*raw).dragging = true;
            SetCapture(hwnd);
            SetCursor(LoadCursorW(null_mut(), IDC_CROSS));
            0
        }
        WM_MOUSEMOVE if (*raw).dragging => {
            let mut point: POINT = zeroed();
            GetCursorPos(&mut point);
            SetWindowPos(
                hwnd,
                HWND_TOPMOST,
                point.x - (*raw).offset.x,
                point.y - (*raw).offset.y,
                0,
                0,
                SWP_NOSIZE | SWP_NOACTIVATE,
            );
            0
        }
        WM_LBUTTONUP if (*raw).dragging => {
            finish(hwnd, true);
            0
        }
        WM_CAPTURECHANGED if (*raw).dragging => {
            finish(hwnd, false);
            0
        }
        WM_RBUTTONUP | WM_CLOSE => {
            finish(hwnd, false);
            0
        }
        WM_KEYDOWN if w == 27 => {
            finish(hwnd, false);
            0
        }
        WM_SETCURSOR => {
            SetCursor(LoadCursorW(null_mut(), IDC_CROSS));
            1
        }
        WM_PAINT => {
            let mut paint: PAINTSTRUCT = zeroed();
            let dc = BeginPaint(hwnd, &mut paint);
            let (background, _, _, _) = crate::gui::dialog_palette();
            let (_, text, accent) = crate::gui::header_colors();
            let mut rect: RECT = zeroed();
            GetClientRect(hwnd, &mut rect);
            let brush = CreateSolidBrush(background);
            FillRect(dc, &rect, brush);
            DeleteObject(brush);
            let width = (rect.right - rect.left).max(1);
            let height = (rect.bottom - rect.top).max(1);
            let cx = width / 2;
            let cy = height / 3;
            let radius = height / 5;
            let pen = CreatePen(PS_SOLID, (width / 32).max(1), accent);
            let old_pen = SelectObject(dc, pen);
            let old_brush = SelectObject(dc, GetStockObject(NULL_BRUSH));
            Ellipse(dc, cx - radius, cy - radius, cx + radius, cy + radius);
            MoveToEx(dc, cx, cy - radius - 5, null_mut());
            LineTo(dc, cx, cy + radius + 5);
            MoveToEx(dc, cx - radius - 5, cy, null_mut());
            LineTo(dc, cx + radius + 5, cy);
            SelectObject(dc, old_pen);
            SelectObject(dc, old_brush);
            DeleteObject(pen);
            let dpi = GetDpiForWindow(hwnd).max(96) as i32;
            let font = CreateFontW(
                -12 * dpi / 96,
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
            );
            let old_font = SelectObject(dc, font);
            SetBkMode(dc, TRANSPARENT as i32);
            SetTextColor(dc, text);
            let mut label = RECT {
                left: 0,
                top: height * 2 / 3,
                right: width,
                bottom: height,
            };
            DrawTextW(
                dc,
                wide("Drag to a window\nEsc to cancel").as_ptr(),
                -1,
                &mut label,
                DT_CENTER | DT_WORDBREAK | DT_NOPREFIX,
            );
            SelectObject(dc, old_font);
            DeleteObject(font);
            EndPaint(hwnd, &paint);
            0
        }
        WM_DPICHANGED => {
            let dpi = (w & 0xffff).max(96) as i32;
            let rect = &*(l as *const RECT);
            SetWindowPos(
                hwnd,
                HWND_TOPMOST,
                rect.left,
                rect.top,
                128 * dpi / 96,
                104 * dpi / 96,
                SWP_NOACTIVATE,
            );
            0
        }
        WM_NCDESTROY => {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            drop(Box::from_raw(raw));
            DefWindowProcW(hwnd, msg, w, l)
        }
        _ => DefWindowProcW(hwnd, msg, w, l),
    }
}
pub unsafe fn open(owner: HWND) -> UnboltResult<usize> {
    let instance = GetModuleHandleW(null());
    let class = wide("UnboltHunterTarget");
    let descriptor = WNDCLASSW {
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(proc),
        hInstance: instance,
        lpszClassName: class.as_ptr(),
        hCursor: LoadCursorW(null_mut(), IDC_CROSS),
        ..zeroed()
    };
    RegisterClassW(&descriptor);
    let dpi = GetDpiForWindow(owner).max(96) as i32;
    let mut point = POINT {
        x: 20 * dpi / 96,
        y: 338 * dpi / 96,
    };
    ClientToScreen(owner, &mut point);
    let hwnd = CreateWindowExW(
        WS_EX_TOOLWINDOW | WS_EX_TOPMOST,
        class.as_ptr(),
        wide("Unbolt Hunter — drag onto an application window; Escape cancels").as_ptr(),
        WS_POPUP | WS_BORDER,
        point.x,
        point.y,
        128 * dpi / 96,
        104 * dpi / 96,
        null_mut(),
        null_mut(),
        instance,
        owner,
    );
    if hwnd.is_null() {
        return Err(format!("Hunter target could not open ({})", GetLastError()));
    }
    ShowWindow(hwnd, SW_SHOW);
    SetForegroundWindow(hwnd);
    Ok(hwnd as usize)
}
