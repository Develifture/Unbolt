//! Native header hit-testing/accessibility with palette-aware painting.
#![allow(unsafe_op_in_unsafe_fn)]
use std::{mem::zeroed, ptr::null};
use windows_sys::Win32::{
    Foundation::*,
    Graphics::Gdi::*,
    UI::{
        Controls::*,
        HiDpi::GetDpiForWindow,
        Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass},
        WindowsAndMessaging::*,
    },
};
pub unsafe fn install(list: HWND) {
    let header = SendMessageW(list, LVM_GETHEADER, 0, 0) as HWND;
    if !header.is_null() {
        SetWindowSubclass(header, Some(header_proc), 1, 0);
    }
}
pub unsafe fn refresh(list: HWND) {
    let header = SendMessageW(list, LVM_GETHEADER, 0, 0) as HWND;
    if !header.is_null() {
        InvalidateRect(header, null(), 1);
    }
}
pub unsafe fn sort_marker(list: HWND, column: i32, descending: bool) {
    let header = SendMessageW(list, LVM_GETHEADER, 0, 0) as HWND;
    let count = SendMessageW(header, HDM_GETITEMCOUNT, 0, 0);
    for index in 0..count {
        let mut item: HDITEMW = zeroed();
        item.mask = HDI_FORMAT;
        SendMessageW(
            header,
            HDM_GETITEMW,
            index as usize,
            &mut item as *mut _ as isize,
        );
        item.fmt &= !(HDF_SORTUP | HDF_SORTDOWN);
        if index as i32 == column {
            item.fmt |= if descending { HDF_SORTDOWN } else { HDF_SORTUP };
        }
        SendMessageW(
            header,
            HDM_SETITEMW,
            index as usize,
            &item as *const _ as isize,
        );
    }
    refresh(list);
}
unsafe extern "system" fn header_proc(
    hwnd: HWND,
    msg: u32,
    w: WPARAM,
    l: LPARAM,
    _id: usize,
    _data: usize,
) -> LRESULT {
    if msg == WM_PAINT {
        let mut paint: PAINTSTRUCT = zeroed();
        let dc = BeginPaint(hwnd, &mut paint);
        let (background, text, accent) = crate::gui::header_colors();
        let brush = CreateSolidBrush(background);
        let mut client: RECT = zeroed();
        GetClientRect(hwnd, &mut client);
        FillRect(dc, &client, brush);
        DeleteObject(brush);
        SetBkMode(dc, TRANSPARENT as i32);
        SetTextColor(dc, text);
        let font = SendMessageW(GetParent(hwnd), WM_GETFONT, 0, 0);
        let previous = if font != 0 {
            SelectObject(dc, font as HGDIOBJ)
        } else {
            std::ptr::null_mut()
        };
        let count = SendMessageW(hwnd, HDM_GETITEMCOUNT, 0, 0);
        for index in 0..count {
            let mut rect: RECT = zeroed();
            if SendMessageW(
                hwnd,
                HDM_GETITEMRECT,
                index as usize,
                &mut rect as *mut _ as isize,
            ) == 0
            {
                continue;
            }
            let mut name = vec![0u16; 512];
            let mut item: HDITEMW = zeroed();
            item.mask = HDI_TEXT | HDI_FORMAT;
            item.pszText = name.as_mut_ptr();
            item.cchTextMax = name.len() as i32;
            SendMessageW(
                hwnd,
                HDM_GETITEMW,
                index as usize,
                &mut item as *mut _ as isize,
            );
            let mut label = rect;
            let unit = GetDpiForWindow(hwnd).max(96) as i32;
            label.left += 10 * unit / 96;
            label.right -= 18 * unit / 96;
            DrawTextW(
                dc,
                name.as_ptr(),
                -1,
                &mut label,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
            );
            if item.fmt & (HDF_SORTUP | HDF_SORTDOWN) != 0 {
                SetTextColor(dc, accent);
                let mut arrow = rect;
                arrow.left = arrow.right - 16 * unit / 96;
                let symbol = if item.fmt & HDF_SORTUP != 0 {
                    [0x25b4u16, 0]
                } else {
                    [0x25beu16, 0]
                };
                DrawTextW(
                    dc,
                    symbol.as_ptr(),
                    -1,
                    &mut arrow,
                    DT_CENTER | DT_VCENTER | DT_SINGLELINE,
                );
                SetTextColor(dc, text);
            }
        }
        if !previous.is_null() {
            SelectObject(dc, previous);
        }
        EndPaint(hwnd, &paint);
        return 0;
    }
    if msg == WM_NCDESTROY {
        RemoveWindowSubclass(hwnd, Some(header_proc), 1);
    }
    DefSubclassProc(hwnd, msg, w, l)
}
