#![allow(unsafe_op_in_unsafe_fn)]
use std::{
    mem::{size_of, zeroed},
    ptr::{null, null_mut},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    thread,
};
use unbolt::{
    backup_delete,
    broker::{
        client,
        intent::{Operation, Reply},
    },
    command::wide,
    forced, hunter, inventory,
    model::*,
    records, recovery, scanner, session_review, settings, startup, uninstall,
};
use windows_sys::Win32::{
    Foundation::*,
    Graphics::{
        Dwm::{
            DWMWA_CAPTION_COLOR, DWMWA_TEXT_COLOR, DWMWA_USE_IMMERSIVE_DARK_MODE,
            DwmSetWindowAttribute,
        },
        Gdi::*,
    },
    System::{LibraryLoader::GetModuleHandleW, SystemServices::SS_ICON},
    UI::{
        Controls::*, HiDpi::*, Input::KeyboardAndMouse::EnableWindow, Shell::ShellExecuteW,
        WindowsAndMessaging::*,
    },
};

const SEARCH: usize = 101;
const REFRESH: usize = 102;
const PREVIEW: usize = 103;
const UNINSTALL: usize = 104;
const CLEANUP: usize = 105;
const CANCEL: usize = 106;
const HISTORY: usize = 107;
const RESTORE: usize = 108;
const APPS: usize = 110;
const LEFTOVERS: usize = 111;
const QUIET: usize = 112;
const EXPORT: usize = 113;
const ABOUT: usize = 114;
const THEME: usize = 115;
const NAV_APPS: usize = 120;
const NAV_BACKUPS: usize = 121;
const NAV_HISTORY: usize = 122;
const OPEN_BACKUP: usize = 123;
const FORCED_MSI: usize = 124;
const FORCED_REVIEW_APP: usize = 125;
const FORCED_FOLDER: usize = 126;
const FORCED_MSI_ACTION: usize = 127;
const UNINSTALL_ADMIN: usize = 128;
const FORCED_ADMIN: usize = 129;
const HUNTER: usize = 130;
const HUNTER_APP: usize = 131;
const HUNTER_FOLDER: usize = 132;
const HUNTER_STOP: usize = 133;
const HUNTER_PROPERTIES: usize = 134;
const HUNTER_FORCE: usize = 135;
const HUNTER_DRAG: usize = 136;
const HUNTER_CHOOSE: usize = 137;
const HUNTER_STARTUP: usize = 138;
const NAV_STARTUP: usize = 140;
const STARTUP_DISABLE: usize = 141;
const STARTUP_RESTORE: usize = 142;
const STARTUP_MORE: usize = 143;
const STARTUP_DISABLE_ADMIN: usize = 144;
const STARTUP_RESTORE_ADMIN: usize = 145;
const STARTUP_SHOW_ALL: usize = 146;
const DELETE_BACKUP: usize = 147;
const REVIEW_BACKUP: usize = 148;
const REVIEW_SESSION: usize = 149;
// Win32 MAKEINTRESOURCEW(1): an integer resource identifier, never dereferenced.
const APP_ICON_RESOURCE: *const u16 = std::ptr::without_provenance(1);
fn removal_caption(id: usize) -> Option<&'static str> {
    match id {
        FORCED_REVIEW_APP => Some("Review forced removal for selected app"),
        FORCED_FOLDER => Some("Review an unregistered folder…"),
        FORCED_MSI_ACTION => Some("Windows Installer removal…"),
        UNINSTALL_ADMIN => Some("Uninstall selected as administrator…"),
        FORCED_ADMIN => Some("Remove checked items as administrator…"),
        HUNTER_APP => Some("Select matched application"),
        HUNTER_FOLDER => Some("Open containing folder"),
        HUNTER_STOP => Some("Stop this process…"),
        HUNTER_PROPERTIES => Some("File properties"),
        HUNTER_FORCE => Some("Review forced removal…"),
        HUNTER_DRAG => Some("Drag a target onto a window"),
        HUNTER_CHOOSE => Some("Choose an open window…"),
        HUNTER_STARTUP => Some("Review this program's startup entries…"),
        STARTUP_DISABLE_ADMIN => Some("Disable startup as administrator…"),
        STARTUP_RESTORE_ADMIN => Some("Restore startup as administrator…"),
        STARTUP_SHOW_ALL => Some("Show all startup entries"),
        _ => None,
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Applications,
    Backups,
    History,
    Startup,
}
thread_local! {static ACTIVE_NAV:std::cell::Cell<usize>=const {std::cell::Cell::new(NAV_APPS)};}

#[derive(Clone, Copy)]
struct Palette {
    background: u32,
    surface: u32,
    text: u32,
    muted: u32,
    accent: u32,
}
fn rgb(r: u32, g: u32, b: u32) -> u32 {
    r | (g << 8) | (b << 16)
}
fn palette(dark: bool) -> Palette {
    if dark {
        Palette {
            background: rgb(23, 27, 35),
            surface: rgb(33, 39, 49),
            text: rgb(235, 240, 247),
            muted: rgb(159, 174, 194),
            accent: rgb(94, 210, 192),
        }
    } else {
        Palette {
            background: rgb(242, 246, 250),
            surface: rgb(255, 255, 255),
            text: rgb(30, 43, 61),
            muted: rgb(90, 108, 127),
            accent: rgb(0, 122, 110),
        }
    }
}
pub(crate) fn header_colors() -> (u32, u32, u32) {
    DRAW_STYLE.with(|s| {
        let colors = palette(s.get().0);
        (colors.surface, colors.text, colors.accent)
    })
}
pub(crate) fn dialog_palette() -> (u32, u32, u32, bool) {
    DRAW_STYLE.with(|s| {
        let dark = s.get().0;
        let p = palette(dark);
        (p.surface, p.background, p.text, dark)
    })
}
thread_local! {static DRAW_STYLE:std::cell::Cell<(bool,HBRUSH,HBRUSH)>=const {std::cell::Cell::new((false,std::ptr::null_mut(),std::ptr::null_mut()))};}
thread_local! {static QUIET_SELECTED:std::cell::Cell<bool>=const {std::cell::Cell::new(false)};}

thread_local! { static HANDLING_STATE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
struct DispatchGuard;
impl Drop for DispatchGuard {
    fn drop(&mut self) {
        HANDLING_STATE.with(|flag| flag.set(false));
    }
}

enum Event {
    Inventory(Inventory),
    Preview(Box<ScanReport>),
    ForcedPlan(Result<Box<forced::Plan>, String>),
    Finished(String),
    Progress(String),
    Uninstalled(Vec<Application>, String),
    Backups(Result<records::RecordPage<records::BackupRecord>, String>),
    History(Result<records::RecordPage<records::HistoryRecord>, String>),
    Hunter(Result<Box<hunter::Report>, String>),
    Startup(records::RecordPage<startup::Entry>),
    StartupChanged(String),
    BackupDeleteReview(Result<backup_delete::Plan, String>),
    SavedPreview(Result<Box<Application>, String>),
    SessionReview(Result<Box<session_review::Review>, String>),
}
struct State {
    hwnd: HWND,
    brand_icon: HWND,
    title: HWND,
    subtitle: HWND,
    search: HWND,
    list: HWND,
    candidates: HWND,
    details: HWND,
    status: HWND,
    review_label: HWND,
    quiet: HWND,
    controls: Vec<(usize, HWND)>,
    font: HFONT,
    heading: HFONT,
    dpi: u32,
    apps: Vec<Application>,
    visible: Vec<usize>,
    report: Option<ScanReport>,
    pending_preview: Option<Application>,
    preview_context: Option<String>,
    forced_plan: Option<forced::Plan>,
    refresh_after_result: bool,
    sender: Sender<Event>,
    receiver: Receiver<Event>,
    cancel: Arc<AtomicBool>,
    busy: bool,
    sort_column: i32,
    descending: bool,
    dark: bool,
    background_brush: HBRUSH,
    surface_brush: HBRUSH,
    page: Page,
    backups: Vec<records::BackupRecord>,
    history: Vec<records::HistoryRecord>,
    icons: crate::gui_icons::AppIcons,
    record_result: Option<String>,
    hunter_tile: Option<usize>,
    startup: Vec<startup::Entry>,
    startup_target: Option<std::path::PathBuf>,
}

unsafe fn control(parent: HWND, class: &str, text: &str, style: u32, id: usize) -> HWND {
    CreateWindowExW(
        0,
        wide(class).as_ptr(),
        wide(text).as_ptr(),
        WS_CHILD | WS_VISIBLE | style,
        0,
        0,
        10,
        10,
        parent,
        id as HMENU,
        GetModuleHandleW(null()),
        null(),
    )
}
unsafe fn set_text(hwnd: HWND, text: &str) {
    SetWindowTextW(hwnd, wide(text).as_ptr());
}
unsafe fn get_text(hwnd: HWND) -> String {
    let n = GetWindowTextLengthW(hwnd);
    let mut buf = vec![0u16; n as usize + 1];
    GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32);
    String::from_utf16_lossy(&buf[..n as usize])
}
unsafe fn message(hwnd: HWND, text: &str, title: &str, flags: u32) -> i32 {
    MessageBoxW(hwnd, wide(text).as_ptr(), wide(title).as_ptr(), flags)
}

unsafe fn brand_icon_for_dpi(dpi: u32) -> HICON {
    // Shared resource handles are cached by Windows and must not be destroyed.
    LoadImageW(
        GetModuleHandleW(null()),
        APP_ICON_RESOURCE,
        IMAGE_ICON,
        scale(32, dpi),
        scale(32, dpi),
        LR_SHARED,
    )
}

unsafe fn about(hwnd: HWND, text: &str) {
    let text = wide(text);
    let caption = wide("About Unbolt");
    let params = MSGBOXPARAMSW {
        cbSize: size_of::<MSGBOXPARAMSW>() as u32,
        hwndOwner: hwnd,
        hInstance: GetModuleHandleW(null()),
        lpszText: text.as_ptr(),
        lpszCaption: caption.as_ptr(),
        dwStyle: MB_OK | MB_USERICON,
        lpszIcon: APP_ICON_RESOURCE,
        ..zeroed()
    };
    MessageBoxIndirectW(&params);
}

unsafe fn add_column(list: HWND, index: i32, name: &str, width: i32) {
    let mut text = wide(name);
    let mut column: LVCOLUMNW = zeroed();
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    column.pszText = text.as_mut_ptr();
    column.cx = width;
    column.iSubItem = index;
    SendMessageW(
        list,
        LVM_INSERTCOLUMNW,
        index as usize,
        &column as *const _ as isize,
    );
}

fn scale(value: i32, dpi: u32) -> i32 {
    (value as i64 * dpi as i64 / 96) as i32
}
unsafe fn ui_font(dpi: u32, heading: bool) -> HFONT {
    CreateFontW(
        -scale(if heading { 28 } else { 16 }, dpi),
        0,
        0,
        0,
        if heading { 600 } else { 400 },
        0,
        0,
        0,
        DEFAULT_CHARSET as u32,
        OUT_DEFAULT_PRECIS as u32,
        CLIP_DEFAULT_PRECIS as u32,
        CLEARTYPE_QUALITY as u32,
        DEFAULT_PITCH as u32,
        wide("Segoe UI").as_ptr(),
    )
}
unsafe fn row(list: HWND, index: i32, values: &[String]) {
    for (column, value) in values.iter().enumerate() {
        let mut text = wide(value);
        let mut item: LVITEMW = zeroed();
        item.mask = LVIF_TEXT;
        item.iItem = index;
        item.iSubItem = column as i32;
        item.pszText = text.as_mut_ptr();
        SendMessageW(
            list,
            if column == 0 {
                LVM_INSERTITEMW
            } else {
                LVM_SETITEMW
            },
            0,
            &item as *const _ as isize,
        );
    }
}
unsafe fn selection(list: HWND) -> Vec<usize> {
    let mut result = Vec::new();
    let mut n = -1isize;
    loop {
        n = SendMessageW(list, LVM_GETNEXTITEM, n as usize, LVNI_SELECTED as isize);
        if n < 0 {
            break;
        }
        result.push(n as usize);
    }
    result
}

impl State {
    unsafe fn new(hwnd: HWND) -> Self {
        let (sender, receiver) = mpsc::channel();
        let dpi = GetDpiForWindow(hwnd).max(96);
        let font = ui_font(dpi, false);
        let heading = ui_font(dpi, true);
        let brand_icon = control(hwnd, "STATIC", "", SS_ICON, 202);
        SendMessageW(brand_icon, STM_SETICON, brand_icon_for_dpi(dpi) as usize, 0);
        let title = control(hwnd, "STATIC", "Unbolt", 0, 201);
        let subtitle = control(
            hwnd,
            "STATIC",
            "Your applications. Clear evidence. Recoverable cleanup.",
            0,
            0,
        );
        let search = control(
            hwnd,
            "EDIT",
            "",
            WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL as u32,
            SEARCH,
        );
        SendMessageW(
            search,
            EM_SETCUEBANNER,
            0,
            wide("Search applications or publishers").as_ptr() as isize,
        );
        let list = control(
            hwnd,
            "SysListView32",
            "",
            WS_BORDER | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SHAREIMAGELISTS,
            APPS,
        );
        SendMessageW(
            list,
            LVM_SETEXTENDEDLISTVIEWSTYLE,
            0,
            (LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP) as isize,
        );
        let icons = crate::gui_icons::AppIcons::new(scale(20, dpi));
        crate::gui_header::install(list);
        SendMessageW(list, LVM_SETIMAGELIST, LVSIL_SMALL as usize, icons.handle);
        for (i, (n, w)) in [
            ("Application", 290),
            ("Publisher", 190),
            ("Version", 120),
            ("Size", 100),
            ("Status", 140),
        ]
        .into_iter()
        .enumerate()
        {
            add_column(list, i as i32, n, scale(w, dpi));
        }
        let review_label = control(
            hwnd,
            "STATIC",
            "Leftover review — select an application, then Preview",
            0,
            0,
        );
        let candidates = control(
            hwnd,
            "SysListView32",
            "",
            WS_BORDER | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS,
            LEFTOVERS,
        );
        SendMessageW(
            candidates,
            LVM_SETEXTENDEDLISTVIEWSTYLE,
            0,
            (LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP)
                as isize,
        );
        crate::gui_header::install(candidates);
        for (i, (n, w)) in [
            ("Type", 150),
            ("Confidence", 110),
            ("Location", 370),
            ("Ownership evidence", 470),
        ]
        .into_iter()
        .enumerate()
        {
            add_column(candidates, i as i32, n, scale(w, dpi));
        }
        let details = control(
            hwnd,
            "EDIT",
            "Read-only startup. Nothing is removed until you explicitly choose an action.",
            WS_BORDER | WS_VSCROLL | ES_MULTILINE as u32 | ES_READONLY as u32,
            0,
        );
        let status = control(hwnd, "STATIC", "Starting inventory…", 0, 0);
        let quiet = control(
            hwnd,
            "BUTTON",
            "Quiet uninstall",
            WS_TABSTOP | BS_OWNERDRAW as u32,
            QUIET,
        );
        let mut controls = Vec::new();
        for (id, label) in [
            (REFRESH, "Refresh"),
            (EXPORT, "Export list"),
            (PREVIEW, "Preview leftovers"),
            (UNINSTALL, "Uninstall selected"),
            (FORCED_MSI, "More removal ▾"),
            (CLEANUP, "Clean checked"),
            (CANCEL, "Cancel queue"),
            (HISTORY, "History"),
            (RESTORE, "Browse backups"),
            (ABOUT, "About"),
            (THEME, "Dark theme"),
            (NAV_APPS, "Applications"),
            (NAV_BACKUPS, "Backups & recovery"),
            (NAV_HISTORY, "Operation history"),
            (OPEN_BACKUP, "Open backup folder"),
            (REVIEW_BACKUP, "Review leftovers"),
            (REVIEW_SESSION, "Review pending uninstall"),
            (DELETE_BACKUP, "Delete selected"),
            (HUNTER, "Hunter mode ▾"),
            (NAV_STARTUP, "Startup programs"),
            (STARTUP_DISABLE, "Disable startup"),
            (STARTUP_RESTORE, "Restore startup"),
            (STARTUP_MORE, "Startup actions ▾"),
        ] {
            controls.push((
                id,
                control(hwnd, "BUTTON", label, WS_TABSTOP | BS_OWNERDRAW as u32, id),
            ));
        }
        for (id, h) in &controls {
            if matches!(
                *id,
                HISTORY
                    | OPEN_BACKUP
                    | REVIEW_BACKUP
                    | REVIEW_SESSION
                    | DELETE_BACKUP
                    | STARTUP_DISABLE
                    | STARTUP_RESTORE
                    | STARTUP_MORE
            ) {
                ShowWindow(*h, SW_HIDE);
            }
        }
        for child in [
            subtitle,
            search,
            list,
            review_label,
            candidates,
            details,
            status,
            quiet,
        ]
        .into_iter()
        .chain(controls.iter().map(|(_, h)| *h))
        {
            SendMessageW(child, WM_SETFONT, font as usize, 1);
        }
        SendMessageW(title, WM_SETFONT, heading as usize, 1);
        let colors = palette(false);
        let background_brush = CreateSolidBrush(colors.background);
        let surface_brush = CreateSolidBrush(colors.surface);
        DRAW_STYLE.with(|s| s.set((false, background_brush, surface_brush)));
        Self {
            hwnd,
            title,
            subtitle,
            search,
            list,
            candidates,
            details,
            status,
            review_label,
            quiet,
            controls,
            font,
            heading,
            brand_icon,
            dpi,
            apps: Vec::new(),
            visible: Vec::new(),
            report: None,
            pending_preview: None,
            preview_context: None,
            forced_plan: None,
            refresh_after_result: false,
            sender,
            receiver,
            cancel: Arc::new(AtomicBool::new(false)),
            busy: false,
            sort_column: 0,
            descending: false,
            dark: false,
            background_brush,
            surface_brush,
            page: Page::Applications,
            backups: vec![],
            history: vec![],
            icons,
            record_result: None,
            hunter_tile: None,
            startup: vec![],
            startup_target: None,
        }
    }
    unsafe fn layout(&self) {
        let mut rect: RECT = zeroed();
        GetClientRect(self.hwnd, &mut rect);
        let w = rect.right * 96 / self.dpi as i32;
        let h = rect.bottom * 96 / self.dpi as i32;
        let pad = 198;
        let content = w - pad - 20;
        let compact = content < 850;
        let wrap = if compact { 42 } else { 0 };
        let record_wrap = if self.page == Page::Backups || (self.page == Page::Startup && compact) {
            42
        } else {
            0
        };
        let app_height = ((h - 330 - wrap) * 52 / 100).max(100);
        self.move_control(self.brand_icon, 20, 20, 32, 32, 1);
        self.move_control(self.title, 64, 18, w - 84, 36, 1);
        self.move_control(self.subtitle, pad, 59, content, 24, 1);
        self.move_control(self.search, pad, 94, (content - 280).max(150), 30, 1);
        self.place(NAV_APPS, 20, 138, 156, 40);
        self.place(NAV_BACKUPS, 20, 188, 156, 40);
        self.place(NAV_HISTORY, 20, 238, 156, 40);
        self.place(NAV_STARTUP, 20, 288, 156, 40);
        self.place(HUNTER, 20, 338, 156, 40);
        self.place(REFRESH, w - 282, 93, 116, 32);
        self.place(EXPORT, w - 156, 93, 136, 32);
        self.move_control(
            self.list,
            pad,
            138,
            content,
            if self.page == Page::Applications {
                app_height
            } else {
                h - 342 - record_wrap
            },
            1,
        );
        let y = 148 + app_height;
        self.place(PREVIEW, pad, y, 158, 34);
        self.place(UNINSTALL, pad + 168, y, 162, 34);
        self.place(FORCED_MSI, pad + 340, y, 142, 34);
        self.move_control(
            self.quiet,
            if compact { pad } else { pad + 494 },
            y + 4 + wrap,
            170,
            28,
            1,
        );
        self.place(CANCEL, w - 150, y + wrap, 130, 34);
        self.move_control(self.review_label, pad, y + 49 + wrap, content, 24, 1);
        let candidate_y = y + 80 + wrap;
        let candidate_h = (h - candidate_y - 158).max(48);
        self.move_control(self.candidates, pad, candidate_y, content, candidate_h, 1);
        let actions = if self.page == Page::Applications {
            candidate_y + candidate_h + 9
        } else {
            h - 180 - record_wrap
        };
        self.place(CLEANUP, pad, actions, 178, 34);
        self.place(RESTORE, pad + 190, actions, 150, 34);
        if self.page == Page::Backups {
            self.place(RESTORE, pad, actions, 166, 34);
            self.place(OPEN_BACKUP, pad + 178, actions, 166, 34);
            self.place(REVIEW_BACKUP, pad + 356, actions, 166, 34);
            self.place(DELETE_BACKUP, pad + 534, actions, 166, 34);
        }
        self.place(HISTORY, 20, 288, 156, 34);
        self.place(REVIEW_SESSION, pad, actions, 220, 34);
        if self.page == Page::History {
            self.place(CANCEL, pad + 230, actions, 120, 34);
        }
        self.place(STARTUP_DISABLE, pad, actions, 166, 34);
        self.place(STARTUP_RESTORE, pad + 178, actions, 166, 34);
        self.place(STARTUP_MORE, pad + 356, actions, 180, 34);
        self.place(THEME, w - 306, actions + record_wrap, 112, 34);
        self.place(ABOUT, w - 184, actions + record_wrap, 164, 34);
        if matches!(self.page, Page::Startup | Page::Backups) {
            self.place(CANCEL, 20, 338, 156, 40);
        }
        self.move_control(
            self.details,
            pad,
            actions + 44 + record_wrap,
            content,
            if self.page == Page::Applications {
                52
            } else {
                96
            },
            1,
        );
        self.move_control(self.status, pad, h - 28, content, 24, 1);
        self.fit_columns(
            self.list,
            content,
            match self.page {
                Page::Applications => &[32, 22, 14, 12, 20],
                Page::Backups => &[23, 16, 15, 26, 20],
                Page::History => &[23, 17, 40, 20, 0],
                Page::Startup => &[22, 15, 18, 29, 16],
            },
        );
        self.fit_columns(self.candidates, content, &[16, 12, 32, 40]);
    }
    unsafe fn show_page(&mut self, page: Page) {
        self.show_page_with_target(page, None);
    }
    unsafe fn show_page_with_target(&mut self, page: Page, target: Option<std::path::PathBuf>) {
        if self.busy {
            return;
        }
        self.page = page;
        self.startup_target = target;
        ACTIVE_NAV.with(|s| {
            s.set(match page {
                Page::Applications => NAV_APPS,
                Page::Backups => NAV_BACKUPS,
                Page::History => NAV_HISTORY,
                Page::Startup => NAV_STARTUP,
            })
        });
        set_text(self.search, "");
        SendMessageW(
            self.search,
            EM_SETCUEBANNER,
            0,
            wide(match page {
                Page::Applications => "Search applications or publishers",
                Page::Backups => "Search backup names, locations, or status",
                Page::History => "Search applications, operations, or results",
                Page::Startup => "Search startup names, commands, sources, or state",
            })
            .as_ptr() as isize,
        );
        self.sort_column = match page {
            Page::Applications => 0,
            Page::Backups => 4,
            Page::History => 3,
            Page::Startup => 0,
        };
        self.descending = matches!(page, Page::Backups | Page::History);
        SendMessageW(self.list, LVM_DELETEALLITEMS, 0, 0);
        while SendMessageW(self.list, LVM_DELETECOLUMN, 0, 0) != 0 {}
        let columns = match page {
            Page::Applications => [
                ("Application", 270),
                ("Publisher", 180),
                ("Version", 100),
                ("Size", 90),
                ("Status", 160),
            ],
            Page::Backups => [
                ("Application", 240),
                ("Backup type", 150),
                ("State", 150),
                ("Original location", 340),
                ("Created (UTC)", 180),
            ],
            Page::History => [
                ("Application", 230),
                ("Operation", 165),
                ("Result / details", 460),
                ("Recorded (UTC)", 180),
                ("", 0),
            ],
            Page::Startup => [
                ("Startup item", 200),
                ("State", 150),
                ("Applies to", 160),
                ("Command / file", 380),
                ("Source", 230),
            ],
        };
        for (i, (name, width)) in columns.into_iter().enumerate() {
            add_column(self.list, i as i32, name, scale(width, self.dpi));
        }
        SendMessageW(
            self.list,
            LVM_SETIMAGELIST,
            LVSIL_SMALL as usize,
            if page == Page::Applications {
                self.icons.handle
            } else {
                0
            },
        );
        for h in [self.candidates, self.review_label, self.quiet] {
            ShowWindow(
                h,
                if page == Page::Applications {
                    SW_SHOW
                } else {
                    SW_HIDE
                },
            );
        }
        for (id, h) in &self.controls {
            if *id == RESTORE {
                set_text(
                    *h,
                    if page == Page::Backups {
                        "Restore selected"
                    } else {
                        "Browse backups"
                    },
                );
            }
            let visible = match *id {
                PREVIEW | UNINSTALL | FORCED_MSI | CLEANUP | HUNTER => page == Page::Applications,
                RESTORE => matches!(page, Page::Applications | Page::Backups),
                CANCEL => true,
                OPEN_BACKUP | REVIEW_BACKUP | DELETE_BACKUP => page == Page::Backups,
                HISTORY => false,
                REVIEW_SESSION => page == Page::History,
                STARTUP_DISABLE | STARTUP_RESTORE | STARTUP_MORE => page == Page::Startup,
                _ => true,
            };
            ShowWindow(*h, if visible { SW_SHOW } else { SW_HIDE });
            if *id == CANCEL {
                set_text(
                    *h,
                    if page == Page::History {
                        "Cancel review"
                    } else if matches!(page, Page::Startup | Page::Backups) {
                        "Cancel operation"
                    } else {
                        "Cancel queue"
                    },
                );
            }
            InvalidateRect(*h, null(), 1);
        }
        set_text(
            self.subtitle,
            match page {
                Page::Applications => "Manage applications and review their remaining data",
                Page::Backups => {
                    "Review leftovers, restore a recovery copy, or delete selected backups"
                }
                Page::History => "Search operation results, errors, and recovery events",
                Page::Startup => {
                    "Review startup sources; disable reversibly or restore a saved item"
                }
            },
        );
        self.layout();
        self.refresh();
    }
    unsafe fn fill_records(&mut self) {
        if self.page == Page::Backups {
            for (id, h) in &self.controls {
                if *id == RESTORE {
                    EnableWindow(*h, 0);
                }
            }
        }
        let query = get_text(self.search);
        self.visible = match self.page {
            Page::Backups => self
                .backups
                .iter()
                .enumerate()
                .filter(|(_, r)| r.matches(&query))
                .map(|(i, _)| i)
                .collect(),
            Page::History => self
                .history
                .iter()
                .enumerate()
                .filter(|(_, r)| r.matches(&query))
                .map(|(i, _)| i)
                .collect(),
            Page::Startup => self
                .startup
                .iter()
                .enumerate()
                .filter(|(_, r)| r.matches(&query))
                .map(|(i, _)| i)
                .collect(),
            _ => vec![],
        };
        let column = self.sort_column;
        let descending = self.descending;
        self.visible.sort_by(|a, b| {
            let value = |index: usize| match self.page {
                Page::Backups => {
                    let r = &self.backups[index];
                    match column {
                        1 => r.kind.clone(),
                        2 => r.state.clone(),
                        3 => r.original.clone(),
                        4 => r.id.clone(),
                        _ => r.application.clone(),
                    }
                }
                Page::Startup => {
                    let r = &self.startup[index];
                    match column {
                        1 => r.state.clone(),
                        2 => r.source.scope(),
                        3 => r.display_command(),
                        4 => r.source.kind_label().into(),
                        _ => r.name().into(),
                    }
                }
                _ => {
                    let r = &self.history[index];
                    match column {
                        1 => r.kind.clone(),
                        2 => r.detail.clone(),
                        3 => r.id.clone(),
                        _ => r.application.clone(),
                    }
                }
            };
            let order = value(*a).to_lowercase().cmp(&value(*b).to_lowercase());
            if descending { order.reverse() } else { order }
        });
        SendMessageW(self.list, WM_SETREDRAW, 0, 0);
        SendMessageW(self.list, LVM_DELETEALLITEMS, 0, 0);
        for (row_index, index) in self.visible.iter().enumerate() {
            let values = match self.page {
                Page::Backups => {
                    let r = &self.backups[*index];
                    vec![
                        r.application.clone(),
                        r.kind.clone(),
                        records::state_label(&r.state).into(),
                        records::display_path(&r.original),
                        records::recorded_time(&r.id),
                    ]
                }
                Page::Startup => {
                    let r = &self.startup[*index];
                    vec![
                        r.name().into(),
                        if r.backup.is_some() && r.state == "Disabled by Unbolt" {
                            "Disabled".into()
                        } else if r.state == "Needs recovery review" {
                            "Review recovery".into()
                        } else {
                            r.state.clone()
                        },
                        r.source.scope(),
                        r.display_command(),
                        r.source.kind_label().into(),
                    ]
                }
                _ => {
                    let r = &self.history[*index];
                    vec![
                        r.application.clone(),
                        records::operation_label(&r.kind),
                        records::detail_text(r)
                            .lines()
                            .next()
                            .unwrap_or_default()
                            .to_string(),
                        records::recorded_time(&r.id),
                        String::new(),
                    ]
                }
            };
            row(self.list, row_index as i32, &values);
        }
        SendMessageW(self.list, WM_SETREDRAW, 1, 0);
        InvalidateRect(self.list, null(), 1);
        crate::gui_header::sort_marker(self.list, self.sort_column, self.descending);
        if self.visible.is_empty() {
            set_text(
                self.details,
                if !query.is_empty() {
                    "No records match this search."
                } else if self.page == Page::Startup {
                    "No supported startup sources were found. Services and scheduled tasks are not yet included."
                } else if self.page == Page::Backups {
                    "No backups yet. Backups appear here after reviewed uninstall or cleanup operations."
                } else {
                    "No operations recorded yet."
                },
            );
        }
        set_text(
            self.status,
            &format!(
                "{} matching {}",
                self.visible.len(),
                if self.page == Page::Backups {
                    "backups"
                } else if self.page == Page::Startup {
                    "startup items"
                } else {
                    "history records"
                }
            ),
        );
        if self.page == Page::Startup {
            self.update_startup_actions();
            if let Some(target) = &self.startup_target {
                set_text(
                    self.status,
                    &format!(
                        "{} matching startup {} · Hunter target: {}",
                        self.visible.len(),
                        if self.visible.len() == 1 {
                            "item"
                        } else {
                            "items"
                        },
                        target.file_name().unwrap_or_default().to_string_lossy()
                    ),
                );
            }
        }
        if matches!(self.page, Page::Backups | Page::History) {
            self.update_actions();
        }
    }
    unsafe fn record_selection(&mut self) {
        let Some(index) = selection(self.list)
            .first()
            .and_then(|i| self.visible.get(*i))
            .copied()
        else {
            return;
        };
        match self.page {
            Page::Backups => {
                let r = &self.backups[index];
                for (id, h) in &self.controls {
                    if *id == RESTORE {
                        EnableWindow(*h, (r.recoverable && !self.busy) as i32);
                    }
                }
                set_text(
                    self.details,
                    &format!(
                        "{} · {} · {}\r\n{}",
                        r.application,
                        r.kind,
                        records::state_label(&r.state),
                        records::display_path(&r.original)
                    ),
                );
            }
            Page::History => {
                let r = &self.history[index];
                set_text(
                    self.details,
                    &format!(
                        "{} · {}\r\n{}",
                        r.application,
                        records::operation_label(&r.kind),
                        records::detail_text(r)
                    ),
                );
                self.update_actions();
            }
            Page::Startup => {
                set_text(self.details, &self.startup[index].details());
                self.update_startup_actions();
            }
            _ => {}
        }
    }
    unsafe fn review_session(&mut self) {
        if self.busy || self.page != Page::History {
            return;
        }
        let Some(record) = selection(self.list)
            .first()
            .and_then(|i| self.visible.get(*i))
            .and_then(|i| self.history.get(*i))
            .filter(|r| r.can_review_session())
        else {
            return;
        };
        let (manifest, session_id) = match record.session_review_target() {
            Ok(target) => target,
            Err(error) => {
                set_text(
                    self.details,
                    &format!("Cannot read the uninstall result: {error}"),
                );
                return;
            }
        };
        self.busy(true);
        set_text(
            self.status,
            "Checking the saved registration, installer state, and Windows restart…",
        );
        let tx = self.sender.clone();
        let cancel = self.cancel.clone();
        thread::spawn(move || {
            let result = session_review::prepare(&manifest, &session_id, &cancel).map(Box::new);
            let _ = tx.send(Event::SessionReview(result));
        });
    }
    unsafe fn open_backup_folder(&self) {
        let path = selection(self.list)
            .first()
            .and_then(|i| self.visible.get(*i))
            .and_then(|i| self.backups.get(*i))
            .and_then(|r| r.manifest.parent())
            .map(std::path::Path::to_path_buf);
        if let Some(path) = path {
            ShellExecuteW(
                self.hwnd,
                wide("open").as_ptr(),
                wide(&path.display().to_string()).as_ptr(),
                null(),
                null(),
                SW_SHOWNORMAL,
            );
        }
    }
    unsafe fn toggle_theme(&mut self) {
        self.dark = !self.dark;
        self.apply_theme();
        if let Err(e) = settings::save(&settings::UiSettings { dark: self.dark }) {
            set_text(
                self.status,
                &format!("Theme changed; preference could not be saved: {e}"),
            );
        }
    }
    unsafe fn apply_theme(&mut self) {
        let colors = palette(self.dark);
        let old = (self.background_brush, self.surface_brush);
        self.background_brush = CreateSolidBrush(colors.background);
        self.surface_brush = CreateSolidBrush(colors.surface);
        DRAW_STYLE.with(|s| s.set((self.dark, self.background_brush, self.surface_brush)));
        for list in [self.list, self.candidates] {
            SendMessageW(list, LVM_SETBKCOLOR, 0, colors.surface as isize);
            SendMessageW(list, LVM_SETTEXTBKCOLOR, 0, colors.surface as isize);
            SendMessageW(list, LVM_SETTEXTCOLOR, 0, colors.text as isize);
            InvalidateRect(list, null(), 1);
        }
        if let Some((_, button)) = self.controls.iter().find(|(id, _)| *id == THEME) {
            set_text(
                *button,
                if self.dark {
                    "Light theme"
                } else {
                    "Dark theme"
                },
            );
        }
        InvalidateRect(self.hwnd, null(), 1);
        let dark = self.dark as i32;
        DwmSetWindowAttribute(
            self.hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE as u32,
            &dark as *const _ as *const _,
            size_of::<i32>() as u32,
        );
        DwmSetWindowAttribute(
            self.hwnd,
            DWMWA_CAPTION_COLOR as u32,
            &colors.background as *const _ as *const _,
            size_of::<u32>() as u32,
        );
        DwmSetWindowAttribute(
            self.hwnd,
            DWMWA_TEXT_COLOR as u32,
            &colors.text as *const _ as *const _,
            size_of::<u32>() as u32,
        );
        crate::gui_header::refresh(self.list);
        crate::gui_header::refresh(self.candidates);
        for (_, h) in &self.controls {
            InvalidateRect(*h, null(), 1);
        }
        for h in [
            self.title,
            self.subtitle,
            self.review_label,
            self.details,
            self.status,
            self.quiet,
            self.search,
        ] {
            InvalidateRect(h, null(), 1);
        }
        DeleteObject(old.0);
        DeleteObject(old.1);
    }
    unsafe fn place(&self, id: usize, x: i32, y: i32, w: i32, h: i32) {
        if let Some((_, control)) = self.controls.iter().find(|(n, _)| *n == id) {
            self.move_control(*control, x, y, w, h, 1);
        }
    }
    unsafe fn move_control(&self, control: HWND, x: i32, y: i32, w: i32, h: i32, repaint: i32) {
        MoveWindow(
            control,
            scale(x, self.dpi),
            scale(y, self.dpi),
            scale(w, self.dpi),
            scale(h, self.dpi),
            repaint,
        );
    }
    unsafe fn fit_columns(&self, list: HWND, width: i32, weights: &[i32]) {
        let available = scale(width - 20, self.dpi).max(200);
        let mut cumulative = 0;
        let mut previous = 0;
        for (i, weight) in weights.iter().enumerate() {
            cumulative += weight;
            let end = available * cumulative / 100;
            SendMessageW(list, LVM_SETCOLUMNWIDTH, i, (end - previous) as isize);
            previous = end;
        }
    }
    unsafe fn update_dpi(&mut self, dpi: u32) {
        let old_dpi = self.dpi;
        self.dpi = dpi.max(96);
        SendMessageW(
            self.brand_icon,
            STM_SETICON,
            brand_icon_for_dpi(self.dpi) as usize,
            0,
        );
        let old = (self.font, self.heading);
        self.font = ui_font(self.dpi, false);
        self.heading = ui_font(self.dpi, true);
        for child in [
            self.subtitle,
            self.search,
            self.list,
            self.review_label,
            self.candidates,
            self.details,
            self.status,
            self.quiet,
        ]
        .into_iter()
        .chain(self.controls.iter().map(|(_, h)| *h))
        {
            SendMessageW(child, WM_SETFONT, self.font as usize, 1);
        }
        SendMessageW(self.title, WM_SETFONT, self.heading as usize, 1);
        for list in [self.list, self.candidates] {
            let header = SendMessageW(list, LVM_GETHEADER, 0, 0) as HWND;
            let count = SendMessageW(header, HDM_GETITEMCOUNT, 0, 0);
            for i in 0..count {
                let width = SendMessageW(list, LVM_GETCOLUMNWIDTH, i as usize, 0);
                SendMessageW(
                    list,
                    LVM_SETCOLUMNWIDTH,
                    i as usize,
                    width * self.dpi as isize / old_dpi as isize,
                );
            }
        }
        SendMessageW(self.list, LVM_SETIMAGELIST, LVSIL_SMALL as usize, 0);
        self.icons = crate::gui_icons::AppIcons::new(scale(20, self.dpi));
        SendMessageW(
            self.list,
            LVM_SETIMAGELIST,
            LVSIL_SMALL as usize,
            if self.page == Page::Applications {
                self.icons.handle
            } else {
                0
            },
        );
        if self.page == Page::Applications {
            for (row, &index) in self.visible.iter().enumerate() {
                let mut item: LVITEMW = zeroed();
                item.mask = LVIF_IMAGE;
                item.iItem = row as i32;
                item.iImage = self.icons.index(&self.apps[index]);
                SendMessageW(self.list, LVM_SETITEMW, 0, &item as *const _ as isize);
            }
        }
        DeleteObject(old.0);
        DeleteObject(old.1);
        self.layout();
    }
    unsafe fn busy(&mut self, value: bool) {
        self.busy = value;
        for (id, h) in &self.controls {
            EnableWindow(
                *h,
                if *id == CANCEL {
                    value as i32
                } else {
                    (!value) as i32
                },
            );
        }
        EnableWindow(self.quiet, (!value) as i32);
        if value {
            self.cancel = Arc::new(AtomicBool::new(false));
        } else {
            self.update_actions();
        }
    }
    unsafe fn update_actions(&self) {
        if self.busy {
            return;
        }
        if self.page == Page::History {
            let enabled = selection(self.list).len() == 1
                && selection(self.list)
                    .first()
                    .and_then(|i| self.visible.get(*i))
                    .and_then(|i| self.history.get(*i))
                    .is_some_and(|r| r.can_review_session());
            for (id, h) in &self.controls {
                if *id == REVIEW_SESSION {
                    EnableWindow(*h, enabled as i32);
                }
            }
            return;
        }
        if self.page == Page::Backups {
            let selected = self.selected_backups();
            for (id, h) in &self.controls {
                let enabled = match *id {
                    DELETE_BACKUP => !selected.is_empty(),
                    RESTORE => selected.len() == 1 && selected[0].recoverable,
                    OPEN_BACKUP => selected.len() == 1,
                    REVIEW_BACKUP => {
                        selected.len() == 1 && selected[0].kind == "Registration export"
                    }
                    _ => continue,
                };
                EnableWindow(*h, enabled as i32);
            }
            return;
        }
        if self.page != Page::Applications {
            return;
        }
        let selected = self.selected_apps();
        for (id, h) in &self.controls {
            let enabled = match *id {
                PREVIEW => selected.len() == 1,
                UNINSTALL => {
                    !selected.is_empty()
                        && selected.iter().all(|a| {
                            !a.system_component
                                && if QUIET_SELECTED.with(|v| v.get()) {
                                    !a.quiet_uninstall.trim().is_empty()
                                } else {
                                    !a.uninstall.trim().is_empty()
                                }
                        })
                }
                FORCED_MSI => true,
                CLEANUP => self.report.as_ref().is_some_and(|r| {
                    (self.forced_plan.is_some() || (!r.app_registered && r.errors.is_empty()))
                        && !r.cancelled
                        && (r
                            .candidates
                            .iter()
                            .any(|c| c.confidence == Confidence::High)
                            || r.registry_candidates
                                .iter()
                                .any(|c| c.confidence == Confidence::High))
                }),
                _ => continue,
            };
            EnableWindow(*h, enabled as i32);
        }
    }
    unsafe fn refresh(&mut self) {
        if self.busy {
            return;
        }
        self.busy(true);
        if self.page != Page::Applications {
            let tx = self.sender.clone();
            let page = self.page;
            let cancel = self.cancel.clone();
            let startup_target = self.startup_target.clone();
            set_text(self.status, "Reading local records…");
            thread::spawn(move || {
                let _ = tx.send(if page == Page::Backups {
                    Event::Backups(records::backups())
                } else if page == Page::Startup {
                    let mut entries = startup::collect(&cancel);
                    if let Some(target) = startup_target {
                        entries
                            .records
                            .retain(|entry| !cancelled(&cancel) && entry.launches(&target));
                        if cancelled(&cancel) {
                            entries.errors.push(
                                "Startup target matching cancelled; coverage is incomplete".into(),
                            );
                        }
                    }
                    Event::Startup(entries)
                } else {
                    Event::History(records::history())
                });
            });
            return;
        }
        set_text(self.status, "Reading installed applications…");
        self.forced_plan = None;
        self.report = None;
        SendMessageW(self.candidates, LVM_DELETEALLITEMS, 0, 0);
        set_text(
            self.review_label,
            "Leftover review — select an application, then Preview",
        );
        for (id, h) in &self.controls {
            if *id == CLEANUP {
                set_text(*h, "Clean checked");
            }
        }
        let tx = self.sender.clone();
        let cancel = self.cancel.clone();
        thread::spawn(move || {
            let _ = tx.send(Event::Inventory(inventory::collect(&cancel)));
        });
    }
    unsafe fn fill_apps(&mut self) {
        if self.page != Page::Applications {
            self.fill_records();
            return;
        }
        let query = get_text(self.search).to_lowercase();
        self.visible = self
            .apps
            .iter()
            .enumerate()
            .filter(|(_, a)| {
                a.name.to_lowercase().contains(&query)
                    || a.publisher.to_lowercase().contains(&query)
            })
            .map(|(i, _)| i)
            .collect();
        self.visible.sort_by(|a, b| {
            let (a, b) = (&self.apps[*a], &self.apps[*b]);
            let order = match self.sort_column {
                1 => a.publisher.to_lowercase().cmp(&b.publisher.to_lowercase()),
                2 => a.version.cmp(&b.version),
                3 => a.size_kib.cmp(&b.size_kib),
                4 => (a.system_component, a.uninstall.is_empty())
                    .cmp(&(b.system_component, b.uninstall.is_empty())),
                _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            };
            if self.descending {
                order.reverse()
            } else {
                order
            }
        });
        SendMessageW(self.list, WM_SETREDRAW, 0, 0);
        SendMessageW(self.list, LVM_DELETEALLITEMS, 0, 0);
        for (index, app_index) in self.visible.iter().enumerate() {
            let a = &self.apps[*app_index];
            row(
                self.list,
                index as i32,
                &[
                    a.name.clone(),
                    a.publisher.clone(),
                    a.version.clone(),
                    a.size_kib
                        .map(|n| format!("{:.1} MB", n as f64 / 1024.))
                        .unwrap_or_else(|| "Unknown".into()),
                    if a.system_component {
                        "System component"
                    } else if a.uninstall.is_empty() {
                        "No command"
                    } else {
                        "Registered"
                    }
                    .into(),
                ],
            );
            let icon = self.icons.index(a);
            let mut item: LVITEMW = zeroed();
            item.mask = LVIF_IMAGE;
            item.iItem = index as i32;
            item.iImage = icon;
            SendMessageW(self.list, LVM_SETITEMW, 0, &item as *const _ as isize);
        }
        SendMessageW(self.list, WM_SETREDRAW, 1, 0);
        InvalidateRect(self.list, null(), 1);
        crate::gui_header::sort_marker(self.list, self.sort_column, self.descending);
        set_text(
            self.status,
            &format!(
                "{} shown / {} applications · Version {}",
                self.visible.len(),
                self.apps.len(),
                env!("CARGO_PKG_VERSION")
            ),
        );
        self.update_actions();
    }
    unsafe fn selected_apps(&self) -> Vec<Application> {
        if self.page != Page::Applications {
            return vec![];
        }
        selection(self.list)
            .into_iter()
            .filter_map(|i| self.visible.get(i))
            .map(|i| self.apps[*i].clone())
            .collect()
    }
    unsafe fn selected_backups(&self) -> Vec<records::BackupRecord> {
        if self.page != Page::Backups {
            return vec![];
        }
        selection(self.list)
            .into_iter()
            .filter_map(|i| self.visible.get(i))
            .filter_map(|&i| self.backups.get(i))
            .cloned()
            .collect()
    }
    unsafe fn delete_backups(&mut self) {
        if self.busy {
            return;
        }
        let selected = self.selected_backups();
        if selected.is_empty() {
            return;
        }
        self.busy(true);
        set_text(self.status, "Checking the selected backup copies…");
        let tx = self.sender.clone();
        let cancel = self.cancel.clone();
        thread::spawn(move || {
            let _ = tx.send(Event::BackupDeleteReview(backup_delete::prepare(
                &selected, &cancel,
            )));
        });
    }
    unsafe fn review_backup(&mut self) {
        if self.busy {
            return;
        }
        let selected = self.selected_backups();
        if selected.len() != 1 || selected[0].kind != "Registration export" {
            return;
        }
        let path = selected[0].manifest.clone();
        self.busy(true);
        let tx = self.sender.clone();
        thread::spawn(move || {
            let _ = tx.send(Event::SavedPreview(
                backup_delete::saved_application(&path).map(Box::new),
            ));
        });
    }
    unsafe fn preview(&mut self, app: Application) {
        if self.busy {
            return;
        }
        self.forced_plan = None;
        for (id, h) in &self.controls {
            if *id == CLEANUP {
                set_text(*h, "Clean checked");
            }
        }
        self.busy(true);
        set_text(
            self.status,
            &format!("Checking locations for {}…", app.name),
        );
        let tx = self.sender.clone();
        let cancel = self.cancel.clone();
        let apps = self.apps.clone();
        thread::spawn(move || {
            let _ = tx.send(Event::Preview(Box::new(scanner::scan(
                &app, &apps, &cancel,
            ))));
        });
    }
    unsafe fn show_preview(&mut self, report: ScanReport) {
        SendMessageW(self.candidates, LVM_DELETEALLITEMS, 0, 0);
        set_text(
            self.review_label,
            &format!(
                "{} · {} · {} locations",
                if self.forced_plan.is_some() {
                    "Forced removal review"
                } else {
                    "Leftover review"
                },
                report.app.name,
                report.candidates.len() + report.registry_candidates.len()
            ),
        );
        for (i, c) in report.candidates.iter().enumerate() {
            row(
                self.candidates,
                i as i32,
                &[
                    "Files".into(),
                    format!("{:?}", c.confidence),
                    records::display_path(&c.path.display().to_string()),
                    c.evidence.clone(),
                ],
            );
        }
        for (i, c) in report.registry_candidates.iter().enumerate() {
            row(
                self.candidates,
                (report.candidates.len() + i) as i32,
                &[
                    if self
                        .forced_plan
                        .as_ref()
                        .is_some_and(|p| i >= p.registration_start)
                    {
                        "App-list entry"
                    } else {
                        "Registry settings"
                    }
                    .into(),
                    format!("{:?}", c.confidence),
                    c.label(),
                    c.evidence.clone(),
                ],
            );
        }
        let note = if self.forced_plan.is_some() {
            "Forced removal runs no third-party uninstaller. Check exactly what to remove. Files move to quarantine; app-list entries are backed up and removed last."
        } else if report.app_registered {
            "Application is still registered. Previewed locations may contain active files. Cleanup is blocked until registration is removed."
        } else {
            "Checked High-confidence files are quarantined; registry keys are backed up before removal."
        };
        let errors = report.errors.join("\r\n");
        let count = report.candidates.len() + report.registry_candidates.len();
        let result = if report.cancelled {
            "Scan cancelled; these results may be incomplete.".to_string()
        } else if count == 0 && !report.errors.is_empty() {
            "The scan could not establish a complete result. Review the issues below.".to_string()
        } else if count == 0 {
            "No leftovers found in the supported scan locations. This is not a full-drive scan."
                .to_string()
        } else {
            format!(
                "Found {count} remaining location(s). High-confidence items can be checked for cleanup; Review and Blocked items need further ownership review."
            )
        };
        let context = self
            .preview_context
            .take()
            .map(|s| format!("{s}\r\n"))
            .unwrap_or_default();
        set_text(
            self.details,
            &format!("{context}{result}\r\n{note}\r\n{errors}"),
        );
        set_text(
            self.status,
            &format!(
                "{} location(s) · Preview: {} ms{}",
                count,
                report.elapsed_ms,
                if report.cancelled {
                    " · Cancelled; partial results"
                } else {
                    ""
                }
            ),
        );
        self.report = Some(report);
        self.update_actions();
    }
    unsafe fn removal_options(&mut self) {
        if self.busy {
            return;
        }
        let apps = self.selected_apps();
        let menu = CreatePopupMenu();
        AppendMenuW(
            menu,
            MF_STRING
                | if apps.len() == 1 && !apps[0].system_component {
                    0
                } else {
                    MF_GRAYED
                },
            FORCED_REVIEW_APP,
            wide(removal_caption(FORCED_REVIEW_APP).unwrap()).as_ptr(),
        );
        AppendMenuW(
            menu,
            MF_STRING,
            FORCED_FOLDER,
            wide(removal_caption(FORCED_FOLDER).unwrap()).as_ptr(),
        );
        AppendMenuW(menu, MF_SEPARATOR, 0, null());
        AppendMenuW(
            menu,
            MF_STRING
                | if !apps.is_empty()
                    && apps.iter().all(|a| {
                        !a.system_component
                            && if QUIET_SELECTED.with(|v| v.get()) {
                                !a.quiet_uninstall.trim().is_empty()
                            } else {
                                !a.uninstall.trim().is_empty()
                            }
                    })
                {
                    0
                } else {
                    MF_GRAYED
                },
            UNINSTALL_ADMIN,
            wide(removal_caption(UNINSTALL_ADMIN).unwrap()).as_ptr(),
        );
        AppendMenuW(
            menu,
            MF_STRING
                | if self.forced_plan.is_some() {
                    0
                } else {
                    MF_GRAYED
                },
            FORCED_ADMIN,
            wide(removal_caption(FORCED_ADMIN).unwrap()).as_ptr(),
        );
        AppendMenuW(menu, MF_SEPARATOR, 0, null());
        let msi = !apps.is_empty()
            && apps.iter().all(|a| {
                uninstall::prepare_mode(a, uninstall::Mode::ForcedMsi { quiet: false }).is_ok()
            });
        AppendMenuW(
            menu,
            MF_STRING | if msi { 0 } else { MF_GRAYED },
            FORCED_MSI_ACTION,
            wide(removal_caption(FORCED_MSI_ACTION).unwrap()).as_ptr(),
        );
        // Keep native menu strings for accessibility and keyboard navigation,
        // while drawing the rows in the same font and palette as the window.
        for id in [
            FORCED_REVIEW_APP,
            FORCED_FOLDER,
            UNINSTALL_ADMIN,
            FORCED_ADMIN,
            FORCED_MSI_ACTION,
        ] {
            let item = MENUITEMINFOW {
                cbSize: size_of::<MENUITEMINFOW>() as u32,
                fMask: MIIM_FTYPE,
                fType: MFT_OWNERDRAW,
                ..zeroed()
            };
            SetMenuItemInfoW(menu, id as u32, 0, &item);
        }
        let info = MENUINFO {
            cbSize: size_of::<MENUINFO>() as u32,
            fMask: MIM_BACKGROUND,
            hbrBack: self.surface_brush,
            ..zeroed()
        };
        SetMenuInfo(menu, &info);
        let mut rect: RECT = zeroed();
        if let Some((_, button)) = self.controls.iter().find(|(id, _)| *id == FORCED_MSI) {
            GetWindowRect(*button, &mut rect);
        }
        let action = TrackPopupMenu(
            menu,
            TPM_RETURNCMD | TPM_NONOTIFY | TPM_LEFTALIGN,
            rect.left,
            rect.bottom,
            0,
            self.hwnd,
            null(),
        );
        DestroyMenu(menu);
        match action as usize {
            FORCED_REVIEW_APP => {
                if let Some(app) = apps.first() {
                    self.force_preview(app.clone());
                }
            }
            FORCED_FOLDER => {
                if let Some(app) = crate::gui_force::choose_folder(self.hwnd) {
                    self.force_preview(app);
                }
            }
            FORCED_MSI_ACTION => self.launch_uninstall(true, false),
            UNINSTALL_ADMIN => self.launch_uninstall(false, true),
            FORCED_ADMIN => self.cleanup_forced(true),
            _ => {}
        }
    }
    unsafe fn selected_startup(&self) -> Option<startup::Entry> {
        if self.page != Page::Startup {
            return None;
        }
        let selected = selection(self.list);
        if selected.len() != 1 {
            return None;
        }
        self.visible
            .get(selected[0])
            .and_then(|&i| self.startup.get(i))
            .cloned()
    }
    unsafe fn update_startup_actions(&self) {
        let entry = self.selected_startup();
        for (id, control) in &self.controls {
            let enabled = match *id {
                STARTUP_DISABLE => entry
                    .as_ref()
                    .is_some_and(|e| e.mutable() && e.backup.is_none()),
                STARTUP_RESTORE => entry
                    .as_ref()
                    .is_some_and(|e| e.mutable() && e.backup.is_some()),
                STARTUP_MORE => entry.is_some() || self.startup_target.is_some(),
                _ => continue,
            };
            EnableWindow(*control, (!self.busy && enabled) as i32);
        }
    }
    unsafe fn startup_options(&mut self) {
        let entry = self.selected_startup();
        if self.busy {
            return;
        }
        let menu = CreatePopupMenu();
        for (id, enabled) in [
            (
                STARTUP_DISABLE_ADMIN,
                entry
                    .as_ref()
                    .is_some_and(|e| e.mutable() && e.backup.is_none()),
            ),
            (
                STARTUP_RESTORE_ADMIN,
                entry
                    .as_ref()
                    .is_some_and(|e| e.mutable() && e.backup.is_some()),
            ),
            (STARTUP_SHOW_ALL, self.startup_target.is_some()),
        ] {
            AppendMenuW(
                menu,
                MF_STRING | if enabled { 0 } else { MF_GRAYED },
                id,
                wide(removal_caption(id).unwrap()).as_ptr(),
            );
            let item = MENUITEMINFOW {
                cbSize: size_of::<MENUITEMINFOW>() as u32,
                fMask: MIIM_FTYPE,
                fType: MFT_OWNERDRAW,
                ..zeroed()
            };
            SetMenuItemInfoW(menu, id as u32, 0, &item);
        }
        let info = MENUINFO {
            cbSize: size_of::<MENUINFO>() as u32,
            fMask: MIM_BACKGROUND,
            hbrBack: self.surface_brush,
            ..zeroed()
        };
        SetMenuInfo(menu, &info);
        let mut rect: RECT = zeroed();
        if let Some((_, button)) = self.controls.iter().find(|(id, _)| *id == STARTUP_MORE) {
            GetWindowRect(*button, &mut rect);
        }
        let action = TrackPopupMenu(
            menu,
            TPM_RETURNCMD | TPM_NONOTIFY,
            rect.left,
            rect.bottom,
            0,
            self.hwnd,
            null(),
        );
        DestroyMenu(menu);
        match action as usize {
            STARTUP_DISABLE_ADMIN => self.startup_change(startup::Change::Disable, true),
            STARTUP_RESTORE_ADMIN => self.startup_change(startup::Change::Restore, true),
            STARTUP_SHOW_ALL => self.show_page(Page::Startup),
            _ => {}
        }
    }
    unsafe fn startup_change(&mut self, change: startup::Change, administrator: bool) {
        if self.busy {
            return;
        }
        let Some(entry) = self.selected_startup() else {
            return;
        };
        let operation = if administrator {
            match Operation::startup(&entry, change) {
                Ok(o) => Some(o),
                Err(e) => {
                    set_text(self.details, &e);
                    return;
                }
            }
        } else {
            None
        };
        let question = match change {
            startup::Change::Disable => {
                "Disable this exact startup source? Its original data is saved first. Programs already running will continue."
            }
            startup::Change::Restore => {
                "Restore this saved startup source? It may start the program at the next Windows sign-in. An occupied source is refused."
            }
        };
        if message(
            self.hwnd,
            &format!(
                "{question}\r\n\r\n{}{}\r\n\r\nOther software can change startup sources. Refresh to verify the final status.",
                entry.details(),
                if administrator {
                    "\r\nWindows will ask for administrator access."
                } else {
                    ""
                }
            ),
            "Review startup change",
            MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING,
        ) != IDYES
        {
            return;
        }
        self.busy(true);
        set_text(
            self.status,
            "Backing up and changing the reviewed startup source…",
        );
        let tx = self.sender.clone();
        let cancel = self.cancel.clone();
        thread::spawn(move || {
            let result = match operation {
                Some(o) => client::invoke(o, &cancel).and_then(|reply| match reply {
                    Reply::Startup(out) => Ok(out),
                    _ => Err("Administrator component returned another operation".into()),
                }),
                None => startup::change(&entry, change, &cancel),
            };
            let text = match result {
                Ok(out) => format!(
                    "{}: {}\r\n{}\r\nBackup: {}",
                    out.name,
                    out.state,
                    out.message,
                    out.backup.display()
                ),
                Err(e) => format!("Startup change did not complete: {e}"),
            };
            let _ = tx.send(Event::StartupChanged(text));
        });
    }
    unsafe fn begin_hunter(&mut self) {
        if self.busy || self.page != Page::Applications {
            return;
        }
        let menu = CreatePopupMenu();
        for id in [HUNTER_DRAG, HUNTER_CHOOSE] {
            AppendMenuW(
                menu,
                MF_STRING,
                id,
                wide(removal_caption(id).unwrap()).as_ptr(),
            );
            let item = MENUITEMINFOW {
                cbSize: size_of::<MENUITEMINFOW>() as u32,
                fMask: MIIM_FTYPE,
                fType: MFT_OWNERDRAW,
                ..zeroed()
            };
            SetMenuItemInfoW(menu, id as u32, 0, &item);
        }
        let info = MENUINFO {
            cbSize: size_of::<MENUINFO>() as u32,
            fMask: MIM_BACKGROUND,
            hbrBack: self.surface_brush,
            ..zeroed()
        };
        SetMenuInfo(menu, &info);
        let mut rect: RECT = zeroed();
        if let Some((_, button)) = self.controls.iter().find(|(id, _)| *id == HUNTER) {
            GetWindowRect(*button, &mut rect);
        }
        let action = TrackPopupMenu(
            menu,
            TPM_RETURNCMD | TPM_NONOTIFY,
            rect.left,
            rect.bottom,
            0,
            self.hwnd,
            null(),
        );
        DestroyMenu(menu);
        if action as usize == HUNTER_CHOOSE {
            if let Some((window, pid)) = crate::gui_hunter_choose::choose(self.hwnd) {
                self.busy(true);
                self.hunter_target(window, pid);
            }
            return;
        }
        if action as usize != HUNTER_DRAG {
            return;
        }
        self.busy(true);
        match crate::gui_hunter::open(self.hwnd) {
            Ok(tile) => {
                self.hunter_tile = Some(tile);
                ShowWindow(self.hwnd, SW_MINIMIZE);
                set_text(
                    self.status,
                    "Drag the Hunter target onto an application's open window. Escape or right-click cancels.",
                );
            }
            Err(error) => {
                self.busy(false);
                set_text(self.details, &error);
            }
        }
    }
    unsafe fn hunter_target(&mut self, window: usize, pid: u32) {
        self.hunter_tile = None;
        if window == 0 || pid == 0 {
            self.busy(false);
            set_text(self.status, "Hunter cancelled. No application was changed.");
            return;
        }
        set_text(
            self.status,
            "Identifying the selected window and matching its application…",
        );
        let tx = self.sender.clone();
        let cancel = self.cancel.clone();
        thread::spawn(move || {
            let _ = tx.send(Event::Hunter(
                hunter::inspect_window(window, pid, &cancel).map(Box::new),
            ));
        });
    }
    unsafe fn hunter_review(&mut self, report: hunter::Report) {
        set_text(self.details, &report.details());
        if report.cancelled {
            set_text(self.status, "Hunter cancelled. No application was changed.");
            return;
        }
        let found = report.unique_application();
        set_text(
            self.status,
            if found.is_some() {
                "Hunter identified a candidate. Review its executable and application match before acting."
            } else {
                "Hunter identified the process; application attribution needs review."
            },
        );
        if message(
            self.hwnd,
            &report.details(),
            "Hunter target review",
            MB_OKCANCEL | MB_ICONINFORMATION,
        ) != IDOK
        {
            return;
        }
        let menu = CreatePopupMenu();
        for (id, enabled) in [
            (HUNTER_APP, found.is_some()),
            (
                HUNTER_FORCE,
                found.is_some()
                    || (report.matches.is_empty() && report.inventory_errors.is_empty()),
            ),
            (HUNTER_FOLDER, true),
            (HUNTER_PROPERTIES, true),
            (HUNTER_STARTUP, true),
            (HUNTER_STOP, true),
        ] {
            AppendMenuW(
                menu,
                MF_STRING | if enabled { 0 } else { MF_GRAYED },
                id,
                wide(removal_caption(id).unwrap()).as_ptr(),
            );
            let item = MENUITEMINFOW {
                cbSize: size_of::<MENUITEMINFOW>() as u32,
                fMask: MIIM_FTYPE,
                fType: MFT_OWNERDRAW,
                ..zeroed()
            };
            SetMenuItemInfoW(menu, id as u32, 0, &item);
        }
        let info = MENUINFO {
            cbSize: size_of::<MENUINFO>() as u32,
            fMask: MIM_BACKGROUND,
            hbrBack: self.surface_brush,
            ..zeroed()
        };
        SetMenuInfo(menu, &info);
        let mut point: POINT = zeroed();
        GetCursorPos(&mut point);
        let action = TrackPopupMenu(
            menu,
            TPM_RETURNCMD | TPM_NONOTIFY | TPM_LEFTALIGN,
            point.x,
            point.y,
            0,
            self.hwnd,
            null(),
        );
        DestroyMenu(menu);
        match action as usize {
            HUNTER_FORCE => {
                if let Some(app) = found {
                    self.force_preview(app.clone());
                } else if report.matches.is_empty() && report.inventory_errors.is_empty() {
                    let Some(folder) = report.peer.image.parent() else {
                        return;
                    };
                    let folder = std::path::PathBuf::from(records::display_path(
                        &folder.display().to_string(),
                    ));
                    let name = report
                        .peer
                        .image
                        .file_stem()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .chars()
                        .take(160)
                        .collect::<String>();
                    if message(
                        self.hwnd,
                        &format!(
                            "Review this unregistered program's executable folder?\r\n\r\n{}\r\n\r\nThe folder can contain shared files or user data. Nothing is removed during review; choose exact supported items and confirm separately.",
                            folder.display()
                        ),
                        "Review Hunter folder",
                        MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING,
                    ) != IDYES
                    {
                        return;
                    }
                    match forced::folder_target(&format!("{name} (window target)"), &folder) {
                        Ok(app) => self.force_preview(app),
                        Err(error) => set_text(self.details, &error),
                    }
                }
            }
            HUNTER_STARTUP => {
                if let Err(error) = hunter::validate(&report.peer) {
                    set_text(self.details, &error);
                    return;
                }
                self.show_page_with_target(Page::Startup, Some(report.peer.image.clone()));
                set_text(
                    self.subtitle,
                    "Startup sources matching the Hunter target · Startup actions shows all entries",
                );
                self.record_result = Some(format!(
                    "Hunter target: {}\r\nOnly saved launch targets matching this exact executable are shown. Shared commands remain separate entries for individual review. No startup source has changed.\r\n\r\nShell launchers, unresolved links, services, tasks, and Windows approval may provide other startup routes. Use Startup actions → Show all startup entries to inspect the complete supported list.",
                    records::display_path(&report.peer.image.display().to_string())
                ));
            }
            HUNTER_APP => {
                if let Some(app) = found {
                    // This selection grants no execution permission. Normal/forced
                    // actions continue through their existing fresh review gates.
                    if let Some(existing) = self.apps.iter_mut().find(|a| a.id == app.id) {
                        *existing = app.clone();
                    } else {
                        self.apps.push(app.clone());
                    }
                    set_text(self.search, "");
                    self.fill_apps();
                    if let Some(row) = self.visible.iter().position(|&i| self.apps[i].id == app.id)
                    {
                        let item = LVITEMW {
                            stateMask: LVIS_SELECTED | LVIS_FOCUSED,
                            state: LVIS_SELECTED | LVIS_FOCUSED,
                            ..zeroed()
                        };
                        SendMessageW(self.list, LVM_SETITEMSTATE, row, &item as *const _ as isize);
                        SendMessageW(self.list, LVM_ENSUREVISIBLE, row, 0);
                        self.update_actions();
                    }
                    set_text(self.details, &report.details());
                    set_text(
                        self.status,
                        "Matched application selected. Choose Preview or More removal to review an action.",
                    );
                }
            }
            HUNTER_FOLDER | HUNTER_PROPERTIES => {
                if let Err(error) = hunter::validate(&report.peer) {
                    set_text(self.details, &error);
                    return;
                }
                let path = if action as usize == HUNTER_FOLDER {
                    report.peer.image.parent().unwrap()
                } else {
                    &report.peer.image
                };
                let path = wide(&records::display_path(&path.display().to_string()));
                let verb = wide(if action as usize == HUNTER_FOLDER {
                    "open"
                } else {
                    "properties"
                });
                let mut info: windows_sys::Win32::UI::Shell::SHELLEXECUTEINFOW = zeroed();
                info.cbSize = size_of_val(&info) as u32;
                info.fMask = windows_sys::Win32::UI::Shell::SEE_MASK_INVOKEIDLIST
                    | windows_sys::Win32::UI::Shell::SEE_MASK_NOASYNC;
                info.hwnd = self.hwnd;
                info.lpVerb = verb.as_ptr();
                info.lpFile = path.as_ptr();
                info.nShow = SW_SHOWNORMAL;
                if windows_sys::Win32::UI::Shell::ShellExecuteExW(&mut info) == 0 {
                    set_text(
                        self.details,
                        &format!(
                            "Windows could not open the selected item ({})",
                            GetLastError()
                        ),
                    );
                }
            }
            HUNTER_STOP => {
                if message(
                    self.hwnd,
                    &format!(
                        "Stop this exact process? Unsaved work may be lost. Other processes and files will remain unchanged.\r\n\r\nProcess {}\r\n{}",
                        report.peer.pid,
                        records::display_path(&report.peer.image.display().to_string())
                    ),
                    "Review process stop",
                    MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING,
                ) != IDYES
                {
                    return;
                }
                self.busy(true);
                let tx = self.sender.clone();
                thread::spawn(move || {
                    let text = match hunter::stop(&report.peer) {
                        Ok(()) => {
                            let detail = format!(
                                "Stopped process {}: {}",
                                report.peer.pid,
                                records::display_path(&report.peer.image.display().to_string())
                            );
                            match recovery::history("hunter-stop", &report.window_title, &detail) {
                                Ok(()) => detail,
                                Err(error) => {
                                    format!("{detail}\r\nHistory could not be saved: {error}")
                                }
                            }
                        }
                        Err(error) => format!("Process was not confirmed stopped: {error}"),
                    };
                    let _ = tx.send(Event::Finished(text));
                });
            }
            _ => {}
        }
    }
    unsafe fn force_preview(&mut self, app: Application) {
        if self.busy {
            return;
        }
        self.report = None;
        self.forced_plan = None;
        SendMessageW(self.candidates, LVM_DELETEALLITEMS, 0, 0);
        self.busy(true);
        set_text(
            self.status,
            &format!("Reviewing forced removal for {}…", app.name),
        );
        let tx = self.sender.clone();
        let cancel = self.cancel.clone();
        thread::spawn(move || {
            let _ = tx.send(Event::ForcedPlan(
                forced::preview(&app, &cancel).map(Box::new),
            ));
        });
    }
    unsafe fn cleanup_forced(&mut self, administrator: bool) {
        let Some(plan) = self.forced_plan.clone() else {
            return;
        };
        let is_checked = |i| {
            SendMessageW(
                self.candidates,
                LVM_GETITEMSTATE,
                i,
                LVIS_STATEIMAGEMASK as isize,
            ) & 0x3000
                == 0x2000
        };
        let selection = forced::Selection {
            files: (0..plan.report.candidates.len())
                .filter(|&i| is_checked(i))
                .collect(),
            registry: (0..plan.report.registry_candidates.len())
                .filter(|&i| is_checked(plan.report.candidates.len() + i))
                .collect(),
        };
        if selection.files.is_empty() && selection.registry.is_empty() {
            message(
                self.hwnd,
                "Check the exact items you want to remove.",
                "Forced removal review",
                MB_OK,
            );
            return;
        }
        if selection
            .files
            .iter()
            .any(|&i| plan.report.candidates[i].confidence != Confidence::High)
            || selection
                .registry
                .iter()
                .any(|&i| plan.report.registry_candidates[i].confidence != Confidence::High)
        {
            message(
                self.hwnd,
                "A checked item is blocked or still needs ownership review. Close running applications, then review again.",
                "Forced removal blocked",
                MB_OK | MB_ICONWARNING,
            );
            return;
        }
        let operation = if administrator {
            match Operation::forced(&plan, &selection) {
                Ok(operation) => Some(operation),
                Err(error) => {
                    message(self.hwnd, &error, "Review changed", MB_OK | MB_ICONWARNING);
                    return;
                }
            }
        } else {
            None
        };
        let labels = selection
            .files
            .iter()
            .map(|&i| plan.report.candidates[i].path.display().to_string())
            .chain(
                selection
                    .registry
                    .iter()
                    .map(|&i| plan.report.registry_candidates[i].label()),
            )
            .collect::<Vec<_>>()
            .join("\r\n");
        if message(
            self.hwnd,
            &format!(
                "Remove these checked items for {} without running its uninstaller?\r\n\r\nFiles move to quarantine. Registry entries are backed up. Checked app-list entries are removed last, only after the selected cleanup succeeds.{}\r\n\r\n{}",
                plan.report.app.name,
                if administrator {
                    "\r\nWindows will ask for administrator access for this operation."
                } else {
                    ""
                },
                labels
            ),
            "Review forced removal",
            MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING,
        ) != IDYES
        {
            return;
        }
        self.forced_plan = None;
        self.report = None;
        SendMessageW(self.candidates, LVM_DELETEALLITEMS, 0, 0);
        self.refresh_after_result = true;
        self.busy(true);
        set_text(self.status, "Backing up and removing reviewed items…");
        let tx = self.sender.clone();
        let cancel = self.cancel.clone();
        thread::spawn(move || {
            let result = match operation {
                Some(operation) => {
                    client::invoke(operation, &cancel).and_then(|reply| match reply {
                        Reply::Forced(outcome) => Ok(outcome),
                        _ => Err("Administrator component returned a different operation".into()),
                    })
                }
                None => forced::execute(&plan, &selection, &cancel),
            };
            let text = match result {
                Ok(outcome) => format!(
                    "{}\r\n{}",
                    outcome.status,
                    outcome
                        .items
                        .iter()
                        .map(|item| format!(
                            "{}: {} — {}{}",
                            item.label,
                            item.state,
                            item.message,
                            item.backup
                                .as_ref()
                                .map(|p| format!("\r\nBackup: {}", p.display()))
                                .unwrap_or_default()
                        ))
                        .collect::<Vec<_>>()
                        .join("\r\n")
                ),
                Err(e) => format!(
                    "Forced removal did not complete: {e}\r\nReview backups before retrying."
                ),
            };
            let _ = tx.send(Event::Finished(text));
        });
    }
    unsafe fn launch_uninstall(&mut self, forced: bool, administrator: bool) {
        if self.busy {
            return;
        }
        let apps = self.selected_apps();
        if apps.is_empty() {
            message(
                self.hwnd,
                "Select one or more applications. Use Ctrl or Shift for a batch.",
                "Uninstall",
                MB_OK,
            );
            return;
        }
        let quiet = QUIET_SELECTED.with(|v| v.get());
        let mode = if forced {
            uninstall::Mode::ForcedMsi { quiet }
        } else if quiet {
            uninstall::Mode::Quiet
        } else {
            uninstall::Mode::Normal
        };
        let mut commands = String::new();
        let mut operations = Vec::new();
        for a in &apps {
            match uninstall::prepare_mode(a, mode) {
                Ok(c) => commands.push_str(&format!("{}\r\n{}\r\n\r\n", a.name, c.original)),
                Err(e) => {
                    message(
                        self.hwnd,
                        &format!("{}: {e}", a.name),
                        "Command needs review",
                        MB_OK | MB_ICONWARNING,
                    );
                    return;
                }
            }
            let operation = if administrator {
                match Operation::uninstall(a, mode) {
                    Ok(operation) => Some(operation),
                    Err(error) => {
                        message(
                            self.hwnd,
                            &format!("{}: {error}", a.name),
                            "Administrator review",
                            MB_OK | MB_ICONWARNING,
                        );
                        return;
                    }
                }
            } else {
                None
            };
            operations.push(operation);
        }
        set_text(self.details, &commands);
        if message(
            self.hwnd,
            &format!(
                "Start uninstalling {} selected application(s)?\r\n\r\n{}\r\nRegistry registration backups are saved first. {} Cancelling stops the queue; an uninstaller already running will continue.",
                apps.len(),
                commands,
                if administrator {
                    "Windows will ask for administrator access for each application."
                } else {
                    "Each application's own uninstaller may request elevation or interaction."
                }
            ),
            "Review uninstall commands",
            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2,
        ) != IDYES
        {
            return;
        }
        self.report = None;
        self.forced_plan = None;
        SendMessageW(self.candidates, LVM_DELETEALLITEMS, 0, 0);
        self.busy(true);
        let tx = self.sender.clone();
        let cancel = self.cancel.clone();
        thread::spawn(move || {
            let mut done = Vec::new();
            let mut summary = Vec::new();
            for (app, operation) in apps.into_iter().zip(operations) {
                if cancelled(&cancel) {
                    break;
                }
                let _ = tx.send(Event::Progress(format!("Uninstalling {}…", app.name)));
                let result = match operation {
                    Some(operation) => {
                        client::invoke(operation, &cancel).and_then(|reply| match reply {
                            Reply::Uninstall(outcome) => Ok(outcome),
                            _ => {
                                Err("Administrator component returned a different operation".into())
                            }
                        })
                    }
                    None => uninstall::run_mode(&app, mode, &cancel),
                };
                match result {
                    Ok(out) => {
                        // Only a revalidated attempt may seed a leftover preview.
                        done.push(app.clone());
                        summary.push(format!("{}: {}", app.name, out.status));
                        if !out.safe_to_scan {
                            break;
                        }
                    }
                    Err(e) => {
                        summary.push(format!("{}: {e}", app.name));
                        break;
                    }
                }
            }
            let _ = tx.send(Event::Uninstalled(done, summary.join("\r\n")));
        });
    }
    unsafe fn cleanup(&mut self) {
        if self.busy {
            return;
        }
        if self.forced_plan.is_some() {
            self.cleanup_forced(false);
            return;
        }
        let Some(report) = &self.report else {
            return;
        };
        let checked = report
            .candidates
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                SendMessageW(
                    self.candidates,
                    LVM_GETITEMSTATE,
                    *i,
                    LVIS_STATEIMAGEMASK as isize,
                ) & 0x3000
                    == 0x2000
            })
            .map(|(_, c)| c.clone())
            .collect::<Vec<_>>();
        let registry_checked = report
            .registry_candidates
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                SendMessageW(
                    self.candidates,
                    LVM_GETITEMSTATE,
                    report.candidates.len() + *i,
                    LVIS_STATEIMAGEMASK as isize,
                ) & 0x3000
                    == 0x2000
            })
            .map(|(_, c)| c.clone())
            .collect::<Vec<_>>();
        if checked.is_empty() && registry_checked.is_empty() {
            message(
                self.hwnd,
                "Check the locations you want to quarantine.",
                "Cleanup",
                MB_OK,
            );
            return;
        }
        if report.app_registered
            || checked.iter().any(|c| c.confidence != Confidence::High)
            || registry_checked
                .iter()
                .any(|c| c.confidence != Confidence::High)
        {
            message(
                self.hwnd,
                "Only high-confidence leftovers of an unregistered application can be quarantined. Active, shared, and name-only locations are excluded.",
                "Cleanup blocked",
                MB_OK | MB_ICONWARNING,
            );
            return;
        }
        if message(
            self.hwnd,
            &format!(
                "Back up and clean these selected locations? Files move to quarantine; registry keys are removed after backup.\r\n\r\n{}",
                checked
                    .iter()
                    .map(|c| c.path.display().to_string())
                    .chain(registry_checked.iter().map(|c| c.label()))
                    .collect::<Vec<_>>()
                    .join("\r\n")
            ),
            "Review cleanup",
            MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING,
        ) != IDYES
        {
            return;
        }
        let app = report.app.clone();
        self.busy(true);
        let cancel = self.cancel.clone();
        let tx = self.sender.clone();
        thread::spawn(move || {
            let mut messages = Vec::new();
            for c in checked {
                if cancelled(&cancel) {
                    break;
                }
                messages.push(match recovery::quarantine(&app, &c, &cancel) {
                    Ok(p) => format!("Quarantined {}. Backup: {}", c.path.display(), p.display()),
                    Err(e) => format!("{}: {e}", c.path.display()),
                });
            }
            for c in registry_checked {
                if cancelled(&cancel) {
                    break;
                }
                messages.push(match unbolt::registry_cleanup::cleanup(&app, &c, &cancel) {
                    Ok(p) => format!(
                        "Removed registry key {}. Backup: {}",
                        c.label(),
                        p.display()
                    ),
                    Err(e) => format!("{}: {e}", c.label()),
                });
            }
            let _ = tx.send(Event::Finished(messages.join("\r\n")));
        });
    }
    unsafe fn restore(&mut self) {
        if self.busy {
            return;
        }
        if self.page != Page::Backups {
            self.show_page(Page::Backups);
            return;
        }
        let selected = selection(self.list)
            .first()
            .and_then(|i| self.visible.get(*i))
            .and_then(|i| self.backups.get(*i));
        let Some(backup) = selected else {
            message(
                self.hwnd,
                "Select the backup you want to restore.",
                "Restore",
                MB_OK,
            );
            return;
        };
        if !backup.recoverable {
            message(
                self.hwnd,
                "This item is an export, is already restored, or needs recovery review. Open its folder to inspect the saved data.",
                "Backup needs review",
                MB_OK,
            );
            return;
        }
        let path = backup.manifest.clone();
        if recovery::manifest_description(&path).is_none() {
            message(
                self.hwnd,
                "No recoverable quarantined items found.",
                "Restore",
                MB_OK,
            );
            return;
        }
        let description = recovery::manifest_description(&path).unwrap_or_default();
        if message(
            self.hwnd,
            &format!(
                "Restore this selected backup?\r\n\r\n{description}\r\n\r\nExisting destination content will not be overwritten."
            ),
            "Review restore",
            MB_YESNO | MB_DEFBUTTON2,
        ) != IDYES
        {
            return;
        }
        self.busy(true);
        let tx = self.sender.clone();
        thread::spawn(move || {
            let result = match recovery::restore(&path) {
                Ok(_) => "Restored successfully.".into(),
                Err(e) => e,
            };
            let _ = tx.send(Event::Finished(result));
        });
    }
    unsafe fn poll(&mut self) {
        while let Ok(event) = self.receiver.try_recv() {
            match event {
                Event::Backups(result) => {
                    self.busy(false);
                    match result {
                        Ok(page) => {
                            self.backups = page.records;
                            self.fill_records();
                            set_text(self.details, &{
                                let mut result=self.record_result.take().unwrap_or_else(||"Select a backup to see its original location and recovery status.".into());
                                if !page.errors.is_empty() {
                                    result.push_str("\r\n");
                                    result.push_str(&page.errors.join("\r\n"));
                                }
                                result
                            });
                        }
                        Err(e) => set_text(self.details, &e),
                    }
                }
                Event::History(result) => {
                    self.busy(false);
                    match result {
                        Ok(page) => {
                            self.history = page.records;
                            self.fill_records();
                            set_text(
                                self.details,
                                &if page.errors.is_empty() {
                                    self.record_result.take().unwrap_or_else(|| "Select an operation to inspect the complete result. Select Pending uninstall or Uninstall result to review after restarting Windows. Pending entries are discovered from saved sessions even when their history entry is missing.".into())
                                } else {
                                    page.errors.join("\r\n")
                                },
                            );
                        }
                        Err(e) => set_text(self.details, &e),
                    }
                }
                Event::Hunter(result) => {
                    self.busy(false);
                    match result {
                        Ok(report) => self.hunter_review(*report),
                        Err(error) => {
                            set_text(self.details, &error);
                            set_text(
                                self.status,
                                "Hunter could not identify this window. No application was changed.",
                            );
                        }
                    }
                }
                Event::Startup(page) => {
                    self.busy(false);
                    self.startup = page.records;
                    self.fill_records();
                    self.update_startup_actions();
                    let mut text=self.record_result.take().unwrap_or_else(||"Configured sources may still be blocked by Windows startup approval. Select an item to see its exact command and location. Services and scheduled tasks are not yet included.".into());
                    if !page.errors.is_empty() {
                        text.push_str("\r\nCoverage issues:\r\n");
                        text.push_str(&page.errors.join("\r\n"));
                    }
                    set_text(self.details, &text);
                }
                Event::StartupChanged(text) => {
                    self.busy(false);
                    self.record_result = Some(text);
                    self.refresh();
                }
                Event::Inventory(data) => {
                    self.busy(false);
                    self.apps = data.apps;
                    self.fill_apps();
                    set_text(
                        self.details,
                        &format!(
                            "{}Inventory: {} ms · {} applications · {} read errors{}\r\n{}",
                            self.record_result
                                .take()
                                .map(|s| format!("{s}\r\n"))
                                .unwrap_or_default(),
                            data.elapsed_ms,
                            self.apps.len(),
                            data.errors.len(),
                            if data.cancelled {
                                " · Cancelled / partial"
                            } else {
                                ""
                            },
                            data.errors.join("\r\n")
                        ),
                    );
                    if let Some(app) = self.pending_preview.take() {
                        self.preview(app);
                    }
                }
                Event::SavedPreview(result) => {
                    self.busy(false);
                    match result {
                        Ok(app) => {
                            self.pending_preview = Some(*app);
                            self.show_page(Page::Applications);
                        }
                        Err(error) => set_text(self.details, &error),
                    }
                }
                Event::SessionReview(result) => {
                    self.busy(false);
                    match result {
                        Ok(plan) => {
                            if message(
                                self.hwnd,
                                &plan.description(),
                                "Review pending uninstall",
                                MB_YESNO | MB_DEFBUTTON2 | MB_ICONQUESTION,
                            ) == IDYES
                            {
                                self.busy(true);
                                self.refresh_after_result = true;
                                let tx = self.sender.clone();
                                let cancel = self.cancel.clone();
                                thread::spawn(move || {
                                    let result = plan.execute(&cancel).unwrap_or_else(|e| e);
                                    let _ = tx.send(Event::Finished(result));
                                });
                            } else {
                                set_text(
                                    self.status,
                                    "Uninstall review cancelled. The session was not changed.",
                                );
                            }
                        }
                        Err(error) => set_text(self.details, &error),
                    }
                }
                Event::BackupDeleteReview(result) => {
                    self.busy(false);
                    match result {
                        Ok(plan) => {
                            if message(
                                self.hwnd,
                                &plan.description(),
                                "Permanently delete selected backups",
                                MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING,
                            ) == IDYES
                            {
                                self.busy(true);
                                let tx = self.sender.clone();
                                let cancel = self.cancel.clone();
                                thread::spawn(move || {
                                    let result = plan.execute(&cancel).unwrap_or_else(|e| e);
                                    let _ = tx.send(Event::Finished(result));
                                });
                            } else {
                                set_text(
                                    self.status,
                                    "Backup deletion cancelled. Nothing was deleted.",
                                );
                            }
                        }
                        Err(error) => {
                            set_text(self.details, &error);
                            set_text(
                                self.status,
                                "Backup deletion could not start. Nothing was deleted.",
                            );
                        }
                    }
                }
                Event::Preview(report) => {
                    self.busy(false);
                    self.show_preview(*report);
                }
                Event::ForcedPlan(result) => {
                    self.busy(false);
                    match result {
                        Ok(plan) => {
                            let report = plan.report.clone();
                            self.forced_plan = Some(*plan);
                            for (id, h) in &self.controls {
                                if *id == CLEANUP {
                                    set_text(*h, "Remove checked");
                                }
                            }
                            self.show_preview(report);
                        }
                        Err(e) => {
                            set_text(self.details, &e);
                            set_text(self.status, "Forced removal needs review.");
                        }
                    }
                }
                Event::Progress(text) => set_text(self.status, &text),
                Event::Finished(text) => {
                    self.busy(false);
                    set_text(self.details, &text);
                    set_text(self.status, "Operation finished. Review the result above.");
                    if self.page == Page::Backups || self.refresh_after_result {
                        self.refresh_after_result = false;
                        self.record_result = Some(text);
                        self.refresh();
                    }
                }
                Event::Uninstalled(apps, text) => {
                    self.busy(false);
                    set_text(self.details, &text);
                    set_text(
                        self.status,
                        if apps.is_empty() {
                            "Queue stopped. Review the result above before continuing."
                        } else {
                            "Uninstall attempt finished; reviewing remaining locations."
                        },
                    );
                    if let Some(app) = apps.last() {
                        self.preview(app.clone());
                        self.preview_context = Some(text);
                    }
                }
            }
        }
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if msg == WM_MEASUREITEM && lparam != 0 {
        let item = &mut *(lparam as *mut MEASUREITEMSTRUCT);
        if item.CtlType == ODT_MENU
            && let Some(caption) = removal_caption(item.itemID as usize)
        {
            let dpi = GetDpiForWindow(hwnd).max(96);
            let dc = GetDC(hwnd);
            let font = ui_font(dpi, false);
            let old = SelectObject(dc, font);
            let text = wide(caption);
            let mut size: SIZE = zeroed();
            GetTextExtentPoint32W(dc, text.as_ptr(), (text.len() - 1) as i32, &mut size);
            SelectObject(dc, old);
            DeleteObject(font);
            ReleaseDC(hwnd, dc);
            item.itemWidth = (size.cx + scale(36, dpi)).max(scale(320, dpi)) as u32;
            item.itemHeight = scale(36, dpi) as u32;
            return 1;
        }
    }
    if msg == WM_DRAWITEM {
        let item = &*(lparam as *const DRAWITEMSTRUCT);
        if item.CtlType == ODT_MENU
            && let Some(caption) = removal_caption(item.itemID as usize)
        {
            let dark = DRAW_STYLE.with(|s| s.get().0);
            let colors = palette(dark);
            let disabled = item.itemState & (ODS_DISABLED | ODS_GRAYED) != 0;
            let selected = !disabled && item.itemState & ODS_SELECTED != 0;
            let brush = CreateSolidBrush(if selected {
                colors.accent
            } else {
                colors.surface
            });
            FillRect(item.hDC, &item.rcItem, brush);
            DeleteObject(brush);
            let font = ui_font(GetDpiForWindow(hwnd).max(96), false);
            let old = SelectObject(item.hDC, font);
            SetBkMode(item.hDC, TRANSPARENT as i32);
            SetTextColor(
                item.hDC,
                if disabled {
                    colors.muted
                } else if selected {
                    if dark {
                        rgb(20, 32, 42)
                    } else {
                        rgb(255, 255, 255)
                    }
                } else {
                    colors.text
                },
            );
            let mut rect = item.rcItem;
            rect.left += scale(12, GetDpiForWindow(hwnd).max(96));
            DrawTextW(
                item.hDC,
                wide(caption).as_ptr(),
                -1,
                &mut rect,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX,
            );
            SelectObject(item.hDC, old);
            DeleteObject(font);
            return 1;
        }
        if item.CtlType == ODT_BUTTON {
            return DRAW_STYLE.with(|style| {
                let (dark, _, _) = style.get();
                let colors = palette(dark);
                let primary = matches!(item.CtlID as usize, UNINSTALL | CLEANUP)
                    || ACTIVE_NAV.with(|s| s.get() == item.CtlID as usize);
                let disabled = item.itemState & ODS_DISABLED != 0;
                let background = if primary && !disabled {
                    colors.accent
                } else {
                    colors.surface
                };
                let foreground = if disabled {
                    colors.muted
                } else if primary {
                    if dark {
                        rgb(20, 32, 42)
                    } else {
                        rgb(255, 255, 255)
                    }
                } else {
                    colors.text
                };
                let brush = CreateSolidBrush(background);
                let base = CreateSolidBrush(colors.background);
                FillRect(item.hDC, &item.rcItem, base);
                DeleteObject(base);
                let old_brush = SelectObject(item.hDC, brush);
                let old_pen = SelectObject(item.hDC, GetStockObject(NULL_PEN));
                let radius = scale(8, GetDpiForWindow(item.hwndItem).max(96));
                RoundRect(
                    item.hDC,
                    item.rcItem.left,
                    item.rcItem.top,
                    item.rcItem.right,
                    item.rcItem.bottom,
                    radius,
                    radius,
                );
                SelectObject(item.hDC, old_pen);
                SelectObject(item.hDC, old_brush);
                DeleteObject(brush);
                let font = SendMessageW(item.hwndItem, WM_GETFONT, 0, 0);
                let old_font = if font != 0 {
                    SelectObject(item.hDC, font as HGDIOBJ)
                } else {
                    null_mut()
                };
                SetBkMode(item.hDC, TRANSPARENT as i32);
                SetTextColor(item.hDC, foreground);
                let text = if item.CtlID as usize == QUIET {
                    format!(
                        "{} Quiet uninstall",
                        if QUIET_SELECTED.with(|v| v.get()) {
                            "☑"
                        } else {
                            "☐"
                        }
                    )
                } else {
                    get_text(item.hwndItem)
                };
                let mut rect = item.rcItem;
                DrawTextW(
                    item.hDC,
                    wide(&text).as_ptr(),
                    -1,
                    &mut rect,
                    DT_CENTER | DT_VCENTER | DT_SINGLELINE,
                );
                if item.itemState & ODS_FOCUS != 0 {
                    InflateRect(&mut rect, -3, -3);
                    DrawFocusRect(item.hDC, &rect);
                }
                if !old_font.is_null() {
                    SelectObject(item.hDC, old_font);
                }
                1
            });
        }
    }
    if matches!(msg, WM_CTLCOLORSTATIC | WM_CTLCOLOREDIT | WM_CTLCOLORBTN) {
        return DRAW_STYLE.with(|style| {
            let (dark, background, surface) = style.get();
            if background.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            let colors = palette(dark);
            let dc = wparam as HDC;
            SetTextColor(
                dc,
                if GetDlgCtrlID(lparam as HWND) == 201 {
                    colors.accent
                } else if msg == WM_CTLCOLORSTATIC {
                    colors.muted
                } else {
                    colors.text
                },
            );
            SetBkMode(dc, TRANSPARENT as i32);
            if msg == WM_CTLCOLOREDIT {
                SetBkColor(dc, colors.surface);
                surface as isize
            } else {
                SetBkColor(dc, colors.background);
                background as isize
            }
        });
    }
    if msg == WM_ERASEBKGND {
        return DRAW_STYLE.with(|style| {
            let (_, brush, _) = style.get();
            if brush.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            let mut rect: RECT = zeroed();
            GetClientRect(hwnd, &mut rect);
            FillRect(wparam as HDC, &rect, brush);
            1
        });
    }
    if msg == WM_CREATE {
        let mut state = Box::new(State::new(hwnd));
        state.dark = settings::load().dark;
        state.apply_theme();
        state.layout();
        state.refresh();
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, Box::into_raw(state) as isize);
        SetTimer(hwnd, 1, 100, None);
        return 0;
    }
    let raw = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut State;
    if raw.is_null() {
        return DefWindowProcW(hwnd, msg, wparam, lparam);
    }
    // Native controls and modal dialogs can synchronously dispatch nested messages.
    // Do not create overlapping references to State while a handler owns it.
    let _guard = if matches!(
        msg,
        WM_SIZE
            | WM_DPICHANGED
            | WM_TIMER
            | WM_COMMAND
            | WM_NOTIFY
            | crate::gui_hunter::TARGET_CHOSEN
    ) {
        if HANDLING_STATE.with(|flag| flag.replace(true)) {
            return DefWindowProcW(hwnd, msg, wparam, lparam);
        }
        Some(DispatchGuard)
    } else {
        None
    };
    // Child-control calls can reenter the window procedure. Avoid touching State for unhandled notifications.
    match msg {
        crate::gui_hunter::TARGET_CHOSEN => {
            (*raw).hunter_target(lparam as usize, wparam as u32);
            0
        }
        WM_SIZE => {
            (*raw).layout();
            0
        }
        WM_GETMINMAXINFO => {
            let info = &mut *(lparam as *mut MINMAXINFO);
            info.ptMinTrackSize = POINT {
                x: scale(880, GetDpiForWindow(hwnd).max(96)),
                y: scale(600, GetDpiForWindow(hwnd).max(96)),
            };
            0
        }
        WM_DPICHANGED => {
            (*raw).update_dpi((wparam & 0xffff) as u32);
            let rect = &*(lparam as *const RECT);
            SetWindowPos(
                hwnd,
                null_mut(),
                rect.left,
                rect.top,
                rect.right - rect.left,
                rect.bottom - rect.top,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
            (*raw).layout();
            0
        }
        WM_TIMER => {
            (*raw).poll();
            0
        }
        WM_COMMAND => {
            let id = wparam & 0xffff;
            let code = (wparam >> 16) & 0xffff;
            if id == SEARCH && code == EN_CHANGE as usize {
                (*raw).fill_apps();
                return 0;
            }
            if code != BN_CLICKED as usize {
                return 0;
            }
            match id {
                REFRESH => (*raw).refresh(),
                NAV_APPS => (*raw).show_page(Page::Applications),
                NAV_BACKUPS => (*raw).show_page(Page::Backups),
                NAV_HISTORY => (*raw).show_page(Page::History),
                NAV_STARTUP => (*raw).show_page(Page::Startup),
                STARTUP_DISABLE => (*raw).startup_change(startup::Change::Disable, false),
                STARTUP_RESTORE => (*raw).startup_change(startup::Change::Restore, false),
                STARTUP_MORE => (*raw).startup_options(),
                OPEN_BACKUP => (*raw).open_backup_folder(),
                DELETE_BACKUP => (*raw).delete_backups(),
                REVIEW_BACKUP => (*raw).review_backup(),
                REVIEW_SESSION => (*raw).review_session(),
                PREVIEW => {
                    let apps = (*raw).selected_apps();
                    if let Some(a) = apps.first() {
                        (*raw).preview(a.clone());
                    } else {
                        message(hwnd, "Select an application first.", "Preview", MB_OK);
                    }
                }
                UNINSTALL => (*raw).launch_uninstall(false, false),
                FORCED_MSI => (*raw).removal_options(),
                HUNTER => (*raw).begin_hunter(),
                CLEANUP => (*raw).cleanup(),
                RESTORE => (*raw).restore(),
                THEME => (*raw).toggle_theme(),
                QUIET => {
                    QUIET_SELECTED.with(|v| v.set(!v.get()));
                    InvalidateRect((*raw).quiet, null(), 1);
                    (*raw).update_actions();
                }
                CANCEL => {
                    (*raw).cancel.store(true, Ordering::Relaxed);
                    if let Some(tile) = (*raw).hunter_tile {
                        PostMessageW(tile as HWND, WM_CLOSE, 0, 0);
                    }
                    set_text(
                        (*raw).status,
                        if (*raw).page == Page::Backups {
                            "Cancellation requested. The result will show any backups already deleted."
                        } else {
                            "Cancellation requested. An already running third-party uninstaller is not terminated."
                        },
                    );
                }
                HISTORY => {
                    (*raw).show_page(Page::History);
                }
                EXPORT => {
                    let export_state = &*raw;
                    let path = recovery::data_dir().join(match export_state.page {
                        Page::Applications => "applications.json",
                        Page::Backups => "backups.json",
                        Page::History => "history-export.json",
                        Page::Startup => "startup-export.json",
                    });
                    let bytes = match export_state.page {
                        Page::Applications => serde_json::to_vec_pretty(&export_state.apps),
                        Page::Backups => serde_json::to_vec_pretty(&export_state.backups),
                        Page::History => serde_json::to_vec_pretty(&export_state.history),
                        Page::Startup => serde_json::to_vec_pretty(
                            &export_state
                                .visible
                                .iter()
                                .filter_map(|&i| export_state.startup.get(i))
                                .collect::<Vec<_>>(),
                        ),
                    };
                    let result = std::fs::create_dir_all(recovery::data_dir())
                        .and_then(|_| std::fs::write(&path, bytes.unwrap()));
                    set_text(
                        (*raw).details,
                        &match result {
                            Ok(_) => format!("Exported to {}", path.display()),
                            Err(e) => e.to_string(),
                        },
                    );
                }
                ABOUT => {
                    about(
                        hwnd,
                        &format!(
                            "Unbolt {}\r\nNative Windows application manager and uninstaller\r\n\r\nInstalled applications · Reviewed uninstall · Leftover inspection · Recoverable cleanup · Backup management · Operation history · Hunter window targeting · Startup settings\r\n\r\nFiles move to quarantine before cleanup. Shared and protected locations stay blocked. Quarantine requires storage on the same volume.\r\n\r\nElevated operations, reboot continuation, and recovery across different user accounts require further validation. See the included documentation for supported operations and limitations.\r\n\r\nMIT licensed · github.com/Develifture/Unbolt",
                            env!("CARGO_PKG_VERSION")
                        ),
                    );
                }
                _ => {}
            }
            0
        }
        WM_NOTIFY => {
            let header = &*(lparam as *const NMHDR);
            if header.code == NM_CUSTOMDRAW && matches!(header.idFrom, APPS | LEFTOVERS) {
                let draw = &*(lparam as *const NMLVCUSTOMDRAW);
                if draw.nmcd.dwDrawStage == CDDS_PREPAINT {
                    return CDRF_NOTIFYPOSTPAINT as isize;
                }
                if draw.nmcd.dwDrawStage == CDDS_POSTPAINT
                    && SendMessageW(header.hwndFrom, LVM_GETITEMCOUNT, 0, 0) == 0
                {
                    let label = if header.idFrom == LEFTOVERS {
                        if let Some(report) = &(*raw).report {
                            if report.cancelled {
                                "Scan cancelled. Review the partial result below."
                            } else if !report.errors.is_empty() {
                                "Scan needs review.\nSee the issues below; no cleanup was started."
                            } else {
                                "No leftovers found in the supported locations.\nUse Backups → Review leftovers to revisit a removed application."
                            }
                        } else {
                            "Select an application and choose Preview leftovers.\nReview ownership evidence before checking an item."
                        }
                    } else {
                        match (*raw).page {
                            Page::Applications => "No applications match your search.",
                            Page::Backups => "Your recoverable backups will appear here.",
                            Page::History => "Operation results will appear here.",
                            Page::Startup if (*raw).startup_target.is_some() => {
                                "No startup sources match this Hunter target.\nUse Startup actions to show all supported entries."
                            }
                            Page::Startup => {
                                "No startup sources match this view.\nClear your search or choose Refresh."
                            }
                        }
                    };
                    let mut area: RECT = zeroed();
                    GetClientRect(header.hwndFrom, &mut area);
                    let native_header = SendMessageW(header.hwndFrom, LVM_GETHEADER, 0, 0) as HWND;
                    let mut heading: RECT = zeroed();
                    GetClientRect(native_header, &mut heading);
                    let padding = scale(20, (*raw).dpi);
                    area.left += padding;
                    area.right -= padding;
                    area.top += heading.bottom;
                    let mut measured = area;
                    let old_font = SelectObject(draw.nmcd.hdc, (*raw).font);
                    SetBkMode(draw.nmcd.hdc, TRANSPARENT as i32);
                    SetTextColor(draw.nmcd.hdc, palette((*raw).dark).muted);
                    DrawTextW(
                        draw.nmcd.hdc,
                        wide(label).as_ptr(),
                        -1,
                        &mut measured,
                        DT_CENTER | DT_WORDBREAK | DT_CALCRECT | DT_NOPREFIX,
                    );
                    area.top += (area.bottom - area.top - (measured.bottom - measured.top)) / 2;
                    DrawTextW(
                        draw.nmcd.hdc,
                        wide(label).as_ptr(),
                        -1,
                        &mut area,
                        DT_CENTER | DT_WORDBREAK | DT_NOPREFIX,
                    );
                    SelectObject(draw.nmcd.hdc, old_font);
                }
                return CDRF_DODEFAULT as isize;
            }
            if header.idFrom == APPS && header.code == LVN_COLUMNCLICK {
                let notify = &*(lparam as *const NMLISTVIEW);
                if (*raw).sort_column == notify.iSubItem {
                    (*raw).descending = !(*raw).descending;
                } else {
                    (*raw).sort_column = notify.iSubItem;
                    (*raw).descending = false;
                }
                (*raw).fill_apps();
            }
            if header.idFrom == APPS && header.code == LVN_ITEMCHANGED {
                let notify = &*(lparam as *const NMLISTVIEW);
                if notify.uNewState & LVIS_SELECTED != 0 {
                    (*raw).record_selection();
                }
                (*raw).update_actions();
            }
            0
        }
        WM_CLOSE => {
            if (*raw).busy {
                message(
                    hwnd,
                    "Cancel the current queue and wait for it to stop before closing. A third-party uninstaller already started continues independently.",
                    "Operation in progress",
                    MB_OK,
                );
                return 0;
            }
            DestroyWindow(hwnd);
            0
        }
        WM_DESTROY => {
            KillTimer(hwnd, 1);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            let state = Box::from_raw(raw);
            DeleteObject(state.font);
            DeleteObject(state.heading);
            DRAW_STYLE.with(|s| s.set((false, null_mut(), null_mut())));
            DeleteObject(state.background_brush);
            DeleteObject(state.surface_brush);
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

pub fn run() {
    unsafe {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        let controls = INITCOMMONCONTROLSEX {
            dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES,
        };
        InitCommonControlsEx(&controls);
        let instance = GetModuleHandleW(null());
        let name = wide("UnboltWindow");
        let class = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wndproc),
            hInstance: instance,
            lpszClassName: name.as_ptr(),
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            hIcon: LoadIconW(instance, APP_ICON_RESOURCE),
            hbrBackground: (COLOR_WINDOW + 1) as HBRUSH,
            ..zeroed()
        };
        RegisterClassW(&class);
        let hwnd = CreateWindowExW(
            WS_EX_APPWINDOW,
            name.as_ptr(),
            wide("Unbolt").as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            scale(1180, GetDpiForSystem().max(96)),
            scale(860, GetDpiForSystem().max(96)),
            null_mut(),
            null_mut(),
            instance,
            null(),
        );
        if hwnd.is_null() {
            message(
                null_mut(),
                "Unable to create the main window.",
                "Unbolt",
                MB_OK | MB_ICONERROR,
            );
            return;
        }
        let mut monitor: MONITORINFO = zeroed();
        monitor.cbSize = size_of::<MONITORINFO>() as u32;
        if GetMonitorInfoW(
            MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST),
            &mut monitor,
        ) != 0
        {
            let dpi = GetDpiForWindow(hwnd).max(96);
            let margin = scale(24, dpi);
            let width =
                scale(1180, dpi).min(monitor.rcWork.right - monitor.rcWork.left - margin * 2);
            let height =
                scale(860, dpi).min(monitor.rcWork.bottom - monitor.rcWork.top - margin * 2);
            SetWindowPos(
                hwnd,
                null_mut(),
                monitor.rcWork.left + (monitor.rcWork.right - monitor.rcWork.left - width) / 2,
                monitor.rcWork.top + (monitor.rcWork.bottom - monitor.rcWork.top - height) / 2,
                width,
                height,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
        }
        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);
        let mut msg: MSG = zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            if IsDialogMessageW(hwnd, &msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
}
