//! Process lifetime tracking. A job is assigned before the target starts running.
use crate::{
    UnboltResult,
    command::{self, UninstallCommand},
    model::cancelled,
    recovery,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    sync::{Condvar, Mutex, atomic::AtomicBool},
    thread,
    time::{Duration, Instant},
};
static MONITORS: (Mutex<usize>, Condvar) = (Mutex::new(0), Condvar::new());
struct MonitorGuard;
impl MonitorGuard {
    fn new() -> Self {
        *MONITORS.0.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        Self
    }
}
impl Drop for MonitorGuard {
    fn drop(&mut self) {
        let mut count = MONITORS.0.lock().unwrap_or_else(|e| e.into_inner());
        *count -= 1;
        MONITORS.1.notify_all();
    }
}
pub fn wait_for_background_monitors() {
    let mut count = MONITORS.0.lock().unwrap_or_else(|e| e.into_inner());
    while *count != 0 {
        count = MONITORS.1.wait(count).unwrap_or_else(|e| e.into_inner());
    }
}
use windows_sys::Win32::{
    Foundation::*,
    System::{JobObjects::*, Threading::*},
    UI::{
        Shell::{SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW},
        WindowsAndMessaging::SW_SHOWNORMAL,
    },
};

struct Handle(HANDLE);
pub(crate) struct ApplicationLease {
    _handle: Handle,
}
// Kernel process/job handles support cross-thread use; the owner closes once.
unsafe impl Send for Handle {}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
pub(crate) fn reserve_application(
    storage: &Path,
    application_id: &str,
) -> UnboltResult<ApplicationLease> {
    fs::create_dir_all(storage).map_err(|e| e.to_string())?;
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    fs::canonicalize(storage)
        .map_err(|e| e.to_string())?
        .hash(&mut hash);
    application_id.hash(&mut hash);
    unsafe {
        let handle = CreateEventW(
            null(),
            1,
            0,
            // Reserve this application across Unbolt windows sharing storage.
            command::wide(&format!("Local\\UnboltApplication-{:016x}", hash.finish())).as_ptr(),
        );
        if handle.is_null() {
            return Err("Cannot reserve application operation".into());
        }
        let lease = ApplicationLease {
            _handle: Handle(handle),
        };
        if GetLastError() == ERROR_ALREADY_EXISTS {
            return Err("This application already has a running Unbolt installer session".into());
        }
        Ok(lease)
    }
}
pub fn assert_forced_ready(application_id: &str) -> UnboltResult<()> {
    assert_idle(application_id)?;
    if let Some(session) = sessions()?
        .into_iter()
        .filter(|s| s.application_id == application_id)
        .max_by_key(|s| (crate::records::stamp(&s.id), s.id.clone()))
        && !session.restart_resolved()
        && (session.error.is_some()
            || matches!(session.exit_code, Some(3010 | 1641))
            || session.exit_code.is_none())
    {
        return Err(
            "Resolve the pending restart or process-tracking result before forced removal".into(),
        );
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub created: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub application_id: String,
    pub state: String,
    pub scope: String,
    pub root: ProcessIdentity,
    pub job_name: Option<String>,
    pub exit_code: Option<i32>,
    pub total_processes: u32,
    pub error: Option<String>,
    #[serde(default)]
    pub boot_id: Option<u32>,
    #[serde(default)]
    pub restart_review: Option<RestartReview>,
    #[serde(default)]
    pub registration_export: Option<PathBuf>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RestartReview {
    pub baseline_boot: u32,
    pub resolved_boot: Option<u32>,
}
impl Session {
    pub(crate) fn restart_resolved(&self) -> bool {
        self.state == "resolved-after-restart"
            && self.error.is_none()
            && matches!(self.exit_code, Some(0 | 3010 | 1641))
            && self
                .restart_review
                .as_ref()
                .is_some_and(|r| r.resolved_boot.is_some_and(|boot| boot > r.baseline_boot))
    }
    fn terminal(&self) -> bool {
        self.state == "completed" || self.restart_resolved()
    }
    pub(crate) fn needs_registration_export(&self) -> bool {
        !self.restart_resolved()
            && (!self.terminal() || matches!(self.exit_code, Some(3010 | 1641)))
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessResult {
    pub session: Session,
    pub cancelled: bool,
    pub elapsed_ms: u128,
    pub safe_to_scan: bool,
}

fn identity(handle: HANDLE) -> UnboltResult<ProcessIdentity> {
    unsafe {
        let (mut created, mut exited, mut kernel, mut user) = (
            FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            },
            FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            },
            FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            },
            FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            },
        );
        if GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) == 0 {
            return Err(format!("Cannot read process identity ({})", GetLastError()));
        }
        Ok(ProcessIdentity {
            pid: GetProcessId(handle),
            created: ((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64,
        })
    }
}
fn active_count(job: HANDLE) -> UnboltResult<(u32, u32)> {
    unsafe {
        let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = std::mem::zeroed();
        if QueryInformationJobObject(
            job,
            JobObjectBasicAccountingInformation,
            &mut info as *mut _ as *mut _,
            std::mem::size_of_val(&info) as u32,
            null_mut(),
        ) == 0
        {
            return Err(format!("Cannot query installer job ({})", GetLastError()));
        }
        Ok((info.ActiveProcesses, info.TotalProcesses))
    }
}

struct Running {
    root: Handle,
    job: Option<Handle>,
    session: Session,
}
impl Running {
    fn poll(&mut self) -> UnboltResult<bool> {
        unsafe {
            match WaitForSingleObject(self.root.0, 0) {
                WAIT_OBJECT_0 => {
                    let mut code = 0;
                    if GetExitCodeProcess(self.root.0, &mut code) == 0 {
                        return Err("Cannot read installer exit status".into());
                    }
                    self.session.exit_code = Some(code as i32);
                }
                WAIT_TIMEOUT => {}
                _ => return Err("Cannot wait for installer process".into()),
            }
            if let Some(job) = &self.job {
                let (active, total) = active_count(job.0)?;
                self.session.total_processes = total;
                Ok(active == 0 && self.session.exit_code.is_some())
            } else {
                Ok(self.session.exit_code.is_some())
            }
        }
    }
}

fn native_launch(
    cmd: &UninstallCommand,
    id: &str,
    storage: &Path,
    export: Option<&Path>,
) -> Result<Running, u32> {
    unsafe {
        let name = format!("Local\\UnboltInstaller-{}", recovery::unique_id());
        let job = CreateJobObjectW(null(), command::wide(&name).as_ptr());
        if job.is_null() {
            return Err(GetLastError());
        }
        let job = Handle(job);
        let executable = command::wide(&cmd.executable);
        let line = std::iter::once(command::quote_argument(&cmd.executable))
            .chain(cmd.arguments.iter().map(|a| command::quote_argument(a)))
            .collect::<Vec<_>>()
            .join(" ");
        let mut line = command::wide(&line);
        let working = Path::new(&cmd.executable)
            .parent()
            .map(|p| command::wide(&p.display().to_string()));
        let mut startup: STARTUPINFOW = std::mem::zeroed();
        startup.cb = std::mem::size_of_val(&startup) as u32;
        let mut info: PROCESS_INFORMATION = std::mem::zeroed();
        if CreateProcessW(
            executable.as_ptr(),
            line.as_mut_ptr(),
            null(),
            null(),
            0,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            null(),
            working.as_ref().map_or(null(), |w| w.as_ptr()),
            &startup,
            &mut info,
        ) == 0
        {
            return Err(GetLastError());
        }
        let root = Handle(info.hProcess);
        let main_thread = Handle(info.hThread);
        if AssignProcessToJobObject(job.0, root.0) == 0 {
            let e = GetLastError();
            TerminateProcess(root.0, 1);
            WaitForSingleObject(root.0, 1000);
            return Err(e);
        }
        let identity = match identity(root.0) {
            Ok(i) => i,
            Err(_) => {
                TerminateProcess(root.0, 1);
                return Err(ERROR_INVALID_DATA);
            }
        };
        let session = Session {
            id: recovery::unique_id(),
            application_id: id.into(),
            state: "launch-prepared".into(),
            scope: "job-contained descendants".into(),
            root: identity,
            job_name: Some(name),
            exit_code: None,
            total_processes: 1,
            error: None,
            boot_id: crate::session_review::boot_id().ok(),
            restart_review: None,
            registration_export: export.map(Path::to_path_buf),
        };
        // Keep a durable record before the suspended target executes any code.
        if save(storage, &session).is_err() {
            TerminateProcess(root.0, 1);
            return Err(ERROR_WRITE_FAULT);
        }
        if ResumeThread(main_thread.0) == u32::MAX {
            let e = GetLastError();
            TerminateProcess(root.0, 1);
            return Err(e);
        }
        Ok(Running {
            root,
            job: Some(job),
            session: Session {
                state: "running".into(),
                ..session
            },
        })
    }
}
fn elevated_launch(
    cmd: &UninstallCommand,
    id: &str,
    export: Option<&Path>,
) -> UnboltResult<Running> {
    unsafe {
        let executable = command::wide(&cmd.executable);
        let verb = command::wide("runas");
        let parameters = command::wide(
            &cmd.arguments
                .iter()
                .map(|a| command::quote_argument(a))
                .collect::<Vec<_>>()
                .join(" "),
        );
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = std::mem::size_of_val(&info) as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        info.lpVerb = verb.as_ptr();
        info.lpFile = executable.as_ptr();
        info.lpParameters = parameters.as_ptr();
        info.nShow = SW_SHOWNORMAL;
        if ShellExecuteExW(&mut info) == 0 {
            return Err(format!(
                "Elevation cancelled or launch failed ({})",
                GetLastError()
            ));
        }
        if info.hProcess.is_null() {
            return Err("Elevated process has no trackable handle".into());
        }
        let root = Handle(info.hProcess);
        let identity = identity(root.0)?;
        Ok(Running {
            root,
            job: None,
            session: Session {
                id: recovery::unique_id(),
                application_id: id.into(),
                state: "running".into(),
                scope: "elevated root only; descendants unverified".into(),
                root: identity,
                job_name: None,
                exit_code: None,
                total_processes: 1,
                error: None,
                boot_id: crate::session_review::boot_id().ok(),
                restart_review: None,
                registration_export: export.map(Path::to_path_buf),
            },
        })
    }
}
pub(crate) fn save(root: &Path, session: &Session) -> UnboltResult<PathBuf> {
    fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let path = root.join(format!("{}.json", session.id));
    let pending = root.join(format!("{}.{}.pending", session.id, recovery::unique_id()));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&pending)
        .map_err(|e| e.to_string())?;
    use std::io::Write;
    file.write_all(&serde_json::to_vec_pretty(session).map_err(|e| e.to_string())?)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    fs::rename(pending, &path).map_err(|e| e.to_string())?;
    Ok(path)
}
pub fn run(
    cmd: &UninstallCommand,
    application_id: &str,
    cancel: &AtomicBool,
) -> UnboltResult<ProcessResult> {
    run_at(
        cmd,
        application_id,
        cancel,
        &recovery::data_dir().join("process-sessions"),
    )
}
pub fn run_at(
    cmd: &UninstallCommand,
    application_id: &str,
    cancel: &AtomicBool,
    storage: &Path,
) -> UnboltResult<ProcessResult> {
    if cancelled(cancel) {
        return Err("Cancelled before launch".into());
    }
    let lease = reserve_application(storage, application_id)?;
    run_reserved(cmd, application_id, cancel, storage, lease, None)
}
pub(crate) fn run_reserved(
    cmd: &UninstallCommand,
    application_id: &str,
    cancel: &AtomicBool,
    storage: &Path,
    lease: ApplicationLease,
    export: Option<&Path>,
) -> UnboltResult<ProcessResult> {
    if cancelled(cancel) {
        return Err("Cancelled before launch".into());
    }
    // Reserve writable session storage before target execution begins.
    fs::create_dir_all(storage).map_err(|e| e.to_string())?;
    let probe = storage.join(format!("{}.probe", recovery::unique_id()));
    fs::write(&probe, b"session").map_err(|e| e.to_string())?;
    fs::remove_file(probe).map_err(|e| e.to_string())?;
    for session in sessions_at(storage)?
        .into_iter()
        .filter(|s| s.application_id == application_id)
    {
        if !session.terminal() {
            return Err(
                "An earlier installer session requires review before another launch".into(),
            );
        }
    }
    if cancelled(cancel) {
        return Err("Cancelled before launch".into());
    }
    let started = Instant::now();
    let mut running = match native_launch(cmd, application_id, storage, export) {
        Ok(r) => r,
        Err(740) => elevated_launch(cmd, application_id, export)?,
        Err(e) => {
            return Err(format!(
                "Target did not start; tracked launch failed (Windows error {e})"
            ));
        }
    };
    if let Err(e) = save(storage, &running.session) {
        running.session.error = Some(e);
    }
    loop {
        match running.poll() {
            Ok(true) => {
                running.session.state = if running.job.is_some() {
                    "completed"
                } else {
                    "completed-needs-review"
                }
                .into();
                if let Err(error) = save(storage, &running.session) {
                    running.session.error =
                        Some(format!("Cannot persist completed process session: {error}"));
                }
                return Ok(ProcessResult {
                    safe_to_scan: running.job.is_some()
                        && running.session.error.is_none()
                        && running.session.exit_code == Some(0),
                    session: running.session,
                    cancelled: false,
                    elapsed_ms: started.elapsed().as_millis(),
                });
            }
            Ok(false) => {}
            Err(e) => {
                running.session.error = Some(e);
                break;
            }
        }
        if cancelled(cancel) {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    running.session.state = "monitoring-after-queue-stop".into();
    let _ = save(storage, &running.session);
    let session = running.session.clone();
    let storage = storage.to_path_buf();
    // The monitor retains handles. No KILL_ON_JOB_CLOSE flag is used, and no
    // started installer is terminated when the user cancels the queue.
    let monitor = MonitorGuard::new();
    thread::spawn(move || {
        let _monitor = monitor;
        let _lease = lease;
        loop {
            match running.poll() {
                Ok(true) => {
                    running.session.state = if running.job.is_some() {
                        "completed"
                    } else {
                        "completed-needs-review"
                    }
                    .into();
                    let _ = save(&storage, &running.session);
                    break;
                }
                Ok(false) => {}
                Err(e) => {
                    running.session.error = Some(e);
                    running.session.state = "monitor-interrupted".into();
                    let _ = save(&storage, &running.session);
                    break;
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
    });
    Ok(ProcessResult {
        session,
        cancelled: true,
        elapsed_ms: started.elapsed().as_millis(),
        safe_to_scan: false,
    })
}
pub fn sessions() -> UnboltResult<Vec<Session>> {
    let root = recovery::data_dir().join("process-sessions");
    sessions_at(&root)
}
pub(crate) fn sessions_at(root: &Path) -> UnboltResult<Vec<Session>> {
    if !root.exists() {
        return Ok(vec![]);
    }
    let mut sessions = Vec::new();
    for entry in fs::read_dir(root).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let s = serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        sessions.push(s);
    }
    Ok(sessions)
}
pub fn assert_idle(application_id: &str) -> UnboltResult<()> {
    for session in sessions()?
        .into_iter()
        .filter(|s| s.application_id == application_id)
    {
        if !session.terminal() {
            return Err(format!(
                "Installer session requires review before cleanup: {} ({})",
                session.state, session.scope
            ));
        }
    }
    Ok(())
}

pub fn assert_cleanup_ready(application_id: &str) -> UnboltResult<()> {
    assert_cleanup_ready_at(
        &recovery::data_dir().join("process-sessions"),
        application_id,
    )
}
pub fn assert_cleanup_ready_at(storage: &Path, application_id: &str) -> UnboltResult<()> {
    let records = sessions_at(storage)?;
    for session in records
        .iter()
        .filter(|s| s.application_id == application_id)
    {
        if !session.terminal() {
            return Err(format!(
                "Cleanup deferred while an installer session needs review: {} ({})",
                session.state, session.scope
            ));
        }
    }
    // A successful, fully tracked retry supersedes earlier completed failures.
    if let Some(session) = records
        .into_iter()
        .filter(|s| s.application_id == application_id)
        .max_by_key(|s| {
            (
                s.id.split('-')
                    .next()
                    .and_then(|v| v.parse::<u128>().ok())
                    .unwrap_or(0),
                s.id.clone(),
            )
        })
        && !session.restart_resolved()
        && (session.error.is_some() || session.exit_code != Some(0))
    {
        return Err(format!(
            "Cleanup deferred: installer session {} reported {:?}. Restart or resolve its result first.",
            session.id, session.exit_code
        ));
    }
    Ok(())
}
