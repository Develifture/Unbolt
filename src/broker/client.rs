use super::{
    identity::{self, Handle},
    intent::{Message, Operation, PROTOCOL, Reply, Request},
    transport::Server,
};
use crate::{UnboltResult, command, crypto, recovery};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::*,
    System::Threading::*,
    UI::{
        Shell::{SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW},
        WindowsAndMessaging::SW_HIDE,
    },
};
fn helper_path() -> UnboltResult<PathBuf> {
    let parent = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .parent()
        .ok_or("Unbolt executable has no directory")?
        .to_path_buf();
    ["unbolt-helper.exe", "UnboltHelper.exe"]
        .iter()
        .map(|name| parent.join(name))
        .find(|path| path.is_file())
        .ok_or("The Unbolt administrator component is missing beside the application".into())
}
fn launch(path: &std::path::Path, args: &[String], elevate: bool) -> UnboltResult<Handle> {
    if !elevate {
        // Do not inherit any caller handles: even an unrelated inheritable pipe
        // could otherwise keep a CLI's redirected output open after it exits.
        unsafe {
            let executable = command::wide(&path.display().to_string());
            let mut line = command::wide(
                &std::iter::once(command::quote_argument(&path.display().to_string()))
                    .chain(args.iter().map(|a| command::quote_argument(a)))
                    .collect::<Vec<_>>()
                    .join(" "),
            );
            let mut startup: STARTUPINFOW = std::mem::zeroed();
            startup.cb = std::mem::size_of_val(&startup) as u32;
            let mut info: PROCESS_INFORMATION = std::mem::zeroed();
            if CreateProcessW(
                executable.as_ptr(),
                line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                CREATE_NO_WINDOW,
                std::ptr::null(),
                std::ptr::null(),
                &startup,
                &mut info,
            ) == 0
            {
                return Err(format!("Cannot start helper process ({})", GetLastError()));
            }
            CloseHandle(info.hThread);
            return Ok(Handle(info.hProcess));
        }
    }
    unsafe {
        let executable = command::wide(&path.display().to_string());
        let verb = command::wide("runas");
        let parameters = command::wide(
            &args
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
        info.nShow = SW_HIDE;
        if ShellExecuteExW(&mut info) == 0 {
            return Err(format!(
                "Administrator access was cancelled or the component could not start ({})",
                GetLastError()
            ));
        }
        if info.hProcess.is_null() {
            return Err("Administrator component has no process handle".into());
        }
        Ok(Handle(info.hProcess))
    }
}
pub fn invoke(operation: Operation, cancel: &AtomicBool) -> UnboltResult<Reply> {
    let data = recovery::data_dir();
    identity::check_chain(&data, true)?;
    fs::create_dir_all(&data).map_err(|e| e.to_string())?;
    invoke_at(
        operation,
        cancel,
        &fs::canonicalize(data).map_err(|e| e.to_string())?,
        true,
    )
}
pub fn invoke_at(
    operation: Operation,
    cancel: &AtomicBool,
    data: &std::path::Path,
    elevate: bool,
) -> UnboltResult<Reply> {
    if cancel.load(Ordering::Relaxed) {
        return Err("Cancelled before administrator request".into());
    }
    let parent = identity::process(unsafe { GetCurrentProcessId() })?;
    identity::scope(&parent, data)?;
    let server = Server::create(&parent.sid)?;
    let args = vec![
        "--ipc".into(),
        server.name.clone(),
        server.nonce.clone(),
        parent.pid.to_string(),
        parent.created.to_string(),
    ];
    let handle = launch(&helper_path()?, &args, elevate)?;
    let pid = unsafe { GetProcessId(handle.0) };
    let expected = identity::process(pid)?;
    server.connect(cancel, Duration::from_secs(30))?;
    if server.pipe.client_pid()? != pid {
        return Err("The helper connection came from another process".into());
    }
    identity::check_peer(&identity::process(pid)?, &expected)?;
    match server.pipe.receive(cancel, Duration::from_secs(10))? {
        Message::Hello { protocol, nonce }
            if protocol == PROTOCOL && crypto::same_nonce(&nonce, &server.nonce) => {}
        _ => return Err("The helper did not confirm this operation's identity".into()),
    }
    server.pipe.send(
        &Message::Request(Box::new(Request {
            protocol: PROTOCOL,
            data: data.into(),
            operation,
            fixture: !elevate,
        })),
        cancel,
    )?;
    let mut sent_cancel = false;
    let io_cancel = AtomicBool::new(false);
    loop {
        if cancel.load(Ordering::Relaxed) && !sent_cancel {
            server.pipe.send(&Message::Cancel, &io_cancel)?;
            sent_cancel = true;
        }
        if server.pipe.available()? {
            return match server.pipe.receive(&io_cancel, Duration::from_secs(30))? {
                Message::Result(reply) => Ok(reply),
                Message::Failed(error) => Err(error),
                _ => Err("Unexpected helper response".into()),
            };
        }
        if unsafe { WaitForSingleObject(handle.0, 0) } != WAIT_TIMEOUT {
            return Err("The administrator component stopped before reporting a result".into());
        }
        thread::sleep(Duration::from_millis(50));
    }
}
