//! Ask Windows which processes hold the selected application's files. Never
//! call Restart Manager shutdown/restart APIs as part of a preview or cleanup.
use crate::{UnboltResult, command::wide, model::cancelled, scanner};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::Path,
    ptr::{null, null_mut},
    sync::atomic::AtomicBool,
};
use windows_sys::Win32::System::RestartManager::*;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LockingProcess {
    pub pid: u32,
    pub name: String,
}
struct Session(u32);
impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            RmEndSession(self.0);
        }
    }
}
pub fn blockers(path: &Path, cancel: &AtomicBool) -> UnboltResult<Vec<LockingProcess>> {
    unsafe {
        let mut handle = 0;
        let mut key = [0u16; 33];
        let code = RmStartSession(&mut handle, 0, key.as_mut_ptr());
        if code != 0 {
            return Err(format!(
                "Cannot inspect files in use (Windows error {code})"
            ));
        }
        let session = Session(handle);
        let mut stack = vec![path.to_path_buf()];
        let mut batch = Vec::new();
        let mut count = 0;
        while let Some(path) = stack.pop() {
            if cancelled(cancel) {
                return Err("File-use inspection cancelled".into());
            }
            count += 1;
            if count > 100_000 {
                return Err("Application exceeds file-use inspection limit".into());
            }
            let metadata = scanner::snapshot(&path)?;
            if metadata.is_dir {
                for child in fs::read_dir(&path).map_err(|e| e.to_string())? {
                    stack.push(child.map_err(|e| e.to_string())?.path());
                }
            } else {
                let resolved = fs::canonicalize(path).map_err(|e| e.to_string())?;
                batch.push(wide(&crate::records::display_path(
                    &resolved.display().to_string(),
                )));
                if batch.len() == 128 {
                    register(&session, &batch)?;
                    batch.clear();
                }
            }
        }
        if !batch.is_empty() {
            register(&session, &batch)?;
        }
        for _ in 0..3 {
            let (mut needed, mut count, mut reasons) = (0, 0, 0);
            let code = RmGetList(session.0, &mut needed, &mut count, null_mut(), &mut reasons);
            if code == 0 {
                return Ok(vec![]);
            }
            if code != 234 || needed > 4096 {
                return Err(format!(
                    "Cannot read file-use results (Windows error {code})"
                ));
            }
            let mut results: Vec<RM_PROCESS_INFO> =
                (0..needed).map(|_| std::mem::zeroed()).collect();
            count = needed;
            let code = RmGetList(
                session.0,
                &mut needed,
                &mut count,
                results.as_mut_ptr(),
                &mut reasons,
            );
            if code == 234 {
                continue;
            }
            if code != 0 || count as usize > results.len() {
                return Err(format!("File-use query failed (Windows error {code})"));
            }
            return Ok(results
                .into_iter()
                .take(count as usize)
                .map(|p| LockingProcess {
                    pid: p.Process.dwProcessId,
                    name: String::from_utf16_lossy(
                        &p.strAppName[..p
                            .strAppName
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(p.strAppName.len())],
                    ),
                })
                .collect());
        }
        Err("Files in use changed repeatedly; review again".into())
    }
}
unsafe fn register(session: &Session, batch: &[Vec<u16>]) -> UnboltResult<()> {
    let pointers = batch.iter().map(|s| s.as_ptr()).collect::<Vec<_>>();
    let code = unsafe {
        RmRegisterResources(
            session.0,
            pointers.len() as u32,
            pointers.as_ptr(),
            0,
            null(),
            0,
            null(),
        )
    };
    if code != 0 {
        return Err(format!(
            "Cannot inspect application resources (Windows error {code})"
        ));
    }
    Ok(())
}
