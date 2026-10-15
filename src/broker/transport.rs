//! Local-only one-instance pipe, bounded framing, and cancellable overlapped I/O.
use super::{identity::Handle, intent::Message};
use crate::{UnboltResult, command::wide, crypto};
use std::{
    mem::{size_of, zeroed},
    ptr::{null, null_mut},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{
        Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW, SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::*,
    System::{IO::*, Pipes::*, Threading::*},
};
pub const MAX_FRAME: usize = 2 * 1024 * 1024;
pub struct Pipe {
    handle: Handle,
}
pub struct Server {
    pub pipe: Pipe,
    pub nonce: String,
    pub name: String,
}
impl Server {
    pub fn create(sid: &str) -> UnboltResult<Self> {
        if !sid.starts_with("S-1-")
            || sid.len() > 256
            || sid
                .chars()
                .any(|c| !c.is_ascii_digit() && c != 'S' && c != '-')
        {
            return Err("Invalid pipe owner".into());
        }
        let nonce = crypto::nonce()?;
        let name = format!("\\\\.\\pipe\\LOCAL\\Unbolt-{}", &nonce[..32]);
        unsafe {
            let sddl = format!("D:P(A;;GA;;;{sid})(A;;GA;;;SY)(A;;0x0012019b;;;BA)");
            let mut descriptor = null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(&sddl).as_ptr(),
                1,
                &mut descriptor,
                null_mut(),
            ) == 0
            {
                return Err("Cannot restrict helper connection permissions".into());
            }
            let attributes = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            let handle = CreateNamedPipeW(
                wide(&name).as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                65536,
                65536,
                30000,
                &attributes,
            );
            LocalFree(descriptor);
            if handle == INVALID_HANDLE_VALUE {
                return Err(format!(
                    "Cannot reserve helper connection ({})",
                    GetLastError()
                ));
            }
            Ok(Self {
                pipe: Pipe {
                    handle: Handle(handle),
                },
                nonce,
                name,
            })
        }
    }
    pub fn connect(&self, cancel: &AtomicBool, timeout: Duration) -> UnboltResult<()> {
        unsafe {
            let event = event()?;
            let mut io: OVERLAPPED = zeroed();
            io.hEvent = event.0;
            if ConnectNamedPipe(self.pipe.handle.0, &mut io) != 0 {
                return Ok(());
            }
            let code = GetLastError();
            if code == ERROR_PIPE_CONNECTED {
                return Ok(());
            }
            if code != ERROR_IO_PENDING {
                return Err(format!("Helper connection failed ({code})"));
            }
            wait(self.pipe.handle.0, &mut io, cancel, timeout).map(|_| ())
        }
    }
    pub fn disconnect(&self) {
        unsafe {
            DisconnectNamedPipe(self.pipe.handle.0);
        }
    }
}
impl Pipe {
    pub fn open(name: &str) -> UnboltResult<Self> {
        let suffix = name
            .strip_prefix("\\\\.\\pipe\\LOCAL\\Unbolt-")
            .ok_or("Invalid local helper endpoint")?;
        if suffix.len() != 32
            || !suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        {
            return Err("Invalid local helper endpoint".into());
        }
        unsafe {
            // Explicit data/attribute/control rights omit CREATE_PIPE_INSTANCE.
            let handle = CreateFileW(
                wide(name).as_ptr(),
                0x00120083,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                null_mut(),
            );
            if handle == INVALID_HANDLE_VALUE {
                return Err(format!("Cannot connect to Unbolt ({})", GetLastError()));
            }
            Ok(Self {
                handle: Handle(handle),
            })
        }
    }
    pub fn client_pid(&self) -> UnboltResult<u32> {
        unsafe {
            let mut pid = 0;
            if GetNamedPipeClientProcessId(self.handle.0, &mut pid) == 0 {
                return Err("Cannot authenticate helper process".into());
            }
            Ok(pid)
        }
    }
    pub fn server_pid(&self) -> UnboltResult<u32> {
        unsafe {
            let mut pid = 0;
            if GetNamedPipeServerProcessId(self.handle.0, &mut pid) == 0 {
                return Err("Cannot authenticate Unbolt process".into());
            }
            Ok(pid)
        }
    }
    pub fn available(&self) -> UnboltResult<bool> {
        unsafe {
            let mut count = 0;
            if PeekNamedPipe(
                self.handle.0,
                null_mut(),
                0,
                null_mut(),
                &mut count,
                null_mut(),
            ) == 0
            {
                return Err("Helper connection closed".into());
            }
            Ok(count > 0)
        }
    }
    pub fn send(&self, message: &Message, cancel: &AtomicBool) -> UnboltResult<()> {
        let bytes = serde_json::to_vec(message).map_err(|e| e.to_string())?;
        if bytes.len() > MAX_FRAME {
            return Err("Helper message exceeds bounded size".into());
        }
        self.write_all(&(bytes.len() as u32).to_le_bytes(), cancel)?;
        self.write_all(&bytes, cancel)
    }
    pub fn receive(&self, cancel: &AtomicBool, timeout: Duration) -> UnboltResult<Message> {
        let mut length = [0u8; 4];
        self.read_all(&mut length, cancel, timeout)?;
        let length = u32::from_le_bytes(length) as usize;
        if length == 0 || length > MAX_FRAME {
            return Err("Invalid helper frame length".into());
        }
        let mut bytes = vec![0; length];
        self.read_all(&mut bytes, cancel, timeout)?;
        serde_json::from_slice(&bytes).map_err(|_| "Malformed or unsupported helper message".into())
    }
    fn write_all(&self, bytes: &[u8], cancel: &AtomicBool) -> UnboltResult<()> {
        let mut remaining = bytes;
        while !remaining.is_empty() {
            let count = self.transfer(
                remaining.as_ptr() as *mut _,
                remaining.len(),
                true,
                cancel,
                Duration::from_secs(30),
            )?;
            if count == 0 {
                return Err("Helper connection stopped accepting data".into());
            }
            remaining = &remaining[count..];
        }
        Ok(())
    }
    fn read_all(
        &self,
        bytes: &mut [u8],
        cancel: &AtomicBool,
        timeout: Duration,
    ) -> UnboltResult<()> {
        let mut offset = 0;
        let started = Instant::now();
        while offset < bytes.len() {
            let left = timeout
                .checked_sub(started.elapsed())
                .ok_or("Helper read timed out")?;
            let count = self.transfer(
                bytes[offset..].as_mut_ptr(),
                bytes.len() - offset,
                false,
                cancel,
                left,
            )?;
            if count == 0 {
                return Err("Helper connection closed during a message".into());
            }
            offset += count;
        }
        Ok(())
    }
    fn transfer(
        &self,
        buffer: *mut u8,
        length: usize,
        write: bool,
        cancel: &AtomicBool,
        timeout: Duration,
    ) -> UnboltResult<usize> {
        unsafe {
            let event = event()?;
            let mut io: OVERLAPPED = zeroed();
            io.hEvent = event.0;
            let mut transferred = 0;
            let ok = if write {
                WriteFile(
                    self.handle.0,
                    buffer,
                    length as u32,
                    &mut transferred,
                    &mut io,
                )
            } else {
                ReadFile(
                    self.handle.0,
                    buffer,
                    length as u32,
                    &mut transferred,
                    &mut io,
                )
            };
            if ok != 0 {
                if GetOverlappedResult(self.handle.0, &io, &mut transferred, 0) == 0 {
                    return Err("Cannot read helper transfer completion".into());
                }
                return Ok(transferred as usize);
            }
            let code = GetLastError();
            if code != ERROR_IO_PENDING {
                return Err(format!("Helper channel I/O failed ({code})"));
            }
            wait(self.handle.0, &mut io, cancel, timeout).map(|n| n as usize)
        }
    }
}
fn event() -> UnboltResult<Handle> {
    unsafe {
        let h = CreateEventW(null(), 1, 0, null());
        if h.is_null() {
            return Err("Cannot allocate helper I/O event".into());
        }
        Ok(Handle(h))
    }
}
unsafe fn wait(
    handle: HANDLE,
    io: &mut OVERLAPPED,
    cancel: &AtomicBool,
    timeout: Duration,
) -> UnboltResult<u32> {
    let started = Instant::now();
    let mut interrupted = false;
    loop {
        let state = unsafe { WaitForSingleObject(io.hEvent, 50) };
        if state == WAIT_OBJECT_0 {
            break;
        }
        if state != WAIT_TIMEOUT || cancel.load(Ordering::Relaxed) || started.elapsed() >= timeout {
            interrupted = true;
            unsafe {
                CancelIoEx(handle, io);
            }
            // OVERLAPPED and its buffer must remain alive until cancellation completes.
            let mut count = 0;
            unsafe {
                GetOverlappedResult(handle, io, &mut count, 1);
            }
            break;
        }
    }
    if interrupted {
        return Err("Helper I/O cancelled or timed out".into());
    }
    let mut count = 0;
    if unsafe { GetOverlappedResult(handle, io, &mut count, 0) } == 0 {
        return Err(format!("Helper channel completion failed ({})", unsafe {
            GetLastError()
        }));
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_local_pipe_round_trip_binds_to_current_process() {
        let server = Server::create(&crate::broker::identity::current_sid().unwrap()).unwrap();
        let name = server.name.clone();
        let task = std::thread::spawn(move || {
            let client = Pipe::open(&name).unwrap();
            assert_eq!(client.server_pid().unwrap(), unsafe {
                GetCurrentProcessId()
            });
            client
                .send(
                    &Message::Hello {
                        protocol: 1,
                        nonce: "a".repeat(64),
                    },
                    &AtomicBool::new(false),
                )
                .unwrap();
            assert!(matches!(
                client
                    .receive(&AtomicBool::new(false), Duration::from_secs(5))
                    .unwrap(),
                Message::Cancel
            ));
        });
        server
            .connect(&AtomicBool::new(false), Duration::from_secs(5))
            .unwrap();
        assert_eq!(server.pipe.client_pid().unwrap(), unsafe {
            GetCurrentProcessId()
        });
        assert!(matches!(
            server
                .pipe
                .receive(&AtomicBool::new(false), Duration::from_secs(5))
                .unwrap(),
            Message::Hello { .. }
        ));
        server
            .pipe
            .send(&Message::Cancel, &AtomicBool::new(false))
            .unwrap();
        task.join().unwrap();
    }
    #[test]
    fn oversized_and_remote_endpoint_inputs_are_rejected_before_io() {
        assert!(Pipe::open("\\\\remote\\pipe\\LOCAL\\Unbolt-123").is_err());
        let server = Server::create(&crate::broker::identity::current_sid().unwrap()).unwrap();
        assert!(
            server
                .pipe
                .send(
                    &Message::Failed("x".repeat(MAX_FRAME + 1)),
                    &AtomicBool::new(false)
                )
                .unwrap_err()
                .contains("bounded size")
        );
        assert!(
            server
                .connect(&AtomicBool::new(true), Duration::from_secs(5))
                .is_err()
        );
    }
}
