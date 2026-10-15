# Administrator component

The native desktop's **More removal** menu now offers **Uninstall selected as administrator…** and, after a forced review, **Remove checked items as administrator…**. Both show the existing final review, with No as the default, before invoking Windows UAC. A separate Rust executable performs one approved operation. It installs no service or driver.

## Request and caller validation

- The GUI creates a random local pipe with one instance, first-instance reservation, a restricted discretionary ACL, and remote clients rejected. Its frame limit is 2 MiB.
- The desktop binds the connection to the actual child process handle/PID. The helper binds the server to the caller PID and creation time and checks its live process image and Windows session. The peer SID comes from the process token, rather than a request field. A 256-bit CNG nonce binds the handshake to that operation.
- Requests carry a registered-app identity or an explicit folder target and fingerprints of reviewed state. The helper independently rebuilds inventory, command, executable digest, forced plan, file snapshots, and registry fingerprints. Changed or unsupported selections fail before execution. There is no general script or arbitrary-executable protocol operation.
- Storage is constrained to a local caller-profile Unbolt directory. Caller HKCU, profile directories, and supported environment expansion remain operation-local when another account grants elevation. Windows and machine roots come from Windows APIs. Reparse and device/network paths are excluded from the supported helper paths.
- Cancellation stops queued work. Once an uninstaller starts, the helper retains its job/process monitor even if the desktop disconnects. No kill-on-close job option is used.

The client executable path check is not code-signature verification. The component is unsigned, and metadata/path checks do not atomically exclude every concurrent filesystem race. This is an early implementation; it has not passed a privileged-security audit. Parent and helper protocol checks do not establish that every file an application's registered uninstaller touches is safe.

## Verification

Production `UnboltCLI.exe helper-check` verifies the real separate-process connection without elevation or mutation. Controlled feature-gated integration fixtures verify:

1. Removal of one owned temporary app directory and its unique HKCU app-list entry, with restorable file and typed registration backups.
2. Rejection of changed directory contents, substituted app state, and a changed uninstaller binary, retaining the original fixture resources.
3. Queue cancellation followed by caller exit, while the helper keeps monitoring the owned test uninstaller and writes its eventual successful completion.
4. Abrupt disconnection of a test-owned caller while its installer runs; the helper stops the queue, keeps the running monitor, and records completion.
5. Disable and restore of a uniquely owned HKCU startup value with exact raw type/bytes preserved; changed-value review rejection. Only this fixture value is affected.

Tests invoke the actual adjacent helper executable through the local pipe. Their non-elevated mutation exception exists only in `test-fixtures` builds, requires a private fixture root/app/key prefix, and revalidates the fixture's owned directory. Ordinary builds reject fixture mutation. Test executables are not packaged.

Real UAC execution, alternate-account UAC, elevated job membership, delegated installer services, reboot continuation, privileged registry owner/group recovery, and disposable-VM uninstall/recovery scenarios remain unverified or unfinished. Normal uninstall's older automatic elevation fallback still tracks only the root and defers cleanup; use the explicit administrator workflow to exercise the new helper once its elevated behavior has been validated. The helper supports reviewed uninstall, forced removal, and startup disable/restore. Other privileged recovery and ordinary-leftover operations remain pending.

## Primary API references

- [Named-pipe security and access rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights): explicit access masks avoid granting another process pipe-instance creation rights through generic write access.
- [GetNamedPipeServerProcessId](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeserverprocessid): endpoint process identity and the local pipe namespace.
- [GetNamedPipeClientProcessId](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid): client process identity.
- [CancelIoEx](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex): overlapped operations must finish cancellation before their buffers and OVERLAPPED structures are released.
