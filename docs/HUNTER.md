# Hunter mode

The Applications page has **Hunter mode**, with a floating target and a keyboard-friendly open-window chooser. Both identify a running window's process and compare its actual executable path with the installed-app inventory. Identification performs no uninstall, file removal, or process stop.

The floating target hides the main window while you drag it, hides itself before looking up the window below the pointer, and restores the main window before presenting the result. Escape, right-click, or the main Cancel queue control cancels the picker. Its target, instructions, colors, and dimensions use the native palette and monitor DPI.

The window chooser enumerates visible titled windows, excludes Unbolt's own process, and supports arrow keys, Tab, Enter, double-click, and Cancel. The chosen HWND and PID are rechecked before inspection. The process creation time, token SID, executable, and Windows session are captured and rechecked while inventory is built. A reused/closed window or process is rejected.

## Attribution and actions

An executable inside a useful registered InstallLocation is an exact path match. An executable inside the registered uninstaller's directory supplies weaker supporting evidence. Drive roots, profile/storage roots, and Windows directories are excluded from directory attribution. Filename/name guesses do not pick an app. Shared or overlapping roots remain multiple candidates; incomplete inventory or ambiguous attribution disables automatic selection and direct forced-app review.

After the result review, available actions are:

- Select the unique matched application in the main list for the existing reviewed uninstall/preview workflows.
- Review forced removal for that application. An unmatched program can enter an explicitly confirmed review of its executable folder; this is not a claim that the folder covers the entire program.
- Open its containing folder or native executable properties, after checking that the reviewed process still has the same identity.
- Review startup entries whose saved launch target matches the captured executable. Registry commands and readable Shell links are supported; multiple sources remain separate. Each disable/restore uses the Startup page's existing backup and confirmation flow. Show all startup entries returns to the full supported list. This is not proof of complete startup coverage; see STARTUP.md.
- Stop the exact reviewed process after a second confirmation with No as default and an unsaved-work warning. The termination handle must match the captured creation time. Windows processes, Unbolt's own executable storage, critical processes, inaccessible processes, and other users' processes are excluded. Only that process is stopped; its files, registration, and descendants are not deleted. The outcome is recorded in history.

Attribution is an explanation to review, not proof of ownership of every directory item. Cleanup continues through the existing shared-path, files-in-use, snapshot, backup, and final-selection checks.

## Full scope still outstanding

Desktop shortcut and tray attribution, live hover descriptions, wider startup attribution, stop-and-delete coordination, web search, configurable target size/transparency, persistent Hunter auto-start, and privileged cross-user stopping still require work. Additional Hunter operations remain outside the current feature set. The full cross-window drag gesture still requires manual/runtime validation because the desktop automation tool constrains drag endpoints to one window's bounds.

## Evidence and references

Controlled tests cover exact/shared/overlapping path matches, broad-root exclusion, own-process refusal, visible-window enumeration, actual point-to-window lookup, window/PID mismatch, stale process identity refusal, and stopping an owned temporary process while retaining its executable and registry entry. The floating target's appearance and cancellation were inspected in the native running app.

The Windows adapter uses [WindowFromPoint](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-windowfrompoint) and [IsProcessCritical](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-isprocesscritical); a failed critical-process check blocks stopping.
