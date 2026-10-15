# Startup programs

The native **Startup programs** page lists Run and RunOnce registry values in the current-user and machine 32/64-bit views, plus regular files in the current-user and common Startup folders. It supports search, sorting, JSON export, exact-item review, reversible disable, and restore. The page labels configured sources separately from entries disabled by Unbolt.

Select one item to see its full command, source, scope, and any issue. **Disable startup** and **Restore startup** show a final confirmation with No selected. The **Startup actions** menu offers the same reviewed operation through the administrator component. These actions do not launch or stop a running program.

## Backup and recovery

Registry changes save the exact value type and bytes before removing only that value. REG_SZ and REG_EXPAND_SZ are supported; other types are read-only. Restore refuses an existing value. Folder files have metadata and SHA-256 checks and move to a saved payload without replacing a destination or crossing volumes. Reparse points, protected roots, and Unbolt's storage are excluded. A changed folder location invalidates the earlier review and saved-file restoration.

Backups live in `%LOCALAPPDATA%\Unbolt\startup-backups`. They join **Backups & recovery**, and successful changes join **Operation history**. Interrupted prepared records can be reviewed for recovery; changed payloads or occupied sources are refused. Keep the manifest and payload together.

When Windows registry transactions are available they are used. This host returned error 6801, so verification exercised a checked ordinary registry handle with a fresh value comparison. The result records that fallback. It cannot atomically exclude an independent writer changing the same value between comparison and mutation. File snapshot checks also do not exclude every concurrent filesystem change.

## Meaning and remaining scope

**Configured** means the source exists. Windows' separate startup approval may block it; restoring a source does not override that approval. Shortcut entries show their saved target and arguments, with their working folder and original launch-file location in details. Unbolt reads saved Shell-link properties without calling Resolve, Save, or launching the target. Invalid/unsupported links retain a readable target-details issue; their exact launch file can still be backed up and disabled. The original registry command remains unexpanded for review and recovery.

Hunter's **Review this program's startup entries** action rechecks the captured process and opens a view of exact saved targets matching its executable. Multiple sources remain separate. Disable and restore still require individual source review and confirmation. **Startup actions → Show all startup entries** returns to the supported full list. Startup export follows the displayed filter and sort order. Launchers, relative/ambiguous commands, unresolved links, non-filesystem targets, services, and tasks can supply other startup routes; an empty matching view does not prove a program cannot start automatically.

Adding entries, editing commands, publisher/running metadata, services, scheduled tasks, Windows approval controls, all-profile enumeration, and broader startup attribution remain pending. Actual UAC/alternate-account execution and disposable-VM coverage are also pending. See the feature coverage document for the current scope.

Saved argument strings use the Windows property store to avoid the truncation possible in the legacy fixed-buffer GetArguments API. See [Microsoft's Shell-link arguments documentation](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ishelllinkw-getarguments) and [saved path flags](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ishelllinkw-getpath).

Production `UnboltCLI.exe startup` is read-only and returns the entries and coverage errors as JSON.
