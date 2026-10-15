<p align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="assets/brand/unbolt-horizontal-color.png"><img src="assets/brand/unbolt-horizontal-ink.png" alt="Unbolt" width="420"></picture></p>

# Unbolt

A free, native Windows application manager and uninstaller written in Rust.

Unbolt lists installed applications, launches their registered uninstallers, reviews remaining data, and backs up supported cleanup operations. Its native interface supports light and dark themes, keyboard navigation, and DPI scaling.

## Download

Get the Windows x64 ZIP from [GitHub Releases](https://github.com/Develifture/Unbolt/releases/latest). Extract it and keep Unbolt.exe, UnboltCLI.exe, and UnboltHelper.exe together. Open Unbolt.exe to start.

The portable release does not install a service, driver, browser frontend, or .NET runtime. Windows system libraries remain operating-system dependencies. The executables are currently unsigned.

## What is included

- Installed application inventory, search, sorting, icons, and JSON export.
- Reviewed normal and sequential batch uninstall. Quiet mode uses registered quiet commands.
- Windows Installer command handling and process monitoring.
- Leftover previews with ownership evidence and High, Review, or Blocked classification.
- File quarantine and supported registry backups before selected cleanup.
- Backup browsing, selected restoration, permanent backup disposal, and operation history.
- Saved uninstall records that can reopen leftover review after an app disappears.
- Explicit folder and app-list removal review with files-in-use checks.
- Hunter window targeting and executable-based startup review.
- Reversible management of supported Run, RunOnce, and Startup-folder entries.
- A separate administrator component for supported, explicitly reviewed operations.

## Uninstall and cleanup

Select an application and choose Uninstall selected. Review its registered command before starting. Its own uninstaller may ask for interaction or administrator access.

Unbolt then opens a read-only leftover review. An empty result explains whether supported locations had no matches or the scan needs attention. Cleanup remains blocked while registration, process monitoring, or a reboot requirement is unresolved.

Only supported High-confidence items qualify for ordinary cleanup. Name-only matches require further ownership review. Protected roots, shared application folders, and reparse points remain blocked even if a checkbox is checked. File cleanup moves data to quarantine; registry cleanup saves a typed backup before removal. Quarantine storage must be on the same volume.

## Backups

Backups & recovery supports search and sorting:

- Select a recoverable record and choose Restore selected. Existing destinations are not overwritten.
- Select an uninstall registration export and choose Review leftovers to revisit a removed application.
- Select records and choose Delete selected to permanently discard those recovery copies after confirmation. Original application files are not deletion targets. Disabled startup sources stay disabled.
- Unfinished backup states require recovery review before disposal.

Uninstall-registration exports can be inspected but do not have typed in-app restoration. Local settings, history, process sessions, and recovery records use %LOCALAPPDATA%\Unbolt. Do not edit backup payloads or manifests while an operation is running.

## Command line

The production CLI exposes read-only operations:

    .\UnboltCLI.exe inventory inventory.json
    .\UnboltCLI.exe preview 'Application name'
    .\UnboltCLI.exe saved-preview 'C:\path\to\registry-backups\1234-1-0\application.json'
    .\UnboltCLI.exe forced-preview 'Application name'
    .\UnboltCLI.exe forced-folder 'Application name' 'C:\Example\Application'
    .\UnboltCLI.exe command 'Application name'
    .\UnboltCLI.exe backups
    .\UnboltCLI.exe history --json
    .\UnboltCLI.exe sessions
    .\UnboltCLI.exe startup
    .\UnboltCLI.exe helper-check

Use exact inventory IDs when names are ambiguous. Helper-check verifies the adjacent component without elevation or removal. Use desktop review screens for changes.

## Supported scope and validation

Version 0.1.0 is the first public release. It covers the operations above; it is not a full-drive ownership scanner.

Actual elevated operations, alternate-account behavior, delegated installer services, reboot continuation, and complete recovery scenarios still need disposable-VM validation. Filesystem metadata checks do not atomically exclude every independent concurrent write. The unsigned administrator component has not passed an independent privileged-security audit.

Installation recording, package-app management, browser extensions, broader resource scanning, and additional startup tools are outside this release. See [feature coverage](docs/FULL-FEATURES.md), [verification](docs/VERIFICATION.md), and [administrator details](docs/ADMINISTRATOR.md).

## Build from source

Use Windows x64, Rust 1.98 or newer, the MSVC toolchain, and Windows SDK build tools.

    cargo test --locked --features test-fixtures
    cargo clippy --locked --all-targets -- -D warnings
    cargo clippy --locked --all-targets --features test-fixtures -- -D warnings
    powershell -ExecutionPolicy Bypass -File scripts/package.ps1

The package script creates Unbolt-0.1.0-windows-x64 with only the three production executables, documentation, dependency notices, and a file-hash manifest. Fixture executables are excluded. Tests are retained in the source repository to verify supported behavior.

## License

The independently written source is MIT licensed. Dependencies retain their own licenses and notices.
