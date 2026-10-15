<p align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="assets/brand/unbolt-horizontal-color.png"><img src="assets/brand/unbolt-horizontal-ink.png" alt="Unbolt" width="420"></picture></p>

# Unbolt: Free, open-source Windows uninstaller

Unbolt is a free, open-source Windows uninstaller written in Rust. Uninstall desktop applications, inspect leftover files and registry entries, and keep recovery copies for supported cleanup operations.

The portable app uses a native Windows interface with light and dark themes, keyboard navigation, and DPI scaling. You review ownership evidence before choosing what to clean.

**[Download for Windows x64](https://github.com/Develifture/Unbolt/releases/latest)** · [Features](#features) · [Frequently asked questions](#frequently-asked-questions) · [Documentation](#documentation) · [Report a problem](https://github.com/Develifture/Unbolt/issues)

## Download and get started

1. Open [GitHub Releases](https://github.com/Develifture/Unbolt/releases/latest) and download **Unbolt-0.1.0-windows-x64.zip**.
2. Extract the ZIP. Keep **Unbolt.exe**, **UnboltCLI.exe**, and **UnboltHelper.exe** together.
3. Open **Unbolt.exe**, select an application, and choose **Uninstall selected** or **Preview leftovers**.
4. Review the results. Eligible leftovers are removed only after you choose **Clean checked** and confirm.

The release includes **SHA256SUMS.txt** for verifying the downloaded ZIP. Version **0.1.0** is the first public release; the executables are unsigned. See [supported scope and validation](#supported-scope-and-validation) before using administrator or recovery operations.

The portable release does not install a service or driver and does not require a browser frontend or .NET runtime. Windows system libraries remain operating-system dependencies.

## Features

| Task                            | What Unbolt provides                                                                                                                                                |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Find installed applications     | Search, sorting, application icons, and JSON inventory export.                                                                                                      |
| Uninstall software              | Reviewed registered uninstall commands, sequential batch uninstall, Windows Installer handling, and process monitoring. Quiet mode uses registered quiet commands.  |
| Review app leftovers            | File and registry candidates with ownership evidence and High, Review, or Blocked classifications. Saved records can reopen review after an application disappears. |
| Clean selected leftovers        | File quarantine and supported registry backups, with checks for shared and protected locations.                                                                     |
| Manage recovery backups         | Browse, restore supported records, permanently delete selected backups, and inspect operation history.                                                              |
| Review forced removal           | Explicit folder and registered-app review, with files-in-use checks.                                                                                                |
| Identify a running app          | Hunter window targeting, matched-application review, and executable-based startup lookup.                                                                           |
| Manage startup programs         | Reversible changes to supported Run, RunOnce, and Startup-folder entries.                                                                                           |
| Review administrator operations | A separate companion component for supported operations that you explicitly review.                                                                                 |

See [feature coverage](docs/FULL-FEATURES.md) for the implemented scope and remaining work.

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

## Frequently asked questions

### Does Unbolt automatically delete leftover files?

No. Previewing leftovers is read-only. After an uninstall, Unbolt opens a leftover review; you choose eligible items, select **Clean checked**, and confirm before cleanup starts.

### Why is Clean checked disabled even when an item is checked?

A checked box does not establish ownership. Ordinary cleanup accepts supported High-confidence items only. Shared folders, protected locations, and reparse points stay Blocked; name-only matches need further review. Unresolved registration, process monitoring, or reboot status can also prevent cleanup.

### Can I delete the recovery backups?

Yes. In **Backups & recovery**, select records and choose **Delete selected**. After confirmation, Unbolt permanently discards those recovery copies. This does not delete the original application files or re-enable a disabled startup entry. Unfinished backup states require recovery review first.

### Can Unbolt undo a complete application uninstall?

No. Recovery covers supported file quarantine, typed registry backups, and startup changes. It does not reinstall an application or undo everything its own uninstaller changed. Uninstall-registration exports can be inspected but cannot currently be restored through the app.

### Is Unbolt free and portable?

Yes. The source is [MIT licensed](LICENSE), and the Windows x64 release runs from its extracted folder. Local settings, history, and recovery records are stored in **%LOCALAPPDATA%\Unbolt**, so those records remain outside the portable application folder.

### Does Unbolt remove Microsoft Store apps or browser extensions?

Those workflows are outside version 0.1.0. This release focuses on registered desktop applications and the supported cleanup and startup operations described above.

## Documentation

- [Feature coverage and remaining work](docs/FULL-FEATURES.md)
- [Validation results and limitations](docs/VERIFICATION.md)
- [Administrator component](docs/ADMINISTRATOR.md)
- [Forced removal](docs/FORCED-REMOVAL.md)
- [Hunter mode](docs/HUNTER.md)
- [Startup programs](docs/STARTUP.md)
- [Release history](CHANGELOG.md)

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

## Help and contributions

[Open an issue](https://github.com/Develifture/Unbolt/issues) for a reproducible problem or feature request. Include the Unbolt version, Windows version, steps to reproduce, and the expected result. Remove private paths and application data from any logs you share.

Pull requests are welcome. For code changes, run the checks in [Build from source](#build-from-source), describe the behavior being changed, and keep cleanup and recovery protections intact.

## Acknowledgments

Unbolt was developed with assistance from [OpenAI Codex](https://github.com/codex).

## License

The independently written source is MIT licensed. Dependencies retain their own licenses and notices.
