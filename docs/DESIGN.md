# Architecture

Unbolt is a Windows x64 desktop application. Application-owned runtime code is Rust; the interface uses direct Windows controls. The GUI and CLI share the same inventory, scanning, process, and recovery modules.

## Operation flow

Inventory -> explicit selection -> command review -> application uninstaller -> leftover inspection -> selected cleanup -> recovery record and result.

Read-only preview is available independently of uninstall. Saved application records retain enough inventory information to review supported locations after registration disappears.

## Modules

- inventory: both registry views, current-user and machine records, cautious deduplication.
- command: environment expansion, executable validation, Windows argument handling.
- process: pre-launch operation reservations, suspended launch and job assignment, durable sessions, cancellation monitoring.
- scanner: supported paths, snapshots, ownership classification, protected/shared-resource exclusions.
- registry_cleanup and registration: bounded product settings and app-list entries with typed recovery.
- forced and activity: explicit folder review, selected operations, Windows Restart Manager inspection.
- recovery, records, and backup_delete: quarantine, restoration, selected backup disposal, searchable results.
- startup and shell_link: supported configured sources and saved shortcut properties.
- hunter: process/window identity and application attribution.
- broker: bounded one-operation helper requests, process-bound local pipe, caller-local scope, revalidation.
- gui: native controls, background workers, result presentation, explicit confirmations.

## Mutation rules

Normal startup is read-only. Mutation requires an explicit user action. Cleanup revalidates reviewed state; failed backups, protected/shared locations, reparse paths, unresolved sessions, or changed targets block the affected operation.

Files are moved into same-volume quarantine rather than copied and deleted across volumes. Registry records preserve raw values and supported security metadata. Restore refuses occupied destinations.

Backup disposal targets only direct records inside known Unbolt stores. It does not follow original or stored paths supplied by a manifest. Changed, unfinished, escaped, and reparse-backed records are refused.

## Interface

Applications, Backups & recovery, Operation history, and Startup programs use native tables and controls. Search and sorting operate on already-read records. Background workers handle inventory and scanning. The selected theme persists, and layout supports monitor DPI changes.

## Validation boundary

Owned fixtures cover mutation and recovery; live read-only checks cover real inventory and presentation. These checks do not establish complete installer-service attribution, every concurrent filesystem race, cross-volume quarantine, or fully validated privileged execution.