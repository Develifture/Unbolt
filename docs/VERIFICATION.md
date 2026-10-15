# Verification

## Source checks

The release baseline has 71 passing checks: 56 library checks, one GUI icon check, one files-in-use fixture, five helper fixtures, one Hunter fixture, and seven process-lifecycle fixtures. Run the current source checks again when changing runtime behavior.

Both production and test-fixtures Clippy configurations are checked with warnings denied. Fixture launchers are feature gated and excluded from portable packages.

## Exercised behavior

- Inventory view merging and cautious identity handling.
- Windows argument escaping, Windows Installer switches, and missing-package parsing without targeting an installed product.
- Process descendants, cancellation, durable sessions, duplicate reservation, and reboot status.
- Protected/shared locations, local canonical path prefixes, traversal, and reparse exclusions.
- A real owned registration becoming unregistered while its exact remaining directory stays visible.
- Quarantine, conflict-preserving restore, registry raw values, changed-state rejection, and backup failures.
- Separate helper-process requests, changed-state/binary rejection, caller disconnect, and continued installer monitoring.
- Hunter process/window identity and exact startup-target matching.
- Startup disable/restore, shortcut metadata, and interrupted-record handling.
- Disposal of all five supported backup types, retained originals and sibling backups, cancellation, stale review, nested manifest names, and junction rejection.

## Native interface checks

Live checks verified real inventory, themed tables and controls, backup navigation, saved-record leftover review, and the permanent-loss confirmation with No as default. Cancelling that confirmation retained existing user backups. Actual deletion was exercised only on owned fixtures.

The 0.1.0 production executable was opened after final branding changes. Its embedded Windows icon, scaled header icon, About artwork, and version display were inspected in the native interface.

A shared plug-in container stays Blocked even when checked. A name-only application-data folder remains Review rather than being promoted to High. Empty scans distinguish no supported matches from errors or cancellation.

## Release checks

Re-run the complete source checks after branding/storage changes. Verify the versioned portable package, three intended executables, dependency notices, file hashes, adjacent-helper connection, and actual native window. Published release checksums identify the distributed ZIP.

## Limits

Real elevated operations, alternate-account UAC, delegated installer services, reboot continuation, privileged ownership recovery, full accessibility, cross-monitor DPI changes, and comprehensive disposable-VM uninstall/recovery coverage remain outstanding. Metadata/path checks do not atomically rule out every concurrent writer. The administrator component is unsigned and has not received an independent privileged-security audit.

Passing source and owned-fixture checks does not establish complete production stability for every supported Windows application.
