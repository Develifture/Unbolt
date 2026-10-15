# Changelog

## Unreleased

- Reject changed application details, including installation folders and merged registry sources, before uninstall backup or launch. Rejected attempts do not seed a leftover preview.
- Add Operation history → Review pending uninstall for supported deferred sessions. A later Windows boot, absent registration, stopped recorded processes, and fresh folder-use checks are required. Legacy records first capture a boot reference. Resolution preserves the original exit result and does not perform cleanup.
- Add regression coverage for stale uninstall review and restart-session resolution. Actual UAC/reboot validation remains outstanding.

## 0.1.0

First public Unbolt release.

- Native application inventory and reviewed uninstall workflows.
- Leftover evidence, protected/shared-location checks, and recoverable cleanup.
- Saved-record rescan, selected backup disposal, and operation history.
- Hunter window targeting and reversible startup settings.
- Standalone branding, versioned portable packaging, dependency notices, and checksums.

See README.md and docs/VERIFICATION.md for supported scope and validation limits.
