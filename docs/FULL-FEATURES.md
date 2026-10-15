# Feature coverage

This file distinguishes implemented operations from remaining work.

| Area | Included | Remaining |
| --- | --- | --- |
| Inventory | Current-user and machine registry views, search/sort/icons/export | Broader package sources |
| Uninstall | Registered normal/quiet commands, sequential batches, Windows Installer handling | Installer-service attribution and reboot continuation |
| Process monitoring | Windows jobs, durable sessions, queue cancellation and continued monitoring | Fully validated elevated descendants and restart recovery |
| Leftovers | Recorded folders, supported name matches, bounded product registry discovery, evidence | Services, tasks, shortcuts, COM, broader and all-user discovery |
| Cleanup | Selected supported items, protected/shared/reparse exclusions, quarantine and typed registry backups | Cross-volume storage and wider ownership attribution |
| Forced removal | Explicit folder/registered-app review, files-in-use checks, app-list entries removed last | Broader resources and VM coverage |
| Backups | Search/sort, selected restoration, saved-record preview, permanent disposal | Within-backup selection and full registry recovery |
| Startup | Run/RunOnce, Startup folders, saved shortcut properties, disable/restore | Add/edit, Windows approval, services/tasks, all profiles |
| Hunter | Window chooser/target, identity checks, matched-app review, exact process stop/startup lookup | Full drag validation, desktop/tray attribution and more tools |
| Administrator helper | One reviewed request, scoped storage/identity, revalidation, cancellation | Actual UAC, alternate-account/privileged validation, signing and security review |
| Interface | Native controls, light/dark themes, DPI layout, clear result states | Full accessibility and monitor-transition coverage |
| Other tools | Read-only JSON exports | Installation recording, package apps, browser extensions and cleaners |

The implemented subset does not imply every installer, ownership edge case, or recovery scenario has been validated.