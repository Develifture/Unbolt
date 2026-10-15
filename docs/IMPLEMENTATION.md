# Implementation and maintenance

The Rust library is shared by the native desktop application, the read-only command-line interface, and the one-operation administrator helper.

For changes, preserve explicit selection, reviewed command/state checks, protected/shared-path exclusions, backup-before-cleanup behavior, and conflict-preserving restore. Keep filesystem work off the UI thread.

Run formatting, both Clippy configurations, and fixture tests before packaging. Build production binaries without the test-fixtures feature. Check the actual portable package, adjacent-helper handshake, manifest hashes, and native UI before publishing.

Version strings come from Cargo package metadata. Portable release names use Unbolt-VERSION-windows-x64. Keep local records, generated artifacts, and previous binaries outside Git.