use std::{fs, sync::atomic::AtomicBool};
use unbolt::{UnboltResult, forced, inventory, process, records, recovery, scanner, uninstall};

fn run() -> UnboltResult<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let cancel = AtomicBool::new(false);
    let command = args.first().map(String::as_str).unwrap_or("help");
    match command {
        "saved-preview" => {
            let path = std::path::Path::new(
                args.get(1)
                    .ok_or("Supply the saved application.json path from an uninstall backup")?,
            );
            let app = unbolt::backup_delete::saved_application(path)?;
            let inventory = inventory::collect(&cancel);
            let mut report = scanner::scan(&app, &inventory.apps, &cancel);
            report.errors.extend(inventory.errors);
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
            );
        }
        "startup" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&unbolt::startup::collect(&cancel))
                    .map_err(|e| e.to_string())?
            );
        }
        "helper-fixture" => {
            #[cfg(feature = "test-fixtures")]
            {
                helper_fixture(&args)?;
            }
            #[cfg(not(feature = "test-fixtures"))]
            {
                return Err("Controlled helper fixtures are not included in this build".into());
            }
        }
        "helper-check" => {
            let data = if let Some(path) = args.get(1) {
                std::path::PathBuf::from(path)
            } else {
                recovery::data_dir()
            };
            unbolt::broker::identity::validate_storage_candidate(&data)?;
            fs::create_dir_all(&data).map_err(|e| e.to_string())?;
            let reply = unbolt::broker::client::invoke_at(
                unbolt::broker::intent::Operation::Inspect,
                &cancel,
                &fs::canonicalize(data).map_err(|e| e.to_string())?,
                false,
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&reply).map_err(|e| e.to_string())?
            );
        }
        "inventory" => {
            let data = inventory::collect(&cancel);
            let json = serde_json::to_string_pretty(&data).map_err(|e| e.to_string())?;
            if let Some(path) = args.get(1) {
                fs::write(path, json).map_err(|e| e.to_string())?;
            } else {
                println!("{json}");
            }
        }
        "preview" | "command" | "forced-preview" => {
            let query = args
                .get(1)
                .ok_or("Supply an exact application ID or unique name")?;
            let data = inventory::collect(&cancel);
            let matching = data
                .apps
                .iter()
                .filter(|a| a.id == *query || a.name.eq_ignore_ascii_case(query))
                .collect::<Vec<_>>();
            if matching.len() != 1 {
                return Err(format!(
                    "Expected one match; found {}. Use an exact inventory ID.",
                    matching.len()
                ));
            }
            if command == "command" {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&uninstall::prepare_mode(
                        matching[0],
                        if args.iter().any(|a| a == "--forced-msi") {
                            uninstall::Mode::ForcedMsi {
                                quiet: args.iter().any(|a| a == "--quiet"),
                            }
                        } else if args.iter().any(|a| a == "--quiet") {
                            uninstall::Mode::Quiet
                        } else {
                            uninstall::Mode::Normal
                        }
                    )?)
                    .unwrap()
                );
            } else if command == "forced-preview" {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&forced::preview(matching[0], &cancel)?)
                        .map_err(|e| e.to_string())?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&scanner::scan(matching[0], &data.apps, &cancel))
                        .unwrap()
                );
            }
        }
        "history" if args.iter().any(|a| a == "--json") => println!(
            "{}",
            serde_json::to_string_pretty(&records::history()?).map_err(|e| e.to_string())?
        ),
        "backups" => println!(
            "{}",
            serde_json::to_string_pretty(&records::backups()?).map_err(|e| e.to_string())?
        ),
        "sessions" => println!(
            "{}",
            serde_json::to_string_pretty(&process::sessions()?).map_err(|e| e.to_string())?
        ),
        "forced-folder" => {
            let name = args
                .get(1)
                .ok_or("Supply product name and absolute folder path")?;
            let path = std::path::Path::new(args.get(2).ok_or("Supply an absolute folder path")?);
            let app = forced::folder_target(name, path)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&forced::preview(&app, &cancel)?)
                    .map_err(|e| e.to_string())?
            );
        }
        "history" => println!("{}", recovery::read_history()?),
        "help" | "--help" => println!(
            "Unbolt {}\n\nRead-only commands:\n  inventory [output.json]\n  preview <exact ID or unique name>\n  saved-preview <saved application.json path>\n  forced-preview <exact ID or unique name>\n  forced-folder <product name> <absolute folder>\n  command <exact ID or unique name> [--quiet] [--forced-msi]\n  history [--json]\n  backups\n  sessions\n  startup\n  helper-check\n\nUse the desktop review screens for uninstall, cleanup, and startup changes.",
            env!("CARGO_PKG_VERSION")
        ),
        _ => return Err("Unknown command; use --help".into()),
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

#[cfg(feature = "test-fixtures")]
fn helper_fixture(args: &[String]) -> UnboltResult<()> {
    use unbolt::{
        broker::{
            client,
            intent::{Operation, Reply},
        },
        command, forced,
        model::RegistrySource,
    };
    use winreg::{RegKey, enums::*};
    let supplied = std::path::PathBuf::from(args.get(1).ok_or("Fixture root required")?);
    if !supplied.is_absolute()
        || !supplied
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("unbolt-helper-fixture-"))
    {
        return Err("Not a helper fixture root".into());
    }
    fs::create_dir_all(&supplied).map_err(|e| e.to_string())?;
    let root = std::path::PathBuf::from(unbolt::records::display_path(
        &fs::canonicalize(&supplied)
            .map_err(|e| e.to_string())?
            .display()
            .to_string(),
    ));
    let folder = root.join("App");
    fs::create_dir_all(&folder).map_err(|e| e.to_string())?;
    fs::write(folder.join("owned.txt"), b"owned helper fixture").map_err(|e| e.to_string())?;
    let data = root.join(recovery::DATA_DIRECTORY);
    fs::create_dir_all(&data).map_err(|e| e.to_string())?;
    if args
        .get(2)
        .is_some_and(|s| s == "startup" || s == "startup-stale")
    {
        return startup_helper_fixture(&data, args.get(2).is_some_and(|s| s == "startup-stale"));
    }
    let name = format!(
        "UnboltHelperFixtureX{}",
        recovery::unique_id().replace('-', "X")
    );
    let source = RegistrySource {
        hive: "HKCU".into(),
        view: KEY_WOW64_64KEY,
        key: format!("{}\\{name}", inventory::UNINSTALL_ROOT),
    };
    fs::write(
        root.join("registration.json"),
        serde_json::to_vec(&source).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    struct KeyCleanup(String);
    impl Drop for KeyCleanup {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.0);
        }
    }
    let _cleanup = KeyCleanup(source.key.clone());
    let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
        .create_subkey(&source.key)
        .map_err(|e| e.to_string())?;
    key.set_value("DisplayName", &name)
        .map_err(|e| e.to_string())?;
    key.set_value("InstallLocation", &folder.display().to_string())
        .map_err(|e| e.to_string())?;
    let mode = args.get(2).map(String::as_str).unwrap_or("force");
    if matches!(mode, "uninstall" | "disconnect" | "binary-changed") {
        let original = std::env::current_exe()
            .map_err(|e| e.to_string())?
            .parent()
            .unwrap()
            .join("unbolt-test-fixture.exe");
        let executable = folder.join("fixture.exe");
        fs::copy(original, &executable).map_err(|e| e.to_string())?;
        let cmd = format!(
            "{} held {}",
            command::quote_argument(&executable.display().to_string()),
            command::quote_argument(&root.join("ready.txt").display().to_string())
        );
        key.set_value("UninstallString", &cmd)
            .map_err(|e| e.to_string())?;
    }
    drop(key);
    let cancel = std::sync::Arc::new(AtomicBool::new(false));
    let app = inventory::collect(&cancel)
        .apps
        .into_iter()
        .find(|a| a.name == name)
        .ok_or("Fixture registration not visible")?;
    let mut operation = if matches!(mode, "uninstall" | "disconnect" | "binary-changed") {
        Operation::uninstall(&app, uninstall::Mode::Normal)?
    } else {
        let plan = forced::preview(&app, &cancel)?;
        Operation::forced(
            &plan,
            &forced::Selection {
                files: vec![0],
                registry: (0..plan.report.registry_candidates.len()).collect(),
            },
        )?
    };
    if mode == "changed" {
        fs::write(folder.join("owned.txt"), b"changed after review").map_err(|e| e.to_string())?;
    }
    if mode == "binary-changed" {
        // A harmless appended byte preserves a loadable PE but changes its digest.
        use std::io::Write;
        fs::OpenOptions::new()
            .append(true)
            .open(folder.join("fixture.exe"))
            .and_then(|mut file| file.write_all(b"changed after review"))
            .map_err(|e| e.to_string())?;
    }
    if mode == "uninstall" {
        let flag = cancel.clone();
        let marker = root.join("ready.txt");
        std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
            while !marker.exists() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            flag.store(true, std::sync::atomic::Ordering::Relaxed);
        });
    }
    if mode == "wrong-target"
        && let Operation::Forced {
            target: unbolt::broker::intent::Target::Registered { expected, .. },
            ..
        } = &mut operation
    {
        *expected = [0; 32];
    }
    let result = client::invoke_at(
        operation,
        &cancel,
        &fs::canonicalize(&data).map_err(|e| e.to_string())?,
        false,
    );
    match result {
        Ok(reply) => {
            let status = match &reply {
                Reply::Forced(out) => out.status.clone(),
                Reply::Uninstall(out) => out.status.clone(),
                _ => "unexpected reply".into(),
            };
            println!(
                "{}",
                serde_json::json!({"reply":reply,"status":status,"folder_exists":folder.exists(),"registered":inventory::registered(&app)?})
            );
        }
        Err(error) => println!(
            "{}",
            serde_json::json!({"error":error,"folder_exists":folder.exists(),"registered":inventory::registered(&app)?})
        ),
    }
    Ok(())
}
#[cfg(feature = "test-fixtures")]
fn startup_helper_fixture(data: &std::path::Path, stale: bool) -> UnboltResult<()> {
    use unbolt::{
        broker::{
            client,
            intent::{Operation, Reply},
        },
        command,
        model::RegistrySource,
        startup::{self, Change, Source},
    };
    use winreg::{RegKey, RegValue, enums::*};
    let name = format!("UnboltStartupFixture{}", recovery::unique_id());
    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(startup::RUN, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY)
        .map_err(|e| e.to_string())?;
    struct Cleanup<'a>(&'a RegKey, String);
    impl Drop for Cleanup<'_> {
        fn drop(&mut self) {
            let _ = self.0.delete_value(&self.1);
        }
    }
    let _cleanup = Cleanup(&key, name.clone());
    let bytes = command::wide("%USERPROFILE%\\UnboltStartupFixtureMissing.exe --fixture")
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    key.set_raw_value(
        &name,
        &RegValue {
            vtype: REG_EXPAND_SZ,
            bytes: bytes.clone().into(),
        },
    )
    .map_err(|e| e.to_string())?;
    let source = Source::Registry {
        location: RegistrySource {
            hive: "HKCU".into(),
            view: KEY_WOW64_64KEY,
            key: startup::RUN.into(),
        },
        name: name.clone(),
    };
    let flag = AtomicBool::new(false);
    let entry = startup::resolve(&source, None, &flag)?;
    let operation = Operation::startup(&entry, Change::Disable)?;
    if stale {
        key.set_value(&name, &"changed after review")
            .map_err(|e| e.to_string())?;
    }
    let data = fs::canonicalize(data).map_err(|e| e.to_string())?;
    let reply = client::invoke_at(operation, &flag, &data, false);
    if stale {
        println!(
            "{}",
            serde_json::json!({"error":reply.err(),"value":key.get_value::<String,_>(&name).map_err(|e|e.to_string())?})
        );
        return Ok(());
    }
    let Reply::Startup(disabled) = reply? else {
        return Err("Unexpected startup helper reply".into());
    };
    if key.get_raw_value(&name).is_ok() {
        return Err("Owned startup source was not disabled".into());
    }
    let mut restore = entry;
    restore.state = "Disabled by Unbolt".into();
    restore.backup = disabled
        .backup
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .map(str::to_owned);
    let reply = client::invoke_at(
        Operation::startup(&restore, Change::Restore)?,
        &flag,
        &data,
        false,
    )?;
    let restored = key.get_raw_value(&name).map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::json!({"disabled":disabled,"restored":reply,"raw_type_preserved":restored.vtype==REG_EXPAND_SZ,"raw_bytes_preserved":restored.bytes.as_ref()==bytes})
    );
    Ok(())
}
