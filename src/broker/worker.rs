use super::{
    identity::{self, Peer},
    intent::{Message, Operation, PROTOCOL, Reply, Request},
    transport::Pipe,
};
use crate::{UnboltResult, context, crypto, forced, process, uninstall};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

pub fn main_from_args() -> UnboltResult<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 5 || args[0] != "--ipc" || !crypto::valid_nonce(&args[2]) {
        return Err("This component is started by Unbolt for one reviewed operation".into());
    }
    let expected_pid = args[3]
        .parse::<u32>()
        .map_err(|_| "Invalid caller process")?;
    let expected_created = args[4]
        .parse::<u64>()
        .map_err(|_| "Invalid caller creation time")?;
    serve(&args[1], &args[2], expected_pid, expected_created)
}
fn serve(name: &str, nonce: &str, parent_pid: u32, parent_created: u64) -> UnboltResult<()> {
    let pipe = Pipe::open(name)?;
    if pipe.server_pid()? != parent_pid {
        return Err("Helper endpoint belongs to a different Unbolt process".into());
    }
    let parent = identity::process(parent_pid)?;
    if parent.created != parent_created {
        return Err("Unbolt process identity was reused".into());
    }
    identity::check_parent(&parent)?;
    let cancel = Arc::new(AtomicBool::new(false));
    pipe.send(
        &Message::Hello {
            protocol: PROTOCOL,
            nonce: nonce.into(),
        },
        &cancel,
    )?;
    let request = match pipe.receive(&cancel, Duration::from_secs(30))? {
        Message::Request(request) if request.protocol == PROTOCOL => *request,
        _ => return Err("Unsupported helper request".into()),
    };
    let parent_now = identity::process(parent_pid)?;
    identity::check_peer(&parent_now, &parent)?;
    let scope = identity::scope(&parent, &request.data)?;
    let flag = cancel.clone();
    let peer = parent.clone();
    let task =
        thread::spawn(move || context::with_scope(scope, || dispatch(request, &peer, &flag)));
    let mut connected = true;
    let mut protocol_error = None;
    while !task.is_finished() {
        match pipe.available() {
            Ok(true) => match pipe.receive(&AtomicBool::new(false), Duration::from_secs(5)) {
                Ok(Message::Cancel) => cancel.store(true, Ordering::Relaxed),
                _ => {
                    cancel.store(true, Ordering::Relaxed);
                    protocol_error = Some(
                        "Helper operation stopped because its control messages changed".to_string(),
                    );
                    break;
                }
            },
            Ok(false) => {}
            Err(_) => {
                connected = false;
                cancel.store(true, Ordering::Relaxed);
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    let result = task
        .join()
        .map_err(|_| "Helper operation failed internally")?;
    if connected {
        let message = match protocol_error {
            Some(error) => Message::Failed(error),
            None => match result {
                Ok(reply) => Message::Result(reply),
                Err(error) => Message::Failed(error),
            },
        };
        let _ = pipe.send(&message, &AtomicBool::new(false));
    }
    // Retain job/process handles after the desktop closes or stops its queue.
    process::wait_for_background_monitors();
    Ok(())
}
fn dispatch(request: Request, parent: &Peer, cancel: &AtomicBool) -> UnboltResult<Reply> {
    let elevated = identity::elevated()?;
    if let Operation::Inspect = request.operation {
        return Ok(Reply::Inspect {
            caller_sid: parent.sid.clone(),
            elevated,
            data: crate::recovery::data_dir(),
        });
    }
    if request.fixture && !fixture_allowed(&request.operation, &request.data) {
        return Err("Operation is outside the controlled helper fixture".into());
    }
    if !elevated && !request.fixture {
        return Err("Administrator access is required for this helper operation".into());
    }
    match request.operation {
        Operation::Forced {
            target,
            files,
            registry,
        } => {
            let app = target.resolve(cancel)?;
            if let Some(path) = app.location.as_deref() {
                identity::check_chain(path, true)?;
            }
            if request.fixture {
                check_fixture_app(&app, &request.data)?;
            }
            let plan = forced::preview(&app, cancel)?;
            let selection = super::intent::resolve_selection(&plan, &files, &registry)?;
            forced::execute(&plan, &selection, cancel).map(Reply::Forced)
        }
        Operation::Uninstall {
            target,
            mode,
            command,
            binary,
        } => {
            let app = target.resolve(cancel)?;
            if request.fixture {
                check_fixture_app(&app, &request.data)?;
            }
            if crypto::fingerprint(&uninstall::prepare_mode(&app, mode)?)? != command {
                return Err("Uninstall command changed since review".into());
            }
            let prepared = uninstall::prepare_mode(&app, mode)?;
            identity::check_chain(std::path::Path::new(&prepared.executable), false)?;
            if crypto::file(std::path::Path::new(&prepared.executable))? != binary {
                return Err("Uninstaller binary changed since review".into());
            }
            uninstall::run_mode(&app, mode, cancel).map(Reply::Uninstall)
        }
        Operation::Inspect => unreachable!(),
        Operation::Startup {
            source,
            backup,
            expected,
            change,
        } => {
            let entry = crate::startup::resolve(&source, backup.as_deref(), cancel)?;
            if entry.fingerprint()? != expected {
                return Err("Startup item changed since review".into());
            }
            crate::startup::change(&entry, change, cancel).map(Reply::Startup)
        }
    }
}
fn fixture_allowed(operation: &Operation, data: &std::path::Path) -> bool {
    #[cfg(feature = "test-fixtures")]
    {
        let parent = data.parent();
        let fixture = parent
            .and_then(|p| p.file_name())
            .and_then(|p| p.to_str())
            .is_some_and(|p| p.starts_with("unbolt-helper-fixture-"));
        if !fixture {
            return false;
        }
        if let Operation::Startup { source, .. } = operation {
            return matches!(source,crate::startup::Source::Registry{location,name}if location.hive=="HKCU"&&name.starts_with("UnboltStartupFixture"));
        }
        let target = match operation {
            Operation::Forced { target, .. } | Operation::Uninstall { target, .. } => target,
            _ => return false,
        };
        match target {
            super::intent::Target::Registered { id, .. } => {
                id.starts_with("HKCU:")
                    && id
                        .rsplit('\\')
                        .next()
                        .is_some_and(|n| n.to_ascii_lowercase().starts_with("unbolthelperfixture"))
            }
            super::intent::Target::Folder { name, path, .. } => {
                name.starts_with("UnboltHelperFixture")
                    && parent.is_some_and(|p| {
                        path.starts_with(p) && path.file_name().is_some_and(|n| n == "App")
                    })
            }
        }
    }
    #[cfg(not(feature = "test-fixtures"))]
    {
        let _ = (operation, data);
        false
    }
}
fn check_fixture_app(app: &crate::model::Application, data: &std::path::Path) -> UnboltResult<()> {
    if !app.name.starts_with("UnboltHelperFixture")
        || !app
            .location
            .as_ref()
            .is_some_and(|p| std::fs::canonicalize(p).ok() == data.parent().map(|p| p.join("App")))
        || app.sources.iter().any(|s| {
            s.hive != "HKCU"
                || !s
                    .key
                    .rsplit('\\')
                    .next()
                    .is_some_and(|n| n.starts_with("UnboltHelperFixture"))
        })
    {
        return Err("Controlled helper fixture points outside its owned resources".into());
    }
    Ok(())
}
