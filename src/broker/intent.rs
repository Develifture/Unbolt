//! Compact reviewed intents. Registry values and arbitrary command payloads are
//! rebuilt from current state rather than accepted from the pipe.
use crate::{UnboltResult, crypto, forced, inventory, model::*, uninstall};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::atomic::AtomicBool};
pub const PROTOCOL: u32 = 1;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "source", deny_unknown_fields)]
pub enum Target {
    Registered {
        id: String,
        expected: [u8; 32],
    },
    Folder {
        name: String,
        path: PathBuf,
        expected: [u8; 32],
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIntent {
    pub path: PathBuf,
    pub snapshot: FileSnapshot,
    pub signature: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyIntent {
    pub source: RegistrySource,
    pub fingerprint: [u8; 32],
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "operation", content = "intent", deny_unknown_fields)]
pub enum Operation {
    Inspect,
    Forced {
        target: Target,
        files: Vec<FileIntent>,
        registry: Vec<KeyIntent>,
    },
    Uninstall {
        target: Target,
        mode: uninstall::Mode,
        command: [u8; 32],
        binary: [u8; 32],
    },
    Startup {
        source: crate::startup::Source,
        backup: Option<String>,
        expected: [u8; 32],
        change: crate::startup::Change,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub protocol: u32,
    pub data: PathBuf,
    pub operation: Operation,
    pub fixture: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "message", content = "data", deny_unknown_fields)]
pub enum Message {
    Hello { protocol: u32, nonce: String },
    Request(Box<Request>),
    Cancel,
    Result(Reply),
    Failed(String),
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", content = "data", deny_unknown_fields)]
pub enum Reply {
    Inspect {
        caller_sid: String,
        elevated: bool,
        data: PathBuf,
    },
    Forced(forced::Outcome),
    Uninstall(uninstall::UninstallOutcome),
    Startup(crate::startup::Outcome),
}

fn target(app: &Application) -> UnboltResult<Target> {
    let expected = crypto::fingerprint(app)?;
    if app.sources.is_empty() {
        Ok(Target::Folder {
            name: app.name.clone(),
            path: app
                .location
                .clone()
                .ok_or("A manual target needs its directory")?,
            expected,
        })
    } else {
        Ok(Target::Registered {
            id: app.id.clone(),
            expected,
        })
    }
}
impl Operation {
    pub fn startup(
        entry: &crate::startup::Entry,
        change: crate::startup::Change,
    ) -> UnboltResult<Self> {
        if !entry.mutable() {
            return Err("Startup item needs review before it can change".into());
        }
        Ok(Self::Startup {
            source: entry.source.clone(),
            backup: entry.backup.clone(),
            expected: entry.fingerprint()?,
            change,
        })
    }
    pub fn forced(plan: &forced::Plan, selection: &forced::Selection) -> UnboltResult<Self> {
        let mut files = Vec::new();
        let mut registry = Vec::new();
        for &i in &selection.files {
            let c = plan
                .report
                .candidates
                .get(i)
                .ok_or("File selection outside review")?;
            if c.confidence != Confidence::High {
                return Err("A selected file item still needs review".into());
            }
            files.push(FileIntent {
                path: c.path.clone(),
                snapshot: c.snapshot.clone(),
                signature: c.tree_signature,
            });
        }
        for &i in &selection.registry {
            let c = plan
                .report
                .registry_candidates
                .get(i)
                .ok_or("Registry selection outside review")?;
            if c.confidence != Confidence::High {
                return Err("A selected registry item still needs review".into());
            }
            registry.push(KeyIntent {
                source: c.source.clone(),
                fingerprint: crypto::fingerprint(&c.snapshot)?,
            });
        }
        Ok(Self::Forced {
            target: target(&plan.report.app)?,
            files,
            registry,
        })
    }
    pub fn uninstall(app: &Application, mode: uninstall::Mode) -> UnboltResult<Self> {
        let prepared = uninstall::prepare_mode(app, mode)?;
        Ok(Self::Uninstall {
            target: target(app)?,
            mode,
            command: crypto::fingerprint(&prepared)?,
            binary: crypto::file(std::path::Path::new(&prepared.executable))?,
        })
    }
}
impl Target {
    pub fn resolve(&self, cancel: &AtomicBool) -> UnboltResult<Application> {
        let (app, expected) = match self {
            Self::Registered { id, expected } => {
                if id.len() > 32768 || id.contains('\0') {
                    return Err("Invalid application identity".into());
                }
                let current = inventory::collect(cancel);
                if current.cancelled || !current.errors.is_empty() {
                    return Err("Current application inventory could not be verified".into());
                }
                (
                    current
                        .apps
                        .into_iter()
                        .find(|a| a.id == *id)
                        .ok_or("Selected application changed; review again")?,
                    expected,
                )
            }
            Self::Folder {
                name,
                path,
                expected,
            } => (forced::folder_target(name, path)?, expected),
        };
        if crypto::fingerprint(&app)? != *expected {
            return Err("Application details changed since review".into());
        }
        Ok(app)
    }
}
pub fn resolve_selection(
    plan: &forced::Plan,
    files: &[FileIntent],
    keys: &[KeyIntent],
) -> UnboltResult<forced::Selection> {
    if files.len() > 100_000 || keys.len() > 4096 || files.is_empty() && keys.is_empty() {
        return Err("Invalid helper selection size".into());
    }
    let mut result = forced::Selection::default();
    for intent in files {
        let i = plan
            .report
            .candidates
            .iter()
            .position(|c| {
                c.path == intent.path
                    && c.snapshot == intent.snapshot
                    && c.tree_signature == intent.signature
                    && c.confidence == Confidence::High
            })
            .ok_or("Selected directory changed or no longer supports cleanup")?;
        result.files.push(i);
    }
    for intent in keys {
        let mut matched = None;
        for (i, c) in plan.report.registry_candidates.iter().enumerate() {
            if c.source == intent.source
                && c.confidence == Confidence::High
                && crypto::fingerprint(&c.snapshot)? == intent.fingerprint
            {
                matched = Some(i);
                break;
            }
        }
        result
            .registry
            .push(matched.ok_or("Selected registry key changed or no longer supports cleanup")?);
    }
    result.files.sort_unstable();
    result.files.dedup();
    result.registry.sort_unstable();
    result.registry.dedup();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn arbitrary_command_and_unknown_request_fields_are_not_protocol_operations() {
        let raw = serde_json::json!({"protocol":1,"data":"C:\\Temp\\Unbolt","fixture":false,"operation":{"operation":"Run","intent":{"executable":"cmd.exe","arguments":["/c","anything"]}}});
        assert!(serde_json::from_value::<Request>(raw).is_err());
        let raw = serde_json::json!({"protocol":1,"data":"C:\\Temp\\Unbolt","fixture":false,"extra":true,"operation":{"operation":"Inspect"}});
        assert!(serde_json::from_value::<Request>(raw).is_err());
    }
}
