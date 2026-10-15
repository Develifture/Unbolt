use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistrySource {
    pub hive: String,
    pub view: u32,
    pub key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Application {
    pub id: String,
    pub name: String,
    pub publisher: String,
    pub version: String,
    pub location: Option<PathBuf>,
    pub uninstall: String,
    pub quiet_uninstall: String,
    pub size_kib: Option<u32>,
    pub system_component: bool,
    pub sources: Vec<RegistrySource>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Inventory {
    pub apps: Vec<Application>,
    pub errors: Vec<String>,
    pub elapsed_ms: u128,
    pub cancelled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Confidence {
    High,
    Review,
    Blocked,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Candidate {
    pub path: PathBuf,
    pub confidence: Confidence,
    pub evidence: String,
    pub snapshot: FileSnapshot,
    pub tree_signature: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileSnapshot {
    pub is_dir: bool,
    pub len: u64,
    pub modified_ns: u128,
    pub created_ticks: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanReport {
    pub app: Application,
    pub candidates: Vec<Candidate>,
    #[serde(default)]
    pub registry_candidates: Vec<crate::registry_cleanup::RegistryCandidate>,
    pub errors: Vec<String>,
    pub elapsed_ms: u128,
    pub cancelled: bool,
    pub app_registered: bool,
}

pub fn cancelled(flag: &std::sync::atomic::AtomicBool) -> bool {
    flag.load(std::sync::atomic::Ordering::Relaxed)
}
