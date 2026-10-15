//! Creates two isolated temporary backups for a real UI restore-selection check.
use std::{fs, path::PathBuf, sync::atomic::AtomicBool};
use unbolt::{model::*, recovery, scanner};
fn main() {
    let root = std::env::temp_dir().join(format!("unbolt-ui-fixture-{}", recovery::unique_id()));
    fs::create_dir_all(&root).unwrap();
    let mut outputs = Vec::new();
    let cancel = AtomicBool::new(false);
    for label in ["A", "B"] {
        let path = root.join(label);
        fs::create_dir(&path).unwrap();
        fs::write(
            path.join("verify.txt"),
            format!("Unbolt controlled UI fixture {label}"),
        )
        .unwrap();
        let app = Application {
            id: format!("unbolt-ui-fixture-{label}"),
            name: format!("Unbolt UI verification {label}"),
            publisher: "Unbolt fixture".into(),
            version: "test".into(),
            location: Some(path.clone()),
            uninstall: String::new(),
            quiet_uninstall: String::new(),
            size_kib: None,
            system_component: false,
            sources: vec![],
        };
        let candidate = Candidate {
            path: path.clone(),
            confidence: Confidence::High,
            evidence: "Controlled temporary fixture".into(),
            snapshot: scanner::snapshot(&path).unwrap(),
            tree_signature: Some(scanner::tree_signature(&path, &cancel).unwrap()),
        };
        let manifest = recovery::quarantine(&app, &candidate, &cancel).unwrap();
        outputs.push(serde_json::json!({"label":label,"original":path,"manifest":manifest}));
    }
    let output = serde_json::json!({"root":root,"fixtures":outputs});
    let report = PathBuf::from("work/ui-recovery-fixture.json");
    fs::create_dir_all("work").unwrap();
    fs::write(&report, serde_json::to_vec_pretty(&output).unwrap()).unwrap();
    println!("{}", report.display());
}
