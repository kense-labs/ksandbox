//! Gate 7: SBOM generation must name this crate and its direct graph.
//!
//! The checked-in generator is a bash script; run it on Unix CI/builders.
//! Windows release SBOMs are produced on a Unix host (see RELEASE_CHECKLIST).

#![cfg(unix)]

use std::process::Command;

#[test]
fn gate7_sbom_script_emits_cyclonedx_with_ksandbox() {
    let out = tempfile::NamedTempFile::new().unwrap();
    let out_path = out.path();
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/generate-sbom.sh");
    let status = Command::new("bash")
        .arg(script)
        .arg(out_path)
        .status()
        .expect("failed to spawn SBOM script");
    assert!(status.success(), "generate-sbom.sh failed: {status}");

    let body = std::fs::read_to_string(out_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["bomFormat"], "CycloneDX");
    assert_eq!(json["specVersion"], "1.5");
    // The SBOM root component is named from cargo metadata, so the assertion
    // follows this crate's package name instead of a hardcoded string.
    let pkg_name = env!("CARGO_PKG_NAME");
    assert_eq!(json["metadata"]["component"]["name"], pkg_name);
    let names = json["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["name"].as_str())
        .collect::<Vec<_>>();
    assert!(
        names.contains(&pkg_name),
        "SBOM missing {pkg_name} component: {names:?}"
    );
    assert!(
        names.contains(&"tokio"),
        "SBOM missing tokio (direct dependency): {names:?}"
    );
}
