#![cfg(test)]

use super::*;

#[test]
fn snapshot_preserves_nested_credentials_package_aliases_and_control_write_exceptions() {
    let workspace = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let root = workspace.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("nested")).unwrap();
    std::fs::create_dir_all(root.join("node_modules/package")).unwrap();
    std::fs::write(root.join("nested/.env.production"), "SECRET=1").unwrap();
    std::fs::hard_link(
        root.join("nested/.env.production"),
        root.join("node_modules/package/config"),
    )
    .unwrap();
    std::fs::write(root.join("source.rs"), "fn main() {}").unwrap();
    let snapshot = WorkspaceFilesystemBoundary::compile(
        &SandboxPolicy::kbash_baseline(),
        &root,
        scratch.path(),
    )
    .unwrap();
    for secret in ["nested/.env.production", "node_modules/package/config"] {
        assert!(snapshot.deny_read.contains(&root.join(secret)), "{secret}");
        assert!(
            snapshot
                .deny_write
                .iter()
                .any(|path| root.join(secret).starts_with(path)),
            "{secret}"
        );
    }
    for control in [".git", ".kbox", ".agents"] {
        assert!(snapshot.deny_write.contains(&root.join(control)));
    }
    assert!(snapshot
        .write_exceptions
        .contains(&root.join(".kbox/loops")));
    assert!(!snapshot
        .deny_read
        .iter()
        .any(|path| root.join("source.rs").starts_with(path)));
    assert!(snapshot
        .deny_read
        .iter()
        .all(|path| path.starts_with(&root)));
    assert_eq!(snapshot.workspace, root);
}
