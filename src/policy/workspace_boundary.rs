use std::path::{Path, PathBuf};

use anyhow::Result;

use super::{BackendCapabilities, EnforcedPolicy, SandboxPolicy};

/// Native policy snapshot for another executor sharing the same workspace.
/// Paths outside the workspace remain the executor's default-denied responsibility.
#[derive(Debug, Clone)]
pub struct WorkspaceFilesystemBoundary {
    /// Canonical workspace root against which these absolute paths were resolved.
    pub workspace: PathBuf,
    /// Subtrees whose data must not be read.
    pub deny_read: Vec<PathBuf>,
    /// Subtrees that must not be mutated, including protected control metadata.
    pub deny_write: Vec<PathBuf>,
    /// Writable subtrees beneath otherwise write-denied control metadata.
    pub write_exceptions: Vec<PathBuf>,
}

impl WorkspaceFilesystemBoundary {
    /// Compile the existing native policy, including credential and hard-link discovery.
    /// This produces policy facts; callers must prove their executor enforces them.
    pub fn compile(document: &SandboxPolicy, workspace: &Path, scratch: &Path) -> Result<Self> {
        let policy = EnforcedPolicy::compile(
            document,
            workspace,
            scratch,
            BackendCapabilities::native_gate2(),
        )?;
        let workspace = policy.workspace;
        let within_workspace = |paths: Vec<PathBuf>| {
            paths
                .into_iter()
                .filter(|path| path.starts_with(&workspace))
                .collect()
        };
        Ok(Self {
            deny_read: within_workspace(policy.deny_read),
            deny_write: within_workspace(policy.deny_write),
            write_exceptions: within_workspace(policy.write_exceptions),
            workspace,
        })
    }
}

#[cfg(test)]
#[path = "workspace_boundary_tests.rs"]
mod tests;
