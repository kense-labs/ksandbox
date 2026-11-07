# KSandbox

KSandbox is a Rust-native, fail-closed **process sandbox for agents**. It runs untrusted tool commands as a bounded process tree, with workspace, credential, environment, network, and lifecycle limits enforced by the host OS—so any agent host (CLI, IDE, orchestrator, or SDK) can embed the same boundary.

There is no Node.js runtime, npm package, or product-specific daemon in the execution path.

English | [简体中文](README.zh-CN.md)

## How it works

KSandbox is a **library and CLI, not a daemon**. Your agent constructs a `NativeSandbox` for one workspace, then runs tool commands through it:

- Policy is the single source of truth. Platform backends enforce it; they never silently broaden when a host feature is missing.
- Backends are selected at compile time: Seatbelt on macOS, Bubblewrap + seccomp on Linux, AppContainer + Job Object on Windows.
- Missing launchers, unavailable namespaces, or failed capability probes return an error instead of executing on the host.
- Captured output is bounded (100 KiB). Deadlines terminate the complete descendant tree.

```text
CommandRequest
    │
    ├── canonical workspace + private scratch directory
    ├── sanitized environment + protected path set
    └── native backend
          ├── macOS  → Seatbelt
          ├── Linux  → Bubblewrap + seccomp
          └── Windows → AppContainer + Job Object
                    │
                    └── bounded CommandOutput + observer events
```

## Quick start

Add the crate from this repository (crate versions are immutable when published; bump intentionally):

```toml
[dependencies]
ksandbox = { git = "https://github.com/kense-labs/ksandbox" }
```

Run a command through the native boundary:

```rust,no_run
use ksandbox::NativeSandbox;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let workspace = std::env::current_dir()?;
    let sandbox = NativeSandbox::new(workspace)?;

    // Fail before running a tool when the host cannot provide the boundary.
    sandbox.probe().await?;

    let output = sandbox.exec_command("echo inside sandbox").await?;
    println!("{}", output.stdout);
    Ok(())
}
```

`CommandOutput` contains separate `stdout` and `stderr`, an exit code, and a `timed_out` flag. An optional `OutputObserver` can receive live deltas and final accounting.

### CLI

```sh
cargo build --release
./target/release/ksandbox probe
./target/release/ksandbox exec -- 'echo inside sandbox'
./target/release/ksandbox capabilities
./target/release/ksandbox digest
```

`ksandbox-relay` is the guest TCP→Unix CONNECT helper used by the Linux netns mediation bridge. Build it alongside `ksandbox`, place it next to the host executable, or set `K_SANDBOX_RELAY`.

## What is enforced

The default agent profile is intentionally strict:

- network access and host Unix-domain sockets are denied
- writes are limited to the canonical workspace and a private scratch directory
- credentials, secret files, `.git`, agent metadata, and shell/tool bootstrap files are protected
- symbolic-link escapes and source-tree hard-link aliases are rejected
- child environments are sanitized; shell injection variables are removed
- host-held secrets are delivered only as redacted sentinels unless mediation is active
- deadlines kill the full descendant tree; output capture stays bounded
- a missing launcher or failed probe errors out instead of running on the host

These guarantees apply to the process tree, not only the first shell. See [SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md) for platform claims, residuals, and protected paths.

## Native boundaries

| Host | Boundary | Host requirement |
| --- | --- | --- |
| macOS | Seatbelt profile plus process-group lifecycle | System `/usr/bin/sandbox-exec` |
| Linux | Bubblewrap user/mount/PID/IPC/UTS namespaces plus seccomp | `bwrap` (via `K_SANDBOX_BWRAP_PATH`, `/usr/bin/bwrap`, or `PATH`) and an unprivileged user namespace |
| Windows | PowerShell 7 inside an AppContainer, restricted workspace ACLs, temporary drive, and kill-on-close Job Object | PowerShell 7 under system Program Files |
| Other targets | Explicit unsupported-platform error | No host fallback |

Windows executions are serialized because temporary ACL and device-map changes are shared process state; cleanup restores the exact prior ACL state.

## Scope

The deny-all baseline is shipped and tested on macOS, Linux, and Windows. Later gates add typed policy, resource quotas, deeper mounts, opt-in mediated HTTP(S) / SOCKS, grants, and security release packaging. Virtual bash and in-process language VMs are non-goals.

See [ROADMAP.md](ROADMAP.md) for ranked capabilities and exit criteria. Release evidence helpers live under [docs/](docs/) and `scripts/`.

## Development

Install the platform prerequisites, then run the same gates used by CI:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

The CI matrix covers `ubuntu-latest`, `macos-14`, and `windows-latest`. Security-sensitive changes should include a negative test proving that a denied operation cannot reach the host through a descendant, inherited handle, environment variable, symlink, hard link, socket, or alternate network path.

Generate a CycloneDX SBOM:

```sh
./scripts/generate-sbom.sh sbom.cdx.json
```

## License

MIT. See [LICENSE](LICENSE).
