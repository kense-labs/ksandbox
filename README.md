# KSandbox

A Rust-native, fail-closed **process sandbox for agents**. Embed it in any agent host—CLI, IDE, orchestrator, or SDK—to run untrusted tool commands as an OS-enforced process tree with workspace, credential, environment, network, and lifecycle limits.

English | [简体中文](README.zh-CN.md)

## How it works

KSandbox is a **library and CLI**. The agent binds one `NativeSandbox` to a workspace, then executes tool commands through it:

- Policy decides; the OS backend enforces. Missing host capabilities fail closed—never silent fallback to bare execution.
- Compile-time backends: Seatbelt (macOS), Bubblewrap + seccomp (Linux), AppContainer + Job Object (Windows).
- Output is capped at 100 KiB; timeouts kill the full descendant tree.

```text
Agent / host
    │
    ▼
NativeSandbox + SandboxPolicy
    │
    ├── workspace + private scratch
    ├── sanitized environment
    └── OS backend → bounded CommandOutput
```

## Quick start

```toml
[dependencies]
ksandbox = { git = "https://github.com/kense-labs/ksandbox" }
```

```rust,no_run
use ksandbox::NativeSandbox;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let sandbox = NativeSandbox::new(std::env::current_dir()?)?;
    sandbox.probe().await?; // fail if the host cannot provide the boundary

    let output = sandbox.exec_command("echo inside sandbox").await?;
    println!("{}", output.stdout);
    Ok(())
}
```

`CommandOutput` has separate `stdout` / `stderr`, an exit code, and `timed_out`. Attach an `OutputObserver` for live deltas.

### CLI

```sh
cargo build --release
./target/release/ksandbox probe
./target/release/ksandbox exec -- 'echo inside sandbox'
./target/release/ksandbox capabilities
./target/release/ksandbox digest
```

For Linux mediated networking, also build `ksandbox-relay` (guest TCP→Unix bridge) and place it next to the host binary, or set `K_SANDBOX_RELAY`.

## Default policy

Deny-all by default; guarantees apply to the whole process tree:

- no network or host Unix-domain sockets
- writes only under the workspace and a private scratch directory
- credentials, `.git`, agent metadata, and shell/tool bootstrap files protected
- symlink / hardlink escape paths rejected
- environment scrubbed; host secrets never land in the child (sentinels only unless mediation is on)
- missing launcher or failed probe → error, not host execution

Details: [SECURITY.md](SECURITY.md), [THREAT_MODEL.md](THREAT_MODEL.md).

## Platforms

| Host | Boundary | Requirement |
| --- | --- | --- |
| macOS | Seatbelt + process-group lifecycle | `/usr/bin/sandbox-exec` |
| Linux | Bubblewrap namespaces + seccomp | `bwrap` + unprivileged user namespaces |
| Windows | AppContainer + Job Object (PowerShell 7) | PowerShell 7 under Program Files |
| Other | Unsupported | No host fallback |

Opt-in surfaces (mediated HTTP/SOCKS, grants, deeper mounts) stay off until enabled and only where the backend can enforce them.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

CI: `ubuntu-latest`, `macos-14`, `windows-latest`. Roadmap and release evidence: [ROADMAP.md](ROADMAP.md), [docs/](docs/).

## License

MIT. See [LICENSE](LICENSE).
