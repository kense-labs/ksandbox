# KSandbox

[English](README.md) | 简体中文

Rust 原生、失败闭合的 **Agent 进程沙箱**。嵌入任意 Agent 宿主（CLI、IDE、编排器或 SDK），把不受信任的工具命令放进由操作系统强制的有界进程树，限制工作区、凭证、环境、网络与生命周期。

## 工作模型

KSandbox 是 **库与 CLI**。Agent 为工作区绑定一个 `NativeSandbox`，再通过它执行工具命令：

- 策略决定，OS 后端强制执行。宿主能力不足则失败闭合，绝不静默退回裸跑。
- 编译期后端：macOS Seatbelt、Linux Bubblewrap + seccomp、Windows AppContainer + Job Object。
- 输出上限 100 KiB；超时杀死整棵后代进程树。

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

## 快速开始

```toml
[dependencies]
ksandbox = { git = "https://github.com/kense-labs/ksandbox" }
```

```rust,no_run
use ksandbox::NativeSandbox;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let sandbox = NativeSandbox::new(std::env::current_dir()?)?;
    sandbox.probe().await?; // 宿主无法提供边界时先失败

    let output = sandbox.exec_command("echo inside sandbox").await?;
    println!("{}", output.stdout);
    Ok(())
}
```

`CommandOutput` 含分离的 `stdout` / `stderr`、退出码与 `timed_out`。可用 `OutputObserver` 收实时增量。

### CLI

```sh
cargo build --release
./target/release/ksandbox probe
./target/release/ksandbox exec -- 'echo inside sandbox'
./target/release/ksandbox capabilities
./target/release/ksandbox digest
```

Linux 中介网络还需构建 `ksandbox-relay`（客体内 TCP→Unix 桥），放到宿主二进制旁，或设置 `K_SANDBOX_RELAY`。

## 默认策略

默认 deny-all；保证作用于整棵进程树：

- 无网络、无宿主 Unix 域套接字
- 写入仅限工作区与私有临时目录
- 保护凭证、`.git`、Agent 元数据与 shell/工具引导文件
- 拒绝符号链接 / 硬链接逃逸
- 清理环境；密钥不进入子进程（无中介时仅哨兵）
- 缺启动器或探测失败 → 报错，不在宿主裸跑

细节见 [SECURITY.md](SECURITY.md)、[THREAT_MODEL.md](THREAT_MODEL.md)。

## 平台

| 宿主 | 边界 | 要求 |
| --- | --- | --- |
| macOS | Seatbelt + 进程组生命周期 | `/usr/bin/sandbox-exec` |
| Linux | Bubblewrap 命名空间 + seccomp | `bwrap` + 非特权用户命名空间 |
| Windows | AppContainer + Job Object（PowerShell 7） | Program Files 下的 PowerShell 7 |
| 其他 | 不支持 | 无宿主回退 |

可选能力（中介 HTTP/SOCKS、grant、更深挂载）默认关闭，且仅在后端能强制时启用。

## 开发

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

CI：`ubuntu-latest`、`macos-14`、`windows-latest`。路线图与发布证据：[ROADMAP.md](ROADMAP.md)、[docs/](docs/)。

## 许可证

MIT。见 [LICENSE](LICENSE)。
