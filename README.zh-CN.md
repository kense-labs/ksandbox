# KSandbox

[English](README.md) | 简体中文

KSandbox 是面向**任意 Agent** 的 Rust 原生、失败闭合（fail-closed）**进程沙箱**。它把不受信任的工具命令关进有界进程树，由宿主操作系统强制执行工作区、凭证、环境、网络与生命周期限制；CLI、IDE、编排器或 SDK 都可以嵌入同一套边界。

执行路径中没有 Node.js 运行时、npm 包或产品专用守护进程。

## 工作模型

KSandbox 是 **库与 CLI，不是守护进程**。Agent 为主机工作区构造 `NativeSandbox`，再通过它执行工具命令：

- 策略层是唯一真相来源。平台后端强制执行策略；宿主功能缺失时不会静默放宽。
- 后端在编译时选择：macOS 用 Seatbelt，Linux 用 Bubblewrap + seccomp，Windows 用 AppContainer + Job Object。
- 缺少启动器、命名空间不可用或能力探测失败时返回错误，而不是在宿主上执行。
- 捕获输出上限为 100 KiB。截止时间会终止完整的后代进程树。

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

## 快速开始

从本仓库引入 crate（发布版本不可变；升级时请有意改版本号）：

```toml
[dependencies]
ksandbox = { git = "https://github.com/kense-labs/ksandbox" }
```

通过原生边界运行命令：

```rust,no_run
use ksandbox::NativeSandbox;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let workspace = std::env::current_dir()?;
    let sandbox = NativeSandbox::new(workspace)?;

    // 宿主无法提供边界时，先失败，不要跑工具。
    sandbox.probe().await?;

    let output = sandbox.exec_command("echo inside sandbox").await?;
    println!("{}", output.stdout);
    Ok(())
}
```

`CommandOutput` 包含分开的 `stdout` 与 `stderr`、退出码，以及 `timed_out` 标志。可选的 `OutputObserver` 可接收实时增量与最终核算。

### CLI

```sh
cargo build --release
./target/release/ksandbox probe
./target/release/ksandbox exec -- 'echo inside sandbox'
./target/release/ksandbox capabilities
./target/release/ksandbox digest
```

`ksandbox-relay` 是 Linux netns 中介桥使用的客体内 TCP→Unix CONNECT 助手。与 `ksandbox` 一并构建，放到宿主可执行文件旁，或设置 `K_SANDBOX_RELAY`。

## 当前强制执行的内容

默认的 Agent 配置故意严格：

- 拒绝网络访问与宿主 Unix 域套接字
- 写入仅限于规范工作区与私有临时目录
- 保护凭证、密钥文件、`.git`、Agent 元数据，以及 shell/工具引导文件
- 拒绝符号链接与源树硬链接逃逸
- 清理子进程环境，并移除 shell 注入变量
- 宿主持有密钥仅以脱敏哨兵下发；未开启中介时拒绝运行
- 截止时间终止完整后代树，输出捕获保持有界
- 缺少启动器或探测失败时返回错误，而不是在宿主上执行

这些保证适用于进程树，而不仅是第一个 shell。威胁模型、平台注意事项与精确受保护路径见 [SECURITY.md](SECURITY.md) 与 [THREAT_MODEL.md](THREAT_MODEL.md)。

## 原生边界

| 宿主 | 边界 | 宿主要求 |
| --- | --- | --- |
| macOS | Seatbelt 配置文件加上进程组生命周期 | 系统 `/usr/bin/sandbox-exec` |
| Linux | Bubblewrap 用户/挂载/PID/IPC/UTS 命名空间加上 seccomp | `bwrap`（经 `K_SANDBOX_BWRAP_PATH`、`/usr/bin/bwrap` 或 `PATH`）与非特权用户命名空间 |
| Windows | AppContainer 内的 PowerShell 7、受限工作区 ACL、临时驱动器，以及 kill-on-close Job Object | 系统 Program Files 下的 PowerShell 7 |
| 其他目标 | 显式的不支持平台错误 | 无宿主回退 |

Windows 执行会串行化，因为临时 ACL 与设备映射变更是共享进程状态；清理会恢复精确的先前 ACL 状态。

## 范围

Deny-all 基线已在 macOS、Linux 与 Windows 上交付并测试。后续门禁按第一性原理排序：类型化策略、资源配额、更深挂载、可选中介 HTTP(S)/SOCKS、grant，以及安全发布。虚拟 bash 与进程内语言 VM 为非目标。

使命、非目标与退出条件见 [ROADMAP.md](ROADMAP.md)。发布证据脚本见 [docs/](docs/) 与 `scripts/`。

## 开发

安装平台前置条件，然后运行与 CI 相同的门禁：

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

CI 矩阵覆盖 `ubuntu-latest`、`macos-14` 与 `windows-latest`。安全敏感变更应包含负面测试，证明被拒绝的操作无法通过后代、继承句柄、环境变量、符号链接、硬链接、套接字或替代网络路径到达宿主。

生成 CycloneDX SBOM：

```sh
./scripts/generate-sbom.sh sbom.cdx.json
```

## 许可证

MIT。见 [LICENSE](LICENSE)。
