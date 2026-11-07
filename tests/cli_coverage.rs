//! Extra CLI coverage: help/errors/probe/relay parse + short-lived relay bind.

use std::process::{Command, Stdio};
use std::time::Duration;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ksandbox")
}

fn relay_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ksandbox-relay")
}

#[test]
fn cli_missing_command_prints_usage() {
    let output = Command::new(bin()).output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Usage:"), "{stderr}");
    assert!(stderr.contains("missing command"), "{stderr}");
}

#[test]
fn cli_help_flags_succeed() {
    for flag in ["help", "-h", "--help"] {
        let output = Command::new(bin()).arg(flag).output().unwrap();
        assert!(
            output.status.success(),
            "flag={flag} stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("Usage:"), "flag={flag} stderr={stderr}");
    }
}

#[test]
fn cli_unknown_command_fails() {
    let output = Command::new(bin()).arg("not-a-command").output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown command"), "{stderr}");
}

#[test]
fn cli_probe_reports_backend() {
    let workspace = tempfile::tempdir().unwrap();
    let output = Command::new(bin())
        .args(["probe", "--workspace", workspace.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ok backend="), "{stdout}");
    assert!(stdout.contains("unavailable="), "{stdout}");
}

#[test]
fn cli_exec_rejects_missing_separator() {
    let workspace = tempfile::tempdir().unwrap();
    let output = Command::new(bin())
        .args([
            "exec",
            "--workspace",
            workspace.path().to_str().unwrap(),
            "echo",
            "no-dash-dash",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unexpected argument") || stderr.contains("use --"),
        "{stderr}"
    );
}

#[test]
fn cli_exec_rejects_empty_command_after_separator() {
    let workspace = tempfile::tempdir().unwrap();
    let output = Command::new(bin())
        .args([
            "exec",
            "--workspace",
            workspace.path().to_str().unwrap(),
            "--",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requires a command"), "{stderr}");
}

#[test]
fn cli_relay_requires_unix_path() {
    let output = Command::new(bin()).args(["relay"]).output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("relay requires --unix"), "{stderr}");
}

#[test]
fn cli_relay_rejects_bad_listen_and_unknown_flag() {
    let output = Command::new(bin())
        .args(["relay", "--unix", "/tmp/x.sock", "--listen", "not-an-addr"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("listen") || stderr.contains("invalid"),
        "{stderr}"
    );

    let output = Command::new(bin())
        .args(["relay", "--unix", "/tmp/x.sock", "--bogus"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unexpected argument"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn relay_binary_help_and_error_paths() {
    let help = Command::new(relay_bin()).arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(
        String::from_utf8_lossy(&help.stderr).contains("Usage:"),
        "{}",
        String::from_utf8_lossy(&help.stderr)
    );

    let missing = Command::new(relay_bin()).output().unwrap();
    assert!(!missing.status.success());
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("missing --unix"),
        "{}",
        String::from_utf8_lossy(&missing.stderr)
    );

    let bad = Command::new(relay_bin())
        .args(["--unix", "/tmp/x.sock", "--nope"])
        .output()
        .unwrap();
    assert!(!bad.status.success());
    assert!(
        String::from_utf8_lossy(&bad.stderr).contains("unexpected argument"),
        "{}",
        String::from_utf8_lossy(&bad.stderr)
    );

    let bad_listen = Command::new(relay_bin())
        .args(["--unix", "/tmp/x.sock", "--listen", "bad"])
        .output()
        .unwrap();
    assert!(!bad_listen.status.success());
}

#[cfg(unix)]
#[tokio::test]
async fn relay_library_forwards_and_cli_relay_starts() {
    use ksandbox::TcpUnixRelay;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener as TokioTcpListener, TcpStream, UnixListener};

    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("upstream.sock");
    let unix_listener = UnixListener::bind(&sock).unwrap();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = unix_listener.accept().await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });

    let relay = TcpUnixRelay::bind("127.0.0.1:0".parse().unwrap(), &sock)
        .await
        .unwrap();
    let addr = relay.listen_addr();
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(b"ping").await.unwrap();
    let mut reply = [0u8; 4];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"pong");
    relay.shutdown().await;
    upstream.await.unwrap();

    // Cover CLI `ksandbox relay` parse + bind without hanging the suite:
    // bind an ephemeral TCP port, start the CLI against a dummy unix socket,
    // confirm the port is taken, then kill.
    let sock2 = dir.path().join("cli.sock");
    let _keep = UnixListener::bind(&sock2).unwrap();
    let probe = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = probe.local_addr().unwrap();
    drop(probe);

    let mut child = Command::new(bin())
        .args([
            "relay",
            "--unix",
            sock2.to_str().unwrap(),
            "--listen",
            &listen.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let mut bound = false;
    for _ in 0..50 {
        if TcpStream::connect(listen).await.is_ok() {
            bound = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(bound, "CLI relay never accepted connections on {listen}");

    // Same bind path via ksandbox-relay binary (help/errors covered above).
    let sock3 = dir.path().join("bin.sock");
    let _keep3 = UnixListener::bind(&sock3).unwrap();
    let probe = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = probe.local_addr().unwrap();
    drop(probe);
    let mut child = Command::new(relay_bin())
        .args([
            "--unix",
            sock3.to_str().unwrap(),
            "--listen",
            &listen.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut bound = false;
    for _ in 0..50 {
        if TcpStream::connect(listen).await.is_ok() {
            bound = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        bound,
        "ksandbox-relay never accepted connections on {listen}"
    );
}
