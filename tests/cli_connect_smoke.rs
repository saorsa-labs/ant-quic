#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

fn free_localhost_addr() -> SocketAddr {
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("bind ephemeral localhost port");
    let addr = listener.local_addr().expect("get local addr");
    drop(listener);
    addr
}

fn parse_local_identity_peer_id(line: &str) -> Option<String> {
    let event = "\"event\":\"local_identity\"";
    let key = "\"peer_id\":\"";
    if !line.contains(event) {
        return None;
    }
    let start = line.find(key)? + key.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    let peer_id = &rest[..end];
    if peer_id.len() == 64 && peer_id.chars().all(|ch| ch.is_ascii_hexdigit()) {
        Some(peer_id.to_string())
    } else {
        None
    }
}

#[test]
fn cli_connect_smoke() {
    let bin = env!("CARGO_BIN_EXE_ant-quic");
    let listen_addr = free_localhost_addr();

    let mut listener = Command::new(bin)
        .arg("--listen")
        .arg(listen_addr.to_string())
        .arg("--no-default-bootstrap")
        .arg("--json")
        .arg("--duration")
        .arg("12")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn listener ant-quic");

    let listener_stdout = listener
        .stdout
        .take()
        .expect("listener stdout should be piped");
    let listener_stderr = listener
        .stderr
        .take()
        .expect("listener stderr should be piped");
    let stdout_handle = std::thread::spawn(move || {
        let reader = BufReader::new(listener_stdout);
        for line in reader.lines() {
            let _ = line.expect("read listener stdout line");
        }
    });
    let stderr_handle = std::thread::spawn(move || {
        let reader = BufReader::new(listener_stderr);
        for line in reader.lines() {
            let _ = line.expect("read listener stderr line");
        }
    });

    std::thread::sleep(Duration::from_millis(800));
    assert!(
        listener
            .try_wait()
            .expect("check listener liveness")
            .is_none(),
        "listener should still be running before launching connector"
    );

    let connector = Command::new(bin)
        .arg("--connect")
        .arg(listen_addr.to_string())
        .arg("--no-default-bootstrap")
        .arg("--json")
        .arg("--duration")
        .arg("6")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run connector ant-quic");

    assert!(
        connector.status.success(),
        "connector should exit successfully; status={:?}, stderr={} stdout={}",
        connector.status,
        String::from_utf8_lossy(&connector.stderr),
        String::from_utf8_lossy(&connector.stdout)
    );

    let connector_stdout = String::from_utf8_lossy(&connector.stdout);
    assert!(
        connector_stdout.contains("\"event\":\"peer_connected\""),
        "connector stdout should contain peer_connected JSON event; stdout={} stderr={}",
        connector_stdout,
        String::from_utf8_lossy(&connector.stderr)
    );

    let _ = listener.kill();
    let _ = listener.wait();
    stdout_handle
        .join()
        .expect("join listener stdout drain thread");
    stderr_handle
        .join()
        .expect("join listener stderr drain thread");
}

#[test]
fn cli_connect_peer_id_smoke() {
    let bin = env!("CARGO_BIN_EXE_ant-quic");
    let listen_addr = free_localhost_addr();

    let mut listener = Command::new(bin)
        .arg("--listen")
        .arg(listen_addr.to_string())
        .arg("--no-default-bootstrap")
        .arg("--json")
        .arg("--full-key")
        .arg("--duration")
        .arg("12")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn listener ant-quic");

    let listener_stdout = listener
        .stdout
        .take()
        .expect("listener stdout should be piped");
    let listener_stderr = listener
        .stderr
        .take()
        .expect("listener stderr should be piped");
    let (tx, rx) = mpsc::channel();

    let stdout_tx = tx.clone();
    let stdout_handle = std::thread::spawn(move || {
        let reader = BufReader::new(listener_stdout);
        let mut all_stdout = String::new();
        for line in reader.lines() {
            let line = line.expect("read listener stdout line");
            all_stdout.push_str(&line);
            all_stdout.push('\n');
            if let Some(peer_id) = parse_local_identity_peer_id(&line) {
                let _ = stdout_tx.send(peer_id);
            }
        }
        all_stdout
    });

    let stderr_handle = std::thread::spawn(move || {
        let reader = BufReader::new(listener_stderr);
        let mut all_stderr = String::new();
        for line in reader.lines() {
            let line = line.expect("read listener stderr line");
            all_stderr.push_str(&line);
            all_stderr.push('\n');
            if let Some(peer_id) = parse_local_identity_peer_id(&line) {
                let _ = tx.send(peer_id);
            }
        }
        all_stderr
    });

    let peer_id = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("listener should emit local_identity JSON event on stdout or stderr");

    std::thread::sleep(Duration::from_millis(300));
    assert!(
        listener
            .try_wait()
            .expect("check listener liveness")
            .is_none(),
        "listener should still be running before launching connector"
    );

    let connector = Command::new(bin)
        .arg("--connect-peer-id")
        .arg(&peer_id)
        .arg("--known-peers")
        .arg(listen_addr.to_string())
        .arg("--json")
        .arg("--duration")
        .arg("6")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run peer-id connector ant-quic");

    assert!(
        connector.status.success(),
        "peer-id connector should exit successfully; status={:?}, stderr={} stdout={}",
        connector.status,
        String::from_utf8_lossy(&connector.stderr),
        String::from_utf8_lossy(&connector.stdout)
    );

    let connector_stdout = String::from_utf8_lossy(&connector.stdout);
    assert!(
        connector_stdout.contains("\"event\":\"peer_connected\""),
        "peer-id connector stdout should contain peer_connected JSON event; stdout={} stderr={}",
        connector_stdout,
        String::from_utf8_lossy(&connector.stderr)
    );

    let _ = listener.kill();
    let _ = listener.wait();
    let listener_stdout_output = stdout_handle.join().expect("join stdout reader thread");
    let listener_stderr_output = stderr_handle.join().expect("join stderr reader thread");
    assert!(
        listener_stdout_output.contains("\"event\":\"local_identity\"")
            || listener_stderr_output.contains("\"event\":\"local_identity\""),
        "listener output should contain local_identity JSON event; stdout={} stderr={}",
        listener_stdout_output,
        listener_stderr_output
    );
}
