#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{BufRead, BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread::JoinHandle;
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

struct ListenerProcess {
    child: Option<Child>,
    stdout_handle: Option<JoinHandle<String>>,
    stderr_handle: Option<JoinHandle<String>>,
}

impl ListenerProcess {
    fn new(mut child: Child, peer_id_tx: Option<mpsc::Sender<String>>) -> Self {
        let listener_stdout = child
            .stdout
            .take()
            .expect("listener stdout should be piped");
        let listener_stderr = child
            .stderr
            .take()
            .expect("listener stderr should be piped");

        Self {
            child: Some(child),
            stdout_handle: Some(spawn_output_drain(listener_stdout, peer_id_tx.clone())),
            stderr_handle: Some(spawn_output_drain(listener_stderr, peer_id_tx)),
        }
    }

    fn is_running(&mut self) -> bool {
        self.child
            .as_mut()
            .expect("listener child should be present")
            .try_wait()
            .expect("check listener liveness")
            .is_none()
    }

    fn stop(&mut self) -> (String, String) {
        self.kill_and_wait();
        let stdout = self
            .stdout_handle
            .take()
            .expect("listener stdout drain thread should be present")
            .join()
            .expect("join listener stdout drain thread");
        let stderr = self
            .stderr_handle
            .take()
            .expect("listener stderr drain thread should be present")
            .join()
            .expect("join listener stderr drain thread");
        (stdout, stderr)
    }

    fn kill_and_wait(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for ListenerProcess {
    fn drop(&mut self) {
        self.kill_and_wait();
        if let Some(handle) = self.stdout_handle.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.stderr_handle.take() {
            let _ = handle.join();
        }
    }
}

fn spawn_output_drain<R: Read + Send + 'static>(
    stream: R,
    peer_id_tx: Option<mpsc::Sender<String>>,
) -> JoinHandle<String> {
    std::thread::spawn(move || {
        let reader = BufReader::new(stream);
        let mut output = String::new();
        for line in reader.lines() {
            let line = line.expect("read listener output line");
            output.push_str(&line);
            output.push('\n');
            if let (Some(tx), Some(peer_id)) = (&peer_id_tx, parse_local_identity_peer_id(&line)) {
                let _ = tx.send(peer_id);
            }
        }
        output
    })
}

#[test]
fn cli_connect_smoke() {
    let bin = env!("CARGO_BIN_EXE_ant-quic");
    let listen_addr = free_localhost_addr();

    let mut listener = ListenerProcess::new(
        Command::new(bin)
            .arg("--listen")
            .arg(listen_addr.to_string())
            .arg("--no-default-bootstrap")
            .arg("--json")
            .arg("--duration")
            .arg("12")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn listener ant-quic"),
        None,
    );

    std::thread::sleep(Duration::from_millis(800));
    assert!(
        listener.is_running(),
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

    let (_listener_stdout_output, _listener_stderr_output) = listener.stop();

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
}

#[test]
fn cli_connect_peer_id_smoke() {
    let bin = env!("CARGO_BIN_EXE_ant-quic");
    let listen_addr = free_localhost_addr();
    let (tx, rx) = mpsc::channel();

    let mut listener = ListenerProcess::new(
        Command::new(bin)
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
            .expect("spawn listener ant-quic"),
        Some(tx),
    );

    let peer_id = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("listener should emit local_identity JSON event on stdout or stderr");

    std::thread::sleep(Duration::from_millis(300));
    assert!(
        listener.is_running(),
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

    let (listener_stdout_output, listener_stderr_output) = listener.stop();

    assert!(
        listener_stdout_output.contains("\"event\":\"local_identity\"")
            || listener_stderr_output.contains("\"event\":\"local_identity\""),
        "listener output should contain local_identity JSON event; stdout={} stderr={}",
        listener_stdout_output,
        listener_stderr_output
    );

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
}
