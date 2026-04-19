#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use ant_quic::PeerId;
use std::collections::HashSet;
use std::time::Duration;
use support::{make_node, normalize_local_addr, spawn_accept_loop, test_guard};
use tokio::time::{sleep, timeout};

const PEER_COUNT: usize = 3;
const MESSAGES_PER_PEER: usize = 8;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn symmetric_peer_mesh_delivers_all_messages_from_multiple_connected_peers() {
    let _guard = test_guard().await;

    let hub = make_node(vec![]).await;
    let hub_addr = normalize_local_addr(hub.local_addr().expect("hub addr"));
    let hub_id = hub.peer_id();
    let accept_hub = spawn_accept_loop(hub.clone());

    let mut peers = Vec::new();
    let mut accept_peers = Vec::new();
    for index in 0..PEER_COUNT {
        let peer = make_node(vec![hub_addr]).await;
        let peer_id = peer.peer_id();
        let accept_peer = spawn_accept_loop(peer.clone());

        let connection = timeout(Duration::from_secs(10), peer.connect_addr(hub_addr))
            .await
            .expect("connect timeout")
            .expect("connect result");
        assert_eq!(connection.peer_id, hub_id);

        peers.push((index, peer, peer_id));
        accept_peers.push(accept_peer);
    }

    sleep(Duration::from_millis(150)).await;

    let mut send_tasks = Vec::new();
    for (index, peer, _) in &peers {
        let peer = peer.clone();
        let peer_index = *index;
        send_tasks.push(tokio::spawn(async move {
            for seq in 0..MESSAGES_PER_PEER {
                let payload = format!("peer-{peer_index}-message-{seq}");
                peer.send(&hub_id, payload.as_bytes())
                    .await
                    .expect("peer send");
            }
        }));
    }

    for task in send_tasks {
        task.await.expect("send task join");
    }

    let expected: HashSet<(PeerId, String)> = peers
        .iter()
        .flat_map(|(index, _, peer_id)| {
            (0..MESSAGES_PER_PEER).map(move |seq| (*peer_id, format!("peer-{index}-message-{seq}")))
        })
        .collect();

    let mut seen = HashSet::new();
    while seen.len() < expected.len() {
        let (from, payload) = timeout(Duration::from_secs(10), hub.recv())
            .await
            .expect("hub recv timeout")
            .expect("hub recv");
        let payload = String::from_utf8(payload.to_vec()).expect("utf8 payload");
        assert!(
            expected.contains(&(from, payload.clone())),
            "unexpected message from {from:?}: {payload}"
        );
        assert!(
            seen.insert((from, payload.clone())),
            "duplicate message from {from:?}: {payload}"
        );
    }

    assert_eq!(seen, expected);

    // The same established peer connections should work in the reverse direction too.
    for (index, peer, peer_id) in &peers {
        let ack = format!("ack-from-hub-{index}");
        hub.send(peer_id, ack.as_bytes())
            .await
            .expect("hub ack send");
        let (from, payload) = timeout(Duration::from_secs(5), peer.recv())
            .await
            .expect("peer recv timeout")
            .expect("peer recv");
        assert_eq!(from, hub_id);
        assert_eq!(payload, ack.as_bytes());
    }

    for (_, peer, _) in peers {
        peer.shutdown().await;
    }
    hub.shutdown().await;
    for handle in accept_peers {
        handle.abort();
    }
    accept_hub.abort();
}
