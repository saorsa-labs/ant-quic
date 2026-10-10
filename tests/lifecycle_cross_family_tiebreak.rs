#![allow(clippy::expect_used, clippy::unwrap_used)]

//! #317: the cross-family registration decision itself.
//!
//! `simultaneous_connect_dedup::test_tiebreaker_deterministic` checks that both
//! ends of a simultaneous open settle on one shared connection. That end state
//! can also follow a wrong decision, because rejection closes and repromotion
//! recover from it. This test checks the decision directly.
//!
//! Two connections to one peer identity with different initiators are in
//! different lifecycle families. Registration must keep the connection with
//! the greater lifecycle connection id (the TLS exporter with the production
//! label and context below), whatever its local side and whichever connection
//! registers first.
//!
//! Only endpoint A decides. A's two connections go to two endpoints with one
//! identity (B and B'), so B and B' each hold one connection and never close
//! A's winner, and nothing can repromote a loser at A. A's choice is final.
//! The decision is read from A's lifecycle trace (the registration of each
//! connection, with its lifecycle connection id) and checked against A's
//! winner map through the production exporter.
//!
//! Both registration orders are tested. In each, the two connections have
//! opposite local sides at A. The connection ids are random, so each order is
//! repeated until both outcomes (the later connection wins, the earlier one
//! wins) have been seen. A rule biased to one side, or to registration order,
//! is then wrong at least once per order and the test fails.

mod support;

use ant_quic::{P2pEndpoint, PeerId, Side};
use std::sync::Arc;
use std::time::Duration;
use support::{
    CONNECT_TIMEOUT, lifecycle_events, make_isolated_node_with_keypair, normalize_local_addr,
    reset_lifecycle_events, reusable_keypair, spawn_accept_loop, test_guard,
};
use tokio::time::{Instant, sleep, timeout};

/// The production lifecycle connection id: `NatTraversalEndpoint::
/// lifecycle_connection_id_for` exports these. Its ordering is the
/// cross-family rank (`canonical_sort_key_cmp`).
const LIFECYCLE_ID_LABEL: &[u8] = b"ant-quic/lifecycle-connection-id/v1";
const LIFECYCLE_ID_CONTEXT: &[u8] = b"canonical";
/// The lifecycle trace records the first 8 bytes of the id, as hex.
const TRACE_ID_BYTES: usize = 8;
/// Each trial's outcome is a fair coin, so missing one outcome in this many
/// trials of a correct endpoint has probability 2 * 2^-24 per order.
const MAX_TRIALS_PER_ORDER: usize = 24;
const STEP_WAIT: Duration = Duration::from_secs(10);

/// Registration order at the deciding endpoint A.
#[derive(Clone, Copy, Debug)]
enum Order {
    /// C1 is A's own outbound connection (Client at A); C2 arrives inbound
    /// from B' (Server at A).
    OutboundThenInbound,
    /// C1 arrives inbound from B (Server at A); C2 is A's own outbound
    /// connection to B' (Client at A).
    InboundThenOutbound,
}

impl Order {
    fn first_side(self) -> Side {
        match self {
            Self::OutboundThenInbound => Side::Client,
            Self::InboundThenOutbound => Side::Server,
        }
    }

    fn second_side(self) -> Side {
        match self {
            Self::OutboundThenInbound => Side::Server,
            Self::InboundThenOutbound => Side::Client,
        }
    }
}

/// One registration at A (a trace transition out of `Init`).
#[derive(Clone, Debug)]
struct Registration {
    /// First 8 bytes of the lifecycle connection id, lowercase hex.
    id: String,
    /// `Live` (admitted) or `Superseded` (rejected at registration).
    to_state: String,
}

fn trace_peer_prefix(peer: &PeerId) -> String {
    hex::encode(&peer.0[..4])
}

/// A's registrations for `peer`, in trace order. Only A has connections whose
/// remote is `peer`; B and B' trace under A's peer id.
fn registrations_for(peer: &PeerId) -> Vec<Registration> {
    let prefix = trace_peer_prefix(peer);
    lifecycle_events()
        .into_iter()
        .filter(|event| event.fields.get("peer_id") == Some(&prefix))
        .filter(|event| event.fields.get("from_state").map(String::as_str) == Some("Init"))
        .map(|event| Registration {
            id: event
                .fields
                .get("connection_id")
                .cloned()
                .unwrap_or_default(),
            to_state: event.fields.get("to_state").cloned().unwrap_or_default(),
        })
        .collect()
}

async fn wait_for_registrations(peer: &PeerId, count: usize) -> Vec<Registration> {
    let deadline = Instant::now() + STEP_WAIT;
    loop {
        let registrations = registrations_for(peer);
        if registrations.len() >= count {
            return registrations;
        }
        assert!(
            Instant::now() < deadline,
            "A did not register {count} connection(s) within {STEP_WAIT:?}: {registrations:?}"
        );
        sleep(Duration::from_millis(10)).await;
    }
}

/// The production lifecycle connection id of `connection`, as the trace
/// records it.
fn traced_lifecycle_id(connection: &ant_quic::high_level::Connection) -> String {
    let mut id = [0u8; 32];
    connection
        .export_keying_material(&mut id, LIFECYCLE_ID_LABEL, LIFECYCLE_ID_CONTEXT)
        .expect("lifecycle exporter");
    hex::encode(&id[..TRACE_ID_BYTES])
}

/// Wait until A's winner map holds the connection whose lifecycle id is
/// `expected`. The trace line is written just before the winner-map update,
/// so this can lag the trace by a moment. No endpoint other than A decides,
/// so nothing can close A's winner and trigger a repromotion meanwhile.
async fn wait_for_live_id(
    node: &P2pEndpoint,
    peer: &PeerId,
    expected: &str,
) -> ant_quic::high_level::Connection {
    let deadline = Instant::now() + STEP_WAIT;
    loop {
        let live = node.get_quic_connection(peer).expect("lookup");
        if let Some(connection) = &live
            && traced_lifecycle_id(connection) == expected
        {
            return connection.clone();
        }
        let seen = live.as_ref().map(traced_lifecycle_id);
        assert!(
            Instant::now() < deadline,
            "A's live connection is {seen:?}, expected lifecycle id {expected}"
        );
        sleep(Duration::from_millis(10)).await;
    }
}

async fn connect(from: &Arc<P2pEndpoint>, to: &Arc<P2pEndpoint>) {
    let addr = normalize_local_addr(to.local_addr().expect("bound addr"));
    timeout(CONNECT_TIMEOUT, from.connect_addr(addr))
        .await
        .expect("connect timeout")
        .expect("connect");
}

/// One trial. Returns whether the later connection (C2) won at A.
async fn trial(order: Order) -> bool {
    let b_keypair = reusable_keypair();
    let a = make_isolated_node_with_keypair(reusable_keypair()).await;
    let b = make_isolated_node_with_keypair(b_keypair.clone()).await;
    let b2 = make_isolated_node_with_keypair(b_keypair).await;
    let b_id = b.peer_id();
    assert_eq!(b2.peer_id(), b_id, "B' must have B's identity");
    let accepts = [
        spawn_accept_loop(a.clone()),
        spawn_accept_loop(b.clone()),
        spawn_accept_loop(b2.clone()),
    ];

    // C1, registered at A.
    match order {
        Order::OutboundThenInbound => connect(&a, &b).await,
        Order::InboundThenOutbound => connect(&b, &a).await,
    }
    let first = wait_for_registrations(&b_id, 1).await;
    assert_eq!(first.len(), 1, "{order:?}: one registration before C2");
    assert_eq!(
        first[0].to_state, "Live",
        "{order:?}: C1 is A's first connection"
    );
    let id1 = first[0].id.clone();
    // Also proves that the trace carries the production lifecycle id.
    let c1 = wait_for_live_id(&a, &b_id, &id1).await;
    assert_eq!(c1.side(), order.first_side(), "{order:?}: C1's side at A");

    // C2, from the other initiator: a cross-family registration at A.
    match order {
        Order::OutboundThenInbound => connect(&b2, &a).await,
        Order::InboundThenOutbound => connect(&a, &b2).await,
    }
    let registrations = wait_for_registrations(&b_id, 2).await;
    assert_eq!(registrations.len(), 2, "{order:?}: {registrations:?}");
    let id2 = registrations[1].id.clone();
    assert_eq!(id2.len(), id1.len());
    assert_ne!(
        id1, id2,
        "{order:?}: equal 8-byte id prefixes cannot be ranked"
    );

    // The registration decision, from the trace: C2 admitted (`Live`, C1
    // superseded) or rejected at registration (`Superseded`).
    let c2_state = registrations[1].to_state.as_str();
    assert!(
        matches!(c2_state, "Live" | "Superseded"),
        "{order:?}: unexpected C2 registration state {c2_state}"
    );
    let later_won = c2_state == "Live";
    // Equal-length lowercase hex compares like the bytes it encodes.
    let greater = if id2 > id1 { &id2 } else { &id1 };
    assert_eq!(
        later_won,
        id2 > id1,
        "{order:?}: A must keep the greater lifecycle connection id \
         (C1 {id1} on {:?}, C2 {id2} on {:?}); C2 {}",
        order.first_side(),
        order.second_side(),
        if later_won { "won" } else { "was rejected" },
    );

    // Independent check: A's winner map holds the greater id, on its side.
    let winner = wait_for_live_id(&a, &b_id, greater).await;
    let winner_side = if later_won {
        order.second_side()
    } else {
        order.first_side()
    };
    assert_eq!(winner.side(), winner_side, "{order:?}: winner's side at A");

    for node in [&a, &b, &b2] {
        let _ = timeout(Duration::from_secs(2), node.shutdown()).await;
    }
    for accept in accepts {
        accept.abort();
    }
    later_won
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cross_family_registration_keeps_greater_lifecycle_connection_id() {
    let _guard = test_guard().await;
    reset_lifecycle_events();

    for order in [Order::OutboundThenInbound, Order::InboundThenOutbound] {
        let mut later_won = 0usize;
        let mut earlier_won = 0usize;
        let mut trials = 0usize;
        while (later_won == 0 || earlier_won == 0) && trials < MAX_TRIALS_PER_ORDER {
            trials += 1;
            if trial(order).await {
                later_won += 1;
            } else {
                earlier_won += 1;
            }
        }
        println!(
            "#317 {order:?}: {trials} trial(s), later won {later_won}, earlier won {earlier_won}"
        );
        assert!(
            later_won > 0 && earlier_won > 0,
            "{order:?}: only one outcome in {trials} trials (later won {later_won}, \
             earlier won {earlier_won}). A correct decision gives each outcome with \
             probability 1/2; a side- or order-biased decision gives only one."
        );
    }
}
