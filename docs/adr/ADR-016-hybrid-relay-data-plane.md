# ADR-016: Hybrid Datagram/Stream Relay Data Plane

## Status

Accepted (2026-08-26)

## Supersedes (conditionally)

[ADR-009](ADR-009-masque-relay-data-plane.md) § Decision 2 ("Stream-Based Forwarding") - superseded
for regular-packet forwarding once this ADR's gate passes. ADR-009's stream lane, secondary-endpoint
design, proactive-setup model, and address-propagation decision all remain in force.

## Context

ADR-009 chose a single reliable ordered QUIC stream with `[4-byte length][packet]` framing for the
relay hop because QUIC-datagram payloads (~1120 B practical budget after tunnel overhead) cannot
carry 1200 B QUIC Initial packets. That rationale is sound **only for oversized packets**; it
concedes more than necessary for everything else:

- Post-handshake short-header packets mostly fit the datagram budget, yet travel over the reliable
  ordered stream today.
- Consequences of stream-only carriage:
  - **Head-of-line blocking**: one lost tunnel segment stalls every relayed flow until
    retransmission, though the end-to-end QUIC connections are loss-tolerant by design.
  - **Reliability stacking**: inner QUIC retransmits loss the stream already repaired - wasted
    bandwidth and artificial latency inflation that behaves unlike the UDP path it emulates.
  - **Congestion coupling**: single-stream dynamics degrade throughput under loss for bulk flows,
    the classic TCP-over-TCP failure mode TURN-style proxies avoid by forwarding unreliably.

A hybrid keeps ADR-009's true invariant (Initial packets must survive intact) while restoring
UDP-like semantics for regular traffic.

## Decision

Two-lane relay forwarding, selected per packet:

1. **Datagram lane (default)**: packets with on-wire size ≤ `P_max` carry as QUIC DATAGRAM frames on
   the existing relay session. Unordered, unreliable - exactly UDP semantics across the hop.
2. **Stream lane**: anything larger than `P_max` - always including full Initial packets - uses the
   current length-prefixed stream framing unchanged. Reliability here is required precisely because
   these packets have no retransmission story if lost.
3. **Session-negotiated `P_max`**: computed from the negotiated session limits minus measured outer
   overhead (outer headers + varint lengths), refined empirically at session establishment;
   never guessed below the 1200 B + margin needed for Initial-carriage decisions.
4. **Single congestion controller, honest accounting**: both lanes share the session's QUIC CC -
   correct, since the hop genuinely is one bottleneck. Tuning items recorded as follow-ups: ACK
   frequency tuning for the datagram-heavy profile and scheduler notes for mixed lanes.
5. **Gate before default-flip**:
   - Config `relay_forward_mode = stream | hybrid`, shipping default `stream`.
   - Land hybrid implementation behind the flag; soak in the network-namespace harness used by
     [ADR-009] (`MASQUERADE --random-fully`) plus targeted loss-injection tests comparing p95 RTT
     inflation, retransmission ratios, and Initial-delivery reliability between modes.
   - Flip default to `hybrid` only when benchmarks show parity on Initial delivery and improvement
     on loss-path metrics, citing [ADR-013](ADR-013-measured-connectivity-metrics.md) counters.
6. **Compatibility**: during transition both modes may coexist; mode is per-session so peers on
   older code remain served via the stream lane without protocol rupture.

## Consequences

### Positive

- Removes head-of-line blocking for the common case; relay-hop behaviour converges toward the TURN
  semantics it replaces while staying purely peer-operated.
- Restores accurate loss signal to inner QUIC connections (their CC sees real loss instead of
  artificially-ordered delivery).
- Keeps ADR-009's correctness guarantee where it actually matters.

### Negative

- Two lanes = two code paths to test; cancellation/cleanup edge cases grew when reliability work
  touched the socket layer before, and now apply to lane switching too.
- Lossy hops will drop relayed payloads loudly rather than hiding damage under ordering - a
  semantic change applications should not notice but tests must.
- Benchmark infrastructure burden sits ahead of any user-visible benefit until defaults flip.

## Alternatives Considered

1. **Keep stream-only until direct migration almost always succeeds anyway**
   - Rejected: symmetric-NAT nodes persist (CGNAT growth per arXiv studies), so the relay path is a
     permanent tier, not a transitional hack.
2. **Mandate oversized packets be fragmented across multiple datagrams**
   - Rejected: reinvents fragmentation under our own error modes while the stream lane already does
     the job for the rare case; two mechanisms for the same packet class would be worse than one.
3. **Wait for the listen-draft RFC and use its proxy semantics wholesale**
   - Deferred, not rejected: [ADR-012](ADR-012-standards-basis-refresh.md) tracks publication; the
     custom data plane then either aligns or gets encapsulated behind it.

## Validation

- Stream-lane behaviour that must stay intact is covered by `tests/masque_integration_tests.rs`
  (`test_e2e_relay_scenario`, `test_e2e_migration_scenario`, `test_compressed_datagram_roundtrip`)
  and `src/masque/relay_server.rs::test_handle_client_datagram_records_bytes_and_datagram_count`;
  these must pass unchanged with `relay_forward_mode = stream`.
- Implementing PR must add the `relay_forward_mode` config surface (`stream | hybrid`, shipped default
  `stream`) with a test asserting that default, plus lane-selection unit tests in
  `src/masque/relay_socket.rs`: packets at or below `P_max` take the datagram lane, packets above
  `P_max` and every Initial take the length-prefixed stream lane, and `P_max` is never computed
  below 1200 B plus margin.
- Loss-injection tests comparing `stream` and `hybrid` on p95 RTT inflation, retransmission ratio,
  and Initial-delivery reliability must exist before the default flips;
  `tests/compat_datagram_drop_tests.rs` shows the existing pattern for forcing datagram loss.
- Compatibility (Decision 6): a test must show a `hybrid`-capable peer serving a `stream`-only peer
  over the stream lane without session failure.
- Default-flip PR must cite ADR-013 counters (`relay_session_bytes_total`,
  `time_to_establish_seconds{method=relay}`) before/after from the namespace harness used for
  ADR-009.
- Revisit trigger: `draft-ietf-masque-connect-udp-listen` is published as an RFC (tracked by
  ADR-012) - evaluate whether its proxy semantics subsume the custom hybrid data plane.

## References

- Superseded design rationale: [ADR-009](ADR-009-masque-relay-data-plane.md) § Alternatives 1 & 2
- Implementation sites: `src/masque/relay_socket.rs` (framing), `src/masque/relay_server.rs`
  (forwarding pump), `src/masque/migration.rs` (escape-to-direct)
- Semantics reference: RFC 9297 (HTTP Datagrams), RFC 9298 (CONNECT-UDP), RFC 9000 §8 (amplification)
- Related: [ADR-006](ADR-006-masque-relay-fallback.md),
  [ADR-013](ADR-013-measured-connectivity-metrics.md),
  [ADR-015](ADR-015-paced-candidate-spray-punching.md)

## Notes for AI-assisted work

Drafted with AI assistance; reviewed and accepted by the project owner on 2026-08-26. Accepted ADRs are immutable: create a new superseding ADR rather than editing this one.
