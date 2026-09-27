# ant-quic

QUIC transport with native NAT traversal and pure post-quantum crypto, built for
P2P networks (used by `saorsa-gossip`, `x0x` and the Autonomi ecosystem).
Rust 2024, MSRV 1.88, MIT OR Apache-2.0.

## Not a Quinn fork (for contributions)
ant-quic began as a Quinn fork and GitHub still shows it as one, but it is an
independent project. Never open PRs against, push to, or add a remote for
`quinn-rs/quinn`; pass `--repo saorsa-labs/ant-quic` to `gh pr create` so it
doesn't default to the upstream parent (`prevent-upstream-pr.yml` also guards
this). `src/high_level/` is ant-quic's own evolved copy of Quinn's async API,
not an external dependency.

## Design invariants
- **Symmetric P2P.** Every node connects, accepts and coordinates; there are no
  client/server/bootstrap roles. Say "known peers" (`known_peers`), not
  "bootstrap nodes". (ADR-004)
- **Pure PQC, always on.** ML-KEM-768 (IANA 0x0201) key exchange and ML-DSA-65
  (0x0901) signatures on every connection; no hybrid or classical fallback, no
  feature flag. Authentication uses raw public keys (RFC 7250-style) — no X.509,
  no CA. PeerId = SHA-256(ML-DSA-65 public key). Spec:
  `docs/rfcs/ant-quic-pqc-authentication.md`. (ADR-003)
- **Native QUIC NAT traversal — no STUN, ICE or TURN.** Addresses are learned from
  local interfaces and from peers via `OBSERVED_ADDRESS`; hole punching is
  coordinated over existing QUIC connections. When punching fails, the fallback is
  a MASQUE CONNECT-UDP relay run by another peer (ADR-005/006/009/016).
- Dual-stack: a single IPv6 socket with `IPV6_V6ONLY=0` serves IPv4 too (ADR-008).
- WASM is not supported (raw UDP sockets).

## Wire codepoints are frozen
Deployed peers speak these, so never change them silently; differences from
future RFCs must go through negotiation under our own spec versioning (ADR-012).
They are pinned by tests in `src/transport_parameters.rs`,
`tests/nat_traversal_frame_tests.rs` and `tests/frame_encoding_tests.rs`.
- Transport params: `0x3d7e9f0bca12fea6` (NAT traversal), `0x3d7e9f0bca12fea8`
  (RFC-format frames), `0x9f81a176` (address discovery)
- Frames: `ADD_ADDRESS` 0x3d7e90/91, `PUNCH_ME_NOW` 0x3d7e92/93,
  `REMOVE_ADDRESS` 0x3d7e94, `OBSERVED_ADDRESS` 0x9f81a6/a7 (IPv4/IPv6 pairs)

The external drafts in `docs/rfcs/` (`draft-seemann-quic-nat-traversal-02`,
`draft-ietf-quic-address-discovery-00`) are provenance, not conformance targets;
the normative self-hosted spec `docs/rfcs/ant-quic-nat-traversal.md` is still to
be written.

## Wording rules for docs, comments and logs
- Don't use "DHT"/"Kademlia"/"routing table" — ant-quic provides no record
  storage/lookup; only a single explicit non-goal statement may name it (ADR-011).
- Don't publish connectivity success percentages; describe tiers (Direct,
  Punched, Relayed) qualitatively. Rates belong in telemetry (ADR-013).

## Code map
- Primary API: `P2pEndpoint` in `src/p2p_endpoint.rs`, configured with
  `P2pConfig` (`src/unified_config.rs`). Dialing goes through one orchestration
  path: `connect_known_peers()`, `connect_addr()`, `connect_peer()`.
- `src/nat_traversal_api.rs` — `NatTraversalEndpoint` and its `poll()` state machine
- `src/connection/nat_traversal.rs` — per-connection traversal state;
  `src/candidate_discovery*` — candidate gathering
- `src/endpoint.rs`, `src/connection/`, `src/frame*` — core QUIC with extension frames
- `src/crypto/pqc/` — PQC; `src/masque/`, `src/relay/` — relay; `src/bootstrap_cache/`
- `src/bin/ant-quic.rs` — CLI (`--listen`, default `[::]:0`; `--known-peers`; `--connect`)
- Cargo features are deliberately few: default `platform-verifier`,
  `network-discovery`; opt-in `ble` (macOS needs an app bundle, ADR-010),
  `trace`, `arbitrary`, `__qlog`.

## Build and test
`just --list`. Main recipes:
- `just full-test` — the PR-style gate: fmt-check, lint (`--all-features`),
  lib/doc tests, `tests/quick`, `tests/standard`, release-mode `tests/property_tests`,
  bench compile. CI's blocking clippy is `--all-features --lib --bins --examples
  -D warnings`; test-target clippy runs but is non-blocking.
- `just quick-test` skips a few environment-sensitive tests (`auto_binding`,
  `binding_stream`, `kem_group_is_restricted_with_provider`) — see the justfile.
- Heavy suites are manual: `heavy-nat` (Docker), `heavy-long`, `heavy-bench`,
  `heavy-mdns` (needs `ANT_QUIC_LIVE_MDNS=1`), `heavy-upnp` (`ANT_QUIC_LIVE_UPNP=1`).
- The workspace includes `ant-quic-workspace-hack`, managed by cargo-hakari
  (`.config/hakari.toml`); after changing dependencies run `cargo hakari generate`.
- Mark tests that take more than ~5 minutes `#[ignore]`.
- Logging: `RUST_LOG=ant_quic::nat_traversal=debug`, `ant_quic::connection=trace`.
- Commits follow Conventional Commits (changelog via `cliff.toml`).

## Docs
- Architecture: `docs/architecture/` (`ARCHITECTURE.md`, `PROTOCOL_EXTENSIONS.md`,
  `PEER_IDENTITY_AND_ADDRESSING.md`); `docs/NAT_TRAVERSAL_GUIDE.md`,
  `docs/TROUBLESHOOTING.md`
- Specs and drafts: `docs/rfcs/`
- ADRs: `docs/adr/` (process in `docs/adr/TOOLING.md`). Before changing
  architecture, protocols, crypto, network behaviour, public APIs or operational
  invariants, check the ADRs; new decisions go in a Proposed ADR from
  `docs/adr/TEMPLATE.md`. Accepted ADRs are immutable (supersede instead), and
  only a human marks an ADR Accepted.
