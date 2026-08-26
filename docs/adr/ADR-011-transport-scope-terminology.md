# ADR-011: Transport-Scope Terminology Boundary

## Status

Accepted (2026-08-26)

## Supersedes

Specific wording within [ADR-009](ADR-009-masque-relay-data-plane.md) (§ "DHT Address Propagation",
§ Implementation Status row "ADD_ADDRESS -> DHT bridge"). ADR-009 itself remains immutable per the
accepted-ADR immutability rule; this ADR carries forward its intent with corrected vocabulary.

## Context

ant-quic is a connectivity substrate: QUIC transport, NAT traversal, address discovery, and peer
relay. It intentionally stops short of overlay semantics ([ADR-005](ADR-005-native-quic-nat-traversal.md)
explicitly lists record storage and lookup semantics as non-goals).

However, distributed-lookup vocabulary from consuming overlays has leaked into this crate. An audit
on 2026-08-26 found:

| Class | Location | Problem |
|-------|----------|---------|
| Code surface | `src/link_transport.rs` (lines 23, 47, 184, 218-229, 284, 296-313, 383-396, 419-454, 509, 1161, tests 1452-1617) | A hardcoded `StreamTypeFamily::Dht` (byte range 0x10-0x1F), `StreamType::DhtQuery/DhtStore/...`, and `StreamFilter::dht_only()` bake one overlay category into the public protocol-type model |
| Comments/API docs | `src/nat_traversal_api.rs:598,1892,2404,2724`; `src/shared.rs:86`; `src/connection/mod.rs:4901`; `src/high_level/endpoint.rs:1082`; `src/p2p_endpoint.rs:1985` | Address updates described as feeding "the DHT bridge" / "the DHT routing table"; a DHT self-lookup suggested as an endpoint behaviour |
| Accepted ADR prose | ADR-009 §Context step 3, § "DHT Address Propagation" (lines 29, 78-93) | Describes relay addresses propagating through "the DHT" as if this crate participated in a network-wide database |
| Other docs | `docs/architecture/UNIFIED_CONNECTIVITY_PLAN.md:255`; `docs/rfcs/ant-quic-pqc-authentication.md:96` | Future-integration and PeerId rationale wording |
| Permitted (non-goal statements) | `docs/adr/ADR-005-native-quic-nat-traversal.md:36` | Explicit prohibition context - see Decision §Permitted |

The leak matters because it invites readers and contributors to assume this crate maintains or
queries a network-wide address database. It does not. Facts observed by this crate flow only over
live connections and out of a single typed event boundary; persistence and network-wide propagation
of those facts belong entirely to the consuming overlay.

## Decision

### 1. Vocabulary boundary

The term "DHT" (and equivalents such as "distributed hash table", "Kademlia", "routing table",
"DHT entry") is prohibited in all ant-quic artifacts - documentation, ADR prose, code identifiers,
log messages, and comments - **except** in non-goal statements.

**Permitted**: a single scope statement asserting that this crate does not provide distributed
record-storage/lookup semantics. Renaming that statement to avoid the word entirely obscures the
boundary it enforces, so one explicit prohibition per document is allowed where needed.

**Required replacements** elsewhere:

| Instead of | Use |
|------------|-----|
| "ADD_ADDRESS → DHT bridge" | "peer-address notification (an event consumed by overlays)" |
| "update the DHT routing table" | "update their own address book" (consumer responsibility) |
| "propagate through the DHT" | "advertise on live connections; consumers persist/forward as they see fit" |
| "address resolved from the DHT" | "any address the initiator learned via any means" |
| `StreamTypeFamily::Dht`, `StreamType::DhtXxx`, `StreamFilter::dht_only()` | See Decision 2 |

### 2. Generalize the protocol-type model

Rename the DHT-specific stream-type family to an overlay-neutral name (for example
`StreamTypeFamily::OverlayService`), keeping the existing numeric allocation (0x10-0x1F) unchanged so
deployed peers negotiating these type codes remain compatible. Registered variants and filters are
renamed on the same principle (`query/store` become overlay-neutral operation names). One overlay
category must never be named in the shared abstraction ([ADR-001](ADR-001-link-transport-abstraction.md)).

### 3. Event-boundary contract

Normative statement for the whole crate: ant-quic learns addresses only from connections it holds;
it exposes them only through endpoint events and query APIs scoped to known peers; it performs no
further distribution. What consumes, stores, indexes, or re-advertises those addresses is entirely
the overlay's concern. Event-channel names and doc comments are updated accordingly (the channel at
`nat_traversal_api.rs:598` becomes a consumer-neutral "address notification sink").

## Consequences

### Positive

- Contributors stop assuming hidden network-wide state exists in this crate.
- The public type model stays honest: one transport, many overlays, no favourites.
- Cross-repo contracts clarify cleanly: saorsa-core consumes events; ant-quic emits them.

### Negative

- Mechanical rename touches ~35 sites across 8 source files plus 3 docs; churn with no behaviour change.
- Test names/identifiers referencing the old family need coordinated rename to keep greps honest.

## Alternatives Considered

1. **Keep DHT naming as legacy alias, add neutral names alongside**
   - Rejected: aliases preserve exactly the vocabulary this ADR removes; greps stay polluted.
2. **Edit ADR-009 in place to fix wording**
   - Rejected: accepted ADRs are immutable (see [ADR-010](ADR-010-ble-transport-opt-in.md)); supersession is the mechanism.
3. **Ban even non-goal statements containing the term**
   - Rejected: hiding the scoping sentence makes the boundary harder to teach; one disciplined exception is clearer.

## Remediation Inventory

- Rename sweep: `src/link_transport.rs`, `src/link_transport_impl.rs:1606`, `src/nat_traversal_api.rs`,
  `src/shared.rs:86`, `src/connection/mod.rs:4901`, `src/high_level/endpoint.rs:1082`,
  `src/p2p_endpoint.rs:1985`
- Doc sweep: `docs/architecture/UNIFIED_CONNECTIVITY_PLAN.md:255`,
  `docs/rfcs/ant-quic-pqc-authentication.md:96` (rationale reworded to "compact identifier suitable
  for any consumer-side addressing layer")
- ADR-009 is left byte-for-byte untouched (immutable per the governance gate); the supersession is
  recorded here only (§Supersedes, §References)
- Research doc sweep: `docs/research/CONSTRAINED_TRANSPORTS.md` (`RoutingTable` -> `RouteTable`,
  "routing table" -> "route table")

### Migration (breaking public API - next release must be a minor bump, 0.28.0)

The rename sweep changes public identifiers. Downstream crates must update:

| Before | After |
|--------|-------|
| `StreamTypeFamily::Dht` | `StreamTypeFamily::OverlayService` |
| `StreamType::DhtQuery` / `DhtStore` / `DhtWitness` / `DhtReplication` | `StreamType::ServiceQuery` / `ServiceStore` / `ServiceWitness` / `ServiceReplication` |
| `StreamType::is_dht()` | `StreamType::is_overlay_service()` |
| `StreamTypeFamily::dht_only()` | `StreamTypeFamily::overlay_service_only()` |
| `StreamTypeFamily::dht_types()` | `StreamTypeFamily::service_types()` |

Wire bytes (0x10-0x1F) are unchanged, so peers on either side of the rename interoperate.
`StreamType` derives serde and unit variants serialize by name, so any downstream code that
serde-encodes `StreamType` (ant-quic itself never does - the wire path is the raw first byte)
will see `"DhtQuery"` become `"ServiceQuery"`; treat such encodings as version-scoped.

## Validation

- `src/link_transport.rs::tests::test_stream_type_from_byte` and `test_protocol_id_from_string` pin
  the frozen wire bytes (0x10-0x1F -> `ServiceQuery`/`ServiceStore`/`ServiceWitness`/`ServiceReplication`);
  a rename that shifts a byte value fails them.
- `python3 scripts/adr-governance.py --base origin/master` passes: ADR-009 unchanged, this ADR frozen
  at acceptance.
- Vocabulary gate (run before merging any PR): a case-insensitive grep for `\bdht\b`, "distributed
  hash table", "kademlia", "routing table" over `src/ tests/ examples/ benches/ docs/ README.md
  CHANGELOG.md` returns hits only in ADR-005 (non-goal), ADR-009 (frozen original), and this ADR.
- Downstream compile check: saorsa-core / x0x build against the 0.28.0 release using the migration
  table above with no remaining `Dht*` identifiers.
- Revisit trigger: a new stream-type family is added, or a consumer needs a term this ADR prohibits
  for a genuine transport-scope concept - supersede with a new ADR rather than editing this one.

## References

- [ADR-001](ADR-001-link-transport-abstraction.md) - LinkTransport abstraction this boundary protects
- [ADR-004](ADR-004-symmetric-p2p-architecture.md) - symmetric architecture motivating role-free vocabulary
- [ADR-009](ADR-009-masque-relay-data-plane.md) - superseded wording origin

## Notes for AI-assisted work

Drafted with AI assistance; reviewed and accepted by the project owner on 2026-08-26. Accepted ADRs are
immutable: create a new superseding ADR rather than editing this one.
