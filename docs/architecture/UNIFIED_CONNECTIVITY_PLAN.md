# Unified Connectivity Plan

## Status

Implementation plan with the main UPnP + mDNS pieces now landed in code.

- Phase 3.5 router-assisted port mapping is landed with first-party UPnP IGD,
  renewal, shutdown cleanup, additive candidate propagation, and structured
  lifecycle events.
- Phase 4 scoped first-party mDNS is landed as a built-in runtime, including
  browse/advertise support, service/namespace scoping, discover-only vs
  auto-connect policy, structured discovery events/state, and default-on
  zero-config participation for non-loopback endpoints.
- Future provider-generalization work such as PCP/NAT-PMP or a broader peer
  directory abstraction is still follow-up work, not a blocker for the current
  LAN-scoped mDNS + UPnP expectations.

## Goal

Make `ant-quic` own **all connectivity strategy** so consumers do not need to
choose between direct connection, NAT traversal, relay fallback, or proactive
relay setup.

The desired consumer experience is:

- identify the peer to connect to
- optionally enable discovery sources that are valid for the application
- let `ant-quic` do whatever networking work is required to connect

Consumers must **not** need to decide:

- which connect method uses fallback
- when to hole-punch
- when to relay
- whether a target needs proactive relay arming
- whether to race IPv4/IPv6 addresses

## Current implementation reality (2026-04)

Some of this plan is already partially reflected in `ant-quic`, but the work is
not complete yet.

### Already present

- `P2pEndpoint::connect_addr`, `P2pEndpoint::connect_peer`, and
  `P2pEndpoint::connect_known_peers` already converge through one internal
  outbound orchestration path.
- `Node` is mostly a thin façade over `P2pEndpoint` for the common public API.
- `src/unified_config.rs` already contains a public discovery-policy scaffold:
  `DiscoveryPolicy`, `MdnsConfig`, and `AutoConnectPolicy`.
- `connect_known_peers()` already honors parts of discovery policy such as
  static-known-peer enablement and runtime auto-connect behavior.
- `src/port_mapping.rs` now provides a first-party best-effort UPnP IGD
  lifecycle with renewal, shutdown cleanup, and candidate/status propagation.

### Still not present

- there is **not yet** a generalized cross-provider peer directory abstraction;
  the current landed mDNS directory is scoped to first-party LAN discovery
- future PCP/NAT-PMP extensions are still plan-only; the current landed router
  assist runtime remains UPnP IGD-first

### Immediate implication for consumers

Consumers such as `x0x` can now cut over to `ant-quic` for service-scoped,
namespace-scoped LAN discovery without carrying an app-local compile-time mDNS
feature gate. The remaining future work is about broader provider abstraction,
not the core first-party mDNS runtime itself.

## Core principles

### 1. One canonical connection behavior

There must be exactly **one outbound connectivity state machine**.

That state machine is responsible for:

1. connection reuse
2. direct connection attempts
3. dual-stack/Happy Eyeballs racing
4. peer-ID-based NAT traversal and hole punching
5. relay fallback
6. proactive relay setup when the local node is not directly reachable
7. migration to a better direct path when one becomes available

### 2. `PeerId` is durable identity

- **`PeerId`** is the durable authenticated identity
- **`SocketAddr`** is mutable reachability metadata only

Durable state must be keyed by `PeerId`:

- bootstrap/coordinator records
- peer metadata
- long-lived reachability history
- trust/eligibility state

Addresses may change across NAT rebinding, reconnects, roaming, and path
migration, so they must never become the durable identity key.

### 3. Discovery policy is a consumer concern; connectivity strategy is not

Consumers are allowed to decide:

- whether discovery is enabled
- which discovery providers are allowed
- which discovered peers are in-scope for the application
- whether discovered peers should auto-connect or be surfaced for approval
- what trust policy applies

Consumers are **not** allowed to decide:

- direct vs fallback
- hole-punch vs relay
- whether to retry through different routes
- whether to pre-arm relay

### 4. mDNS is optional and scoped

mDNS should be supported as a **first-party optional discovery provider**, but it
must not imply “connect to any ant-quic node visible on the LAN”.

mDNS must be constrained by application policy such as:

- service/application name
- namespace/workspace/network identifier
- browse vs advertise mode
- auto-connect vs discover-only mode
- trust/eligibility policy

mDNS records are locator claims only. Handshake authentication remains the
source of truth for identity.

### 5. Router-assisted port mapping is additive, not primary

`ant-quic` should treat **UPnP IGD port mapping** as a local-router
reachability optimization that complements, but does not replace:

- native QUIC address observation
- peer-assisted NAT traversal and hole punching
- MASQUE relay fallback

Design rules:

- default policy should be **on** for home-friendly consumers
- there must be a simple **off switch** for operators who do not want router
  state changes
- success should publish a better external candidate address when available
- success must **not** be treated as proof of peer-verified direct reachability
- failure must be non-fatal and must fall through to the normal native NAT
  traversal + relay path
- future PCP/NAT-PMP support can be added later, but UPnP IGD is the pragmatic
  first step for consumer routers

In short: router-assisted port mapping is a **best-effort assist layer**, not a
replacement for the core connectivity engine.

## Canonical API direction

`P2pEndpoint` should be the canonical public connectivity surface.

### Target public API

```rust
endpoint.connect_peer(peer_id).await
endpoint.connect_addr(addr).await
endpoint.connect_known_peers().await
```

Where:

- `connect_peer(peer_id)` is the **primary** API for normal consumers
- `connect_addr(addr)` is a convenience wrapper for address-only bootstrap
- `connect_known_peers()` is a bootstrap/discovery convenience

All three must route to the same internal connectivity orchestrator.

### `Node`

`Node` should become a thin façade that forwards into `P2pEndpoint`, not a
separate connectivity behavior surface.

## Discovery model

The public model should expose **discovery policy**, not raw peer/address hints.

### Consumer-facing model

The target model is policy-based discovery configuration. The **currently landed
config shape** already looks roughly like this:

```rust
P2pConfig::builder()
    .discovery(DiscoveryPolicy {
        static_known_peers: true,
        mdns: Some(MdnsConfig {
            enabled: true,
            service: Some("x0x".into()),
            namespace: Some("workspace-123".into()),
            mode: MdnsMode::Both,
            auto_connect: AutoConnectPolicy::Disabled,
            metadata: BTreeMap::new(),
        }),
        auto_connect: AutoConnectPolicy::Disabled,
    })
    .build()?
```

This allows the application to express:

- whether local discovery is enabled
- what service or app is in scope
- what namespace is valid
- whether discovered peers auto-connect or wait for approval
- what trust model applies

It does **not** require the consumer to reason about addresses, NAT traversal,
or relays.

## Internal architecture

### 1. Peer directory

Add an internal peer directory that stores discovery and reachability state.

Once a peer is authenticated, its record is keyed by `PeerId`.

Suggested contents:

- `PeerId`
- latest known addresses
- discovery sources (config, mDNS, gossip, relay advertisement, direct observation)
- freshness timestamps
- reachability history
- verified direct reachability status
- relay-related state
- application eligibility / approval state where needed

This is where “peer hints” exist internally, but they should not be the primary
consumer-facing abstraction.

### 2. Discovery provider layer

Initial provider set:

1. static known peers
2. optional mDNS
3. existing bootstrap/discovery flows
4. future registry/gossip/DHT integrations

All providers feed the same internal peer directory.

### 3. Eligibility and trust layer

Discovery alone must not imply “valid peer”. The application must still be able
to define:

- service scope
- namespace/workspace scope
- allowlist or approval requirements
- auto-connect policy

### 4. Unified connectivity orchestrator

Introduce one internal orchestrator that handles all connection attempts.

Conceptually:

```rust
async fn connect_request(&self, target: ConnectTarget) -> Result<PeerConnection, EndpointError>
```

The exact type can evolve, but it should unify all outbound connection paths.

## Unified connection flow

For `endpoint.connect_peer(peer_id).await`, the orchestrator should:

1. reuse an existing live connection if present
2. look up all known addresses for the target peer
3. try direct connection attempts first
4. race IPv4/IPv6 where appropriate
5. try peer-ID-based hole punching and NAT traversal
6. try relay fallback if direct and hole punch fail
7. proactively arm relay when the local node lacks verified direct reachability
8. continue probing for a direct path after a relayed connection succeeds

The caller should receive a normal connection result plus events indicating how
connectivity was achieved.

## Public API cleanup plan

### APIs to converge or de-emphasize

Current public surfaces split strategy across multiple methods. These need to be
collapsed behind the unified orchestrator.

Targets include:

- direct address connect paths
- peer-id NAT traversal paths
- explicit fallback methods
- router-level peer connect methods that bypass orchestration

The goal is that consumers should never need to ask “which connect method is the
smart one?”.

## Binary plan

The pure `ant-quic` binary must reflect the unified model.

### Requirements

- use the same connectivity orchestrator as the library
- do not expose separate strategy modes for normal operation
- support discovery policy configuration
- emit structured events that prove how connectivity was achieved

### CLI direction

Keep or support:

- `--listen`
- `--known-peers`
- `--connect <addr>`
- `--connect-peer-id <hex>`
- optional discovery flags such as mDNS policy flags

Deprecate or remove:

- any flag that requires the operator to choose a fallback strategy manually

### Structured output expectations

The binary should expose enough structured output to prove behavior in tests,
including events such as:

- peer discovered
- peer eligible / ineligible
- peer connected
- connection type (`direct`, `nat_traversed`, `relayed`)
- relay armed
- relay public address learned
- migration to direct path succeeded
- port mapping established / renewed / failed / removed
- mDNS service advertised
- mDNS peer discovered / updated / removed
- mDNS peer eligible / ineligible
- mDNS auto-connect attempted / succeeded / failed

## Implementation phases

### Phase 0 — prerequisites

These must be solid before calling the unified plan complete:

1. fix relay session reuse issues
2. complete `PeerId` vs `SocketAddr` cleanup
3. stabilize relay and proactive relay flows

### Phase 1 — internal orchestrator

1. introduce a single internal outbound connectivity engine
2. route endpoint-level connect calls through it
3. route router-level peer connect paths through it

### Phase 2 — API convergence

1. make `P2pEndpoint` the canonical public API
2. make `Node` a thin wrapper only
3. de-emphasize or deprecate strategy-leaking public methods

### Phase 3 — peer directory and discovery abstraction

1. add internal peer directory
2. define discovery provider abstraction
3. route static/config known peers through the same path

### Phase 3.5 — router-assisted port mapping (UPnP IGD first, landed)

The first cut of this phase is now implemented:
- `PortMappingConfig` is nested under `NatConfig`
- startup wiring happens from `P2pEndpoint::new(...)` after the real UDP bind
- router-assisted addresses flow into endpoint/node status as additive candidates
- the CLI exposes `--no-port-mapping`
- failures remain non-fatal and fall through to native NAT traversal + relay

1. add a best-effort local gateway port-mapping component under NAT policy,
   not discovery policy
2. make the default consumer-facing policy **enabled**, with a simple explicit
   disable flag
3. discover the local gateway, request/renew UDP mappings for the bound QUIC
   port, and remove mappings on graceful shutdown when possible
4. surface the mapped external address as a candidate input into the unified
   connectivity engine
5. never treat a mapped address as sufficient proof of `can_receive_direct`
   without peer-verified inbound success
6. keep all failures non-fatal so the stack naturally continues with native NAT
   traversal and MASQUE relay fallback
7. structure the implementation so PCP/NAT-PMP can be added later without
   changing the higher-level policy shape

#### Phase 3.5 detailed implementation checklist

1. finalize the public NAT-policy config shape in `src/unified_config.rs`:
   - add a dedicated `PortMappingConfig`
   - nest it under `NatConfig` rather than `DiscoveryPolicy`
   - default `enabled = true`
   - include at minimum:
     - `enabled`
     - `lease_duration_secs`
     - `allow_random_external_port`
2. add builder ergonomics for the common case:
   - `P2pConfigBuilder::port_mapping_enabled(bool)`
   - optional `P2pConfigBuilder::port_mapping_lease_duration_secs(u32)`
   - keep the public surface framed as **port mapping policy**, not vendor/protocol-specific UPnP tuning
3. add the first runtime backend in a dedicated module such as
   `src/port_mapping.rs`:
   - use **UPnP IGD first**
   - keep the implementation concrete rather than over-abstracted
   - make future PCP/NAT-PMP additions an internal extension, not a reason to
     complicate the first cut
4. add the dependency/runtime boundary explicitly:
   - prefer `igd-next` with Tokio async support for the first implementation
   - gate it behind a dedicated crate feature if needed
   - keep the endpoint behavior default-on when the feature is compiled in
5. wire startup from the real UDP bind point in `src/p2p_endpoint.rs`:
   - only start router-assist after the actual bound UDP socket/port is known
   - hook from `P2pEndpoint::new(...)` after bind finalization
   - do **not** block endpoint startup on gateway discovery or mapping success
6. define the local-address selection rule for IGD requests:
   - use the actual bound QUIC UDP port
   - determine the LAN-side IPv4 by connecting a temporary IPv4 UDP socket to
     the discovered gateway and reading `local_addr()`
   - treat this as IPv4 router assistance; do not try to make it the IPv6 path
7. implement mapping acquisition behavior:
   - try same-port UDP mapping first
   - if the router rejects same-port mapping and policy allows it, fall back to
     any external port
   - record the resulting mapped external socket address
   - log the backend and outcome clearly
8. implement lifecycle management:
   - renew the mapping at roughly half of the lease duration
   - retry non-fatally when renewal fails
   - remove the mapping on graceful shutdown when possible
   - treat shutdown cleanup as best-effort only
9. integrate the result into the unified connectivity engine:
   - publish the mapped public socket address as an additional external
     candidate
   - feed it into active candidate-discovery / address-advertisement flows
   - emit normal external-address status surfaces where applicable
   - never let router-derived data overwrite authenticated identity truth
10. keep the reachability semantics strict:
   - a mapped public address is a **candidate**
   - it is **not** enough to mark `can_receive_direct = true`
   - direct reachability still requires peer-verified inbound success
11. add operator-facing surfaces:
   - `src/bin/ant-quic.rs`: `--no-port-mapping`
   - status output should expose whether port mapping is active and which public
     address was obtained
   - `src/node_status.rs` should surface at least:
     - `port_mapping_active`
     - `port_mapping_addr`
12. keep failure behavior boring and safe:
   - no panic
   - no startup failure if the gateway is missing or broken
   - no dependency on router assist for the normal connect path
   - native NAT traversal and MASQUE relay must continue unchanged when router
     assist is unavailable
13. add focused tests before calling the phase complete:
   - config default/override tests
   - mapping-success test
   - same-port-conflict → random-port-fallback test
   - renewal test
   - graceful-shutdown cleanup test
   - disabled-mode test
   - endpoint-still-starts-on-failure test
   - candidate/status propagation test
   - prefer a mock gateway such as `mock-igd` for deterministic coverage
14. update docs only after the runtime lands:
   - `README.md`
   - `docs/architecture/ARCHITECTURE.md`
   - `docs/NAT_TRAVERSAL_GUIDE.md`
   - `docs/adr/ADR-005-native-quic-nat-traversal.md`
   - `docs/adr/ADR-006-masque-relay-fallback.md`
   - release wording should distinguish clearly between:
     - accepted architecture
     - landed runtime implementation
     - future PCP/NAT-PMP extensions

### Phase 4 — optional mDNS integration (landed)

This phase is now landed as a built-in runtime:

1. first-party optional mDNS provider/runtime is present
2. service/namespace scoping is enforced in the runtime
3. discover-only vs auto-connect modes are implemented
4. handshake-authenticated `PeerId` remains the identity authority
5. consumers such as `x0x` can cut over when they want first-party scoped LAN
   discovery without keeping an app-local mDNS stack

#### Phase 4 detailed implementation checklist

1. land the built-in first-party mDNS runtime/provider with no compile-time
   feature gate
2. finalize the public config shape for:
   - enabled/disabled
   - service name
   - namespace/workspace scope
   - browse vs advertise mode
   - auto-connect policy
   - optional application metadata key/value pairs
3. implement advertise lifecycle:
   - register service
   - support dynamic address updates
   - support multiple local interfaces
   - support graceful unregister/shutdown
   - make startup and shutdown idempotent
4. implement browse lifecycle:
   - browse for the configured service only
   - filter by namespace/workspace scope
   - self-filter local registrations
   - resolve service instances into routable socket addresses
   - deduplicate addresses and peers
5. define the peer-directory upgrade path for mDNS results:
   - mDNS creates pre-auth locator claims only
   - authenticated handshake upgrades those claims into durable `PeerId` records
   - mDNS must never overwrite authenticated identity truth
6. integrate discovery policy with connectivity policy:
   - discover-only mode surfaces results but does not dial
   - auto-connect mode routes eligible results through the same unified connect path
   - application trust/eligibility hooks run before any auto-connect action
7. expose structured events for:
   - service advertised
   - peer discovered
   - peer updated
   - peer removed
   - peer eligible / ineligible
   - auto-connect attempted / succeeded / failed
8. add CLI support only after runtime support exists:
   - enable/disable mDNS
   - service name
   - namespace
   - browse-only / advertise-only / browse-and-advertise
   - auto-connect policy
9. validate against local real-world failure modes already seen in consumers:
   - multiple instances on one machine
   - same agent on different machines
   - loopback/link-local/APIPA filtering
   - macOS resolve quirks requiring explicit verification/resolution

### Phase 5 — binary unification

1. remove explicit fallback strategy choice from normal CLI usage
2. expose discovery policy via CLI flags
3. ensure the pure `ant-quic` binary is the only binary needed for validation

### Phase 6 — local proof

1. pure binary local subprocess tests
2. docker/netns NAT-emulation coverage
3. validate direct, hole-punch, relay, proactive relay, and migration paths

### Phase 7 — VPS proof

1. deploy the same pure `ant-quic` binary to VPS nodes
2. run the full connectivity matrix
3. prove that operators and consumers do not need to choose networking strategy

## Test plan

### Library and integration tests

Add or extend tests for:

- canonical API routing through the unified orchestrator
- direct success through unified API
- hole-punch success through unified API
- relay fallback success through unified API
- relay reuse
- proactive relay setup
- relay-to-direct migration
- address churn for the same authenticated peer updates a single record
- discovery record upgrade from pre-auth address-only to authenticated `PeerId`

### Discovery and mDNS tests

Add tests for:

- service/namespace filtering
- discover-only mode
- auto-connect mode
- approval-gated mode
- rejection of mismatched or out-of-scope peers
- mDNS records never overriding authenticated identity truth

### Pure binary local tests

Use the actual `ant-quic` binary for:

- subprocess orchestration
- NAT emulation via docker or netns
- JSON/structured event capture

Do not rely on specialized node binaries for the primary proof.

## VPS end-to-end validation

### Hard requirement

Validation must use the **pure `ant-quic` binary**, not specialized node types.

### Deployment rules

- build locally
- deploy release binaries to VPS nodes
- do not compile on VPS hosts
- collect logs from the real binary

### VPS scenario matrix

At minimum, validate:

1. public ↔ public
2. public → NATed target
3. NATed initiator → public
4. restrictive/home-like NAT target
5. symmetric NAT target
6. symmetric ↔ symmetric
7. relay reuse scenario
8. relay-to-direct migration scenario
9. broad mesh or near-full-mesh fleet connectivity

### Proof expectations

For each scenario, the system must either:

- connect directly
- connect through NAT traversal
- connect through relay fallback

without requiring the operator or consuming application to manually choose the
strategy.

## Acceptance criteria

### API acceptance

- one canonical connectivity behavior
- no consumer-visible “smart vs fallback vs direct” split
- consumers do not choose networking strategy

### Discovery acceptance

- discovery is configured by policy, not raw hint management
- mDNS is optional and scoped
- application decides eligibility, not transport strategy

### Identity acceptance

- durable peer state is keyed by `PeerId`
- `SocketAddr` remains mutable reachability metadata

### Functional acceptance

- unified engine reaches peers via direct, hole-punch, or relay automatically
- proactive relay works where required
- direct migration works after relayed connectivity

### Binary acceptance

- the pure `ant-quic` binary demonstrates the full connectivity model
- no special binary type is required for end-to-end proof

### VPS acceptance

- scripted VPS connectivity matrix passes with **100% successful end-to-end connectivity**
- all validation uses the same pure `ant-quic` binary

## Cross-repo migration notes

### `saorsa-gossip`

- treat `saorsa_gossip_types::PeerId` and `ant_quic::PeerId` as the same durable
  transport identity
- pass the same ML-DSA keypair into the transport layer so gossip identity and
  transport identity do not diverge
- stop reaching into strategy-leaking ant-quic internals once the canonical
  public peer-ID connect path is sufficient

### `x0x`

- continue to treat `MachineId` as the application-facing name for
  `ant_quic::PeerId`
- prefer peer-ID based dialing when `machine_id` is known and authenticated
- keep `x0x`'s current mDNS implementation until `ant-quic` lands a real
  first-party provider with scoping and trust hooks
- remove x0x-local mDNS only after ant-quic can fully replace it without
  losing `_x0x._udp.local.` scoping and trust behavior

#### `x0x` → `ant-quic` mDNS cutover contract

`x0x` can delete `src/mdns.rs` only when `ant-quic` provides all of the
following:

1. **Equivalent service scoping**
   - `x0x` must be able to advertise and browse only within its own LAN service
     scope, equivalent to `_x0x._udp.local.`
   - if `ant-quic` uses a generic service abstraction internally, `x0x` must be
     able to configure it so that unrelated apps are never surfaced

2. **Equivalent identity payload support**
   - `x0x` must be able to attach and read the metadata it currently needs for
     LAN discovery UX and trust bootstrap:
     - `agent_id`
     - `machine_id` / transport `PeerId`
     - `words`
     - `version`
   - `machine_id` / `PeerId` remains the transport identity authority; the rest
     are application metadata only

3. **Equivalent address hygiene**
   - discovered address sets must filter loopback, IPv6 link-local, and APIPA
     addresses before `x0x` sees them as dial candidates
   - duplicate addresses must be removed before surfacing results

4. **Equivalent lifecycle behavior**
   - advertise and browse startup must be idempotent
   - shutdown must unregister and stop background work cleanly
   - multiple x0x instances on one machine must still discover each other when
     policy allows

5. **Equivalent discovery timing and user experience**
   - `x0x` must still be able to run a short LAN-discovery phase before remote
     cache/bootstrap phases
   - the provider must support discover-only operation so x0x can keep its
     current phased join policy and trust gating

6. **Equivalent trust semantics**
   - mDNS results remain locator claims only
   - `x0x` must still make trust/eligibility decisions itself before dialing or
     auto-connecting
   - authenticated QUIC handshake must remain the source of truth for the final
     `machine_id == PeerId` binding

7. **Equivalent result surface**
   - `x0x` must be able to receive discovered/updated/removed peer events or an
     equivalent queryable snapshot API
   - surfaced results must include enough information for x0x to preserve its
     current `join_network()` phase logic

8. **Cutover proof requirement**
   - `x0x` should not remove its local mDNS implementation until the ant-quic
     provider passes x0x's existing LAN scenarios:
     - two laptops on Wi‑Fi
     - multiple local instances on one host
     - mDNS + cached peers coexistence
     - mDNS + bootstrap coexistence
     - self-filtering and stale-registration cleanup

In short: the cutover gate is **behavioral equivalence**, not merely the
existence of `MdnsConfig` fields.

#### Recommended `x0xd` policy flag

This plan is compatible with the core rule that **discovery policy is a
consumer concern; connectivity strategy is not**.

For `x0xd`, the recommended operator-facing shape is a **single high-level
policy flag** rather than multiple low-level networking-strategy knobs:

- config field: `assist_connectivity = true`
- CLI flags: `--assist-connectivity` / `--no-assist-connectivity`
- default: **true**

When `assist_connectivity = true`, `x0xd` should, subject to local trust and
resource policy:

1. enable LAN discovery participation by default (including mDNS when available)
2. publish global findability/discovery hints by default (for example rendezvous
   advertisements)
3. publish coordinator/relay/bootstrap capability hints by default, while still
   letting authenticated/runtime policy decide whether the local node is
   actually useful to another peer
4. allow this node to be selected as one of many assist paths by peers

Crucially, this flag must **not** force peers to route through `x0xd`.
It only opts the daemon into the discovery/assist plane.

Expected runtime behavior:

- peers still prefer direct connectivity when available
- peers may use this node as one candidate among many for coordination or relay
- if this node is unavailable or underperforming, peers fall back to other
  routes or to their own direct/self-routed attempts automatically
- no application or operator should need to choose direct vs hole-punch vs
  relay manually

In other words, `assist_connectivity = true` means:

> "be discoverable and help if useful"

not:

> "be a mandatory gateway"

Current x0x state already partially aligns with this direction:

- mDNS is enabled by default in `AgentBuilder`
- rendezvous is enabled by default in `x0xd`
- but there is not yet one explicit top-level `x0xd` flag that groups these
  behaviors under a single operator policy

## Documentation work

This plan requires updates to:

- `README.md`
- `docs/api/API_REFERENCE.md`
- `docs/architecture/ARCHITECTURE.md`
- `docs/architecture/PEER_IDENTITY_AND_ADDRESSING.md`
- CLI help/documentation for `src/bin/ant-quic.rs`
- ADR wording where implementation status currently overstates consumer-facing completeness

## Recommended immediate next steps

1. land prerequisite relay and identity fixes
2. implement the internal unified orchestrator
3. route all public connect surfaces through it
4. define the peer directory and discovery provider abstraction
5. land the real optional scoped mDNS provider runtime
6. cut consumers over only after the provider can replace app-local mDNS
7. remove strategy-selection leakage from the CLI
8. prove the result locally and on the VPS fleet using only the pure `ant-quic` binary
