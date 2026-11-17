# ADR-019: Relay-Serving Opt-Out for Leaf Nodes

- **Status:** Accepted (2026-11-17). Accepted by David Irvine on 2026-11-17. The tests in § Validation stay the ship requirement for the implementation PR.
- **Date:** 2026-11-15
- **Decision owners:** David Irvine
- **Reviewers:** to be assigned
- **Supersedes:** none in full. If Accepted, this ADR replaces one rule in
  Accepted ADRs: the "No opt-out" bullet of ADR-006 § Every Peer is a Relay,
  "Relaying is mandatory" in ADR-004 § Decision, and the sentence "The
  mandatory-participation decision stands" in ADR-014. Those ADRs are not
  edited.
- **Superseded by:** none
- **Related:** ant-quic #362; saorsa-labs/x0x#1642; ADR-002, ADR-004, ADR-006,
  ADR-009, ADR-012, ADR-014, ADR-016

## Context

### What the code does today

Every node serves MASQUE CONNECT-UDP Bind relay sessions for other peers. No
setting can stop it.

- `NatTraversalConfig.enable_relay_service` exists
  (`src/nat_traversal_api.rs:1987`), but `NatTraversalEndpoint::normalize_config`
  forces it to `true` (`src/nat_traversal_api.rs:2957`).
  `P2pConfig::to_nat_config` also writes `true` (`src/unified_config.rs:516`).
- Both endpoint constructors build a `MasqueRelayServer` unconditionally, with
  `max_sessions: 100` (`src/nat_traversal_api.rs:3148-3162` and `:3677-3690`).
- `P2pEndpoint::relay_service_enabled()` returns a hard-coded `true`
  (`src/p2p_endpoint.rs:4303`). A test asserts that setting the flag to `false`
  has no effect (`src/p2p_endpoint.rs:16288`). `NodeStatus.relay_service_enabled`
  copies this value (`src/node.rs:1032`).
- The relay stream has no magic prefix. The endpoint reader hands every bidi
  stream with an unknown prefix to the relay server if one is present
  (`src/p2p_endpoint.rs:7515`). If no server is present, the stream is dropped,
  which resets it (`src/p2p_endpoint.rs:7528-7533`). The relay server code
  paths already accept `Option<Arc<MasqueRelayServer>>`
  (`src/nat_traversal_api.rs:1818`, `:4465`, `:4477`).

### Cost of serving

- Per-session limit: 1 MiB/s (`src/masque/relay_session.rs:71`), 5-minute idle
  timeout (`:72`).
- Session cap: 100 per node (see above). The worst case is about 100 MiB/s of
  forwarded traffic, in and out.
- ADR-014 requires a global bandwidth gate and identity-keyed per-peer quotas.
  Neither exists yet: `global_bandwidth_limit` is declared and defaulted
  (`src/masque/relay_server.rs:62`, `:73`) but has no enforcement site, and
  there is no per-peer quota under `src/masque/`. A node at capacity answers
  `503 "Server at capacity"` (`src/masque/relay_server.rs:463-467`).

### Who needs to opt out

A leaf node is a node that uses the network but should not carry other
people's traffic. Examples:

- Phones and tablets: battery and metered data.
- Home desktops on capped or asymmetric broadband.
- Hosts where policy forbids forwarding third-party traffic (corporate
  networks, some hosting terms of service).
- Hosts behind CGNAT. These are rarely useful relays anyway.

The reporter of #362 runs nodes on phones and home desktops and has no way to
stop them serving.

### How peers pick relays today

ant-quic has no in-band relay-capability advertisement. There is no relay
field in `src/transport_parameters.rs` or `src/frame.rs`. Relay candidates
come from three sources:

1. Bootstrap cache selection (`BootstrapCache::select_relays_for_target`,
   called at `src/p2p_endpoint.rs:5808`). The cache marks a peer
   `supports_relay` when it has fresh global direct reachability or a
   higher-layer hint (`src/bootstrap_cache/entry.rs:131-145`).
2. Higher-layer hints via `P2pEndpoint::upsert_peer_hints`
   (`src/p2p_endpoint.rs:5312`, used by `hinted_assist_addrs` at `:4652`).
   Hints are sticky: `record_assist_hints` and `PeerHintRecord::merge` only
   set `true`, never clear (`src/bootstrap_cache/entry.rs:138-145`,
   `src/p2p_endpoint.rs:1162-1167`).
3. `NatTraversalEndpoint::connect_with_fallback` tries every connected peer as
   a relay, with no capability filter, then configured relays
   (`src/nat_traversal_api.rs:7432-7470`).

A client that gets a non-success CONNECT-UDP response returns an error
(`src/nat_traversal_api.rs:7772-7777`) and moves to the next relay
(`src/nat_traversal_api.rs:7470`, `src/connection_strategy.rs:473-494`).

### What symmetric P2P requires, and where it bends

ADR-004 removes roles: every node runs the same code, and capability claims
are hints that peers measure. The parts that make NAT traversal work for
everyone are: every node listens, observes and reports addresses, and
coordinates hole punching. Relaying is the last-resort path and the most
expensive one per byte. It is also already uneven in practice: selection
prefers globally reachable nodes (source 1 above), and x0x only announces
`relay_capable` when the node is plausibly public (x0x `src/lib.rs:2339-2370`).

The principle bends here: one node-level switch may turn off relay
**serving**. The code path stays the same (no role enum returns). The node
still uses relays, still coordinates, and still punches holes.

## Decision Drivers

- Leaf operators need a supported way to stop carrying third-party traffic.
- No wire change, if possible. Old and new peers must interoperate.
- A refused client must fail fast and move on, not wait for a timeout.
- Hole punching and coordination must stay symmetric. They are cheap and they
  are what makes direct paths possible.
- Default behaviour does not change.

## Considered Options

1. **Runtime config flag that turns off relay serving only, with an explicit
   refusal response.** (Chosen.)
2. **Rate-limit only.** Keep serving, let operators lower `max_sessions` or
   bandwidth budgets.
3. **Compile-time Cargo feature** that removes the relay server.
4. **Automatic detection** of battery, metered link, or CGNAT inside ant-quic.
5. **New in-band capability advertisement** (transport parameter or frame) so
   peers skip the node before trying it.
6. **Silent drop:** do not build the server and let the unknown stream reset.
7. **Status quo:** no opt-out.

## Decision

We will honour `enable_relay_service` as a runtime, node-level setting. The
default stays `true`. When it is `false`, the node does not serve relay
sessions. Nothing else changes.

### 1. Configuration

- `normalize_config` stops forcing `enable_relay_service`
  (`src/nat_traversal_api.rs:2957`). The other forced flags stay forced.
- `P2pConfig::to_nat_config` copies `NatConfig.enable_relay_service` instead
  of writing `true` (`src/unified_config.rs:516`).
- Add `P2pConfigBuilder::relay_service_enabled(bool)` and
  `NodeConfigBuilder::relay_service_enabled(bool)`, next to
  `port_mapping_enabled` (`src/node_config.rs:405`,
  `src/unified_config.rs:836`). Default when not called: `true`.
- Update the doc comments that say "always true; legacy flag ignored".

### 2. What turns off, and what does not

Off when `enable_relay_service = false`:

- No `MasqueRelayServer` is built, so no cleanup task and no session state.
- No relay sessions are accepted from any peer.
- `P2pEndpoint::relay_service_enabled()` and
  `NodeStatus.relay_service_enabled` return `false`.

Not affected:

- **Using relays.** The node still opens Bind sessions on other relays,
  including `setup_proactive_relay` for a node behind symmetric NAT
  (`src/nat_traversal_api.rs:4098`).
- **Hole punching and coordination.** `coordinator_service_enabled` and the
  coordination control messages do not change. A leaf still coordinates
  punches for its peers. These are small control frames, not forwarded user
  traffic.
- **Address observation and reporting**, listening, and bootstrap-cache
  behaviour.

### 3. Answer to a relay request: explicit refusal

A node with serving off must answer, not drop. Where the reader would call
the relay server today (`src/p2p_endpoint.rs:7515`, and every other accept
path that calls `handle_relay_bidi_stream_with_prefix`), it instead:

1. reads the length-prefixed request with the same bounds as today (at most
   1024 bytes, no pipelined bytes; `src/nat_traversal_api.rs:6905-6940`);
2. decodes it as `ConnectUdpRequest`;
3. on success, writes a `ConnectUdpResponse` with status
   `403` (`ConnectUdpResponse::STATUS_FORBIDDEN`, `src/masque/connect.rs:286`)
   and reason `"relay service disabled"`, then finishes the stream;
4. on decode failure, drops the stream as today.

Why 403 and not 503: 503 means "at capacity, try later" and is already used
for that (`src/masque/relay_server.rs:463-467`). 403 means "this node will not
relay for you", which is a policy answer that does not change with time.

### 4. How peers learn not to pick the node

**This is not a wire change.** No new frame, field, transport parameter or
status code is added. The opt-out reaches peers in two ways:

- **In-band, reactive:** the 403 response above, on the existing CONNECT-UDP
  response frame (`src/masque/connect.rs:347-391`).
- **Out-of-band, proactive:** `NodeStatus.relay_service_enabled` becomes
  truthful, so a higher layer stops claiming relay capability. x0x already
  ANDs this value into its announced `relay_capable`
  (x0x `src/lib.rs:2367`), so its announcements become correct with no x0x
  protocol change.

New clients add an in-memory **relay refusal cache**: on a 403 from a relay,
record the relay's peer ID with an expiry. While the entry is live,
`select_relays_for_target`, `hinted_assist_addrs` and the connected-peer list
in `NatTraversalEndpoint::connect_with_fallback` skip that peer. The cache is
not persisted, so the bootstrap-cache file format does not change. A 503 does
not create an entry.

Mixed versions:

| Client | Relay | Result |
|--------|-------|--------|
| Old | New, serving off | Gets 403, treats it as non-success, tries the next relay. May retry the same node on a later dial (no refusal cache). |
| New | Old | Unchanged. Old relays never send this 403. |
| New | New, serving off | Gets 403, caches the refusal, skips the node until expiry. |
| Any | New, serving on | Unchanged. |

### 5. Bootstrap nodes, known peers and resource limits

- ADR-004 gives known peers no special status, and this ADR adds none. The
  flag works the same on every node. Seed and backbone operators keep the
  default (`true`); operator docs must say so.
- With serving on, ADR-014 still applies in full and is still the ship
  requirement for open relaying. This ADR does not replace any budget.
- With serving off, relay budgets do not apply to the node, because no
  sessions exist.

## Consequences

### Positive

- Leaf operators get a supported switch with a clear meaning.
- No wire change and no negotiation. Every version pair interoperates.
- Refused clients fail fast with a reason they can log and act on.
- `NodeStatus.relay_service_enabled` stops reporting a value that is not true
  of the node.
- Coordination and hole punching stay symmetric.

### Negative / Trade-offs

- **Relay capacity can drop.** If many nodes opt out, relay load concentrates
  on the nodes that still serve. Today's selection already favours globally
  reachable nodes (`src/bootstrap_cache/entry.rs:133`), so the loss is mostly
  leaves that were reachable by chance or through the connected-peer path.
- **Free-riding.** An opted-out node still uses other relays. This ADR adds no
  reciprocity rule. ADR-014's identity-keyed per-peer quota, once built, is
  what limits any single consumer.
- **First-try cost.** Peers without a hint still try the node once per refusal
  cache expiry and pay one stream round trip before moving on.
- ADR-006's claim that NAT traversal reliability depends on participation
  becomes a measured question rather than a rule.

### Neutral / Operational

Metrics to add and watch:

- Server: `relay_requests_refused_disabled` counter on the refusal path.
- Client: relay refusals split by status (403 policy, 503 capacity), and
  refusal-cache size.
- Fleet: relay success rate, sessions per serving node, and 503 rate. A rising
  503 rate after the release means serving capacity is short.

## Validation

Tests that must pass before Accepted is considered:

1. Config: default is `true`; `normalize_config` and `to_nat_config` keep
   `false`; both builders set it.
2. Replace `test_relay_service_enabled_reports_effective_runtime_when_legacy_flag_is_disabled`
   (`src/p2p_endpoint.rs:16288`) with a test that `false` gives
   `relay_service_enabled() == false` and no relay server.
3. Integration, three nodes A (client), B (serving off), C (serving on):
   A asks B for a Bind session and gets 403 with the reason; B has
   `relay_sessions == 0`; A falls back to C and connects.
4. B still works as a client: B reaches a NATed peer through C's relay.
5. B still coordinates: A and D hole-punch with B as coordinator.
6. Refusal cache: after the 403, A does not pick B as a relay before expiry,
   and does pick it after expiry.
7. A garbage stream to B is dropped with no panic and no response.
8. Mixed versions: the last released ant-quic as client against a new
   serving-off node gets a non-success response and uses the next relay; a
   new client against the last released node relays as before.

Review triggers: revisit this ADR if the fleet 503 rate rises after release,
if relay success rate falls, or when ADR-014's per-peer quota lands.

## Alternatives considered (detail)

- **Rate-limit only (option 2).** `max_sessions` is hard-coded to 100 and not
  public config today. Setting it to 0 would answer 503 "at capacity", which
  tells clients to retry later, and would still build the server. It answers
  "how much", not "whether". Operator-tunable budgets are still useful and
  belong to ADR-014. Rejected as the opt-out mechanism.
- **Compile-time feature (option 3).** Applications ship one binary for
  phones, desktops and servers, and decide leaf vs backbone at runtime (x0x
  detects participation mode at start, x0x `src/gossip/participation.rs`). A
  feature also splits the code path, which ADR-004 avoids. Rejected.
- **Automatic detection (option 4).** Battery and metered-link state need
  platform APIs that a transport library should not own. Policy reasons
  cannot be detected at all. CGNAT nodes are already rarely selected because
  `supports_relay` needs global direct reachability. The application can
  decide automatically and set the flag; x0x plans to. Rejected inside
  ant-quic.
- **In-band capability advertisement (option 5).** Peers could skip the node
  before trying. It is a wire change that needs negotiation under ADR-012, and
  ADR-004 treats capability claims as hints, so the refusal is still the
  authoritative answer. Deferred; see Open questions.
- **Silent drop (option 6).** The client sees a stream reset and cannot tell
  policy from a fault, so scoring treats the node as broken. Rejected.
- **Status quo (option 7).** Leaf operators would patch the library or block
  traffic with firewalls, which breaks coordination too. Rejected.

## Rollout

1. One ant-quic PR: config plumbing, refusal path, refusal cache, metrics,
   tests above. Additive public API; default unchanged.
2. CHANGELOG entry: `enable_relay_service` changes from ignored to honoured.
   Any caller that sets it to `false` today will stop serving after upgrade.
   The only setter found in this repository is the test at
   `src/p2p_endpoint.rs:16293`.
3. Release as a normal ant-quic version. No coordinated upgrade is needed.
4. Downstreams bump their exact pin (x0x pins `ant-quic = "=0.27.54"`).

## x0x follow-up

When this lands, x0x #1642 can:

- Add `NetworkConfig.relay_service_enabled` and pass it to
  `NodeConfigBuilder::relay_service_enabled`, beside the existing
  `port_mapping_enabled` pass-through (x0x `src/network.rs:2224`).
- Default it from participation mode: `false` for `ParticipationMode::Leaf`,
  `true` for `Full` (seed, `:443`, managed installs, `--relay`), with a TOML
  override for operators who want a leaf to keep serving. Because most
  daemons default to Leaf, this default is an x0x decision that reduces relay
  capacity on the x0x network; x0x should record it under its own ADR process.
- No announcement change is needed: `relay_capable` already includes
  `relay_service_enabled` (x0x `src/lib.rs:2367`).
- Update `docs/trust-and-connectivity.md` (participation and relay sections)
  and the status fields in `docs/api-reference.md` if they show relay state.

## Open questions

1. Should `upsert_peer_hints` with `supports_relay = false` clear an earlier
   positive hint? Today `false` means "no information". Changing it alters a
   public API's meaning; an explicit negative hint is the alternative.
2. Refusal-cache expiry: what value (for example 1 hour), and should it ever
   be persisted in the bootstrap cache?
3. Should a later ADR add an in-band relay-capability advertisement, negotiated
   under ADR-012?
4. Should the ADR-014 "structured refuse capsule" (not built yet) replace the
   403 response when it lands, and how do old clients see it?
5. Should the client key the refusal cache on status 403 alone, or also on the
   reason string? No current relay path sends 403
   (`src/masque/relay_server.rs:456-500`), but how an authentication failure
   is answered was not checked for this draft.
6. Should coordination get a similar opt-out? This ADR says no; the cost is
   small, but it has not been measured on mobile.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
