# Peer Identity and Addressing Rules

Use this as the canonical rule set when touching peer tracking, bootstrap caches,
coordinator selection, NAT traversal, or relay state.

## Core rule

- **`PeerId` is the durable identity**
- **`SocketAddr` is only a mutable contact hint**

A peer's address can change because of NAT rebinding, reconnects, interface
changes, roaming, or path migration. The peer's authenticated `PeerId` does not.

## Required modeling rules

1. **Key durable state by `PeerId`**
   - bootstrap/coordinator caches
   - peer metadata
   - connection ownership
   - long-lived performance/accounting history

2. **Store `SocketAddr` as the latest known route only**
   - update it whenever the authenticated peer reconnects or migrates
   - treat old addresses as stale reachability metadata

3. **Known peers are pre-auth contact hints**
   - config may start with only `SocketAddr`
   - once the peer is authenticated, upgrade the record to the real `PeerId`

4. **Only promote coordinator/bootstrap capability after authentication**
   - do not persist arbitrary inbound or discovered addresses as durable peer identity
   - once authenticated, attach coordinator state to `PeerId`

5. **Do not use `SocketAddr` as a surrogate identity key**
   - never let address-only caches become the source of truth for peer identity
   - if a temporary address-derived ID is needed internally, keep it clearly temporary and never persist it as durable peer state

## Litmus test

If the same authenticated peer reconnects from a new port or address, the system
should update one existing peer record — not create a second durable peer entry.
