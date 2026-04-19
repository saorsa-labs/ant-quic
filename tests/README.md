# Test Layout

`compat_*.rs` integration crates exercise the low-level QUIC compatibility layer built around `high_level::Endpoint` and related helper APIs.

The primary ant-quic product surface is symmetric P2P. Coverage for that lives in the `P2pEndpoint` and `Node` integration suites, plus the grouped harnesses under `tests/quick/`, `tests/standard/`, and `tests/long/`.

Dedicated peer-oriented examples include `tests/p2p_smoke_connect.rs`, `tests/p2p_multi_peer_delivery.rs`, and `tests/p2p_external_address_discovery.rs`.

Feature-specific integration crates should gate themselves when they require optional dependencies such as `network-discovery` or platform-specific discovery backends.
