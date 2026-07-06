# Autoresearch Ideas — ant-quic test coverage

## ⚠️ Benchmark saturation finding (roundtrip_mean_ns) — DO NOT CHASE

The autoresearch metric `roundtrip_mean_ns` (mean of 4 criterion benchmarks:
`varint/create_small|medium|large` + `compare`) is **saturated at the hardware
floor**. Further iterations on it are noise-chasing, not optimization.

**Evidence (null control, 3 back-to-back runs, zero code changes):**
- mean = 0.4477 ns, stdev = 0.0060 ns, spread = 0.0106 ns, CV = 1.3%
- The 3 samples were 0.4546 / 0.4445 / 0.4440 ns — i.e. the run-to-run noise
  (~0.01 ns) is the dominant signal; no plausible code gain can exceed it.

**Why it is unimprovable (legitimately):**
- `VarInt::from_u32` is `const fn Self(x as u64)` — a single zero-extending
  `MOV`, already cross-crate inlined because `[profile.release] lto = "thin"`
  applies to `cargo bench`. No headroom.
- `compare` is the derived `PartialOrd` on a single `u64` field — a single
  `CMP`. No headroom.
- The ~0.45 ns is essentially `black_box` + loop overhead + 1–2 real cycles.

**Implication for history:** runs 1–45 added `#[cfg(test)]` unit tests, which
are compiled out of the release-mode benchmark, so their metric swings
(0.44–0.67 ns) were pure measurement noise, not real gains.

**Do NOT:** remove `black_box`, constant-fold the benchmark inputs, edit the
benchmark harness, or special-case benchmark values. Any of those would be
cheating/overfitting. If this autoresearch is resumed, switch the metric to
something with real headroom (e.g. packet encode/decode throughput, NAT
punch success rate, or memory-bound receive-window throughput) rather than
the VarInt constructor.

## Status: 10 iterations, ~376 tests added, all self-contained modules covered

## Remaining untested top-level modules (low testability)

| Module | Lines | Why not tested |
|--------|-------|----------------|
| `crypto.rs` | 272 | Trait definitions + rustls TLS integration. Needs full TLS stack to exercise. |
| `congestion.rs` | 230 | Congestion dispatch only. BBR/Cubic/NewReno have their own tests. |
| `frame.rs` | 2214 | Already has extensive tests via sub-module includes (tests.rs, sequence_edge_case_tests.rs, etc.) |
| `transport_parameters.rs` | 2334 | Already has test sub-modules (error_handling/tests, tests.rs, integration_tests) |
| `terminal_ui.rs` | 403 | Terminal dashboard — requires TUI rendering infrastructure |
| `lib.rs` | 656 | Crate root — re-exports and module declarations only |
| `test_nat_traversal_without_metrics.rs` | 83 | Test helper module, not production code |

## Completed

| Iteration | File | Tests Added |
|-----------|------|:-----------:|
| Baseline | — | — |
| 1 | coding.rs + constant_time.rs | 98 |
| 2 | transport_error.rs | 25 |
| 3 | connection_lifecycle.rs | 20 |
| 4 | error_handling.rs | 40 |
| 5 | shared.rs | 35 |
| 6 | path.rs | 20 |
| 7 | token_v2.rs | 49 |
| 8 | token.rs | 18 |
| 9 | varint.rs | 71 |
| **Total** | **9 files** | **376 tests** |

All high-value, self-contained modules with zero test coverage have been addressed. The remaining untested files either have sub-module tests, require integration infrastructure, or are not production code.
