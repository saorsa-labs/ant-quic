# Autoresearch Ideas — ant-quic test coverage

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
