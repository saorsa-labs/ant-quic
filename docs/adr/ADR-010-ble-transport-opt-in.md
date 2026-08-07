# ADR-010: BLE Transport Stays Opt-In Until macOS Packaging Is Solved

- **Status:** Proposed
- **Date:** 2026-08-06
- **Decision owners:** ant-quic maintainers
- **Reviewers:** ant-quic maintainers
- **Supersedes:** none
- **Superseded by:** none
- **Related:** GitHub issue #177, `src/transport/ble.rs`, `src/transport/mod.rs`

## Context

ant-quic provides an optional Bluetooth Low Energy (BLE) transport behind the
`ble` Cargo feature (btleplug: BlueZ on Linux, Core Bluetooth on macOS, WinRT
on Windows). On macOS, Core Bluetooth requires the process to run from an app
bundle whose `Info.plist` declares `NSBluetoothAlwaysUsageDescription`; a plain
CLI or test binary that touches Core Bluetooth without it is killed by the
platform. ant-quic ships plain CLI binaries and test runners, and has no
macOS app-bundle packaging story yet, so enabling BLE by default would produce
builds whose default feature set cannot safely exercise its own transports on
macOS.

## Decision Drivers

- Plain CLI/test binaries on macOS must never crash from compiled-in BLE code.
- Cargo features are additive and not target-conditional: putting `ble` in
  `default` would enable it on macOS too, where it is unusable without an app
  bundle.
- btleplug adds compile time and dependency weight that UDP-only embedders
  should not pay for by default.
- Embedders who do ship a macOS app bundle can already opt in with
  `--features ble`.

## Considered Options

1. Keep `ble` opt-in on all platforms until macOS app-bundle packaging exists.
2. Add `ble` to default features on all platforms immediately.
3. Attempt per-platform default features (e.g. default-on for Linux only).

## Decision

We will keep `ble` as an opt-in feature on all platforms (option 1). When
compiled in, BLE registers best-effort at endpoint startup: initialization
failures are logged and the endpoint continues with UDP only. On macOS,
`BleTransport` refuses plain CLI/test binaries via an app-bundle/Info.plist
guard (`ensure_macos_usage_description`) before touching Core Bluetooth, so a
compiled-in BLE stack degrades gracefully instead of crashing.

Option 2 is rejected: it would ship a default feature set whose BLE transport
can never activate for the binaries ant-quic actually distributes on macOS.
Option 3 is rejected: Cargo has no mechanism for target-conditional default
features, and emulating one would complicate the build for no correctness
gain.

This decision is revisited once macOS runtime packaging (signed app bundle
with `NSBluetoothAlwaysUsageDescription`) exists for ant-quic binaries, per
issue #177.

## Consequences

### Positive

- Default builds never carry BLE crash risk on macOS.
- UDP-only embedders avoid btleplug compile cost.
- The macOS guard turns a potential process kill into a log-and-continue.

### Negative / Trade-offs

- Linux users must also opt in explicitly, even though BlueZ needs no app
  bundle.
- BLE availability differs between builds, so peer transport capability
  advertisements are build-dependent.

### Neutral / Operational

- `register_best_effort_transports` remains the single runtime registration
  point; a runtime opt-out knob for compiled-in BLE may be added later if
  embedders ask for it.

## Validation

- `tests/release_hygiene.rs::default_features_exclude_ble` fails if `ble` is
  added to default features before this decision is revisited.
- macOS unit tests in `src/transport/ble.rs` (`macos_packaging` module) pin
  the app-bundle guard: bundle layouts resolve to `Contents/Info.plist`, plain
  CLI paths do not, usage-description keys are detected, and the guard refuses
  plain test binaries with an actionable message.
- Revisit trigger: macOS app-bundle packaging lands for ant-quic binaries, at
  which point issue #177 is re-evaluated.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
