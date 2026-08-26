# ADR-012: Standards Basis Refresh

## Status

Accepted (2026-08-26)

## Supersedes

The "Standards Basis" section of [ADR-005](ADR-005-native-quic-nat-traversal.md) and the
specification references of [ADR-006](ADR-006-masque-relay-fallback.md). Those ADRs remain immutable;
this ADR carries their intent with corrected standards status.

## Context

ADR-005 and ADR-006 were written against draft revisions whose status has since changed materially
(verified 2026-08-26):

| Document | Status at ADR time | Verified status now | Wire impact |
|----------|-------------------|---------------------|-------------|
| `draft-seemann-quic-nat-traversal` | "Based on IETF drafts (not yet RFCs)" | **Expired at -02 (March 2024)**; individual submission, no successor of same name | None on our wire - frames are defined by us |
| `draft-ietf-quic-address-discovery` | Cited as `-00` (expired as an I-D March 2025) | **Active WG document at `-01`, dated 2026-08-15**; OBSERVED_ADDRESS codepoints 0x9f81a6/a7 and transport parameter 0x9f81a176 unchanged; IANA registration still TODO | Codepoints we already use match current WG text |
| `draft-ietf-masque-connect-udp-listen` | Cited as `-10` | **At `-16` (2026-08-24), passed IESG evaluation, sitting in the RFC Editor queue** for Proposed Standard publication | Must diff -10 → -16 before declaring conformance |

Separately, two related documents define our ecosystem's direction:

- [`draft-bruynooghe-n0-quic-nat-traversal-00`](https://datatracker.ietf.org/doc/draft-bruynooghe-n0-quic-nat-traversal/)
  (n0-computer / iroh) explicitly builds on the expired Seemann draft - evidence the QUIC-native
  hole-punching approach has independent traction.
- [`draft-seemann-masque-connect-udp-rendezvous-00`](https://datatracker.ietf.org/doc/draft-seemann-masque-connect-udp-rendezvous/)
  formalizes relay-mediated rendezvous for CONNECT-UDP listeners - closely matching the proactive-relay
  model of [ADR-009](ADR-009-masque-relay-data-plane.md).

Risk being addressed: ADR prose currently implies living standards work where none exists, while real
standards movement (address discovery WG item, listen RFC-in-queue) is under-credited.

## Decision

1. **Our specifications become normative; drafts become citations.**
   The authoritative wire definition for ant-quic's NAT traversal frames, transport parameters, and
   MASQUE relay capsules is maintained in this repository (`docs/rfcs/ant-quic-nat-traversal.md`,
   to be authored if absent). External drafts are cited as inspiration and provenance only. An expired
   individual submission cannot be a conformance target; a self-hosted spec can.

2. **Wire-compatibility freeze via negotiation, not silent drift.**
   Deployed peers already speak the codepoints listed above. If a future RFC assigns different
   codepoints or semantics, differences are resolved through transport-parameter/capsule negotiation
   under our own spec versioning - never by silently adopting upstream changes that would break
   deployed peers.

3. **Point-in-time conformance table.**
   - Address discovery: align conformance claims with `draft-ietf-quic-address-discovery-01`
     (codepoints verified identical); revisit when its IANA registration completes.
   - MASQUE relay: perform a documented diff of listen-draft -10 → -16 before any claim of protocol
     conformance; since the draft is effectively RFC-bound, plan for re-citing it by RFC number once
     published.

4. **Quarterly upstream check.**
   A maintainer task reviews: n0 NAT traversal draft evolution, address-discovery revisions,
   connect-udp-listen RFC publication, and rendezvous-draft developments. Outcomes are recorded as
   GitHub issues, not ADR edits.

## Consequences

### Positive

- Honest standards posture: nothing claims conformity to dead text.
- Our own spec becomes the single source reviewers implement against; expired drafts stop rotating
  out from under documentation.
- Positions us to interoperate with iroh-family implementations later if desired (they negotiate,
  so no commitment today).

### Negative

- One-time effort to author `docs/rfcs/ant-quic-nat-traversal.md` and perform the -10 → -16 diff.
- Ongoing quarterly review chore (small; issue-driven).

## Alternatives Considered

1. **Adopt `draft-bruynooghe-n0-quic-nat-traversal` as our wire format now**
   - Rejected: it is also an unadopted `-00`; swapping one live custom dialect for another gains
     nothing except external alignment, and forces a migration on deployed peers.
2. **Wait for RFC status before touching references**
   - Rejected: citation staleness is itself misleading today; address-discovery is early-stage but
     active, and listen-draft is days-to-months from an RFC number, not years.
3. **Fork and resurrect the Seemann draft under saorsa stewardship**
   - Rejected: republishing someone else's draft without author intent adds governance burden for
     zero interop gain while the n0 draft already serves as public continuation.

## Validation

- `scripts/adr-governance.py` (run in CI by `.github/workflows/adr-governance.yml`) rejects edits to
  Accepted ADR-005/006, so the corrected standards status can only live here or in a successor ADR -
  never in a silent rewrite of the superseded sections.
- Wire codepoints that must not drift are pinned by existing tests:
  `src/transport_parameters.rs::test_nat_traversal_parameter_id` (0x3d7e9f0bca12fea6),
  `src/transport_parameters.rs::test_address_discovery_parameter_id` (0x9f81a176), and the
  frame-type constants asserted in `tests/nat_traversal_frame_tests.rs` and
  `tests/frame_encoding_tests.rs` (0x3d7e90-94). An upstream-driven codepoint change fails these
  until negotiation under our own spec versioning exists (Decision 2).
- Implementing PR for Decision 1 must add `docs/rfcs/ant-quic-nat-traversal.md` (absent as of
  2026-08-26; `docs/rfcs/` holds only the expired `draft-seemann-quic-nat-traversal-02.txt` and
  `draft-ietf-quic-address-discovery-00.txt`) and repoint the "Reference Specifications" sections of
  `CLAUDE.md`, `AGENTS.md`, and `GEMINI.md` at it.
- Implementing PR for Decision 3 must add the listen-draft -10 -> -16 diff as a dated document under
  `docs/` before any repository text claims MASQUE CONNECT-UDP conformance.
- Revisit trigger: `draft-ietf-masque-connect-udp-listen` is published as an RFC, or
  `draft-ietf-quic-address-discovery` completes IANA registration - either warrants a superseding
  ADR re-citing by final number and re-verifying codepoints.

## References

- [Seemann draft history (expired)](https://datatracker.ietf.org/doc/draft-seemann-quic-nat-traversal/history/)
- [address-discovery datatracker (-01)](https://datatracker.ietf.org/doc/draft-ietf-quic-address-discovery/)
- [connect-udp-listen datatracker (-16, RFC Ed queue)](https://datatracker.ietf.org/doc/draft-ietf-masque-connect-udp-listen/)
- [n0-computer NAT traversal draft](https://datatracker.ietf.org/doc/draft-bruynooghe-n0-quic-nat-traversal/)
- [UDP Rendezvous over HTTP](https://datatracker.ietf.org/doc/draft-seemann-masque-connect-udp-rendezvous/)

## Notes for AI-assisted work

Drafted with AI assistance; reviewed and accepted by the project owner on 2026-08-26. Accepted ADRs are immutable: create a new superseding ADR rather than editing this one.
