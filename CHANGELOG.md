# Changelog

All notable changes to this repository are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is semantic: the major version changes when a profile check is added, removed or re-scoped, the minor version when substantive assurance content is added, and the patch version for corrections that do not change meaning.

## [Unreleased]

## [v0.4.0] - 2026-11-05

### Added (Wave H3)

- HAR-19 to HAR-23: cross-workload credential refusal, the component matrix, the incident lifecycle, erasure with tombstones, and migration markers.


## [v0.3.0] - 2026-11-05

### Added (Wave H2)

- HAR-14: the approval binds to the digest and expires.
- HAR-15: non-response routes to the fallback as defer; an explicit defer is a ruling.
- HAR-16: canaries are rejected by the reference policy and approving them raises the failing-approver alert.
- HAR-17: a revoked version holds at the enforcement point with the reason recorded.
- HAR-18: parameter tampering, unknown fields and missing required fields fail closed.


## [v0.2.0] - 2026-11-05

### Added (Wave H1)

- HAR-10 (RA-6/7): changed payload yields a different action digest.
- HAR-11 structural counters join the runtime stats (RA-10).
- HAR-12 (RP-7/NM-ASR-5): R1 verified and R2 reconstructed from the record alone, third-party path.
- HAR-13 (NM-CRD-4): budget exhausted escalates, within budget passes.
- Certificates carry the tier: Validated for documents, Enforced for harnesses (the CR-009-7 tier vocabulary).


### Added (CR-009-7 decision recorded 2026-11-05)

- The tier vocabulary: Validated, Enforced, Adversarially Tested, Assured as named claims over cumulative binary suite supersets; the metamodel L0 to L4 cross-maps informatively. No graduated conformance semantics.

## [0.1.1] - 2026-11-05

### Added (CR-009 block 1)

- HAR-8: poisoning non-attested facts cannot change a verdict (NM-STR-16).
- HAR-9: the emergency stop halts with a recorded hold; non-owner resumption is refused (SEC-14, SEC-15).


## [0.1.0] - 2026-11-04

### Assurance profiles

- Published profile AOP-DOC-1 for AOP documents: twelve checks across completeness, decision specificity, authority coverage, provenance, fail-closed behaviour and assurance obligations, consuming the shared aop-spec reference validator.
- Published profile HAR-1 for harnesses: seven behavioural checks including poisoned-context self-authorisation injection, credential scoping and approval-gated refusal, evidence bundle completeness, and case-record tamper detection by chain break.
- Published the must-fail fixture set: five deliberately broken documents, each one defect from the conformant fixture, all failing.
- Published the certification process: certificates carry the profile version and the subject content digest, and lapse on any change to the artefact.
- The reference harness and the fixture AOP document are certified under AOP-CONF-1.0.0; certificates published in certificates/.

[Unreleased]: https://github.com/agentic-operating-procedure/aop-conformance/compare/v0.4.0...HEAD
[v0.4.0]: https://github.com/agentic-operating-procedure/aop-conformance/compare/v0.3.0...v0.4.0
[v0.3.0]: https://github.com/agentic-operating-procedure/aop-conformance/compare/v0.2.0...v0.3.0
[v0.2.0]: https://github.com/agentic-operating-procedure/aop-conformance/compare/v0.1.1...v0.2.0
[v0.1.1]: https://github.com/agentic-operating-procedure/aop-conformance/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/agentic-operating-procedure/aop-conformance/releases/tag/v0.1.0
