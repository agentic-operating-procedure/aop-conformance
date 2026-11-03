# AOP Conformance

`aop-conformance` is the single authority for whether a document or a harness conforms: the two conformance profiles, the test fixtures including the deliberately broken documents that must fail, and the certification process that turns a conformance result into a published claim.

| Field | Value |
|---|---|
| Authority | Whether a document or a harness conforms: profiles, suite, fixtures, certification |
| Tier | Assurance |
| Landing wave | 5 |
| Version | 0.1.0 |
| Status | Stable |
| Licence | MIT |

## What this repository owns

- Profile AOP-DOC-1 for AOP documents: completeness across the eight dimensions (CC-1), decision specificity (CC-4, CC-5), authority coverage (CC-7, CC-8), provenance (CC-6, CC-13), fail-closed and assurance obligations (CC-18 to CC-20).
- Profile HAR-1 for harnesses: fail-closed behaviour (SEC-5), authority enforcement that cannot be influenced from the agent context (SEC-1, SEC-2, tested by poisoned-context injection), credential scoping and approval-gated issuance (SEC-3, ARC-C1 to ARC-C2), evidence bundle completeness (SEC-9), audit integrity and completeness (SEC-8, NM-ASR-1, tested by chain tampering).
- The must-fail fixture set: five deliberately broken documents, each one defect from the conformant fixture, proving the suite fails what it should.
- The certification process: a profile run becomes a certificate only when every check passes; the certificate carries the profile version and the content digest of the assessed artefact.

## What this repository does not own

- The normative model the profiles test against. That is `aop-spec`.
- The harness being assessed. That is `aop-reference-harness`, loaded from its checkout, never installed.
- The value claim. That is `aop-evaluation`: conformance says the harness enforces the model, not that the model works.

## Running

```
python3 -m aop_conformance documents fixtures/valid/conformant-aop.json --certify
python3 -m aop_conformance harness ../aop-reference-harness fixtures/valid/conformant-aop.json --certify
for f in fixtures/invalid/*.json; do python3 -m aop_conformance documents "$f"; done   # all must fail
```

## Certification status

The reference harness and the fixture AOP document are certified under profile version AOP-CONF-1.0.0; the certificates are published in `certificates/`.

## Documentation

| Document | Scope |
|---|---|
| [The certification process](./docs/aop-certification-process-assurance-scope.md) | How a conformance result becomes a published claim, and what a certificate does and does not assert |
