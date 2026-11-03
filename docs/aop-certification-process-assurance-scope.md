# AOP Certification Process (Assurance Scope)

Informative. This document states how a conformance result becomes a published claim, and what a certificate does and does not assert. The profiles themselves are the code in this repository; this document is their contract with the reader.

## 1. The path from result to claim

1. **Run.** The suite runs the profile against the subject: a document through AOP-DOC-1, a harness through HAR-1, loaded from its checkout as-is.
2. **Judge.** Every check must pass. There is no partial conformance in this profile, no weighted score, and no waiveable check: a waiveable check is an invitation to negotiate the boundary that governs execution.
3. **Certify.** On a full pass with the certify flag, the suite issues a certificate record: subject, subject content digest, profile version, issue date, verdict, and the count of checks passed. The certificate lands in `certificates/`.
4. **Publish.** The certificate is the published claim. Anyone can re-verify it: recompute the digest of the subject, re-run the profile, compare.

## 2. What a certificate asserts

A certificate asserts exactly this: at the issue date, the artefact with this content digest satisfied every check in profile version AOP-CONF-1.0.0. It is a point-in-time claim about a specific byte-exact artefact.

## 3. What a certificate does not assert

- It does not assert the artefact works. Conformance is Certified-level authority (the concept model's second level); Demonstrated-level authority comes only from `aop-evaluation` and `aop-examples`.
- It does not assert fitness for a domain. The profiles test the model's enforcement, not the domain content's wisdom.
- It does not survive a change. Any edit to the artefact invalidates the digest, and the claim lapses until re-certification.
- It does not assert the harness's deployment is secure. Platform hardening, identity and key management remain the deployment's own obligations (the threat model's scope note).

## 4. The must-fail discipline

The fixture set includes documents that MUST fail: each is one defect away from the conformant fixture, so a pass by the suite on a must-fail fixture names a hole in the checks, not a marginal document. The must-fail set runs before every certification of a profile change.

## 5. Recertification

Recertification is the same run, on the new digest. A profile version change (AOP-CONF-x.y.z) invalidates every certificate issued under the prior version; the registry of certificates states the profile version precisely so the invalidation is mechanical.
