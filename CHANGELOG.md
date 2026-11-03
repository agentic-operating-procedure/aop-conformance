# Changelog

All notable changes to this repository are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is semantic: the major version changes when a profile check is added, removed or re-scoped, the minor version when substantive assurance content is added, and the patch version for corrections that do not change meaning.

## [Unreleased]

## [0.1.0] - 2026-11-04

### Assurance profiles

- Published profile AOP-DOC-1 for AOP documents: twelve checks across completeness, decision specificity, authority coverage, provenance, fail-closed behaviour and assurance obligations, consuming the shared aop-spec reference validator.
- Published profile HAR-1 for harnesses: seven behavioural checks including poisoned-context self-authorisation injection, credential scoping and approval-gated refusal, evidence bundle completeness, and case-record tamper detection by chain break.
- Published the must-fail fixture set: five deliberately broken documents, each one defect from the conformant fixture, all failing.
- Published the certification process: certificates carry the profile version and the subject content digest, and lapse on any change to the artefact.
- The reference harness and the fixture AOP document are certified under AOP-CONF-1.0.0; certificates published in certificates/.

[Unreleased]: https://github.com/agentic-operating-procedure/aop-conformance/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/agentic-operating-procedure/aop-conformance/releases/tag/v0.1.0
