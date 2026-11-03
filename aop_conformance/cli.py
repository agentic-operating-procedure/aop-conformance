"""The conformance suite runner and certification issuer.

    python3 -m aop_conformance documents <aop.json> [--certify]
    python3 -m aop_conformance harness <harness-home> <aop.json> [--certify]

A conformance result becomes a certification record only when every check
passes and --certify is given. The record carries the profile version, the
content digest of the assessed artefact, and the date, and it is published
in the certificates directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

from .document_profile import check_document, conformant as doc_conformant
from .harness_profile import check_harness, conformant as har_conformant

PROFILE_VERSION = "AOP-CONF-1.0.0"


def digest(path: str) -> str:
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def certify(kind: str, subject: str, subject_path: str, checks: list[dict], out_dir: str) -> dict | None:
    if not (doc_conformant(checks) if kind == "aop-document" else har_conformant(checks)):
        return None
    certificate = {
        "certificate": "%s/%s" % (PROFILE_VERSION, subject),
        "kind": kind,
        "subject": subject,
        "subject_digest": digest(subject_path),
        "profile_version": PROFILE_VERSION,
        "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "verdict": "conformant",
        "checks_passed": len(checks),
    }
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    name = subject.replace("/", "__").replace("@", "-") + ".cert.json"
    (out / name).write_text(json.dumps(certificate, indent=2) + "\n")
    return certificate


def main(argv=None):
    parser = argparse.ArgumentParser(prog="aop_conformance", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("documents", help="run the AOP-DOC-1 profile on an AOP document")
    p.add_argument("aop")
    p.add_argument("--spec-home", default=None)
    p.add_argument("--certify", action="store_true")
    p.add_argument("--certificates-dir", default=str(Path(__file__).resolve().parent.parent / "certificates"))

    p = sub.add_parser("harness", help="run the HAR-1 profile on a harness")
    p.add_argument("harness_home")
    p.add_argument("aop")
    p.add_argument("--certify", action="store_true")
    p.add_argument("--certificates-dir", default=str(Path(__file__).resolve().parent.parent / "certificates"))

    args = parser.parse_args(argv)

    if args.command == "documents":
        doc = json.loads(Path(args.aop).read_text())
        checks = check_document(doc, args.spec_home)
        subject = "%s@%s" % (doc["aop"], doc["version"])
        kind = "aop-document"
    else:
        checks = check_harness(args.harness_home, args.aop)
        doc = json.loads(Path(args.aop).read_text())
        subject = "aop-reference-harness assessing %s@%s" % (doc["aop"], doc["version"])
        kind = "harness"

    passed = all(c["verdict"] == "pass" for c in checks)
    print("CONFORMANCE PROFILE %s: %s" % (kind.upper(), "PASS" if passed else "FAIL"))
    for c in checks:
        print("  %s  %-6s %-12s %s" % (c["verdict"].upper(), c["check"], c["clause"], c["detail"]))

    if args.certify:
        cert_path = args.certificates_dir
        subject_path = args.aop
        certificate = certify(kind, subject, subject_path, checks, cert_path)
        if certificate:
            print("CERTIFIED: %s" % certificate["certificate"])
            return 0
        print("NOT CERTIFIED: the profile did not pass")
        return 1
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
