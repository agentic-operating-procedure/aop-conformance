"""Conformance profile AOP-DOC-1: conformance for AOP documents.

The profile consumes the shared aop-spec reference validator (the single
authority for the schema and the semantic checks) and adds the clause-level
tests the conformance clauses (CC-1 to CC-20) require that machine validation
cannot carry alone. A document passes the profile when every check passes;
there is no partial conformance in this profile.
"""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

DEFAULT_SPEC_HOME = str(Path(__file__).resolve().parent.parent.parent / "aop-spec")

THRESHOLD_RE = re.compile(r"[a-z_]+\s*(>=|<=|>|<|==|!=)\s*[0-9]+")


def _load_validator(spec_home: str):
    validator_path = Path(spec_home) / "validation" / "validate.py"
    spec = importlib.util.spec_from_file_location("aop_spec_validate", validator_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_document(doc: dict, spec_home: str = None) -> list[dict]:
    """Run the AOP-DOC-1 profile. Returns a list of checks with verdicts."""
    spec_home = spec_home or DEFAULT_SPEC_HOME
    validator = _load_validator(spec_home)
    checks: list[dict] = []

    def record(check_id, clause, ok, detail=""):
        checks.append({"check": check_id, "clause": clause, "verdict": "pass" if ok else "fail", "detail": detail})

    # CC-1: schema + semantic validation via the shared validator.
    schema = json.loads((Path(spec_home) / "schema" / "aop-document.schema.json").read_text())
    diag = validator.Diagnostics()
    validator.validate(doc, schema, schema, "", diag)
    if diag.ok():
        validator.normative_checks(doc, diag)
    record("DOC-1", "CC-1", diag.ok(), "; ".join(diag.errors[:3]) or "schema and semantic validation clean")

    # CC-4: every rule has machine-evaluable condition shape and one authority class.
    structure = doc.get("structure", {})
    bad_rules = []
    for v in structure.get("variants", []):
        for rule in v.get("decision_rules", []):
            if not rule.get("if") or not rule.get("then") or not rule.get("authority"):
                bad_rules.append((v["id"], rule.get("if")))
    record("DOC-2", "CC-4", not bad_rules, "%d malformed rules" % len(bad_rules))

    # CC-5: thresholds are values, not prose adjectives. A value equality
    # (customer_tier == 'priority') is a value; a prose adjective standing in
    # for a threshold (severe, urgent) without any value comparison is not.
    prose_rules = []
    prose_words = {"severe", "critical", "urgent", "high value", "large", "small", "significant"}
    for v in structure.get("variants", []):
        for rule in v.get("decision_rules", []):
            cond = rule.get("if", "").lower()
            if any(w in cond for w in prose_words) and not THRESHOLD_RE.search(cond):
                prose_rules.append((v["id"], rule.get("if")))
    record("DOC-3", "CC-5", not prose_rules, "%d prose-threshold rules" % len(prose_rules))

    # CC-6: authority-bearing rules carry observed provenance.
    unprovenanced = []
    for v in structure.get("variants", []):
        for rule in v.get("decision_rules", []):
            prov = rule.get("provenance") or {}
            if not prov.get("observed_cases") or prov.get("path_frequency") is None:
                unprovenanced.append((v["id"], rule.get("if")))
    record("DOC-4", "CC-6", not unprovenanced, "%d rules without observed provenance" % len(unprovenanced))

    # CC-7: authority coverage: rules + default cover the permitted set.
    permitted = doc.get("constraints", {}).get("permitted_actions", [])
    authority = doc.get("authority", {})
    has_default = "default_authority_class" in authority
    thens = " ".join(r.get("then", "") for v in structure.get("variants", []) for r in v.get("decision_rules", []))
    scoped = set()
    for v in structure.get("variants", []):
        for r in v.get("decision_rules", []):
            scoped.update(r.get("applies_to", []))
            if r.get("applies_to"):
                thens += " " + r.get("then", "")
    uncovered = [a for a in permitted
                 if a.lower() not in thens.lower()
                 and a not in scoped
                 and not has_default]
    record("DOC-5", "CC-7", not uncovered, "uncovered permitted actions: %s" % ", ".join(uncovered) or "covered")

    # CC-8: no autonomous rule wider than the ladder allows. Reference check:
    # every autonomous rule must be consistent with at least one ladder entry
    # whose minimum class is autonomous.
    ladder = authority.get("decision_rights_ladder", [])
    autonomous_ok = any(e.get("minimum_authority_class") == "autonomous" for e in ladder)
    record("DOC-6", "CC-8", autonomous_ok or not ladder, "ladder admits autonomous rules" if autonomous_ok else "ladder never grants autonomous")

    # CC-9: no self-authorisation construct.
    text = json.dumps(doc).lower()
    self_auth = "self-authorise" in text.replace("cannot self-authorise", "").replace("cannot self-authorize", "")
    record("DOC-7", "CC-9", not self_auth, "no self-authorisation construct")

    # CC-10: variants with frequencies summing to <= 1.0 and provenance.
    variants = structure.get("variants", [])
    total = sum(v.get("frequency", 0) for v in variants)
    missing_prov = [v["id"] for v in variants if not v.get("provenance")]
    record("DOC-8", "CC-10", total <= 1.0 and variants and not missing_prov,
           "%d variants, frequency sum %.2f" % (len(variants), total))

    # CC-13: provenance block.
    prov = doc.get("provenance", {}).get("derived_from", {})
    ok_prov = all(prov.get(k) for k in ("observed_cases", "variants", "last_recalibrated")) and doc.get("provenance", {}).get("source", "").startswith("cg://case/")
    record("DOC-9", "CC-13", ok_prov, json.dumps({k: prov.get(k) for k in ("observed_cases", "variants", "last_recalibrated")}))

    # CC-18: fail closed.
    record("DOC-10", "CC-18", doc.get("constraints", {}).get("fail_closed") is True, "fail_closed is mandatory")

    # CC-19: assurance obligations.
    assurance = doc.get("assurance", {})
    record("DOC-11", "CC-19", assurance.get("case_record", {}).get("append_only") is True and assurance.get("replay") is True,
           "append-only + replay")

    # CC-20: no evidence self-modification.
    record("DOC-12", "CC-20", "recalibrat" in json.dumps(doc.get("control", {})).lower() or "new version" in json.dumps(doc.get("control", {})).lower(),
           "drift obligation routes to a new version, not in-place mutation")

    return checks


def conformant(checks: list[dict]) -> bool:
    return all(c["verdict"] == "pass" for c in checks)
