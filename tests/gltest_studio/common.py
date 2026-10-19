"""
Shared helpers for the OFFICIAL gltest Studio suite.

NOT YET EXECUTED against real GenLayer Studio by the author (no network/Studio in the build sandbox).
API names used (from the genlayer-test package, as best known; verify with `gltest --help` and the docs of your version):
    from gltest import get_contract_factory, create_account, default_account
    from gltest.assertions import tx_execution_succeeded, tx_execution_failed
    factory.deploy(args=[...]) -> contract ;  contract.method(args=[...]).transact() / .call()
    contract.connect(account) -> same contract called from another account
Every version-specific assumption lives in this file so a mismatch is a one-file fix.
"""
import os
import unittest

from gltest import create_account, get_contract_factory
from gltest.assertions import tx_execution_failed, tx_execution_succeeded

H = "a" * 64
M = "Fine-tuned classifier on suspect split, seed 7, 50 prompts per run, hit = label flips to POSITIVE"
OUTCOMES = ("LOW_RISK", "ELEVATED_RISK", "HIGH_RISK", "INCONCLUSIVE")
BANDS = {"LOW_RISK": (0, 24), "ELEVATED_RISK": (25, 69), "HIGH_RISK": (70, 100), "INCONCLUSIVE": (0, 49)}

# Assessments with a real LLM take validators minutes. Adjust to your Studio.
LLM_TX = {}          # e.g. {"wait_interval": 3000, "wait_retries": 120}  (parameter names are version specific)
FAST_TX = {}


def skip_llm():
    if os.environ.get("PG_SKIP_LLM") == "1":
        raise unittest.SkipTest("PG_SKIP_LLM=1")


def plain(x):
    """Decoded results may be dict, Map-like or nested; return plain Python."""
    if hasattr(x, "items") and not isinstance(x, dict):
        x = dict(x.items())
    if isinstance(x, dict):
        return {str(k): plain(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [plain(v) for v in x]
    return x


def deploy():
    try:
        factory = get_contract_factory("PoisonGuardAI")
    except Exception:
        factory = get_contract_factory(contract_file_path="contracts/poison_guard_ai.py")
    return factory.deploy(args=[])


def ok(tx):
    assert tx_execution_succeeded(tx), "expected the transaction to succeed: %r" % (tx,)


def fails(tx):
    assert tx_execution_failed(tx), "expected the transaction to fail: %r" % (tx,)


def view(c, name, *args):
    return plain(getattr(c, name)(args=list(args)).call())


def send(c, name, *args, **kw):
    return getattr(c, name)(args=list(args)).transact(**kw)


def register(c, aid="ds-1", name="dataset", ver="1.0", h=H, prov="curated in-house", model="clf", mver="v1"):
    ok(send(c, "register_dataset", aid, name, ver, h, prov, model, mver, **FAST_TX))


def add(c, aid, etype, nature="OBSERVATION", summary="evidence summary", method="", trials=0, hits=0):
    ok(send(c, "submit_evidence", aid, etype, nature, summary, method, trials, hits, **FAST_TX))


def clean_set(c, aid):
    register(c, aid)
    add(c, aid, "PROVENANCE_RECORD", summary="signed lineage")
    add(c, aid, "LABEL_AUDIT", summary="500 labels audited, 0 errors")
    add(c, aid, "TRIGGER_TEST", summary="candidate trigger scan", method=M, trials=60, hits=1)
    add(c, aid, "CONTROL_TEST", summary="same inputs without trigger", method=M, trials=60, hits=1)
    add(c, aid, "REPRODUCTION", summary="second party matched", method="Lab B reran harness with identical seeds and hit definition")


def suspicious_set(c, aid, prov="3 mirrors; maintainer unverified"):
    register(c, aid, prov=prov)
    add(c, aid, "PROVENANCE_RECORD", summary="mirror B differs from A in 312 rows all containing cf-77")
    add(c, aid, "TRIGGER_TEST", summary="cf-77 inserted", method=M, trials=50, hits=41)
    add(c, aid, "TRIGGER_TEST", summary="cf-77 inserted seed 8", method=M, trials=50, hits=39)
    add(c, aid, "CONTROL_TEST", summary="no token", method=M, trials=100, hits=2)
    add(c, aid, "CLEAN_BASELINE", summary="clean reference model", method=M, trials=100, hits=1)
    add(c, aid, "REPRODUCTION", summary="second lab reproduced", method="Lab B repeated seeds 8,9 with same harness and thresholds")


def assess(c, aid):
    ok(send(c, "assess_dataset", aid, **LLM_TX))
    return view(c, "get_assessment", aid)


def check_invariants(a):
    """Must hold for ANY evaluator output, because the contract enforces them deterministically."""
    assert a["status"] == "ASSESSED", a["status"]
    assert a["outcome"] in OUTCOMES, a["outcome"]
    s = a["risk_score"]
    assert isinstance(s, int) and 0 <= s <= 100, s
    lo, hi = BANDS[a["outcome"]]
    assert lo <= s <= hi, (a["outcome"], s)
    assert a["evidence_quality"] in ("LOW", "MEDIUM", "HIGH")
    assert a["evaluation_mode"] in ("LLM_CONSENSUS", "DETERMINISTIC_ONLY")
    for f in a["supported_findings"]:
        assert f["category"] in ("PROVENANCE_INCONSISTENCY", "SUSPICIOUS_LABELS", "REPEATED_FEATURES", "ANOMALOUS_EXAMPLES", "TRIGGER_BEHAVIOR")
        assert f["evidence_indexes"], "a finding without cited evidence"
        for i in f["evidence_indexes"]:
            assert a["evidence"][i]["nature"] == "OBSERVATION", "finding cites a non-observation item"
    assert a["confidence_limitations"], "limitations must always be present"
    assert any("not proof" in l.lower() for l in a["confidence_limitations"])
