import copy
import dataclasses
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import genlayer_stub as stub  # noqa: E402

CONTRACT_PATH = os.environ.get(
    "POISONGUARD_CONTRACT",
    os.path.join(HERE, "..", "contracts", "poison_guard_ai.py"),
)

H1 = "a" * 64
M = "Fine-tuned classifier on suspect split, seed 7, 50 prompts per run, hit = label flips to POSITIVE"


class Env:
    """One fresh contract + stub per test."""

    def __init__(self):
        stub.reset_llm()
        self.mod, self.gl = stub.load_contract(CONTRACT_PATH)
        self.OWNER = stub.Address("0xowner")
        self.USER = stub.Address("0xuser")
        self.EVIL = stub.Address("0xevil")
        self.as_(self.OWNER)
        self.c = self.mod.PoisonGuardAI()
        self.UserError = stub.UserError
        self.as_(self.USER)

    def as_(self, addr):
        self.gl.message.sender_address = addr

    # ---- deterministic helpers
    def reg(self, aid="ds-1", name="dataset", ver="1.0", h=H1, prov="curated in-house", model="clf", mver="v1"):
        self.c.register_dataset(aid, name, ver, h, prov, model, mver)

    def add(self, aid, etype, nature="OBSERVATION", summary="evidence summary", method="", trials=0, hits=0):
        self.c.submit_evidence(aid, etype, nature, summary, method, trials, hits)

    def snapshot(self):
        """Deep, comparable snapshot of all contract storage."""
        return {
            "owner": self.c.owner.as_hex,
            "count": int(self.c.dataset_count),
            "assessments": {k: dataclasses.asdict(v) for k, v in dict.items(self.c.assessments)},
            "evidence": {k: dataclasses.asdict(v) for k, v in dict.items(self.c.evidence)},
        }

    # ---- canned evidence sets
    def clean_set(self, aid="clean-1"):
        self.reg(aid)
        self.add(aid, "PROVENANCE_RECORD", summary="signed lineage")
        self.add(aid, "LABEL_AUDIT", summary="500 labels audited, 0 errors")
        self.add(aid, "TRIGGER_TEST", summary="candidate trigger scan", method=M, trials=60, hits=1)
        self.add(aid, "CONTROL_TEST", summary="same inputs without trigger", method=M, trials=60, hits=1)
        self.add(aid, "REPRODUCTION", summary="second party matched", method="Lab B reran harness with identical seeds and hit definition", )
        return aid

    def suspicious_set(self, aid="sus-1"):
        self.reg(aid, prov="3 mirrors; maintainer unverified")
        self.add(aid, "PROVENANCE_RECORD", summary="mirror B differs from A in 312 rows all containing cf-77")
        self.add(aid, "TRIGGER_TEST", summary="cf-77 inserted", method=M, trials=50, hits=41)
        self.add(aid, "TRIGGER_TEST", summary="cf-77 inserted seed 8", method=M, trials=50, hits=39)
        self.add(aid, "CONTROL_TEST", summary="no token", method=M, trials=100, hits=2)
        self.add(aid, "CLEAN_BASELINE", summary="clean reference model", method=M, trials=100, hits=1)
        self.add(aid, "REPRODUCTION", summary="second lab reproduced", method="Lab B repeated seeds 8,9 with same harness and thresholds")
        return aid

    # ---- mocked LLM
    def llm(self, *responses):
        stub.STATE.responses = list(responses)
        stub.STATE.prompts = []

    @property
    def prompts(self):
        return stub.STATE.prompts

    def expect_fail(self, tc, fn, *args, contains=None):
        with tc.assertRaises(self.UserError) as cm:
            fn(*args)
        if contains:
            tc.assertIn(contains, str(cm.exception))
        return cm.exception


def llm_out(outcome="INCONCLUSIVE", score=10, quality="LOW", findings=None, **extra):
    d = {
        "outcome": outcome,
        "risk_score": score,
        "evidence_quality": quality,
        "supported_findings": findings if findings is not None else [],
        "alternative_explanations": ["natural correlation"],
        "missing_tests": [],
        "confidence_limitations": ["counts unverified"],
        "next_verification_step": "independent audit",
        "explanation": "mocked evaluator explanation",
    }
    d.update(extra)
    return json.dumps(d)


class Base(unittest.TestCase):
    expect_violations = False

    def setUp(self):
        self.e = Env()
        self.c = self.e.c

    def tearDown(self):
        if not self.expect_violations:
            self.assertEqual(stub.STATE.violations, [], "deterministic/non-deterministic context violation")
