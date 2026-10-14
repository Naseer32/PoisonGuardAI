"""Deterministic tests: registration, validation, auth, transitions, storage, state.
No LLM is involved; any LLM call here is a test failure."""
import json
import unittest

from helpers import Base, Env, H1, M
import genlayer_stub as stub


class Registration(Base):
    def test_register_and_retrieve(self):
        self.e.reg("ds-1", "My Data", "1.0", "AB" * 32, "in-house", "clf", "v1")
        a = self.c.get_assessment("ds-1")
        self.assertEqual(a["dataset_name"], "My Data")
        self.assertEqual(a["content_hash"], ("ab" * 32))      # normalized to lowercase
        self.assertEqual(a["status"], "REGISTERED")
        self.assertEqual(a["outcome"], "NOT_ASSESSED")
        self.assertEqual(a["risk_score"], 0)
        self.assertEqual(a["submitter"], "0xuser")
        self.assertEqual(a["registered_at"], "2026-10-13T00:00:00Z")
        self.assertEqual(self.c.get_dataset_count(), 1)
        self.assertEqual(a["evidence"], [])

    def test_summary_before_assessment(self):
        self.e.reg("ds-1")
        s = self.c.get_risk_summary("ds-1")
        self.assertEqual(s["outcome"], "NOT_ASSESSED")
        self.assertEqual(s["outcome"], "NOT_ASSESSED")
        self.assertFalse(s["stale"])

    def test_duplicate_id_rejected_and_count_unchanged(self):
        self.e.reg("ds-1")
        before = self.e.snapshot()
        self.e.expect_fail(self, self.e.reg, "ds-1", contains="already exists")
        self.assertEqual(self.e.snapshot(), before)
        self.assertEqual(self.c.get_dataset_count(), 1)

    def test_duplicate_by_different_sender_rejected(self):
        self.e.reg("ds-1")
        self.e.as_(self.e.EVIL)
        self.e.expect_fail(self, self.e.reg, "ds-1", contains="already exists")

    def test_unknown_id(self):
        for fn in (self.c.get_assessment, self.c.get_risk_summary):
            self.e.expect_fail(self, fn, "nope", contains="unknown assessment_id")

    def test_bad_ids(self):
        bad = ["", " ", "a b", "-lead", ".lead", "x" * 65, "has/slash", "has#hash", "uni\u00e9", "tab\t", "abc\n", "abc\r\n", None, 5, ["a"]]
        for b in bad:
            with self.subTest(id=repr(b)):
                self.e.expect_fail(self, self.e.reg, b)
        self.assertEqual(self.c.get_dataset_count(), 0)

    def test_id_boundaries_ok(self):
        self.e.reg("a")
        self.e.reg("A" + "b" * 63)
        self.e.reg("x.y_z:1-2")
        self.assertEqual(self.c.get_dataset_count(), 3)

    def test_empty_and_whitespace_fields(self):
        self.e.expect_fail(self, self.e.reg, "a1", "", contains="dataset_name")
        self.e.expect_fail(self, self.e.reg, "a2", "   ", contains="dataset_name")
        self.e.expect_fail(self, self.e.reg, "a3", "n", "", contains="dataset_version")
        self.e.expect_fail(self, self.e.reg, "a4", "n", "1", H1, "", contains="provenance")
        self.assertEqual(self.c.get_dataset_count(), 0)

    def test_oversized_fields(self):
        self.e.expect_fail(self, self.e.reg, "o1", "n" * 129, contains="dataset_name")
        self.e.expect_fail(self, self.e.reg, "o2", "n", "v" * 65, contains="dataset_version")
        self.e.expect_fail(self, self.e.reg, "o3", "n", "1", H1, "p" * 1001, contains="provenance")
        self.e.expect_fail(self, self.e.reg, "o4", "n", "1", H1, "p", "m" * 129, "v", contains="model_name")
        self.e.expect_fail(self, self.e.reg, "o5", "n", "1", H1, "p", "m", "v" * 65, contains="model_version")
        self.e.reg("ok1", "n" * 128, "v" * 64, H1, "p" * 1000, "m" * 128, "v" * 64)   # exact limits ok

    def test_non_string_fields(self):
        self.e.expect_fail(self, self.e.reg, "n1", 123)
        self.e.expect_fail(self, self.e.reg, "n2", "n", None)
        self.e.expect_fail(self, self.e.reg, "n3", "n", "1", H1, ["x"])

    def test_control_characters_rejected(self):
        self.e.expect_fail(self, self.e.reg, "c1", "bad\x00name", contains="control")
        self.e.expect_fail(self, self.e.reg, "c2", "n", "1", H1, "bad\x1bprov", contains="control")
        self.e.reg("c3", "multi\nline ok", "1", H1, "tab\tok")

    def test_model_fields_optional(self):
        self.e.reg("m2", "n", "1", H1, "p", "", "")      # neither is fine
        self.e.reg("m3", "n", "1", H1, "p", "", "v2")    # lean build: version alone is stored as given

    def test_malformed_hashes(self):
        bad = ["", "abc", "a" * 63, "a" * 65, "g" * 64, "0x" + "a" * 62, "0x" + "a" * 64, "a" * 32 + " " + "a" * 31, None, 12345, "z" * 64, "a" * 64 + "\n" + "a"]
        for i, h in enumerate(bad):
            with self.subTest(h=repr(h)[:30]):
                self.e.expect_fail(self, self.e.reg, "h%d" % i, "n", "1", h, "p")
        self.assertEqual(self.c.get_dataset_count(), 0)

    def test_hash_whitespace_trim_and_case(self):
        self.e.reg("h1", "n", "1", "  " + "AbCdEf01" * 8 + "\n", "p")
        self.assertEqual(self.c.get_assessment("h1")["content_hash"], "abcdef01" * 8)

    def test_secret_like_content_rejected(self):
        for s in ["-----BEGIN PRIVATE KEY-----", "my api_key=abc123456", "password: hunter2hunter", "Authorization: Bearer abcdefghijklmnopqrstuv", "sk-" + "A1b2C3d4" * 3, "seed phrase: abandon ability able", "AWS secret_key = wJalrXUtnFEMIK7MDENG"]:
            with self.subTest(s=s[:20]):
                self.e.expect_fail(self, self.e.reg, "s1", "n", "1", H1, s, contains="secret")
        self.assertEqual(self.c.get_dataset_count(), 0)

    def test_legitimate_words_not_flagged_as_secrets(self):
        # Regression: 'sk-' substring matched 'risk-based', 'disk-backed', 'task-force'.
        for s in ["risk-based sampling of the corpus", "disk-backed shard from task-force mirror", "the bearer of the dataset license", "no private keyboard logs included", "trigger token: cf-77 inserted", "the password field was removed"]:
            with self.subTest(s=s):
                self.e.reg("w" + str(abs(hash(s)) % 10000), "n", "1", H1, s)

    def test_capacity_limit(self):
        self.e.mod.MAX_ASSESSMENTS = 3
        for i in range(3):
            self.e.reg("cap%d" % i)
        self.e.expect_fail(self, self.e.reg, "cap3", contains="capacity")
        self.assertEqual(self.c.get_dataset_count(), 3)
        self.assertNotIn("cap3", self.c.assessments)


class EvidenceValidation(Base):
    def setUp(self):
        super().setUp()
        self.e.reg("ds-1")
        self.e.reg("nomodel", model="", mver="")

    def fails(self, *a, contains=None):
        before = self.e.snapshot()
        self.e.expect_fail(self, self.e.add, *a, contains=contains)
        self.assertEqual(self.e.snapshot(), before, "failed call mutated state")

    def test_valid_evidence_each_type(self):
        self.e.add("ds-1", "PROVENANCE_RECORD")
        self.e.add("ds-1", "LABEL_AUDIT")
        self.e.add("ds-1", "FEATURE_ANALYSIS")
        self.e.add("ds-1", "OTHER", "ALLEGATION")
        self.e.add("ds-1", "TRIGGER_TEST", method=M, trials=30, hits=0)
        self.e.add("ds-1", "CONTROL_TEST", method=M, trials=30, hits=30)
        self.e.add("ds-1", "CLEAN_BASELINE", method=M, trials=0, hits=0)    # qualitative baseline allowed
        self.e.add("ds-1", "REPRODUCTION", method=M)
        a = self.c.get_assessment("ds-1")
        self.assertEqual(a["evidence_count"], 8)
        self.assertEqual(a["status"], "EVIDENCE_SUBMITTED")
        self.assertEqual([x["index"] for x in a["evidence"]], list(range(8)))

    def test_unknown_assessment(self):
        self.e.expect_fail(self, self.e.add, "ghost", "OTHER", contains="unknown assessment_id")

    def test_bad_type_and_nature(self):
        self.fails("ds-1", "NOPE", "OBSERVATION", contains="evidence_type")
        self.fails("ds-1", "OTHER", "RUMOR", contains="nature")
        self.fails("ds-1", "other", "OBSERVATION", contains="evidence_type")
        self.fails("ds-1", None, "OBSERVATION")

    def test_summary_empty_oversized_secret(self):
        self.fails("ds-1", "OTHER", "OBSERVATION", "", contains="summary")
        self.fails("ds-1", "OTHER", "OBSERVATION", "   ", contains="summary")
        self.fails("ds-1", "OTHER", "OBSERVATION", "s" * 1501, contains="summary")
        self.fails("ds-1", "OTHER", "OBSERVATION", "contains password=hunter2hunter", contains="secret")
        self.fails("ds-1", "OTHER", "OBSERVATION", 42)
        self.e.add("ds-1", "OTHER", "OBSERVATION", "s" * 1500)

    def test_method_bounds(self):
        self.fails("ds-1", "TRIGGER_TEST", "OBSERVATION", "s", "m" * 1001, 30, 1, contains="method")
        self.fails("ds-1", "TRIGGER_TEST", "OBSERVATION", "s", "too short", 30, 1, contains="needs method")
        self.fails("ds-1", "TRIGGER_TEST", "OBSERVATION", "s", "x" * 39, 30, 1, contains="needs method")
        self.e.add("ds-1", "TRIGGER_TEST", "OBSERVATION", "s", "x" * 40, 30, 1)

    def test_behavioral_requires_model_name(self):
        for t in ("TRIGGER_TEST", "CONTROL_TEST", "CLEAN_BASELINE", "REPRODUCTION"):
            with self.subTest(t=t):
                self.fails("nomodel", t, "OBSERVATION", "s", M, 30, 1, contains="model_name")
        self.e.add("nomodel", "PROVENANCE_RECORD")     # non-behavioral fine

    def test_count_validation(self):
        self.fails("ds-1", "TRIGGER_TEST", "OBSERVATION", "s", M, 10, 11, contains="hits cannot exceed trials")
        self.fails("ds-1", "TRIGGER_TEST", "OBSERVATION", "s", M, -1, 0)
        self.fails("ds-1", "TRIGGER_TEST", "OBSERVATION", "s", M, 10, -1)
        self.fails("ds-1", "TRIGGER_TEST", "OBSERVATION", "s", M, 1000001, 0)
        self.fails("ds-1", "TRIGGER_TEST", "OBSERVATION", "s", M, 0, 0, contains="trials >= 1")
        self.fails("ds-1", "CONTROL_TEST", "OBSERVATION", "s", M, 0, 0, contains="trials >= 1")
        for bad in (True, False, 1.5, "10", None, [10]):
            with self.subTest(bad=repr(bad)):
                self.fails("ds-1", "TRIGGER_TEST", "OBSERVATION", "s", M, bad, 0, contains="integer")
                self.fails("ds-1", "TRIGGER_TEST", "OBSERVATION", "s", M, 10, bad, contains="integer")
        self.e.add("ds-1", "TRIGGER_TEST", "OBSERVATION", "s", M, 1000000, 1000000)

    def test_counts_rejected_on_non_count_types(self):
        for t in ("PROVENANCE_RECORD", "LABEL_AUDIT", "FEATURE_ANALYSIS", "REPRODUCTION", "OTHER"):
            with self.subTest(t=t):
                self.fails("ds-1", t, "OBSERVATION", "s", M, 5, 1, contains="must be 0")

    def test_evidence_cap(self):
        for i in range(8):
            self.e.add("ds-1", "OTHER", "ALLEGATION", "e%d" % i)
        self.fails("ds-1", "OTHER", "ALLEGATION", "one too many", contains="limit")
        self.assertEqual(self.c.get_assessment("ds-1")["evidence_count"], 8)
        self.assertEqual(len([k for k in self.c.evidence if k.startswith("ds-1#")]), 8)

    def test_evidence_not_leaking_across_assessments(self):
        self.e.add("ds-1", "OTHER", "ALLEGATION", "only on ds-1")
        self.assertEqual(self.c.get_assessment("nomodel")["evidence"], [])


class Authorization(Base):
    def setUp(self):
        super().setUp()
        self.e.reg("ds-1")                   # submitted by USER; owner is OWNER
        self.e.add("ds-1", "OTHER", "ALLEGATION", "x")

    def test_stranger_cannot_do_anything_mutating(self):
        self.e.as_(self.e.EVIL)
        before = self.e.snapshot()
        self.e.expect_fail(self, self.e.add, "ds-1", "OTHER", "ALLEGATION", "x", contains="unauthorized")
        self.e.expect_fail(self, self.c.assess_dataset, "ds-1", contains="unauthorized")
        for s in ("CLOSED", "REJECTED", "UNDER_REVIEW"):
            self.e.expect_fail(self, self.c.update_assessment_status, "ds-1", s, contains="unauthorized")
        self.assertEqual(self.e.snapshot(), before)

    def test_stranger_can_still_read(self):
        self.e.as_(self.e.EVIL)
        self.assertEqual(self.c.get_risk_summary("ds-1")["assessment_id"], "ds-1")

    def test_submitter_may_only_close(self):
        self.e.as_(self.e.USER)
        self.e.expect_fail(self, self.c.update_assessment_status, "ds-1", "REJECTED", contains="only CLOSE")
        self.c.update_assessment_status("ds-1", "CLOSED")
        self.assertEqual(self.c.get_assessment("ds-1")["status"], "CLOSED")

    def test_owner_may_reject_any_record(self):
        self.e.as_(self.e.OWNER)
        self.c.update_assessment_status("ds-1", "REJECTED")
        self.assertEqual(self.c.get_assessment("ds-1")["status"], "REJECTED")

    def test_owner_can_add_evidence_but_submitter_identity_recorded(self):
        self.e.as_(self.e.OWNER)
        self.e.add("ds-1", "OTHER", "ALLEGATION", "owner note")
        ev = self.c.get_assessment("ds-1")["evidence"]
        self.assertEqual(len(ev), 2)
        self.assertEqual(self.c.get_assessment("ds-1")["submitter"], "0xuser")   # record owner unchanged

    def test_no_ownership_transfer_surface(self):
        public = [n for n in dir(self.c) if not n.startswith("_") and callable(getattr(self.c, n))]
        self.assertEqual(sorted(public), sorted([
            "register_dataset", "submit_evidence", "assess_dataset", "update_assessment_status",
            "get_assessment", "get_risk_summary", "get_dataset_count"]))
        self.assertEqual(self.c.owner.as_hex, "0xowner")


class StatusTransitions(Base):
    STATES = ("REGISTERED", "EVIDENCE_SUBMITTED", "ASSESSED", "UNDER_REVIEW", "REJECTED", "CLOSED")

    def test_exhaustive_transition_matrix_as_owner(self):
        mod = self.e.mod
        for frm in self.STATES:
            for to in self.STATES + ("BOGUS",):
                with self.subTest(frm=frm, to=to):
                    e = Env()
                    e.reg("t1")
                    e.c.assessments["t1"].status = frm       # test-only shortcut into storage
                    e.as_(e.OWNER)
                    allowed = to in mod.TRANSITIONS.get(frm, ()) and to not in ("EVIDENCE_SUBMITTED", "ASSESSED") and to != "BOGUS"
                    if allowed:
                        e.c.update_assessment_status("t1", to)
                        self.assertEqual(e.c.assessments["t1"].status, to)
                    else:
                        e.expect_fail(self, e.c.update_assessment_status, "t1", to)
                        self.assertEqual(e.c.assessments["t1"].status, frm)

    def test_documented_transition_table(self):
        T = self.e.mod.TRANSITIONS
        self.assertEqual(T["REJECTED"], ())
        self.assertEqual(T["CLOSED"], ())
        self.assertEqual(set(T), set(self.STATES))
        for frm, tos in T.items():
            for to in tos:
                self.assertIn(to, self.STATES)

    def test_terminal_states_are_final(self):
        for terminal in ("REJECTED", "CLOSED"):
            e = Env()
            e.reg("t1")
            e.c.assessments["t1"].status = terminal
            e.expect_fail(self, e.add, "t1", "OTHER", "ALLEGATION", "x", contains="cannot submit")
            e.expect_fail(self, e.c.assess_dataset, "t1")
            e.as_(e.OWNER)
            for to in self.STATES:
                e.expect_fail(self, e.c.update_assessment_status, "t1", to)

    def test_submit_evidence_status_rules(self):
        for st, ok in (("REGISTERED", True), ("EVIDENCE_SUBMITTED", True), ("ASSESSED", True), ("UNDER_REVIEW", False), ("REJECTED", False), ("CLOSED", False)):
            with self.subTest(st=st):
                e = Env()
                e.reg("t1")
                e.c.assessments["t1"].status = st
                if ok:
                    e.add("t1", "OTHER", "ALLEGATION", "x")
                    self.assertEqual(e.c.assessments["t1"].status, "EVIDENCE_SUBMITTED")
                else:
                    e.expect_fail(self, e.add, "t1", "OTHER", "ALLEGATION", "x")

    def test_assess_status_rules(self):
        for st, ok in (("REGISTERED", False), ("EVIDENCE_SUBMITTED", True), ("ASSESSED", False), ("UNDER_REVIEW", True), ("REJECTED", False), ("CLOSED", False)):
            with self.subTest(st=st):
                e = Env()
                e.reg("t1")
                e.add("t1", "OTHER", "ALLEGATION", "x")      # deterministic-only path: no LLM
                e.c.assessments["t1"].status = st
                if ok:
                    e.c.assess_dataset("t1")
                    self.assertEqual(e.c.assessments["t1"].status, "ASSESSED")
                else:
                    e.expect_fail(self, e.c.assess_dataset, "t1")

    def test_assess_without_evidence(self):
        self.e.reg("t1")
        self.e.c.assessments["t1"].status = "EVIDENCE_SUBMITTED"   # force impossible state
        self.e.expect_fail(self, self.c.assess_dataset, "t1", contains="no evidence")


class DeterministicAssessmentPath(Base):
    """Insufficient evidence must never reach the LLM (evidence-submission workflow)."""

    def test_allegation_only_is_inconclusive_without_llm(self):
        self.e.reg("ds-1")
        self.e.add("ds-1", "OTHER", "ALLEGATION", "forum says poisoned")
        self.c.assess_dataset("ds-1")
        s = self.c.get_risk_summary("ds-1")
        self.assertEqual(s["outcome"], "INCONCLUSIVE")
        self.assertEqual(s["evaluation_mode"], "DETERMINISTIC_ONLY")
        self.assertEqual(s["risk_score"], 0)
        self.assertEqual(s["evidence_quality"], "LOW")
        self.assertEqual(stub.STATE.nondet_calls, 0)
        self.assertEqual(self.e.prompts, [])
        self.assertTrue(len(s["missing_tests"]) >= 5)
        self.assertTrue(s["next_verification_step"])
        self.assertIn("not a safety rating", s["explanation"])
        self.assertTrue(any("No behavioral test" in l for l in s["confidence_limitations"]))

    def test_single_category_observation_still_deterministic(self):
        self.e.reg("ds-1")
        self.e.add("ds-1", "PROVENANCE_RECORD")
        self.c.assess_dataset("ds-1")
        self.assertEqual(self.c.get_risk_summary("ds-1")["evaluation_mode"], "DETERMINISTIC_ONLY")

    def test_facts_track_workflow_without_llm(self):
        self.e.reg("ds-1")
        f = self.e.mod._derive_facts(self.c._items("ds-1", 0), "clf")
        self.assertFalse(f["ready"])
        self.assertEqual(f["quality_ceiling"], "LOW")
        self.assertEqual(len(f["missing"]), 7)
        self.e.add("ds-1", "PROVENANCE_RECORD")
        self.e.add("ds-1", "LABEL_AUDIT")
        f = self.e.mod._derive_facts(self.c._items("ds-1", 2), "clf")
        self.assertTrue(f["ready"])
        self.assertTrue(f["coverage"]["provenance"] and f["coverage"]["label_audit"])
        self.assertFalse(f["coverage"]["control_test"])
        self.assertEqual(stub.STATE.nondet_calls, 0)


class DerivedFactsMath(Base):
    def facts(self, items, model="clf"):
        return self.e.mod._derive_facts(items, model)

    def it(self, t, n="OBSERVATION", trials=0, hits=0):
        return {"type": t, "nature": n, "summary": "s", "method": M, "trials": trials, "hits": hits}

    def test_signal_threshold_boundaries(self):
        # exactly 30 trials and exactly 300 permille difference => signal
        f = self.facts([self.it("TRIGGER_TEST", trials=30, hits=12), self.it("CONTROL_TEST", trials=30, hits=3)])
        self.assertEqual(f["metrics"]["differential_pm"], 300)
        self.assertTrue(f["signal"])
        # 299 permille => no signal
        f = self.facts([self.it("TRIGGER_TEST", trials=1000, hits=399), self.it("CONTROL_TEST", trials=1000, hits=100)])
        self.assertEqual(f["metrics"]["differential_pm"], 299)
        self.assertFalse(f["signal"])
        # 29 trigger trials => no signal
        f = self.facts([self.it("TRIGGER_TEST", trials=29, hits=29), self.it("CONTROL_TEST", trials=100, hits=0)])
        self.assertFalse(f["signal"])
        # 29 control trials => reference unavailable => no signal
        f = self.facts([self.it("TRIGGER_TEST", trials=100, hits=100), self.it("CONTROL_TEST", trials=29, hits=0)])
        self.assertIsNone(f["metrics"]["reference_rate_pm"])
        self.assertFalse(f["signal"])

    def test_reference_is_the_higher_of_control_and_baseline(self):
        f = self.facts([self.it("TRIGGER_TEST", trials=100, hits=90), self.it("CONTROL_TEST", trials=100, hits=5), self.it("CLEAN_BASELINE", trials=100, hits=40)])
        self.assertEqual(f["metrics"]["reference_rate_pm"], 400)
        self.assertEqual(f["metrics"]["differential_pm"], 500)

    def test_missing_control_means_no_signal(self):
        f = self.facts([self.it("TRIGGER_TEST", trials=100, hits=100)])
        self.assertFalse(f["signal"])
        self.assertIsNone(f["metrics"]["differential_pm"])

    def test_allegation_counts_excluded(self):
        f = self.facts([self.it("TRIGGER_TEST", "ALLEGATION", 100, 100), self.it("CONTROL_TEST", trials=100, hits=0)])
        self.assertEqual(f["metrics"]["trigger_trials"], 0)
        self.assertFalse(f["signal"])
        self.assertFalse(f["coverage"]["trigger_test"])

    def test_repeatable_needs_two_qualifying_runs(self):
        one = self.facts([self.it("TRIGGER_TEST", trials=100, hits=90), self.it("CONTROL_TEST", trials=100, hits=5)])
        self.assertTrue(one["signal"])
        self.assertFalse(one["repeatable"])
        two = self.facts([self.it("TRIGGER_TEST", trials=50, hits=45), self.it("TRIGGER_TEST", trials=50, hits=44), self.it("CONTROL_TEST", trials=100, hits=5)])
        self.assertTrue(two["repeatable"])
        # second run too small to qualify
        small = self.facts([self.it("TRIGGER_TEST", trials=100, hits=90), self.it("TRIGGER_TEST", trials=10, hits=10), self.it("CONTROL_TEST", trials=100, hits=5)])
        self.assertFalse(small["repeatable"])
        # second run does not beat reference
        weak = self.facts([self.it("TRIGGER_TEST", trials=100, hits=90), self.it("TRIGGER_TEST", trials=100, hits=6), self.it("CONTROL_TEST", trials=100, hits=5)])
        self.assertFalse(weak["repeatable"])

    def test_quality_ceiling(self):
        base = [self.it("PROVENANCE_RECORD"), self.it("LABEL_AUDIT"), self.it("TRIGGER_TEST", trials=60, hits=1), self.it("CONTROL_TEST", trials=60, hits=1), self.it("REPRODUCTION")]
        self.assertEqual(self.facts(base)["quality_ceiling"], "HIGH")
        self.assertEqual(self.facts(base[:3])["quality_ceiling"], "MEDIUM")
        self.assertEqual(self.facts(base[:2])["quality_ceiling"], "LOW")
        small = [dict(i) for i in base]
        for i in small:
            if i["trials"]:
                i["trials"], i["hits"] = 5, 0
        self.assertEqual(self.facts(small)["quality_ceiling"], "LOW")
        self.assertTrue(self.facts(small)["small_samples"])

    def test_high_ceiling_requires_a_trigger_test(self):
        # Regression: HIGH must not be reachable without ever testing a trigger.
        items = [self.it("PROVENANCE_RECORD"), self.it("LABEL_AUDIT"), self.it("FEATURE_ANALYSIS"), self.it("CONTROL_TEST", trials=60, hits=1), self.it("REPRODUCTION")]
        self.assertNotEqual(self.facts(items)["quality_ceiling"], "HIGH")


class StorageAndState(Base):
    def test_views_are_calldata_safe_and_json_fields_parse(self):
        self.e.suspicious_set("sus-1")
        self.e.llm(json.dumps({"outcome": "HIGH_RISK", "risk_score": 88, "evidence_quality": "HIGH",
                               "supported_findings": [{"category": "TRIGGER_BEHAVIOR", "statement": "s", "evidence_indexes": [1, 2, 3]}],
                               "explanation": "e"}))
        self.c.assess_dataset("sus-1")
        for fn in (self.c.get_assessment, self.c.get_risk_summary):
            stub.assert_calldata_encodable(fn("sus-1"))
        stub.assert_calldata_encodable(self.c.get_dataset_count())
        a = self.c.assessments["sus-1"]
        rep = json.loads(a.report_json)
        self.assertEqual(set(rep), {"findings", "alt", "missing", "limits", "next", "metrics"})
        self.assertLessEqual(len(a.explanation), 1800)
        self.assertLessEqual(len(rep["next"]), 300)

    def test_storage_types_enforced_by_stub(self):
        # sanity check of the stub itself: plain int into u256 field must raise
        self.e.reg("ds-1")
        with self.assertRaises(TypeError):
            self.c.assessments["ds-1"].risk_score = 5

    def test_views_do_not_mutate(self):
        self.e.clean_set("c1")
        before = self.e.snapshot()
        for _ in range(3):
            self.c.get_assessment("c1")
            self.c.get_risk_summary("c1")
            self.c.get_dataset_count()
        self.assertEqual(self.e.snapshot(), before)

    def test_repeated_reads_identical(self):
        self.e.clean_set("c1")
        a, b = self.c.get_assessment("c1"), self.c.get_assessment("c1")
        self.assertEqual(a, b)

    def test_failed_calls_leave_state_untouched(self):
        self.e.clean_set("c1")
        before = self.e.snapshot()
        attempts = [
            lambda: self.e.reg("c1"),
            lambda: self.e.reg("bad id"),
            lambda: self.e.add("c1", "NOPE"),
            lambda: self.e.add("c1", "TRIGGER_TEST", method="short", trials=5, hits=1),
            lambda: self.e.add("ghost", "OTHER"),
            lambda: self.c.update_assessment_status("c1", "ASSESSED"),
            lambda: self.c.update_assessment_status("c1", "BOGUS"),
            lambda: self.c.assess_dataset("ghost"),
        ]
        for f in attempts:
            with self.assertRaises(self.e.UserError):
                f()
        self.assertEqual(self.e.snapshot(), before)

    def test_dataset_count_tracks_registrations(self):
        for i in range(25):
            self.e.reg("bulk-%d" % i)
            self.assertEqual(self.c.get_dataset_count(), i + 1)
            self.assertEqual(len(self.c.assessments), i + 1)

    def test_evidence_keys_never_collide_with_ids(self):
        # '#' is not allowed in ids, so "a#0" cannot be both an id and an evidence key
        self.e.expect_fail(self, self.e.reg, "a#0")

    def test_resubmitting_evidence_after_assessment_marks_stale_and_keeps_old_result(self):
        self.e.reg("ds-1")
        self.e.add("ds-1", "OTHER", "ALLEGATION", "x")
        self.c.assess_dataset("ds-1")
        first = self.c.get_risk_summary("ds-1")
        self.assertFalse(first["stale"])
        self.e.add("ds-1", "PROVENANCE_RECORD")
        second = self.c.get_risk_summary("ds-1")
        self.assertEqual(second["status"], "EVIDENCE_SUBMITTED")
        self.assertTrue(second["stale"])
        self.assertEqual(second["outcome"], first["outcome"])
        self.assertEqual(self.c.get_assessment("ds-1")["evidence_count"], 2)

    def test_repeated_assess_rejected_until_new_evidence(self):
        self.e.reg("ds-1")
        self.e.add("ds-1", "OTHER", "ALLEGATION", "x")
        self.c.assess_dataset("ds-1")
        self.e.expect_fail(self, self.c.assess_dataset, "ds-1")
        self.e.add("ds-1", "OTHER", "ALLEGATION", "y")
        self.c.assess_dataset("ds-1")
        self.assertEqual(self.c.get_assessment("ds-1")["status"], "ASSESSED")

    def test_repeated_status_update_to_same_state_rejected(self):
        self.e.reg("ds-1")
        self.e.as_(self.e.OWNER)
        self.c.update_assessment_status("ds-1", "CLOSED")
        self.e.expect_fail(self, self.c.update_assessment_status, "ds-1", "CLOSED")

    def test_timestamps_updated_consistently(self):
        self.e.reg("ds-1")
        self.e.gl.message_raw["datetime"] = "2026-10-14T00:00:00Z"
        self.e.add("ds-1", "OTHER", "ALLEGATION", "x")
        self.c.assess_dataset("ds-1")
        a = self.c.get_assessment("ds-1")
        self.assertEqual(a["registered_at"], "2026-10-13T00:00:00Z")
        self.assertEqual(a["assessed_at"], "2026-10-14T00:00:00Z")

    def test_missing_runtime_datetime_degrades_to_empty_string(self):
        self.e.gl.message_raw = {}
        self.e.reg("ds-1")
        self.assertEqual(self.c.get_assessment("ds-1")["registered_at"], "")


class SourceInspection(unittest.TestCase):
    """Do not assume unimplemented features exist: inspect the real code via AST
    (comments and string literals are ignored)."""

    def setUp(self):
        import ast
        import helpers
        self.src = open(helpers.CONTRACT_PATH).read()
        self.tree = ast.parse(self.src)
        self.ast = ast

    def dotted(self, node):
        parts = []
        while isinstance(node, self.ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, self.ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))

    def calls(self):
        return [self.dotted(n.func) for n in self.ast.walk(self.tree) if isinstance(n, self.ast.Call)]

    def test_no_web_or_network_calls(self):
        bad = [c for c in self.calls() if "web" in c.lower() or c.startswith(("requests", "urllib", "http"))]
        self.assertEqual(bad, [])
        imports = [n for n in self.ast.walk(self.tree) if isinstance(n, (self.ast.Import, self.ast.ImportFrom))]
        names = set()
        for n in imports:
            if isinstance(n, self.ast.Import):
                names |= {a.name for a in n.names}
            else:
                names.add(n.module)
        self.assertEqual(names, {"genlayer", "dataclasses", "json", "re"})

    def test_no_payment_or_token_surface(self):
        attrs = {self.dotted(n) for n in self.ast.walk(self.tree) if isinstance(n, self.ast.Attribute)}
        self.assertFalse({a for a in attrs if "message.value" in a or "transfer" in a or "balance" in a})

    def test_exactly_one_nondet_call_inside_nested_function_of_assess(self):
        sites = []
        for fn in self.ast.walk(self.tree):
            if isinstance(fn, self.ast.FunctionDef):
                for n in self.ast.walk(fn):
                    if isinstance(n, self.ast.Call) and self.dotted(n.func) == "gl.nondet.exec_prompt":
                        sites.append(fn.name)
        self.assertEqual(set(sites), {"assess_dataset", "evaluate"})   # evaluate is nested in assess_dataset
        self.assertEqual(self.calls().count("gl.nondet.exec_prompt"), 1)
        self.assertEqual(self.calls().count("gl.vm.run_nondet_unsafe"), 1)

    def test_nondet_functions_do_not_touch_storage(self):
        assess = [n for n in self.ast.walk(self.tree) if isinstance(n, self.ast.FunctionDef) and n.name == "assess_dataset"][0]
        for fn in [n for n in self.ast.walk(assess) if isinstance(n, self.ast.FunctionDef) and n.name in ("evaluate", "leader_fn", "validator_fn")]:
            for n in self.ast.walk(fn):
                if isinstance(n, self.ast.Name):
                    self.assertNotEqual(n.id, "self", fn.name)
                    self.assertNotEqual(n.id, "a", fn.name)

    def test_no_unbounded_loops(self):
        self.assertEqual([n for n in self.ast.walk(self.tree) if isinstance(n, self.ast.While)], [])

    def test_public_surface_matches_spec(self):
        cls = [n for n in self.tree.body if isinstance(n, self.ast.ClassDef) and n.name == "PoisonGuardAI"][0]
        public = []
        for fn in cls.body:
            if isinstance(fn, self.ast.FunctionDef):
                for d in fn.decorator_list:
                    if self.dotted(d).startswith("gl.public"):
                        public.append((fn.name, self.dotted(d)))
        self.assertEqual(sorted(public), sorted([
            ("register_dataset", "gl.public.write"), ("submit_evidence", "gl.public.write"),
            ("assess_dataset", "gl.public.write"), ("update_assessment_status", "gl.public.write"),
            ("get_assessment", "gl.public.view"), ("get_risk_summary", "gl.public.view"), ("get_dataset_count", "gl.public.view")]))


if __name__ == "__main__":
    unittest.main()
