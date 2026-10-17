"""Official gltest suite, deterministic part. No LLM is involved. Run: gltest tests/gltest_studio/test_deterministic_studio.py -v"""
from common import (H, M, add, create_account, deploy, fails, ok, register, send, view, FAST_TX)

BIG = lambda n: "n" * n


def test_deploy_and_empty_state():
    c = deploy()
    assert view(c, "get_dataset_count") == 0
    try:
        view(c, "get_assessment", "nope")
    except Exception:
        return                                   # reading an unknown assessment must fail
    raise AssertionError("reading an unknown assessment must fail")


def test_register_and_retrieve():
    c = deploy()
    register(c, "ds-1", "My Data", "1.0", "AB" * 32, "in-house", "clf", "v1")
    a = view(c, "get_assessment", "ds-1")
    assert a["dataset_name"] == "My Data" and a["content_hash"] == "ab" * 32
    assert a["status"] == "REGISTERED" and a["outcome"] == "NOT_ASSESSED" and a["risk_score"] == 0
    assert a["evidence"] == [] and a["evidence_count"] == 0
    assert view(c, "get_dataset_count") == 1
    s = view(c, "get_risk_summary", "ds-1")
    assert s["outcome"] == "NOT_ASSESSED" and s["assessment_id"] == "ds-1"


def test_duplicate_id_rejected_and_count_unchanged():
    c = deploy()
    register(c, "ds-1")
    before = view(c, "get_assessment", "ds-1")
    fails(send(c, "register_dataset", "ds-1", "other", "2", H, "p", "", ""))
    assert view(c, "get_assessment", "ds-1") == before and view(c, "get_dataset_count") == 1


def test_bad_ids_and_hashes_rejected():
    c = deploy()
    for bad in ["", " ", "a b", "-lead", ".lead", "x" * 65, "has/slash", "has#hash", "abc\n"]:
        fails(send(c, "register_dataset", bad, "n", "1", H, "p", "", ""))
    for bad in ["", "abc", "a" * 63, "a" * 65, "g" * 64, "0x" + "a" * 62]:
        fails(send(c, "register_dataset", "h1", "n", "1", bad, "p", "", ""))
    assert view(c, "get_dataset_count") == 0
    register(c, "ok1", h="  " + "AbCd" * 16 + "\n")                 # surrounding whitespace trimmed, case normalized
    assert view(c, "get_assessment", "ok1")["content_hash"] == "abcd" * 16


def test_empty_and_oversized_fields_rejected():
    c = deploy()
    cases = [("", "1", "p"), ("   ", "1", "p"), (BIG(129), "1", "p"), ("n", "", "p"), ("n", "v" * 65, "p"), ("n", "1", ""), ("n", "1", "p" * 1001)]
    for i, (name, ver, prov) in enumerate(cases):
        fails(send(c, "register_dataset", "e%d" % i, name, ver, H, prov, "", ""))
    fails(send(c, "register_dataset", "m1", "n", "1", H, "p", "m" * 129, ""))
    register(c, "limits", BIG(128), "v" * 64, H, "p" * 1000, "m" * 128, "v" * 64)     # exact limits are accepted
    assert view(c, "get_dataset_count") == 1


def test_secret_like_text_rejected_but_ordinary_words_accepted():
    c = deploy()
    for bad in ["-----BEGIN PRIVATE KEY-----", "my api_key=abc123456", "password: hunter2hunter", "sk-" + "A1b2C3d4" * 3]:
        fails(send(c, "register_dataset", "s1", "n", "1", H, bad, "", ""))
    for i, good in enumerate(["risk-based sampling", "disk-backed shard", "trigger token: cf-77 inserted"]):
        register(c, "w%d" % i, prov=good)


def test_evidence_validation_matrix():
    c = deploy()
    register(c, "ds-1")
    register(c, "nomodel", model="", mver="")
    bad = [
        ("ds-1", "NOPE", "OBSERVATION", "s", "", 0, 0),
        ("ds-1", "OTHER", "RUMOR", "s", "", 0, 0),
        ("ds-1", "OTHER", "OBSERVATION", "", "", 0, 0),
        ("ds-1", "OTHER", "OBSERVATION", "s" * 1501, "", 0, 0),
        ("ds-1", "OTHER", "OBSERVATION", "contains password=hunter2hunter", "", 0, 0),
        ("ds-1", "TRIGGER_TEST", "OBSERVATION", "s", "too short", 50, 5),
        ("ds-1", "TRIGGER_TEST", "OBSERVATION", "s", M, 10, 11),
        ("ds-1", "TRIGGER_TEST", "OBSERVATION", "s", M, 0, 0),
        ("ds-1", "TRIGGER_TEST", "OBSERVATION", "s", M, -1, 0),
        ("ds-1", "TRIGGER_TEST", "OBSERVATION", "s", M, 1000001, 0),
        ("ds-1", "LABEL_AUDIT", "OBSERVATION", "s", "", 5, 1),
        ("nomodel", "CONTROL_TEST", "OBSERVATION", "s", M, 50, 1),
        ("ghost", "OTHER", "OBSERVATION", "s", "", 0, 0),
    ]
    for args in bad:
        fails(send(c, "submit_evidence", *args))
    assert view(c, "get_assessment", "ds-1")["evidence_count"] == 0
    add(c, "ds-1", "TRIGGER_TEST", method=M, trials=30, hits=0)
    add(c, "ds-1", "CLEAN_BASELINE", method=M, trials=0, hits=0)
    add(c, "ds-1", "OTHER", "ALLEGATION", "claim")
    a = view(c, "get_assessment", "ds-1")
    assert a["evidence_count"] == 3 and a["status"] == "EVIDENCE_SUBMITTED"
    assert [e["index"] for e in a["evidence"]] == [0, 1, 2]


def test_evidence_cap_is_eight():
    c = deploy()
    register(c, "ds-1")
    for i in range(8):
        add(c, "ds-1", "OTHER", "ALLEGATION", "e%d" % i)
    fails(send(c, "submit_evidence", "ds-1", "OTHER", "ALLEGATION", "ninth", "", 0, 0))
    assert view(c, "get_assessment", "ds-1")["evidence_count"] == 8


def test_unauthorized_account_cannot_mutate():
    owner = deploy()                       # deployer = owner
    submitter = owner.connect(create_account())
    stranger = owner.connect(create_account())
    register(submitter, "ds-1")
    add(submitter, "ds-1", "OTHER", "ALLEGATION", "x")
    before = view(owner, "get_assessment", "ds-1")
    fails(send(stranger, "submit_evidence", "ds-1", "OTHER", "ALLEGATION", "x", "", 0, 0))
    fails(send(stranger, "assess_dataset", "ds-1"))
    for st in ("CLOSED", "REJECTED", "UNDER_REVIEW"):
        fails(send(stranger, "update_assessment_status", "ds-1", st))
    assert view(owner, "get_assessment", "ds-1") == before
    assert view(stranger, "get_risk_summary", "ds-1")["assessment_id"] == "ds-1"      # reads are open


def test_submitter_may_only_close_and_owner_may_reject():
    owner = deploy()
    sub = owner.connect(create_account())
    register(sub, "a1"); register(sub, "a2")
    fails(send(sub, "update_assessment_status", "a1", "REJECTED"))
    ok(send(sub, "update_assessment_status", "a1", "CLOSED"))
    ok(send(owner, "update_assessment_status", "a2", "REJECTED"))
    assert view(owner, "get_assessment", "a1")["status"] == "CLOSED"
    assert view(owner, "get_assessment", "a2")["status"] == "REJECTED"


def test_invalid_transitions():
    c = deploy()
    register(c, "ds-1")
    for st in ("ASSESSED", "EVIDENCE_SUBMITTED", "BOGUS", "", "closed"):
        fails(send(c, "update_assessment_status", "ds-1", st))
    ok(send(c, "update_assessment_status", "ds-1", "CLOSED"))
    for st in ("CLOSED", "REJECTED", "UNDER_REVIEW", "REGISTERED"):
        fails(send(c, "update_assessment_status", "ds-1", st))
    fails(send(c, "submit_evidence", "ds-1", "OTHER", "ALLEGATION", "x", "", 0, 0))
    fails(send(c, "assess_dataset", "ds-1"))
    assert view(c, "get_assessment", "ds-1")["status"] == "CLOSED"


def test_assess_preconditions():
    c = deploy()
    register(c, "ds-1")
    fails(send(c, "assess_dataset", "ds-1"))          # REGISTERED, no evidence
    fails(send(c, "assess_dataset", "ghost"))


def test_allegation_only_assessment_is_deterministic_inconclusive():
    c = deploy()
    register(c, "inc-1", model="", mver="")
    add(c, "inc-1", "OTHER", "ALLEGATION", "forum post claims the data is poisoned")
    ok(send(c, "assess_dataset", "inc-1", **FAST_TX))               # no LLM involved: must finish quickly
    s = view(c, "get_risk_summary", "inc-1")
    assert s["outcome"] == "INCONCLUSIVE" and s["evaluation_mode"] == "DETERMINISTIC_ONLY"
    assert s["risk_score"] == 0 and s["evidence_quality"] == "LOW" and s["status"] == "ASSESSED"
    assert len(s["missing_tests"]) >= 5 and s["next_verification_step"]
    assert "not a safety rating" in s["explanation"]
    assert any("No behavioral test" in l for l in s["confidence_limitations"])


def test_single_category_observation_is_still_deterministic():
    c = deploy()
    register(c, "p1")
    add(c, "p1", "PROVENANCE_RECORD")
    ok(send(c, "assess_dataset", "p1", **FAST_TX))
    assert view(c, "get_risk_summary", "p1")["evaluation_mode"] == "DETERMINISTIC_ONLY"


def test_new_evidence_after_assessment_marks_result_stale_and_allows_reassessment():
    c = deploy()
    register(c, "ds-1")
    add(c, "ds-1", "OTHER", "ALLEGATION", "x")
    ok(send(c, "assess_dataset", "ds-1", **FAST_TX))
    first = view(c, "get_risk_summary", "ds-1")
    assert first["stale"] is False
    fails(send(c, "assess_dataset", "ds-1"))                         # already ASSESSED, no new evidence
    add(c, "ds-1", "PROVENANCE_RECORD")
    second = view(c, "get_risk_summary", "ds-1")
    assert second["status"] == "EVIDENCE_SUBMITTED" and second["stale"] is True and second["outcome"] == first["outcome"]
    ok(send(c, "assess_dataset", "ds-1", **FAST_TX))
    assert view(c, "get_risk_summary", "ds-1")["status"] == "ASSESSED"


def test_failed_calls_leave_state_untouched_and_views_are_repeatable():
    c = deploy()
    register(c, "ds-1")
    add(c, "ds-1", "PROVENANCE_RECORD")
    before = view(c, "get_assessment", "ds-1"), view(c, "get_dataset_count")
    for args in [("register_dataset", "ds-1", "n", "1", H, "p", "", ""), ("register_dataset", "bad id", "n", "1", H, "p", "", ""),
                 ("submit_evidence", "ds-1", "NOPE", "OBSERVATION", "s", "", 0, 0), ("update_assessment_status", "ds-1", "ASSESSED")]:
        fails(send(c, *args))
    assert (view(c, "get_assessment", "ds-1"), view(c, "get_dataset_count")) == before
    assert view(c, "get_assessment", "ds-1") == view(c, "get_assessment", "ds-1")


def test_count_tracks_registrations():
    c = deploy()
    for i in range(6):
        register(c, "bulk-%d" % i)
        assert view(c, "get_dataset_count") == i + 1
