"""
UNVERIFIED / NOT EXECUTED.

Written from my recollection of the official `genlayer-test` (gltest) API:
get_contract_factory(), factory.deploy(args=[...]), contract.method(args=[...]).transact()/.call(),
and gltest.assertions.tx_execution_succeeded / tx_execution_failed.
I could not install genlayer-test in my sandbox (no network), so these names, the config file
and the CLI flags may differ in your installed version. Check `gltest --help` and the docs for your
version, adjust, then run. Only DETERMINISTIC flows are covered here; the LLM path needs validator
setup/mocking whose API I could not confirm, so it is a manual Studio step (see README_TESTING.md).
"""
from gltest import get_contract_factory
from gltest.assertions import tx_execution_failed, tx_execution_succeeded

H = "a" * 64
M = "Fine-tuned classifier on suspect split, seed 7, 50 prompts per run, hit = label flips to POSITIVE"


def deploy():
    factory = get_contract_factory("PoisonGuardAI")
    return factory.deploy(args=[])


def test_register_and_get():
    c = deploy()
    r = c.register_dataset(args=["ds-1", "dataset", "1.0", H, "in-house curated", "clf", "v1"]).transact()
    assert tx_execution_succeeded(r)
    a = c.get_assessment(args=["ds-1"]).call()
    assert a["status"] == "REGISTERED" and a["outcome"] == "NOT_ASSESSED"
    assert c.get_dataset_count(args=[]).call() == 1


def test_duplicate_id_and_bad_hash_rejected():
    c = deploy()
    assert tx_execution_succeeded(c.register_dataset(args=["ds-1", "d", "1", H, "p", "", ""]).transact())
    assert tx_execution_failed(c.register_dataset(args=["ds-1", "d", "1", H, "p", "", ""]).transact())
    assert tx_execution_failed(c.register_dataset(args=["ds-2", "d", "1", "xyz", "p", "", ""]).transact())
    assert c.get_dataset_count(args=[]).call() == 1


def test_evidence_validation_and_deterministic_assessment():
    c = deploy()
    c.register_dataset(args=["ds-1", "d", "1", H, "p", "clf", "v1"]).transact()
    assert tx_execution_failed(c.submit_evidence(args=["ds-1", "TRIGGER_TEST", "OBSERVATION", "s", "short", 50, 10]).transact())
    assert tx_execution_succeeded(c.submit_evidence(args=["ds-1", "OTHER", "ALLEGATION", "forum claim", "", 0, 0]).transact())
    # allegation-only evidence => deterministic INCONCLUSIVE, no LLM involved
    assert tx_execution_succeeded(c.assess_dataset(args=["ds-1"]).transact())
    s = c.get_risk_summary(args=["ds-1"]).call()
    assert s["outcome"] == "INCONCLUSIVE" and s["evaluation_mode"] == "DETERMINISTIC_ONLY"


def test_status_transitions():
    c = deploy()
    c.register_dataset(args=["ds-1", "d", "1", H, "p", "", ""]).transact()
    assert tx_execution_failed(c.update_assessment_status(args=["ds-1", "ASSESSED"]).transact())
    assert tx_execution_succeeded(c.update_assessment_status(args=["ds-1", "CLOSED"]).transact())
    assert tx_execution_failed(c.update_assessment_status(args=["ds-1", "REJECTED"]).transact())
