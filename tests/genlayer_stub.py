"""
Strict LOCAL STUB of the parts of the `genlayer` SDK that PoisonGuardAI uses.

IMPORTANT: this is NOT the official GenLayer runtime or the official gltest
workflow. It is a hand-written approximation so deterministic logic can be
tested without Studio. Passing tests here does not prove the contract works on
the real runtime. Where the stub is deliberately STRICTER than I believe the
real runtime to be, it is noted.

Strictness added on purpose:
  * u256 fields only accept U256 instances (a plain int assignment raises).
  * storage dataclass fields are type-checked on every assignment.
  * TreeMap access raises inside a non-deterministic block (nondet code must
    not touch contract storage).
  * gl.nondet.exec_prompt raises when called outside a non-deterministic block.
  * No transaction rollback: a failing write keeps any partial writes, so
    validate-before-write bugs are visible.
"""
import importlib.util
import sys
import types


class StubState:
    in_nondet = False
    prompts = []
    responses = []          # consumed in order; last one repeats
    nondet_calls = 0
    violations = []


STATE = StubState()


def reset_llm():
    STATE.in_nondet = False
    STATE.prompts = []
    STATE.responses = []
    STATE.nondet_calls = 0
    STATE.violations = []


class U256(int):
    def __new__(cls, value=0):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("u256 requires an int")
        if value < 0 or value >= 2 ** 256:
            raise OverflowError("u256 out of range")
        return super().__new__(cls, value)


class Address:
    def __init__(self, hex_value):
        self.as_hex = hex_value

    def __eq__(self, other):
        return isinstance(other, Address) and self.as_hex == other.as_hex

    def __hash__(self):
        return hash(self.as_hex)

    def __repr__(self):
        return "Address(%s)" % self.as_hex


class TreeMap(dict):
    def __class_getitem__(cls, item):
        return cls

    def _guard(self):
        if STATE.in_nondet:
            STATE.violations.append("storage accessed inside non-deterministic block")
            raise RuntimeError("contract storage accessed inside a non-deterministic block")

    def __getitem__(self, k):
        self._guard()
        return super().__getitem__(k)

    def __setitem__(self, k, v):
        self._guard()
        super().__setitem__(k, v)

    def __contains__(self, k):
        self._guard()
        return super().__contains__(k)


def allow_storage(cls):
    annotations = dict(getattr(cls, "__annotations__", {}))

    def __setattr__(self, name, value):
        want = annotations.get(name)
        if want is not None:
            if want is U256:
                ok = isinstance(value, U256)
            elif want is bool:
                ok = isinstance(value, bool)
            elif want is str:
                ok = isinstance(value, str)
            elif want is Address:
                ok = isinstance(value, Address)
            else:
                ok = True
            if not ok:
                raise TypeError("storage field %s expects %s, got %r" % (name, want.__name__, type(value).__name__))
        object.__setattr__(self, name, value)

    cls.__setattr__ = __setattr__
    return cls


class UserError(Exception):
    pass


class Return:
    def __init__(self, calldata):
        self.calldata = calldata


class Contract:
    def __new__(cls, *a, **kw):
        obj = object.__new__(cls)
        for klass in reversed(cls.__mro__):
            for name, ann in getattr(klass, "__annotations__", {}).items():
                if ann is TreeMap:
                    object.__setattr__(obj, name, TreeMap())
                elif ann is U256:
                    object.__setattr__(obj, name, U256(0))
                elif ann is Address:
                    object.__setattr__(obj, name, Address("0x" + "0" * 40))
        return obj


def _exec_prompt(prompt):
    if not STATE.in_nondet:
        STATE.violations.append("exec_prompt outside non-deterministic block")
        raise RuntimeError("exec_prompt called outside a non-deterministic block")
    STATE.prompts.append(prompt)
    if not STATE.responses:
        raise RuntimeError("no mocked LLM response queued")
    idx = min(len(STATE.prompts) - 1, len(STATE.responses) - 1)
    resp = STATE.responses[idx]
    if isinstance(resp, BaseException):
        raise resp
    return resp


def _run_nondet_unsafe(leader_fn, validator_fn):
    """Leader runs, then ONE validator re-runs and judges (stub of consensus)."""
    STATE.nondet_calls += 1
    STATE.in_nondet = True
    try:
        try:
            leader_result = Return(leader_fn())
        except UserError as e:
            raise
        except Exception as e:
            # real runtime: leader error is surfaced to validators as a non-Return result
            leader_result = e
        accepted = validator_fn(leader_result)
    finally:
        STATE.in_nondet = False
    if not accepted:
        raise UserError("validator rejected leader result")
    if not isinstance(leader_result, Return):
        raise UserError("leader failed: %r" % (leader_result,))
    return leader_result.calldata


def build_module():
    gl = types.SimpleNamespace()
    gl.Contract = Contract
    gl.public = types.SimpleNamespace(view=lambda f: f, write=lambda f: f)
    gl.message = types.SimpleNamespace(sender_address=Address("0xowner"))
    gl.message_raw = {"datetime": "2026-10-13T00:00:00Z"}
    gl.nondet = types.SimpleNamespace(exec_prompt=_exec_prompt)
    gl.vm = types.SimpleNamespace(UserError=UserError, Return=Return, run_nondet_unsafe=_run_nondet_unsafe)
    mod = types.ModuleType("genlayer")
    mod.gl = gl
    mod.u256 = U256
    mod.Address = Address
    mod.TreeMap = TreeMap
    mod.allow_storage = allow_storage
    return mod, gl


def load_contract(path):
    """Fresh module + fresh stub per call, so tests never share state."""
    mod, gl = build_module()
    sys.modules["genlayer"] = mod
    spec = importlib.util.spec_from_file_location("poison_guard_ai_under_test", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m, gl


def assert_calldata_encodable(value, path="$"):
    """Views must return only types GenLayer calldata can encode (no floats/Address/etc)."""
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        raise AssertionError("float at %s is not calldata-safe" % path)
    if isinstance(value, list):
        for i, v in enumerate(value):
            assert_calldata_encodable(v, "%s[%d]" % (path, i))
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise AssertionError("non-str key at %s" % path)
            assert_calldata_encodable(v, "%s.%s" % (path, k))
        return
    raise AssertionError("type %s at %s is not calldata-safe" % (type(value).__name__, path))
