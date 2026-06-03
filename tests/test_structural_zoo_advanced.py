"""Advanced obfuscation capability matrix: encryption, memory & looping vIP.

Extends the dispatch-shape zoo (``test_structural_zoo.py``) with techniques
beyond dispatch shape (see ``tests/fixtures/build_vm_zoo_adv.py``):

* encrypted bytecode (opcodes/immediates XOR-encrypted, decrypted live)
* self-decrypting bytecode (startup loop decrypts in place)
* memory-resident vIP (VM-context struct; vIP loaded/stored each step)
* virtual loop (non-monotonic vIP via a backward virtual branch)

Each VM is first executed under Unicorn to prove it is a valid program, then
the unmodified detector is run against the trace.  These document where
dynamic analysis sees through obfuscation (a strength) and where the
structural heuristics still have limits (an honest gap).

Requires the optional ``unicorn`` backend; skipped otherwise.
"""
from __future__ import annotations

import pytest

from dragonslayer.analysis.trace_engine import UNICORN_AVAILABLE

pytestmark = pytest.mark.skipif(
    not UNICORN_AVAILABLE, reason="requires the optional 'unicorn' emulation backend"
)

ADV = ["encrypted_bytecode", "self_decrypting", "memory_vip", "virtual_loop"]


def _trace_adv(name: str):
    from tests.fixtures import build_vm_zoo_adv as adv
    from dragonslayer.analysis.trace_engine import TraceConfig, TraceEngine

    elf, meta = adv._ADV[name]()
    tr = TraceEngine(
        arch="x86_64", config=TraceConfig(max_instructions=6000),
    ).trace(elf, entry_va=meta["entry_va"], image_base=meta["base"])
    return tr, meta


def _final_ebx(trace):
    last = None
    for ti in trace.instructions:
        regs = ti.registers or {}
        val = regs.get("ebx", regs.get("rbx"))
        if isinstance(val, int):
            last = val & 0xFFFFFFFF
    return last


@pytest.mark.parametrize("name", ADV)
def test_adv_sample_is_a_valid_program(name):
    """Each obfuscated VM runs to its expected result under Unicorn — i.e.
    dynamic tracing executes the *real* (decrypted) computation."""
    trace, meta = _trace_adv(name)
    assert _final_ebx(trace) == meta["expected_result"]


@pytest.mark.parametrize("name", ADV)
def test_adv_detected_as_vm(name):
    """Every obfuscation technique is still flagged as a VM structurally."""
    from dragonslayer.analysis.vm_discovery.structural import analyse_vm_structure

    trace, _ = _trace_adv(name)
    assert analyse_vm_structure(trace)["is_vm"], name


def test_encrypted_bytecode_seen_through_dynamically():
    """Bytecode encryption defeats static extraction, but the dynamic trace
    executes the decrypted opcodes — detection and vIP are intact."""
    from dragonslayer.analysis.vm_discovery.structural import analyse_vm_structure

    trace, _ = _trace_adv("encrypted_bytecode")
    report = analyse_vm_structure(trace)
    assert report["is_vm"]
    assert report["vip_register"] == "rsi"
    assert report["indirect_dispatch"] is True


def test_memory_resident_vip_is_found():
    """A vIP living in a VM-context struct (loaded/stored each step) is still
    identified via the register it transits through (rbp here)."""
    from dragonslayer.analysis.vm_discovery.structural import analyse_vm_structure

    trace, _ = _trace_adv("memory_vip")
    report = analyse_vm_structure(trace)
    assert report["is_vm"]
    assert report["vip_register"] == "rbp"


def test_virtual_loop_vip_not_confused_with_accumulator():
    """A virtual backward branch makes the real vIP (rsi) non-monotonic while
    the accumulator only grows.  The fetch-pointer signal must still pick the
    real vIP (rsi), not the monotonically-advancing accumulator."""
    from dragonslayer.analysis.vm_discovery.structural import analyse_vm_structure

    trace, _ = _trace_adv("virtual_loop")
    report = analyse_vm_structure(trace)
    assert report["is_vm"]
    assert report["vip_register"] == "rsi", report


def test_self_decrypting_locates_real_dispatcher():
    """A hot startup decrypt loop must not mask the real dispatcher: the
    detector relocates the dispatch loop around the repeated indirect-dispatch
    site, so indirect dispatch is reported and the handler estimate reflects
    the interpreter (a handful), not the decryptor's iteration count."""
    from dragonslayer.analysis.vm_discovery.structural import analyse_vm_structure

    trace, _ = _trace_adv("self_decrypting")
    report = analyse_vm_structure(trace)
    assert report["is_vm"]
    assert report["vip_register"] == "rsi"
    assert report["indirect_dispatch"] is True, report
    # 4 opcodes (LOAD/ADD/XOR/HALT), not the ~16-iteration decrypt loop.
    assert report["estimated_handlers"] <= 8, report
