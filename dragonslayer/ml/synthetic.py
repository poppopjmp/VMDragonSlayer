"""Synthetic VM-handler dataset generator for the ML handler classifier.

This produces large, *diverse* labelled handler samples so the
``RandomForestClassifier`` (and the ensemble) can be trained and evaluated
without needing real protected binaries.  Each sample is a realistic
fetch/operate/advance VM-handler instruction sequence, then run through a
set of **obfuscation transforms** that mimic what commercial protectors do:

* junk / NOP padding,
* opaque predicates (``xor r,r`` ; ``jz``),
* dead scratch-register arithmetic (MBA-style noise),
* ``lea r,[r]`` / ``xchg r,r`` no-ops,
* register renaming,
* per-protector stylistic flavouring (VMProtect / Themida / Code Virtualizer).

The output dicts match the contract of
:func:`dragonslayer.ml.pipeline.extract_handler_features` (``instructions`` /
``mnemonics`` / ``reads`` / ``writes`` / ``block_count`` / ``operand_width`` /
``category``).
"""
from __future__ import annotations

import random
from typing import Any

from .taxonomy import CANONICAL_CATEGORIES

# A scratch register pool used for renaming / junk so samples don't all look
# identical.
_GP = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"]

Instr = tuple[str, str]
Body = list[Instr]

# ---------------------------------------------------------------------------
# Base templates — several realistic variants per canonical category.
# {VR} = a virtual register slot ([rbp+N]); {imm} an immediate operand.
# ---------------------------------------------------------------------------
_BASE: dict[str, list[Body]] = {
    "arithmetic": [
        [("mov", "rax, [rbp]"), ("mov", "rcx, [rbp+8]"), ("add", "rax, rcx"),
         ("mov", "[rbp+8], rax")],
        [("mov", "rax, [rbp]"), ("mov", "rcx, [rbp+8]"), ("sub", "rax, rcx"),
         ("mov", "[rbp+8], rax")],
        [("mov", "rax, [rbp]"), ("imul", "rax, [rbp+8]"), ("mov", "[rbp], rax")],
        [("mov", "rax, [rbp]"), ("neg", "rax"), ("mov", "[rbp], rax")],
        [("mov", "eax, [rbp]"), ("add", "eax, 1"), ("mov", "[rbp], eax")],
    ],
    "bitwise": [
        [("mov", "rax, [rbp]"), ("mov", "rcx, [rbp+8]"), ("xor", "rax, rcx"),
         ("mov", "[rbp+8], rax")],
        [("mov", "rax, [rbp]"), ("and", "rax, [rbp+8]"), ("mov", "[rbp+8], rax")],
        [("mov", "rax, [rbp]"), ("or", "rax, [rbp+8]"), ("mov", "[rbp+8], rax")],
        [("mov", "rax, [rbp]"), ("not", "rax"), ("mov", "[rbp], rax")],
        [("mov", "cl, [rbp+8]"), ("mov", "rax, [rbp]"), ("shl", "rax, cl"),
         ("mov", "[rbp], rax")],
        [("mov", "cl, [rbp+8]"), ("mov", "rax, [rbp]"), ("ror", "rax, cl"),
         ("mov", "[rbp], rax")],
    ],
    "memory": [
        [("mov", "rax, [rbp]"), ("mov", "rcx, [rax]"), ("mov", "[rbp], rcx")],
        [("mov", "rax, [rbp]"), ("mov", "rcx, [rbp+8]"), ("mov", "[rax], rcx")],
        [("mov", "rax, [rsi]"), ("mov", "[rbp], rax")],
    ],
    "stack": [
        [("mov", "rax, [rbp]"), ("sub", "rbp, 8"), ("mov", "[rbp], rax")],
        [("mov", "rax, [rbp]"), ("add", "rbp, 8"), ("mov", "[rsp], rax")],
        [("push", "qword ptr [rbp]"), ("sub", "rbp, 8")],
    ],
    "control_flow": [
        [("mov", "rax, [rbp]"), ("test", "rax, rax"), ("jz", "0x1000"),
         ("mov", "rsi, [rbp+8]")],
        [("mov", "rsi, [rbp]"), ("jmp", "rsi")],
        [("mov", "rax, [rbp]"), ("cmp", "rax, 0"), ("jne", "0x2000")],
    ],
    "comparison": [
        [("mov", "rax, [rbp]"), ("cmp", "rax, [rbp+8]"), ("setg", "al"),
         ("mov", "[rbp+8], al")],
        [("mov", "rax, [rbp]"), ("test", "rax, rax"), ("setz", "al"),
         ("mov", "[rbp], al")],
        [("mov", "rax, [rbp]"), ("cmp", "rax, [rbp+8]"), ("pushf", ""),
         ("pop", "[rbp+8]")],
    ],
    "crypto": [
        [("mov", "rax, [rbp]"), ("mov", "rcx, [rsi]"), ("xor", "rax, rcx"),
         ("rol", "rax, 7"), ("mov", "[rbp], rax")],
        [("mov", "rax, [rbp]"), ("ror", "rax, 13"), ("xor", "rax, 0x9e3779b9"),
         ("mov", "[rbp], rax")],
        [("mov", "eax, [rsi]"), ("add", "esi, 4"), ("xor", "eax, [rbp]"),
         ("rol", "eax, 11"), ("mov", "[rbp], eax")],
        [("mov", "rax, [rbp]"), ("shl", "rax, 13"), ("xor", "rax, [rbp]"),
         ("shr", "rax, 17"), ("mov", "[rbp], rax")],
    ],
    "vm_control": [
        [("movzx", "eax, byte ptr [rsi]"), ("inc", "rsi"),
         ("jmp", "qword ptr [r10+rax*8]")],
        [("push", "rbp"), ("mov", "rbp, rsp"), ("sub", "rsp, 0x80"),
         ("mov", "rsi, [rbp+0x10]")],
        [("mov", "rsp, [rbp]"), ("pop", "rbp"), ("ret", "")],
        [("movzx", "eax, byte ptr [rsi]"), ("add", "rsi, 1"),
         ("mov", "rcx, [r10+rax*8]"), ("jmp", "rcx")],
    ],
    "conversion": [
        [("movzx", "eax, byte ptr [rbp]"), ("mov", "[rbp], eax")],
        [("movsx", "rax, word ptr [rbp]"), ("mov", "[rbp], rax")],
        [("movsxd", "rax, dword ptr [rbp]"), ("mov", "[rbp], rax")],
    ],
    "system": [
        [("rdtsc", ""), ("mov", "[rbp], eax")],
        [("cpuid", ""), ("mov", "[rbp], eax")],
        [("mov", "ecx, [rbp]"), ("rdmsr", ""), ("mov", "[rbp], eax")],
    ],
    "nop": [
        [("nop", "")],
        [("nop", ""), ("nop", ""), ("nop", "")],
        [("xchg", "ax, ax")],
    ],
    "unknown": [
        [("fldz", ""), ("fstp", "qword ptr [rbp]")],
        [("prefetcht0", "[rbp]")],
        [("pause", "")],
    ],
}
# "stack" canonical op needs push/pop presence; ensure present above.


# ---------------------------------------------------------------------------
# Obfuscation transforms
# ---------------------------------------------------------------------------

def _inject_nops(body: Body, rng: random.Random, n: int) -> Body:
    for _ in range(n):
        body.insert(rng.randint(0, len(body)), ("nop", ""))
    return body


def _inject_opaque_predicate(body: Body, rng: random.Random) -> Body:
    r = rng.choice(_GP)
    pos = rng.randint(0, len(body))
    body[pos:pos] = [("xor", f"{r}, {r}"), ("jz", hex(rng.randint(0x1000, 0x9000)))]
    return body


def _inject_dead_arith(body: Body, rng: random.Random) -> Body:
    """MBA-style dead scratch arithmetic that doesn't touch VM state."""
    r = rng.choice(["r12", "r13", "r14", "r15"])
    pos = rng.randint(0, len(body))
    body[pos:pos] = [
        ("mov", f"{r}, {hex(rng.randint(1, 0xffff))}"),
        (rng.choice(["add", "xor", "sub", "or"]), f"{r}, {hex(rng.randint(1, 0xff))}"),
    ]
    return body


def _inject_reg_nop(body: Body, rng: random.Random) -> Body:
    r = rng.choice(_GP)
    pos = rng.randint(0, len(body))
    nop = rng.choice([("lea", f"{r}, [{r}]"), ("xchg", f"{r}, {r}"), ("mov", f"{r}, {r}")])
    body.insert(pos, nop)
    return body


def _rename_registers(body: Body, rng: random.Random) -> Body:
    """Swap rax<->rdx and rcx<->rbx consistently (semantics-preserving for
    these scratch roles in templates)."""
    if rng.random() < 0.5:
        return body
    swaps = {"rax": "rdx", "rdx": "rax", "rcx": "rbx", "rbx": "rcx",
             "eax": "edx", "edx": "eax", "ecx": "ebx", "ebx": "ecx"}
    out: Body = []
    for mnem, ops in body:
        for a, b in swaps.items():
            ops = ops.replace(a, "§").replace(b, a).replace("§", b)
        out.append((mnem, ops))
    return out


# Per-protector obfuscation intensity (mean count of each transform).
_PROTECTOR_PROFILE: dict[str, dict[str, float]] = {
    "generic":          {"nops": 0.5, "opaque": 0.1, "dead": 0.3, "regnop": 0.3, "rename": 0.3},
    "vmprotect":        {"nops": 1.0, "opaque": 0.4, "dead": 1.2, "regnop": 0.6, "rename": 0.6},
    "themida":          {"nops": 2.0, "opaque": 0.7, "dead": 1.5, "regnop": 1.0, "rename": 0.5},
    "code_virtualizer": {"nops": 0.8, "opaque": 0.3, "dead": 0.8, "regnop": 0.5, "rename": 0.7},
}
PROTECTORS = tuple(_PROTECTOR_PROFILE)


def _obfuscate(body: Body, rng: random.Random, profile: dict[str, float]) -> Body:
    body = _rename_registers(body, rng) if rng.random() < profile["rename"] else body
    for _ in range(_poisson(rng, profile["dead"])):
        body = _inject_dead_arith(body, rng)
    for _ in range(_poisson(rng, profile["regnop"])):
        body = _inject_reg_nop(body, rng)
    if rng.random() < profile["opaque"]:
        body = _inject_opaque_predicate(body, rng)
    body = _inject_nops(body, rng, _poisson(rng, profile["nops"]))
    return body


def _poisson(rng: random.Random, mean: float) -> int:
    """Tiny Knuth Poisson sampler (mean is small)."""
    if mean <= 0:
        return 0
    import math

    limit = math.exp(-mean)
    k, p = 0, 1.0
    while p > limit:
        k += 1
        p *= rng.random()
    return k - 1


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def synth_handler(
    category: str,
    rng: random.Random,
    *,
    protector: str = "generic",
) -> dict[str, Any]:
    """Generate one obfuscated synthetic handler dict for *category*."""
    body = list(rng.choice(_BASE[category]))
    body = _obfuscate(body, rng, _PROTECTOR_PROFILE[protector])

    mnemonics = [m.lower() for m, _ in body]
    instructions = [{"mnemonic": m, "operands": o} for m, o in body]
    reads = [o.split(",")[-1].strip() for m, o in body if "[" in o.split(",")[-1:][0]]
    writes = [o.split(",")[0].strip() for m, o in body if o.startswith("[")]
    return {
        "instructions": instructions,
        "mnemonics": mnemonics,
        "reads": reads,
        "writes": writes,
        "category": category,
        "protector": protector,
        "operand_width": rng.choice([1, 2, 4, 8]),
        "block_count": 1 + mnemonics.count("jz") + mnemonics.count("jne")
        + mnemonics.count("jmp"),
    }


def generate_dataset(
    n_per_category: int = 200,
    *,
    categories: list[str] | None = None,
    protectors: tuple[str, ...] = PROTECTORS,
    seed: int = 1337,
) -> list[dict[str, Any]]:
    """Generate a shuffled, labelled synthetic handler dataset.

    Produces ``n_per_category * len(categories) * len(protectors)`` samples,
    spread evenly across protector flavours.
    """
    rng = random.Random(seed)
    cats = categories or list(CANONICAL_CATEGORIES)
    out: list[dict[str, Any]] = []
    for cat in cats:
        if cat not in _BASE:
            continue
        for _ in range(n_per_category):
            for prot in protectors:
                out.append(synth_handler(cat, rng, protector=prot))
    rng.shuffle(out)
    return out


def featurize(
    dataset: list[dict[str, Any]], *, extended: bool = True,
) -> tuple[list[list[float]], list[str]]:
    """Vectorise *dataset* into ``(X, y)``.

    With ``extended=True`` (default) uses the 146-D feature set (ratios +
    mnemonic bigrams), which separates obfuscated arithmetic/bitwise/crypto
    handlers far better than the compact 17-D set.
    """
    from .pipeline import extract_extended_features, extract_handler_features

    fx = extract_extended_features if extended else extract_handler_features
    X = [fx(h).values for h in dataset]
    y = [h["category"] for h in dataset]
    return X, y


def train_and_evaluate(
    dataset: list[dict[str, Any]] | None = None,
    *,
    n_per_category: int = 200,
    test_frac: float = 0.25,
    seed: int = 1337,
    extended: bool = True,
) -> dict[str, Any]:
    """Train a RandomForest on synthetic data and report held-out metrics.

    Returns a dict with ``accuracy``, ``macro_f1``, ``per_class`` (precision/
    recall/f1/support), ``confusion``, ``labels``, ``top_features``,
    ``n_train``/``n_test``.  Requires scikit-learn.
    """
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import (
        accuracy_score,
        confusion_matrix,
        f1_score,
        precision_recall_fscore_support,
    )
    from sklearn.model_selection import train_test_split

    from .pipeline import EXTENDED_FEATURE_NAMES, HANDLER_FEATURE_NAMES

    feat_names = EXTENDED_FEATURE_NAMES if extended else HANDLER_FEATURE_NAMES

    if dataset is None:
        dataset = generate_dataset(n_per_category=n_per_category, seed=seed)
    X, y = featurize(dataset, extended=extended)
    X_arr = np.asarray(X, dtype=float)

    X_tr, X_te, y_tr, y_te = train_test_split(
        X_arr, y, test_size=test_frac, random_state=seed, stratify=y,
    )
    clf = RandomForestClassifier(
        n_estimators=200, max_depth=None, n_jobs=-1, random_state=seed,
    )
    clf.fit(X_tr, y_tr)
    y_pred = clf.predict(X_te)

    labels = sorted(set(y))
    prec, rec, f1, sup = precision_recall_fscore_support(
        y_te, y_pred, labels=labels, zero_division=0,
    )
    per_class = {
        lbl: {
            "precision": round(float(prec[i]), 3),
            "recall": round(float(rec[i]), 3),
            "f1": round(float(f1[i]), 3),
            "support": int(sup[i]),
        }
        for i, lbl in enumerate(labels)
    }
    importances = sorted(
        zip(feat_names, clf.feature_importances_, strict=False),
        key=lambda kv: kv[1], reverse=True,
    )
    return {
        "accuracy": round(float(accuracy_score(y_te, y_pred)), 4),
        "macro_f1": round(float(f1_score(y_te, y_pred, average="macro")), 4),
        "per_class": per_class,
        "confusion": confusion_matrix(y_te, y_pred, labels=labels).tolist(),
        "labels": labels,
        "top_features": [(n, round(float(v), 4)) for n, v in importances[:10]],
        "n_train": len(X_tr),
        "n_test": len(X_te),
        "model": clf,
    }

