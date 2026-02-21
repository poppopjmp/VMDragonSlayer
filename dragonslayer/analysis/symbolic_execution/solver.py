"""
Symbolic Execution — Solver
============================

Z3-backed constraint solver for resolving symbolic values during VM
handler analysis.  Wraps z3 to provide a simpler interface focused on
common VM deobfuscation tasks:

* Solving opaque predicates (prove always-true / always-false).
* Computing concrete inputs that reach a given handler.
* Simplifying symbolic expressions.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    import z3
    _Z3_AVAILABLE = True
except ImportError:
    z3 = None  # type: ignore[assignment]
    _Z3_AVAILABLE = False

# B57: Import resource-limit exceptions for raising on solver exhaustion.
try:
    from dragonslayer.core.exceptions import ResourceLimitError, AnalysisTimeoutError
except ImportError:  # pragma: no cover — standalone usage
    class ResourceLimitError(RuntimeError):  # type: ignore[no-redef]
        pass
    class AnalysisTimeoutError(RuntimeError):  # type: ignore[no-redef]
        pass


@dataclass
class SolverResult:
    """Outcome of a solver query."""
    satisfiable: bool
    model: Optional[Dict[str, Any]] = None
    simplified: Optional[str] = None
    error: Optional[str] = None


class Z3Solver:
    """
    High-level Z3 wrapper for VM deobfuscation tasks.

    Usage::

        solver = Z3Solver()
        x = solver.bitvec("x", 64)
        solver.add(x + 1 == 42)
        result = solver.check()
        assert result.satisfiable
        assert result.model["x"] == 41
    """

    def __init__(self, timeout_ms: int = 10000, memory_limit_mb: int = 0) -> None:
        if not _Z3_AVAILABLE:
            raise ImportError("z3-solver is required for Z3Solver — install via pip install z3-solver")
        self.timeout_ms = timeout_ms
        self.memory_limit_mb = memory_limit_mb
        self._constraints: List[Any] = []

        # B53: Apply global z3 memory limit if requested
        if memory_limit_mb > 0:
            try:
                z3.set_param("memory_max_size", memory_limit_mb)
            except z3.Z3Exception:
                logger.debug("Failed to set z3 memory limit to %d MB", memory_limit_mb)
        self._constraint_stack: List[int] = []  # indices for push/pop sync
        self._solver = z3.Solver()
        self._solver.set("timeout", timeout_ms)

    @staticmethod
    def available() -> bool:
        """Return *True* if z3 is installed and usable."""
        return _Z3_AVAILABLE

    # -- Variable creation --------------------------------------------------

    @staticmethod
    def bitvec(name: str, bits: int = 64) -> Any:
        """Create a symbolic bit-vector variable.

        Args:
            name: Symbolic variable name (must be unique per solver scope).
            bits: Bit-width of the vector (default 64).

        Returns:
            A z3 ``BitVec`` expression.
        """
        return z3.BitVec(name, bits)

    @staticmethod
    def bitvec_val(value: int, bits: int = 64) -> Any:
        """Create a concrete bit-vector value.

        Args:
            value: Integer value to encode.
            bits: Bit-width of the vector (default 64).

        Returns:
            A z3 ``BitVecVal`` expression.
        """
        return z3.BitVecVal(value, bits)

    # -- Constraint management -----------------------------------------------

    def add(self, *constraints: Any) -> None:
        """Add constraints to the solver.

        Args:
            *constraints: One or more z3 Boolean expressions.
        """
        self._constraints.extend(constraints)
        self._solver.add(*constraints)

    def reset(self) -> None:
        """Clear all constraints and the push/pop stack."""
        self._constraints.clear()
        self._constraint_stack.clear()
        self._solver.reset()

    def push(self) -> None:
        """Save the current constraint count for later :meth:`pop`.

        Creates a checkpoint so that constraints added after this call
        can be discarded by a subsequent :meth:`pop`.

        Raises:
            Nothing — always succeeds.  A corresponding :meth:`pop` is
            required to restore the checkpoint.
        """
        self._constraint_stack.append(len(self._constraints))
        self._solver.push()

    def pop(self) -> None:
        """Restore constraints to the last :meth:`push` checkpoint.

        Raises:
            IndexError: Implicitly, if called without a matching :meth:`push`
                (z3 solver will raise).
        """
        if self._constraint_stack:
            idx = self._constraint_stack.pop()
            self._constraints = self._constraints[:idx]
        self._solver.pop()

    # -- B59: Named constraints & unsat core --------------------------------

    def assert_and_track(self, constraint: Any, name: str) -> None:
        """Add a *named* constraint for unsat-core extraction.

        Unlike :meth:`add`, tracked constraints participate in
        :meth:`unsat_core` so the caller can identify which subset of
        named constraints is responsible for unsatisfiability.
        """
        label = z3.Bool(name)
        self._constraints.append(constraint)
        self._solver.assert_and_track(constraint, label)

    def unsat_core(self) -> List[str]:
        """Return the names of constraints in the UNSAT core.

        Only meaningful after :meth:`check` returns UNSAT and the
        conflicting constraints were added via :meth:`assert_and_track`.
        """
        try:
            core = self._solver.unsat_core()
            return [str(c) for c in core]
        except (z3.Z3Exception, AttributeError):
            return []

    # -- B59: Incremental feasibility check ---------------------------------

    def check_feasibility(
        self, *extra_constraints: Any
    ) -> bool:
        """Check whether *extra_constraints* are feasible under the current
        constraint set **without** permanently adding them.

        Uses push/pop on the persistent solver, avoiding the overhead of
        creating a fresh ``z3.Solver`` instance.

        Returns ``True`` if SAT, ``False`` otherwise (UNSAT or unknown).
        """
        self._solver.push()
        try:
            if extra_constraints:
                self._solver.add(*extra_constraints)
            result = self._solver.check()
            return result == z3.sat
        except (z3.Z3Exception, ValueError):
            return False
        finally:
            self._solver.pop()

    # -- Solving -------------------------------------------------------------

    def check(self, *, raise_on_resource_limit: bool = False) -> SolverResult:
        """Check satisfiability and extract a model if SAT.

        Parameters
        ----------
        raise_on_resource_limit : bool
            When *True*, a solver ``unknown`` result (typically caused by
            timeout or memory exhaustion) raises :class:`ResourceLimitError`
            instead of returning a non-satisfiable :class:`SolverResult`.
        """

        try:
            result = self._solver.check()
            if result == z3.sat:
                model = self._solver.model()
                model_dict: Dict[str, Any] = {}
                for decl in model.decls():
                    val = model[decl]
                    try:
                        model_dict[decl.name()] = val.as_long()
                    except (AttributeError, z3.Z3Exception):
                        model_dict[decl.name()] = str(val)
                return SolverResult(satisfiable=True, model=model_dict)
            elif result == z3.unsat:
                return SolverResult(satisfiable=False)
            else:
                # B57: ``unknown`` — typically timeout or memory exhaustion.
                reason = str(self._solver.reason_unknown())
                if raise_on_resource_limit:
                    if "timeout" in reason.lower():
                        raise AnalysisTimeoutError(
                            f"Z3 solver timed out: {reason}",
                            error_code="SOLVER_TIMEOUT",
                            details={"reason": reason, "timeout_ms": self.timeout_ms},
                        )
                    raise ResourceLimitError(
                        f"Z3 solver returned unknown: {reason}",
                        error_code="SOLVER_RESOURCE_LIMIT",
                        details={"reason": reason, "memory_limit_mb": self.memory_limit_mb},
                    )
                return SolverResult(satisfiable=False, error=f"solver returned unknown: {reason}")
        except (ResourceLimitError, AnalysisTimeoutError):
            raise  # re-raise our own exceptions
        except (z3.Z3Exception, ValueError, TypeError) as exc:
            return SolverResult(satisfiable=False, error=str(exc))

    # -- Analysis helpers ---------------------------------------------------

    def is_opaque_predicate(self, condition: Any) -> Optional[bool]:
        """
        Determine if *condition* is an opaque predicate.

        Returns:
        * ``True`` — always true (tautology).
        * ``False`` — always false (contradiction).
        * ``None`` — genuinely conditional.
        """
        s = z3.Solver()
        s.set("timeout", self.timeout_ms)

        # Check if ¬condition is UNSAT → always true
        s.push()
        s.add(z3.Not(condition))
        if s.check() == z3.unsat:
            s.pop()
            return True

        s.pop()

        # Check if condition is UNSAT → always false
        s.push()
        s.add(condition)
        if s.check() == z3.unsat:
            s.pop()
            return False

        s.pop()
        return None  # Genuinely conditional

    def is_opaque_predicate_with_context(
        self,
        condition: Any,
        path_constraints: Any,
    ) -> Optional[bool]:
        """Determine if *condition* is opaque *under* accumulated path
        constraints.

        Unlike :meth:`is_opaque_predicate` which checks for universal
        tautology/contradiction, this method adds the *path_constraints*
        (a list of z3 expressions or z3-compatible objects) to the solver
        before testing.  A branch that is genuinely conditional in
        isolation may be always-true given the path context.

        Returns ``True``, ``False``, or ``None`` (genuinely conditional
        even under constraints).
        """
        s = z3.Solver()
        s.set("timeout", self.timeout_ms)

        # Add path constraints.
        if path_constraints:
            for c in path_constraints:
                try:
                    s.add(c)
                except (z3.Z3Exception, ValueError, TypeError):
                    continue

        # Check if ¬condition is UNSAT under path → always true in context.
        s.push()
        s.add(z3.Not(condition))
        if s.check() == z3.unsat:
            s.pop()
            return True

        s.pop()

        # Check if condition is UNSAT under path → always false in context.
        s.push()
        s.add(condition)
        if s.check() == z3.unsat:
            s.pop()
            return False

        s.pop()
        return None

    @staticmethod
    def simplify(expr: Any) -> Any:
        """Simplify a z3 expression.

        Args:
            expr: A z3 expression (``BitVec``, ``BoolRef``, etc.).

        Returns:
            The simplified z3 expression.
        """
        return z3.simplify(expr)

    def enumerate_values(
        self,
        expr: Any,
        constraints: List[Any] | None = None,
        max_values: int = 256,
    ) -> List[int]:
        """Enumerate all distinct concrete values of *expr* under constraints.

        Used for indirect dispatch resolution: given a symbolic jump
        target expression, enumerate all concrete addresses the jump may
        resolve to (up to *max_values*).

        Returns a sorted list of concrete ``int`` values.
        """
        s = z3.Solver()
        s.set("timeout", self.timeout_ms)

        all_constraints = list(self._constraints) + (constraints or [])
        if all_constraints:
            s.add(*all_constraints)

        values: List[int] = []
        bits = expr.sort().size() if hasattr(expr, "sort") else 64

        for _ in range(max_values):
            if s.check() != z3.sat:
                break
            model = s.model()
            val = model.eval(expr, model_completion=True)
            try:
                concrete = val.as_long()
            except (AttributeError, z3.Z3Exception):
                break
            values.append(concrete)
            # Exclude this value and continue
            s.add(expr != z3.BitVecVal(concrete, bits))

        return sorted(values)

    def solve_for(self, target_var: Any, constraints: List[Any] | None = None) -> SolverResult:
        """
        Solve for a specific variable given constraints.

        Returns the concrete value of *target_var* (if SAT).
        """
        s = z3.Solver()
        s.set("timeout", self.timeout_ms)
        all_constraints = list(self._constraints) + (constraints or [])
        s.add(*all_constraints)

        if s.check() == z3.sat:
            model = s.model()
            try:
                val = model.eval(target_var, model_completion=True)
                return SolverResult(
                    satisfiable=True,
                    model={str(target_var): val.as_long() if hasattr(val, "as_long") else str(val)},
                )
            except (z3.Z3Exception, ValueError, TypeError, AttributeError) as exc:
                return SolverResult(satisfiable=True, error=f"Eval failed: {exc}")

        return SolverResult(satisfiable=False)

    # -- B68: Streaming / chunked decryption helpers -------------------------

    def solve_xor_key_schedule(
        self,
        ciphertext_chunks: List[int],
        known_plaintext_chunks: List[int],
        bits: int = 64,
    ) -> SolverResult:
        """Solve for a repeating XOR key given known-plaintext pairs.

        Useful for VM bytecode decryption where a portion of the stream
        has known semantics (e.g., ``NOP`` sleds or handler prologues).

        Parameters
        ----------
        ciphertext_chunks:
            Encrypted values extracted from the protected binary.
        known_plaintext_chunks:
            Expected plain values at the same positions.
        bits:
            Bit-width of each chunk (typically 8, 32, or 64).

        Returns
        -------
        SolverResult
            With ``model`` mapping ``key_0 … key_N-1`` to concrete ints.
        """
        if not ciphertext_chunks or len(ciphertext_chunks) != len(known_plaintext_chunks):
            return SolverResult(satisfiable=False, error="chunk length mismatch")

        n = len(ciphertext_chunks)
        key_vars = [z3.BitVec(f"key_{i}", bits) for i in range(n)]

        s = z3.Solver()
        s.set("timeout", self.timeout_ms)

        for i in range(n):
            ct = z3.BitVecVal(ciphertext_chunks[i], bits)
            pt = z3.BitVecVal(known_plaintext_chunks[i], bits)
            s.add(ct ^ key_vars[i] == pt)

        if s.check() == z3.sat:
            model = s.model()
            result_model: Dict[str, Any] = {}
            for kv in key_vars:
                val = model.eval(kv, model_completion=True)
                try:
                    result_model[str(kv)] = val.as_long()
                except (AttributeError, z3.Z3Exception):
                    result_model[str(kv)] = str(val)
            return SolverResult(satisfiable=True, model=result_model)

        return SolverResult(satisfiable=False, error="key schedule unsatisfiable")

    def solve_chained_decryption(
        self,
        ciphertext_chain: List[int],
        initial_state: int,
        bits: int = 64,
        known_plaintexts: Dict[int, int] | None = None,
    ) -> SolverResult:
        """Solve for a chained (CBC-like) XOR decryption key.

        Assumes ``plain[i] = cipher[i] ^ key ^ plain[i-1]`` with
        ``plain[-1] = initial_state``.

        Parameters
        ----------
        known_plaintexts:
            Optional mapping of ``{index: expected_plain_value}`` that
            pins certain plaintext slots, making the key uniquely
            determined.

        Returns
        -------
        SolverResult
            With ``model`` containing the single ``key`` value and
            all recovered ``plain_i`` values.
        """
        if not ciphertext_chain:
            return SolverResult(satisfiable=False, error="empty ciphertext chain")

        n = len(ciphertext_chain)
        key = z3.BitVec("key", bits)
        plains = [z3.BitVec(f"plain_{i}", bits) for i in range(n)]

        s = z3.Solver()
        s.set("timeout", self.timeout_ms)

        prev = z3.BitVecVal(initial_state, bits)
        for i in range(n):
            ct = z3.BitVecVal(ciphertext_chain[i], bits)
            s.add(plains[i] == ct ^ key ^ prev)
            prev = plains[i]

        # Pin known plaintexts to make the key uniquely determined.
        if known_plaintexts:
            for idx, val in known_plaintexts.items():
                if 0 <= idx < n:
                    s.add(plains[idx] == z3.BitVecVal(val, bits))

        if s.check() == z3.sat:
            model = s.model()
            result_model: Dict[str, Any] = {"key": model.eval(key, model_completion=True).as_long()}
            for i, pv in enumerate(plains):
                val = model.eval(pv, model_completion=True)
                try:
                    result_model[f"plain_{i}"] = val.as_long()
                except (AttributeError, z3.Z3Exception):
                    result_model[f"plain_{i}"] = str(val)
            return SolverResult(satisfiable=True, model=result_model)

        return SolverResult(satisfiable=False, error="chained decryption unsatisfiable")

    # -- B69: Adaptive key-schedule length detection -------------------------

    def detect_key_schedule_length(
        self,
        ciphertext: List[int],
        known_plaintext: List[int],
        max_period: int = 32,
        bits: int = 8,
    ) -> SolverResult:
        """Detect the period (key length) of a repeating XOR key schedule.

        Tries increasing key lengths from 1 to *max_period*, checking
        whether a single repeating key of length *k* can explain all
        known-plaintext / ciphertext pairs.

        Parameters
        ----------
        ciphertext, known_plaintext:
            Equal-length sequences of encrypted and expected plain values.
        max_period:
            Maximum key period to try (default 32).
        bits:
            Bit-width per element.

        Returns
        -------
        SolverResult
            ``model["key_length"]`` and ``model["key_0"] … model["key_k-1"]``
            for the shortest satisfying period; or ``satisfiable=False`` if
            no period ≤ *max_period* works.
        """
        if not ciphertext or len(ciphertext) != len(known_plaintext):
            return SolverResult(satisfiable=False, error="input length mismatch")

        n = len(ciphertext)
        for k in range(1, min(max_period, n) + 1):
            key_vars = [z3.BitVec(f"key_{j}", bits) for j in range(k)]
            s = z3.Solver()
            s.set("timeout", self.timeout_ms)

            for i in range(n):
                ct = z3.BitVecVal(ciphertext[i], bits)
                pt = z3.BitVecVal(known_plaintext[i], bits)
                s.add(ct ^ key_vars[i % k] == pt)

            if s.check() == z3.sat:
                model = s.model()
                result_model: Dict[str, Any] = {"key_length": k}
                for j in range(k):
                    val = model.eval(key_vars[j], model_completion=True)
                    try:
                        result_model[f"key_{j}"] = val.as_long()
                    except (AttributeError, z3.Z3Exception):
                        result_model[f"key_{j}"] = str(val)
                return SolverResult(satisfiable=True, model=result_model)

        return SolverResult(satisfiable=False, error=f"no period ≤{max_period} found")

    # -- B71: AES S-box detection --------------------------------------------

    # Standard AES forward S-box (256 entries).
    _AES_SBOX: tuple[int, ...] = (
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
        0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
        0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
        0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
        0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
        0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
        0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
        0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
        0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
        0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
        0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
        0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
        0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
        0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
        0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
        0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
        0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    )

    @classmethod
    def detect_aes_sbox(cls, data: bytes | list[int], *, threshold: float = 0.9) -> dict:
        """Detect whether *data* contains an AES S-box (forward or inverse).

        Scans *data* for a 256-byte window whose values match the
        standard AES S-box with at least *threshold* fraction of
        matching entries.

        Returns
        -------
        dict
            ``{"found": bool, "offset": int|None, "direction": "forward"|"inverse"|None,
               "match_ratio": float}``
        """
        if len(data) < 256:
            return {"found": False, "offset": None, "direction": None, "match_ratio": 0.0}

        sbox_fwd = cls._AES_SBOX
        # Build inverse S-box
        sbox_inv = [0] * 256
        for i, v in enumerate(sbox_fwd):
            sbox_inv[v] = i
        sbox_inv_t = tuple(sbox_inv)

        best: dict = {"found": False, "offset": None, "direction": None, "match_ratio": 0.0}

        raw = bytes(data) if not isinstance(data, bytes) else data
        for off in range(len(raw) - 255):
            window = raw[off:off + 256]
            fwd_hits = sum(1 for i in range(256) if window[i] == sbox_fwd[i])
            inv_hits = sum(1 for i in range(256) if window[i] == sbox_inv_t[i])
            ratio = max(fwd_hits, inv_hits) / 256
            if ratio > best["match_ratio"]:
                best = {
                    "found": ratio >= threshold,
                    "offset": off,
                    "direction": "forward" if fwd_hits >= inv_hits else "inverse",
                    "match_ratio": ratio,
                }
            if ratio >= threshold:
                break  # early exit on first above-threshold match
        return best

    # -- B71: RC4 key-schedule recovery --------------------------------------

    @staticmethod
    def recover_rc4_key(
        initial_sbox: list[int] | bytes,
        key_length: int,
    ) -> SolverResult:
        """Recover an RC4 key from a captured S-box state after KSA.

        Given the 256-byte S-box state produced by RC4 Key Scheduling
        Algorithm (KSA) and the known *key_length*, finds the key bytes.

        For short keys (≤ 3 bytes) uses exhaustive search; for longer
        keys uses a heuristic partial-KSA inversion.

        Parameters
        ----------
        initial_sbox:
            256-byte S-box after KSA (before any PRGA).
        key_length:
            Known or suspected length of the RC4 key.

        Returns
        -------
        SolverResult
            With ``model["key_0"]`` … ``model[f"key_{key_length-1}"]``.
        """
        if len(initial_sbox) != 256:
            return SolverResult(satisfiable=False, error="S-box must be 256 bytes")
        if key_length < 1 or key_length > 256:
            return SolverResult(satisfiable=False, error="key_length must be 1..256")

        target = list(initial_sbox)

        def _ksa(key: bytes) -> list[int]:
            S = list(range(256))
            j = 0
            for i in range(256):
                j = (j + S[i] + key[i % len(key)]) % 256
                S[i], S[j] = S[j], S[i]
            return S

        # Brute-force for short keys (≤ 3 bytes → ≤ 16M candidates)
        if key_length <= 3:
            limit = 256 ** key_length
            for candidate_int in range(limit):
                key_bytes = candidate_int.to_bytes(key_length, "big")
                if _ksa(key_bytes) == target:
                    model = {f"key_{i}": b for i, b in enumerate(key_bytes)}
                    return SolverResult(satisfiable=True, model=model)
            return SolverResult(satisfiable=False, error="no matching RC4 key found")

        # For longer keys: partial inversion heuristic.
        # Invert KSA step-by-step from round 0, recovering key[i%kl].
        # This works when the S-box hasn't been too permuted.
        S = list(range(256))
        j = 0
        key_candidates = [0] * key_length
        for i in range(256):
            # We know S[i] at this point.  The target tells us what
            # S[i] was swapped to eventually, but we can greedily try
            # to find j such that after swap, the S-box converges.
            needed_j = (target[i] - S[i] - j) % 256  # heuristic
            # Not exact — fall back to unknown
            key_candidates[i % key_length] = (needed_j - j - S[i]) % 256
            # Do the forward KSA step
            j_new = (j + S[i] + key_candidates[i % key_length]) % 256
            S[i], S[j_new] = S[j_new], S[i]
            j = j_new

        # Verify
        if _ksa(bytes(key_candidates)) == target:
            model = {f"key_{i}": v for i, v in enumerate(key_candidates)}
            return SolverResult(satisfiable=True, model=model)

        return SolverResult(satisfiable=False, error="RC4 key recovery heuristic failed")

    # -- B72: Cipher-type auto-detection -------------------------------------

    # Well-known constant signatures for common ciphers.
    _CIPHER_SIGNATURES: Dict[str, tuple[tuple[int, ...], str]] = {
        "aes_sbox_fwd": (
            (0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5),
            "AES (forward S-box)",
        ),
        "aes_sbox_inv": (
            (0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38),
            "AES (inverse S-box)",
        ),
        "aes_rcon": (
            (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80),
            "AES (round constants / Rcon)",
        ),
        "des_ip": (
            (58, 50, 42, 34, 26, 18, 10, 2),
            "DES (initial permutation)",
        ),
        "des_sbox1": (
            (14, 4, 13, 1, 2, 15, 11, 8),
            "DES (S-box 1)",
        ),
        "sha256_k_first8": (
            (0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
             0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5),
            "SHA-256 (round constants K)",
        ),
        "rc4_identity_sbox": (
            tuple(range(8)),
            "RC4 (identity S-box initialisation)",
        ),
        "tea_delta": (
            (0x9E, 0x37, 0x79, 0xB9),
            "TEA/XTEA (delta constant 0x9E3779B9)",
        ),
    }

    @classmethod
    def detect_cipher_type(
        cls,
        data: bytes | list[int],
        *,
        min_match_bytes: int = 4,
    ) -> List[Dict[str, Any]]:
        """Auto-detect cipher type(s) by scanning for known constants.

        Searches *data* for well-known S-boxes, permutation tables,
        and magic constants from common ciphers (AES, DES, SHA-256,
        RC4, TEA).

        Parameters
        ----------
        data:
            Raw binary blob to scan.
        min_match_bytes:
            Minimum consecutive matching bytes to report a hit.

        Returns
        -------
        list[dict]
            ``[{cipher, description, offset, match_length}]``
            sorted by match length descending.
        """
        raw = bytes(data) if not isinstance(data, bytes) else data
        hits: List[Dict[str, Any]] = []

        for sig_name, (sig_bytes, description) in cls._CIPHER_SIGNATURES.items():
            # Try byte-level matching (for 8-bit signatures)
            if all(b < 256 for b in sig_bytes):
                needle = bytes(sig_bytes)
                idx = raw.find(needle)
                if idx >= 0:
                    hits.append({
                        "cipher": sig_name,
                        "description": description,
                        "offset": idx,
                        "match_length": len(needle),
                    })
                    continue

            # Try 32-bit word matching (for SHA-256 K constants etc.)
            if all(b >= 256 for b in sig_bytes):
                for endian in ("big", "little"):
                    needle = b"".join(
                        v.to_bytes(4, endian) for v in sig_bytes
                    )
                    idx = raw.find(needle)
                    if idx >= 0:
                        hits.append({
                            "cipher": sig_name,
                            "description": description,
                            "offset": idx,
                            "match_length": len(needle),
                        })
                        break

        # Also run the AES S-box detector for full-table matches
        aes_result = cls.detect_aes_sbox(data)
        if aes_result["found"]:
            hits.append({
                "cipher": f"aes_sbox_{aes_result['direction']}",
                "description": f"AES {aes_result['direction']} S-box (full table)",
                "offset": aes_result["offset"],
                "match_length": 256,
            })

        hits.sort(key=lambda h: h["match_length"], reverse=True)
        return hits
