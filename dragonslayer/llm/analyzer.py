"""
LLM-Assisted Analysis Engine
=============================

Uses ``litellm`` to access any LLM provider (OpenAI, Anthropic, Ollama,
Azure, etc.) for:

1. **Handler Classification** — classify VM bytecode handler semantics
   (arithmetic, memory, branch, stack, …).
2. **Deobfuscation Hints** — given opaque predicates or control-flow
   flattening, suggest simplifications.
3. **Pattern Explanation** — natural-language explanation of matched
   byte patterns.
4. **Code Recovery** — reconstruct high-level pseudocode from lifted IR
   or instruction traces.
5. **Analysis Summarisation** — combine multi-stage results into an
   actionable narrative report.

Configuration (``vmdragonslayer.yml``)::

    llm:
      model: "ollama/llama3"        # any litellm model string
      api_base: "http://localhost:11434"
      temperature: 0.2
      max_tokens: 4096
      timeout: 60
      enabled: true

Or via environment variables::

    LITELLM_MODEL=gpt-4o
    OPENAI_API_KEY=sk-...

    LITELLM_MODEL=ollama/llama3
    OLLAMA_API_BASE=http://localhost:11434
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy litellm import (optional dependency)
# ---------------------------------------------------------------------------

_litellm = None
_LITELLM_AVAILABLE = False


def _ensure_litellm():
    global _litellm, _LITELLM_AVAILABLE
    if _litellm is not None:
        return _LITELLM_AVAILABLE
    try:
        import litellm as _ll
        _litellm = _ll
        _LITELLM_AVAILABLE = True
        # Suppress litellm's noisy logger unless user wants it
        logging.getLogger("LiteLLM").setLevel(logging.WARNING)
    except ImportError:
        _LITELLM_AVAILABLE = False
    return _LITELLM_AVAILABLE


# ---------------------------------------------------------------------------
# LLM → canonical category normalisation
# ---------------------------------------------------------------------------
# The LLM system prompt uses 13 fine-grained categories for better prompting
# accuracy, but the rest of the pipeline (ML model, tests, pipeline stages)
# uses 10 canonical categories from ml.model.HANDLER_CATEGORIES.  This map
# collapses the LLM's labels into the canonical set.

_LLM_TO_CANONICAL: Dict[str, str] = {
    # identity mappings
    "arithmetic": "arithmetic",
    "nop": "nop",
    "unknown": "unknown",
    # renames
    "logic": "bitwise",
    "context_switch": "vm_control",
    # merges
    "memory_read": "memory",
    "memory_write": "memory",
    "stack_push": "stack",
    "stack_pop": "stack",
    "branch_conditional": "control_flow",
    "branch_unconditional": "control_flow",
    "call": "control_flow",
    "return": "control_flow",
}


def _normalize_llm_category(category: str) -> str:
    """Map an LLM-returned category to the canonical handler taxonomy."""
    return _LLM_TO_CANONICAL.get(category, category)


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are an expert binary reverse-engineer specialising in virtual-machine \
based obfuscation (VMProtect, Themida, Code Virtualizer).  You analyse \
disassembly traces, byte patterns, control-flow graphs, and taint maps \
to help deobfuscate protected binaries.  Be precise and technical.  \
When classifying handlers, use these categories: arithmetic, logic, \
memory_read, memory_write, stack_push, stack_pop, branch_conditional, \
branch_unconditional, call, return, nop, context_switch, unknown."""

_HANDLER_CLASSIFICATION_PROMPT = """\
Classify the following VM bytecode handler.  Return a JSON object with keys:
  category    – one of the categories listed in the system prompt
  confidence  – float 0..1
  explanation – one-sentence reasoning
  simplified  – pseudo-C equivalent (or "unknown")

Here are several examples of correct classification:

Example 1 — arithmetic handler:
```
mov eax, [esi]       ; fetch operand from VM bytecode
add [ebp], eax       ; add to top of virtual stack
add esi, 4           ; advance virtual IP
jmp dword [edi]      ; dispatch next handler
```
Result:
{{"category": "arithmetic", "confidence": 0.95, "explanation": "Fetches a 32-bit operand from the bytecode stream and adds it to the virtual stack top, characteristic of a vADD handler.", "simplified": "vSP[0] += bytecode[vIP]; vIP += 4;"}}

Example 2 — stack_push handler:
```
sub ebp, 4           ; grow virtual stack
movzx eax, byte [esi]; fetch 1-byte immediate
mov [ebp], eax       ; push value onto virtual stack
inc esi              ; advance vIP by 1
jmp dword [edi]
```
Result:
{{"category": "stack_push", "confidence": 0.92, "explanation": "Pushes an 8-bit immediate from the bytecode stream onto the virtual stack.", "simplified": "vSP -= 4; vSP[0] = (uint32_t)bytecode[vIP]; vIP += 1;"}}

Example 3 — branch_conditional handler:
```
mov eax, [ebp]       ; pop condition from virtual stack
add ebp, 4
mov ecx, [esi]       ; fetch branch offset
test eax, eax
cmovnz esi, ecx      ; if condition != 0, jump
jmp dword [edi]
```
Result:
{{"category": "branch_conditional", "confidence": 0.90, "explanation": "Pops a condition value and conditionally updates vIP, implementing a virtual conditional branch (vJNZ).", "simplified": "cond = vSP[0]; vSP += 4; if (cond) vIP = offset;"}}

Now classify this handler:
```
{handler_data}
```

Additional context (patterns matched, taint info):
{context}
"""

_DEOBFUSCATION_HINT_PROMPT = """\
The following control-flow structure appears to be obfuscated \
(opaque predicates, flattened control flow, or handler dispatch).  \
Suggest concrete simplifications.  Return a JSON object with keys:
  technique_detected – name of the obfuscation technique
  simplification     – step-by-step simplification approach
  confidence         – float 0..1

Here are examples:

Example 1 — opaque predicate:
```
mov eax, ecx
imul eax, ecx        ; eax = ecx^2
and eax, 1           ; x^2 mod 2
jnz 0xDEAD           ; always falls through (x^2 is always even for even x)
```
Result:
{{"technique_detected": "opaque_predicate", "simplification": "1. Recognise x*x is always >= 0. 2. x^2 mod 2 == (x mod 2)^2 mod 2. 3. For all x, this predicate is constant at runtime. 4. Replace with NOP (always falls through).", "confidence": 0.88}}

Example 2 — control-flow flattening:
```
entry:
  mov [state_var], 0x1A
dispatcher:
  mov eax, [state_var]
  cmp eax, 0x1A ; jz block_A
  cmp eax, 0x2B ; jz block_B
  ...
block_A:
  <real code>
  mov [state_var], 0x2B
  jmp dispatcher
```
Result:
{{"technique_detected": "control_flow_flattening", "simplification": "1. Identify the dispatcher variable ([state_var]). 2. Trace all assignments to state_var to recover block order. 3. Build a map: {{0x1A: block_A, 0x2B: block_B, ...}}. 4. Relink blocks in original order, removing dispatcher.", "confidence": 0.92}}

Now analyse this structure:
```
{structure}
```

Known indicators:
{indicators}
"""

_PATTERN_EXPLANATION_PROMPT = """\
Explain what the following byte-pattern match means in the context \
of VM-based obfuscation.  Be specific about which packer or protector \
likely produced it.

Pattern: {pattern_name} ({pattern_id})
Matched bytes: {matched_bytes}
Offset: {offset}
Handler type: {handler_type}
Architecture: {architecture}

Example:
Pattern: vmp_dispatcher_entry (vmp-dispatch-001)
Matched bytes: 55 8b ec 83 e4 f8 81 ec
Offset: 0x401000
Handler type: dispatcher
Architecture: x86

Result:
{{"explanation": "This is a VMProtect dispatcher entry prologue. The sequence 'push ebp; mov ebp,esp; and esp,-8; sub esp,...' sets up a stack frame with 8-byte alignment, typical of VMProtect's VM entry stub that transitions from native code to virtualised execution.", "packer": "VMProtect", "purpose": "VM entry — initialises the virtual machine context and prepares the virtual stack before dispatching the first handler.", "confidence": 0.88}}

Now explain this pattern:
Provide a JSON object:
  explanation  – 2-3 sentence description
  packer       – most likely packer name
  purpose      – what this pattern accomplishes
  confidence   – float 0..1
"""

_CODE_RECOVERY_PROMPT = """\
Given the following lifted IR / instruction trace from a VM-protected \
binary, reconstruct the most likely high-level pseudocode.

Lifted instructions:
```
{instructions}
```

Taint analysis results:
{taint_info}

Symbolic constraints:
{constraints}

Example — a VM trace that implements memcpy:
Instructions:
```
vPUSH [vSP+0x08]    ; src ptr
vPUSH [vSP+0x10]    ; dst ptr
vPUSH [vSP+0x18]    ; count
vLOAD_BYTE           ; load *src
vSTORE_BYTE          ; store *dst
vINC src             ; src++
vINC dst             ; dst++
vDEC count           ; count--
vJNZ loop            ; if count != 0, loop
```
Result:
{{"pseudocode": "void vm_memcpy(void *dst, void *src, size_t n) {{\\n    while (n--) *dst++ = *src++;\\n}}", "confidence": 0.85, "assumptions": ["Loop body is a single-byte copy", "Pointers are incremented post-copy"]}}

Now reconstruct the code for:
Return a JSON object:
  pseudocode  – reconstructed C-like pseudocode
  confidence  – float 0..1
  assumptions – list of assumptions made
"""

_SUMMARISE_PROMPT = """\
Summarise the following multi-stage binary analysis results into a \
concise, actionable report.  Focus on:
  1. VM protector identification (name, version if possible)
  2. Key findings from each analysis stage
  3. Recommended next steps for deobfuscation
  4. Overall risk / complexity assessment

Analysis results:
{results_json}

Return a JSON object:
  summary          – 3-5 sentence executive summary
  protector        – identified protector name or "unknown"
  key_findings     – list of finding strings
  recommendations  – list of actionable next steps
  complexity       – "low" | "medium" | "high" | "extreme"
  confidence       – float 0..1
"""


# ---------------------------------------------------------------------------
# LLMAnalyzer
# ---------------------------------------------------------------------------


class LLMAnalyzer:
    """
    Stateless LLM assistant for binary deobfuscation analysis.

    Parameters
    ----------
    model : str
        Any ``litellm``-compatible model identifier
        (``"gpt-4o"``, ``"ollama/llama3"``, ``"anthropic/claude-sonnet-4-20250514"``, …).
    api_base : str | None
        Override API base URL (needed for Ollama, vLLM, etc.).
    temperature : float
        Sampling temperature.
    max_tokens : int
        Maximum completion length.
    timeout : float
        Request timeout in seconds.
    """

    def __init__(
        self,
        model: str | None = None,
        api_base: str | None = None,
        temperature: float = 0.2,
        max_tokens: int = 4096,
        timeout: float = 60,
        enabled: bool = True,
    ) -> None:
        self.model = model or os.getenv("LITELLM_MODEL", "ollama/llama3")
        self.api_base = api_base or os.getenv("OLLAMA_API_BASE")
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.enabled = enabled
        self._available: bool | None = None

    # -- availability -------------------------------------------------------

    @property
    def available(self) -> bool:
        """Check if litellm is importable and the model is reachable."""
        if not self.enabled:
            return False
        if self._available is not None:
            return self._available
        self._available = _ensure_litellm()
        return self._available

    # -- core completion wrapper --------------------------------------------

    def _complete(
        self,
        system: str,
        user: str,
        response_format: str = "json",
    ) -> Dict[str, Any]:
        """Send a chat completion and parse the response as JSON."""
        if not self.available:
            return {"error": "LLM not available", "raw": ""}

        kwargs: Dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "timeout": self.timeout,
        }
        if self.api_base:
            kwargs["api_base"] = self.api_base

        try:
            response = _litellm.completion(**kwargs)
            content = response.choices[0].message.content.strip()

            # Try to parse as JSON
            if response_format == "json":
                # Strip markdown code fences if present (```json ... ```)
                content = re.sub(
                    r"^\s*```(?:json)?\s*\n?", "", content,
                )
                content = re.sub(
                    r"\n?\s*```\s*$", "", content,
                )
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    logger.warning("LLM returned non-JSON; wrapping raw text")
                    return {"raw": content}
            return {"raw": content}

        except (ConnectionError, ValueError, TypeError, RuntimeError, OSError, TimeoutError, KeyError) as exc:
            logger.warning("LLM completion failed: %s", exc)
            return {"error": str(exc), "raw": ""}

    # -- public analysis methods --------------------------------------------

    def classify_handler(
        self,
        handler_data: str,
        context: str = "",
    ) -> Dict[str, Any]:
        """
        Classify a VM bytecode handler's semantics.

        Returns ``{category, confidence, explanation, simplified}``.
        The ``category`` value is normalised to the canonical 10-label
        taxonomy defined by :data:`ml.model.HANDLER_CATEGORIES`.
        """
        prompt = _HANDLER_CLASSIFICATION_PROMPT.format(
            handler_data=handler_data,
            context=context or "No additional context.",
        )
        result = self._complete(_SYSTEM_PROMPT, prompt)
        # Normalise LLM's fine-grained categories → canonical taxonomy
        if isinstance(result, dict) and "category" in result:
            result["category"] = _normalize_llm_category(result["category"])
        return result

    def suggest_deobfuscation(
        self,
        structure: str,
        indicators: str = "",
    ) -> Dict[str, Any]:
        """
        Suggest deobfuscation strategies for an obfuscated structure.

        Returns ``{technique_detected, simplification, confidence}``.
        """
        prompt = _DEOBFUSCATION_HINT_PROMPT.format(
            structure=structure,
            indicators=indicators or "None provided.",
        )
        return self._complete(_SYSTEM_PROMPT, prompt)

    def explain_pattern(
        self,
        pattern_name: str,
        pattern_id: str,
        matched_bytes: str,
        offset: int,
        handler_type: str = "",
        architecture: str = "",
    ) -> Dict[str, Any]:
        """
        Explain a matched byte pattern in context.

        Returns ``{explanation, packer, purpose, confidence}``.
        """
        prompt = _PATTERN_EXPLANATION_PROMPT.format(
            pattern_name=pattern_name,
            pattern_id=pattern_id,
            matched_bytes=matched_bytes,
            offset=offset,
            handler_type=handler_type or "unknown",
            architecture=architecture or "x86_64",
        )
        return self._complete(_SYSTEM_PROMPT, prompt)

    def recover_code(
        self,
        instructions: str,
        taint_info: str = "",
        constraints: str = "",
    ) -> Dict[str, Any]:
        """
        Reconstruct pseudocode from lifted IR / instruction traces.

        Returns ``{pseudocode, confidence, assumptions}``.
        """
        prompt = _CODE_RECOVERY_PROMPT.format(
            instructions=instructions,
            taint_info=taint_info or "Not available.",
            constraints=constraints or "Not available.",
        )
        return self._complete(_SYSTEM_PROMPT, prompt)

    def summarise_analysis(
        self,
        results: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Summarise multi-stage analysis results into an actionable report.

        Returns ``{summary, protector, key_findings, recommendations,
        complexity, confidence}``.
        """
        # Truncate to avoid token overflow
        results_json = json.dumps(results, indent=2, default=str)
        if len(results_json) > 30000:
            results_json = results_json[:30000] + "\n... [truncated]"

        prompt = _SUMMARISE_PROMPT.format(results_json=results_json)
        return self._complete(_SYSTEM_PROMPT, prompt)

    def ask(
        self,
        question: str,
        context: str = "",
    ) -> Dict[str, Any]:
        """
        Free-form question about a binary / analysis results.

        Returns ``{raw: "..."}``.
        """
        user_prompt = question
        if context:
            user_prompt = f"Context:\n{context}\n\nQuestion:\n{question}"
        return self._complete(_SYSTEM_PROMPT, user_prompt, response_format="text")


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_analyzer: LLMAnalyzer | None = None


def reset_llm_analyzer() -> None:
    """Reset the module-level singleton (useful for testing / config reload)."""
    global _analyzer
    _analyzer = None


def get_llm_analyzer(**kwargs: Any) -> LLMAnalyzer:
    """
    Return the module-level :class:`LLMAnalyzer` singleton.

    On first call, reads config from ``get_config().llm.*`` and merges
    with provided **kwargs**.
    """
    global _analyzer
    if _analyzer is not None:
        return _analyzer

    # Try to merge config
    try:
        from ..core.config import get_config
        cfg = get_config()
        defaults = {
            "model": cfg.get("llm.model"),
            "api_base": cfg.get("llm.api_base"),
            "temperature": cfg.get("llm.temperature", 0.2),
            "max_tokens": cfg.get("llm.max_tokens", 4096),
            "timeout": cfg.get("llm.timeout", 60),
            "enabled": cfg.get("llm.enabled", True),
        }
        # Filter out None values from config
        defaults = {k: v for k, v in defaults.items() if v is not None}
        defaults.update(kwargs)
        _analyzer = LLMAnalyzer(**defaults)
    except (ValueError, TypeError, KeyError, RuntimeError, OSError):
        _analyzer = LLMAnalyzer(**kwargs)

    return _analyzer
