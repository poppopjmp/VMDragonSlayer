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

Handler disassembly / trace:
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

Obfuscated structure:
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
                # Strip markdown code fences if present
                if content.startswith("```"):
                    lines = content.split("\n")
                    # Remove first line (```json) and last (```)
                    lines = [l for l in lines if not l.strip().startswith("```")]
                    content = "\n".join(lines)
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    logger.warning("LLM returned non-JSON; wrapping raw text")
                    return {"raw": content}
            return {"raw": content}

        except Exception as exc:
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
        """
        prompt = _HANDLER_CLASSIFICATION_PROMPT.format(
            handler_data=handler_data,
            context=context or "No additional context.",
        )
        return self._complete(_SYSTEM_PROMPT, prompt)

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
    except Exception:
        _analyzer = LLMAnalyzer(**kwargs)

    return _analyzer
