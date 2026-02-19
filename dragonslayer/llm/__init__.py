"""
VMDragonSlayer LLM Module
=========================

LLM-assisted binary analysis using `litellm` as the universal model
gateway.  Supports OpenAI, Anthropic, Ollama, Azure, Bedrock, and
every other provider litellm wraps — configurable via
``vmdragonslayer.yml`` or environment variables.

Key classes
-----------
* :class:`LLMAnalyzer` — stateless helper that turns structured analysis
  data into LLM prompts and returns structured guidance.
* :func:`get_llm_analyzer` — module-level singleton accessor.
"""

from __future__ import annotations

from .analyzer import LLMAnalyzer, get_llm_analyzer, reset_llm_analyzer

__all__ = ["LLMAnalyzer", "get_llm_analyzer", "reset_llm_analyzer"]
