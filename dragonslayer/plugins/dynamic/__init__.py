"""
Stage 4 — Dynamic Analysis Plugins
===================================

Ported from Metroplex ``repos/stage4/``.  Each plugin wraps a heavy
third-party tool (angr, Triton, Qiling, …) behind the :class:`Plugin`
interface.

All imports are guarded so the package loads even when the underlying
library is not installed — :meth:`Plugin.available` returns ``False``
in that case.
"""
