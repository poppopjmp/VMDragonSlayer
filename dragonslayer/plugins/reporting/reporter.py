"""
Markdown Report Generator
==========================

Ported from ``repos/stage6/working/reporter/reporter.py``.

Aggregates results from all plugins in ``PluginContext.shared_data``
and produces a structured Markdown report.  Optionally enriches the
report via an Ollama LLM.

Dependencies: ``requests`` (optional, for Ollama enrichment).
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from typing import Any, cast

from .. import Plugin, PluginContext, PluginResult, Stage, register_plugin

logger = logging.getLogger(__name__)

_HAS_REQUESTS = False
try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    pass


# ── Helpers ───────────────────────────────────────────────────────────────


def _get_nested(data: Any, *keys: str) -> Any:
    for key in keys:
        if isinstance(data, dict):
            data = data.get(key)
        else:
            return None
    return data


def _file_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── Report generation ─────────────────────────────────────────────────────


def generate_markdown(
    sample_id: str,
    plugins_data: dict[str, Any],
    file_size: int = 0,
    file_type: str = "Unknown",
) -> str:
    """Build a structured Markdown report from aggregated plugin data."""

    def _get(name: str) -> dict[str, Any]:
        return cast("dict[str, Any]", plugins_data.get(name, {}))

    # --- Hashes ---
    fileinfo = _get("fileinfo")
    vt_data = _get("virustotal")
    sha256 = (
        _get_nested(fileinfo, "sha256")
        or _get_nested(vt_data, "sha256")
        or sample_id
    )
    md5 = _get_nested(fileinfo, "md5") or _get_nested(vt_data, "md5") or ""
    sha1 = _get_nested(fileinfo, "sha1") or _get_nested(vt_data, "sha1") or ""

    # --- AV detections (from individual AV plugin results) ---
    av_names = [
        "avast", "avg", "avira", "bitdefender", "clamav", "comodo",
        "drweb", "eset", "fsecure", "kaspersky", "mcafee", "sophos",
        "windows-defender", "zoner", "fprot", "escan",
    ]
    av_results: list[dict[str, str]] = []
    for av in av_names:
        res = _get(av)
        if isinstance(res, dict):
            infected = res.get("infected")
            if isinstance(infected, str):
                infected = infected.lower() == "true"
            result_name = res.get("result", "")
            if infected or (result_name and str(result_name).lower() not in ("none", "clean", "null", "")):
                av_results.append({
                    "vendor": av.capitalize(),
                    "detection": str(result_name) or "Detected",
                    "engine": str(res.get("engine", "N/A")),
                    "updated": str(res.get("updated", "N/A")),
                })

    # VT scans
    if vt_data and "scans" in vt_data:
        for vendor, res in vt_data["scans"].items():
            if res.get("detected"):
                av_results.append({
                    "vendor": f"{vendor} (VT)",
                    "detection": str(res.get("result", "")),
                    "engine": str(res.get("version", "N/A")),
                    "updated": str(res.get("update", "N/A")),
                })

    # --- Similarity ---
    similarity_data = _get("similarity")
    ssdeep_hash = _get_nested(similarity_data, "ssdeep") or ""
    imphash = _get_nested(similarity_data, "imphash") or ""

    # --- YARA ---
    yara_data = _get("yara") or _get("strelka")
    yara_matches: list[str] = []
    if isinstance(yara_data, dict):
        for m in yara_data.get("matches", []):
            if isinstance(m, dict):
                rule = m.get("rule") or m.get("Rule") or m.get("name")
                if rule:
                    yara_matches.append(str(rule))
            elif isinstance(m, str):
                yara_matches.append(m)

    # --- Strings (from frankenstrings or floss) ---
    strings: list[str] = []
    franken = _get("frankenstrings")
    floss = _get("floss")
    if floss and "strings" in floss:
        strings = floss["strings"][:100]
    elif franken:
        fs = franken.get("strings", {})
        if isinstance(fs, dict):
            strings = fs.get("ascii", [])[:50] + fs.get("unicode", [])[:50]
        elif isinstance(fs, list):
            strings = fs[:100]

    # --- PE info ---
    pe_data = _get("pe_analyzer") or _get("pe-analyzer") or _get("strelka")
    sections: list[str] = []
    imports_summary: list[str] = []
    if isinstance(pe_data, dict):
        pe_inner = pe_data.get("pe", pe_data)  # strelka wraps in .pe
        for sec in pe_inner.get("sections", []):
            name = sec.get("Name") or sec.get("name")
            if name:
                sections.append(str(name))
        imps = pe_inner.get("imports", {})
        if isinstance(imps, dict):
            for dll, funcs in imps.items():
                imports_summary.append(f"{dll}: {len(funcs)} functions")
        elif isinstance(imps, list):
            for imp in imps:
                if isinstance(imp, dict):
                    dll = imp.get("dll") or imp.get("name", "")
                    count = len(imp.get("functions", imp.get("imports", [])) or [])
                    imports_summary.append(f"{dll}: {count} functions")

    # --- Network ---
    network = _get("network_graph") or {}
    domains = network.get("domains", [])

    # --- IOCs from frankenstrings ---
    iocs = franken.get("iocs", {}) if franken else {}
    if not domains and "domain" in iocs:
        domains = iocs["domain"]
    urls = iocs.get("url", [])
    ips = [ip for ip in iocs.get("ip", []) if ip not in ("1.0.0.0", "6.0.0.0", "127.0.0.1", "0.0.0.0")]  # noqa: S104  (filter list, not a bind address)

    # --- Dynamic analysis summary ---
    angr_data = _get("angr")
    triton_data = _get("triton")
    qiling_data = _get("qiling")
    blackfyre_data = _get("blackfyre")

    # =====================================================================
    # Build Markdown
    # =====================================================================
    md = f"# Malware Analysis Report: {sample_id}\n\n"

    # 1. Executive Summary
    md += "## 1. Executive Summary\n"
    md += f"- **Sample ID:** {sample_id}\n"
    md += f"- **File Type:** {file_type}\n"
    md += f"- **File Size:** {file_size} bytes\n"
    verdict = "**Malicious**" if av_results or yara_matches else "Undetermined"
    md += f"- **Verdict:** {verdict}\n"
    if av_results:
        md += f"- **Detection Count:** {len(av_results)}\n"
    md += "\n"

    # 2. Identification
    md += "## 2. Identification\n"
    md += "| Algorithm | Hash |\n|---|---|\n"
    md += f"| MD5 | `{md5 or 'N/A'}` |\n"
    md += f"| SHA1 | `{sha1 or 'N/A'}` |\n"
    md += f"| SHA256 | `{sha256}` |\n\n"

    # 3. AV Detections
    md += "## 3. Antivirus Detections\n"
    if av_results:
        md += "| Vendor | Detection | Engine | Updated |\n|---|---|---|---|\n"
        for r in av_results:
            md += f"| {r['vendor']} | `{r['detection']}` | {r['engine']} | {r['updated']} |\n"
    else:
        md += "No detections found in available plugins.\n"
    md += "\n"

    # 4. Similarity
    md += "## 4. Similarity\n"
    md += "| Algorithm | Hash |\n|---|---|\n"
    md += f"| SSDeep | `{ssdeep_hash or 'N/A'}` |\n"
    md += f"| ImpHash | `{imphash or 'N/A'}` |\n\n"

    # 5. YARA
    md += "## 5. YARA Rules\n"
    if yara_matches:
        for rule in yara_matches:
            md += f"- `{rule}`\n"
    else:
        md += "No YARA rules matched.\n"
    md += "\n"

    # 6. Static Analysis
    md += "## 6. Static Analysis\n"
    if sections:
        md += "### Sections\n"
        md += ", ".join(f"`{s}`" for s in sections) + "\n\n"
    if imports_summary:
        md += "### Imports\n"
        for imp in imports_summary[:10]:
            md += f"- {imp}\n"
        if len(imports_summary) > 10:
            md += f"- … and {len(imports_summary) - 10} more DLLs\n"
        md += "\n"
    if strings:
        md += "### Interesting Strings\n```text\n"
        for s in strings[:20]:
            if isinstance(s, str) and 4 < len(s) < 100:
                md += f"{s}\n"
        md += "```\n"

    # 7. Dynamic Analysis
    dynamic_sections: list[str] = []
    if isinstance(angr_data, dict) and angr_data.get("function_count"):
        dynamic_sections.append(
            f"- **angr:** {angr_data['function_count']} functions, "
            f"{angr_data.get('total_blocks', 0)} blocks"
        )
    if isinstance(triton_data, dict) and triton_data.get("instructions_executed"):
        dynamic_sections.append(
            f"- **Triton:** {triton_data['instructions_executed']} instructions executed"
        )
    if isinstance(qiling_data, dict) and qiling_data.get("unique_blocks"):
        dynamic_sections.append(
            f"- **Qiling:** {qiling_data['unique_blocks']} unique blocks emulated"
        )
    if isinstance(blackfyre_data, dict) and blackfyre_data.get("function_count"):
        dynamic_sections.append(
            f"- **Blackfyre:** {blackfyre_data['function_count']} functions extracted"
        )

    if dynamic_sections:
        md += "## 7. Dynamic Analysis\n"
        md += "\n".join(dynamic_sections) + "\n\n"

    # ── VM Deobfuscation Analysis ──────────────────────────────────────
    vm_info = plugins_data.get("vm_discovery", {})
    taint_results = plugins_data.get("taint_results", {})
    symex_results = plugins_data.get("symbolic_execution", {})
    dispatcher_results = plugins_data.get("dispatcher_analysis", {})

    has_vm = vm_info.get("vm_detected") or vm_info.get("protector_name")
    if has_vm or dispatcher_results or taint_results:
        md += "## VM Deobfuscation Analysis\n\n"

        # --- Protector identification ---
        if vm_info:
            protector = vm_info.get("protector_name") or vm_info.get("vm_type") or "Unknown"
            confidence = vm_info.get("confidence", 0)
            md += "### Protector Identification\n"
            md += f"- **Protector:** {protector}\n"
            if confidence:
                md += f"- **Confidence:** {confidence:.0%}\n"
            dispatchers = vm_info.get("dispatchers") or vm_info.get("dispatcher_addresses", [])
            if dispatchers:
                md += f"- **Dispatcher addresses:** {', '.join(f'`0x{d:x}`' if isinstance(d, int) else f'`{d}`' for d in dispatchers)}\n"
            sigs = vm_info.get("signatures_matched", [])
            if sigs:
                md += f"- **Signatures matched:** {len(sigs)}\n"
            md += "\n"

        # --- Dispatcher / handler table ---
        if dispatcher_results:
            dt = dispatcher_results.get("dispatch_table", {})
            handlers = dt.get("handlers", []) if isinstance(dt, dict) else []
            md += "### Dispatcher & Handler Table\n"
            dispatchers_found = dispatcher_results.get("dispatchers", [])
            if dispatchers_found:
                md += f"- **Dispatchers found:** {len(dispatchers_found)}\n"
                for d in dispatchers_found[:5]:
                    addr = d.get("address", 0) if isinstance(d, dict) else d
                    md += f"  - `0x{addr:x}`\n" if isinstance(addr, int) else f"  - `{addr}`\n"
            if handlers:
                md += f"- **Handlers identified:** {len(handlers)}\n"
                md += "\n| Opcode | Address | Size |\n|---|---|---|\n"
                for h in handlers[:30]:
                    opc = h.get("opcode", "?")
                    addr = h.get("address", 0)
                    size = h.get("size", "?")
                    md += f"| `0x{opc:02x}` | `0x{addr:x}` | {size} |\n" if isinstance(opc, int) and isinstance(addr, int) else f"| `{opc}` | `{addr}` | {size} |\n"
            md += "\n"

        # --- Symbolic execution results ---
        if symex_results:
            md += "### Symbolic Execution\n"
            paths = symex_results.get("paths_explored", 0)
            opaques = symex_results.get("opaque_predicates", [])
            md += f"- **Paths explored:** {paths}\n"
            if opaques:
                md += f"- **Opaque predicates detected:** {len(opaques)}\n"
                for op in opaques[:10]:
                    addr = op.get("address", 0)
                    desc = op.get("description", op.get("type", ""))
                    md += f"  - `0x{addr:x}`: {desc}\n" if isinstance(addr, int) else f"  - {desc}\n"
            constraints = symex_results.get("constraints", [])
            if constraints:
                md += f"- **Symbolic constraints:** {len(constraints)}\n"
            md += "\n"

        # --- Taint analysis ---
        if taint_results:
            md += "### Taint Analysis\n"
            flow_summary = taint_results.get("data_flow_summary", {})
            vreg_map = taint_results.get("virtual_register_map", {})
            handler_boundaries = taint_results.get("handler_boundaries", [])
            mem_summary = taint_results.get("memory_taint_summary", {})

            if vreg_map:
                md += "**Virtual Register Mapping:**\n\n"
                md += "| Native Register | VM Role |\n|---|---|\n"
                for native, role in sorted(vreg_map.items()):
                    md += f"| `{native}` | {role} |\n"
                md += "\n"

            evt_counts = flow_summary.get("event_type_counts", {})
            if evt_counts:
                md += "**Taint Flow Statistics:**\n\n"
                for etype, count in sorted(evt_counts.items()):
                    md += f"- {etype}: {count}\n"
                md += "\n"

            if flow_summary.get("has_implicit_flow"):
                md += "> ⚠️ **Implicit control-flow taint detected** — tainted data affects branch decisions.\n\n"
            if flow_summary.get("has_memory_flow"):
                md += "> 📝 **Memory taint propagation detected** — tainted data flows through memory.\n\n"

            if handler_boundaries:
                md += f"**Handler boundaries detected:** {len(handler_boundaries)}\n"
                for hb in handler_boundaries[:15]:
                    addr = hb.get("address", 0)
                    ev = hb.get("evidence", "")
                    md += f"- `0x{addr:x}` ({ev})\n" if isinstance(addr, int) else f"- {addr} ({ev})\n"
                md += "\n"

            if mem_summary and mem_summary.get("tainted_locations", 0) > 0:
                md += f"**Tainted memory locations:** {mem_summary['tainted_locations']}\n\n"

    # 8. Network Indicators
    if domains or urls or ips:
        md += "## 8. Network Indicators\n"
        if domains:
            md += "### Domains\n"
            for d in domains:
                md += f"- `{d}`\n"
            md += "\n"
        if urls:
            md += "### URLs\n"
            for u in urls:
                md += f"- `{u}`\n"
            md += "\n"
        if ips:
            md += "### IPs\n"
            for ip in ips:
                md += f"- `{ip}`\n"
            md += "\n"

    # 9. Executed Plugins
    md += "## 9. Executed Plugins\n"
    for p in sorted(plugins_data.keys()):
        md += f"- {p}\n"
    md += "\n"

    return md


# ── Ollama enrichment ─────────────────────────────────────────────────────


def enrich_with_ollama(
    report: str,
    ollama_url: str = "http://localhost:11434",
    model: str = "deepseek-coder-v2",
) -> str | None:
    """Send the raw report to Ollama for MITRE ATT&CK mapping + enrichment."""
    if not _HAS_REQUESTS:
        return None

    prompt = (
        "You are an expert malware analyst. Enrich the following automated "
        "malware analysis report:\n\n"
        f"{report}\n\n"
        "Instructions:\n"
        "1. Preserve the original Markdown structure.\n"
        "2. Add a '## MITRE ATT&CK Mapping' section after the Executive Summary.\n"
        "3. Add a brief AI Evaluation subsection under Static Analysis.\n"
        "4. Do not fabricate data or alter hash values.\n"
        "5. Output ONLY the enriched Markdown report.\n"
    )
    payload = {"model": model, "prompt": prompt, "stream": False}
    try:
        resp = requests.post(f"{ollama_url}/api/generate", json=payload, timeout=600)
        resp.raise_for_status()
        return cast("str | None", resp.json().get("response", ""))
    except (ConnectionError, ValueError, TypeError, RuntimeError, OSError, TimeoutError) as exc:
        logger.warning("Ollama enrichment failed: %s", exc)
        return None


# ── Plugin ────────────────────────────────────────────────────────────────


@register_plugin
class ReporterPlugin(Plugin):
    """Aggregate all plugin data into a Markdown report."""

    name = "reporter"
    stage = Stage.REPORTING
    description = "Structured Markdown report with optional Ollama enrichment"

    def execute(
        self,
        file_path: str,
        file_data: bytes,
        context: PluginContext,
    ) -> PluginResult:
        t0 = time.monotonic()
        try:
            sample_id = context.sample_hash or _file_sha256(file_data)
            file_type = "Unknown"
            if file_data[:2] == b"MZ":
                file_type = "PE"
            elif file_data[:4] == b"\x7fELF":
                file_type = "ELF"

            report = generate_markdown(
                sample_id=sample_id,
                plugins_data=context.shared_data,
                file_size=len(file_data),
                file_type=file_type,
            )

            # Optional Ollama enrichment
            enable_ai = context.config.get("reporter.enable_ai", False)
            enriched = None
            if enable_ai:
                ollama_url = context.config.get("ollama.url", "http://localhost:11434")
                model = context.config.get("ollama.model", "deepseek-coder-v2")
                enriched = enrich_with_ollama(report, ollama_url, model)

            final_report = enriched or report

            # Save report if work_dir is available
            output_path = ""
            if context.work_dir:
                output_path = os.path.join(context.work_dir, f"{sample_id}_report.md")
                try:
                    with open(output_path, "w", encoding="utf-8") as f:
                        f.write(final_report)
                except OSError as exc:
                    logger.warning("Could not write report: %s", exc)
                    output_path = ""

            return self._make_result(
                success=True,
                data={
                    "report": final_report,
                    "output_path": output_path,
                    "enriched": enriched is not None,
                    "length": len(final_report),
                },
                duration=time.monotonic() - t0,
            )
        except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, OSError, IndexError) as exc:
            logger.exception("Reporter failed")
            return self._make_result(
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )
