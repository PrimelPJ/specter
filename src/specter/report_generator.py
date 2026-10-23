"""
Analysis report generator for malware samples.

Aggregates results from all Specter analysis modules into a structured
JSON dict and a self-contained HTML report suitable for analyst review
or SIEM ingest.
"""

from __future__ import annotations

import html
import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from specter.behavioral import BehaviorReport, BehaviorCategory
from specter.classifier import ClassificationResult, MalwareClass
from specter.entropy import SectionEntropyResult
from specter.fuzzy_hash import FuzzyDigest
from specter.network_extractor import NetworkExtractionResult, NetworkIndicator
from specter.pe_parser import PEFile
from specter.string_extractor import StringExtractionResult
from specter.yara_engine import YaraMatch


# ---------------------------------------------------------------------------
# Risk scorer
# ---------------------------------------------------------------------------

class RiskScorer:
    """
    Computes a 0–100 risk score by weighting evidence from all analysis
    modules. Higher weight components:
      - YARA rule hits (most specific signal)
      - Classification confidence
      - Behavioral indicators (suspicious API calls, injection, persistence)
      - Network IOC count
      - High-entropy sections (packing / encryption indicator)
    """

    # Maximum contribution per category (weights sum to 100)
    _YARA_MAX = 30
    _CLASS_MAX = 25
    _BEHAV_MAX = 25
    _NET_MAX = 10
    _ENTROPY_MAX = 10

    def score(
        self,
        yara_matches: List[YaraMatch],
        classification: Optional[ClassificationResult],
        behavior: Optional[BehaviorReport],
        network: Optional[NetworkExtractionResult],
        pe_entropy: Optional[List[SectionEntropyResult]],
    ) -> Tuple[int, Dict[str, int]]:
        """
        Return (total_score, breakdown_dict) where each key is a
        component name and the value is its contribution.
        """
        breakdown: Dict[str, int] = {}

        # YARA hits: up to 30 points, 5 per rule (capped)
        yara_score = min(len(yara_matches) * 5, self._YARA_MAX)
        breakdown["yara"] = yara_score

        # Classification confidence scaled by threat level
        if classification:
            level_multiplier = {
                "critical": 1.0,
                "high": 0.85,
                "medium": 0.60,
                "low": 0.30,
                "clean": 0.0,
            }.get(classification.threat_level.value, 0.5)
            class_score = round(classification.confidence * level_multiplier * self._CLASS_MAX)
            breakdown["classification"] = min(class_score, self._CLASS_MAX)
        else:
            breakdown["classification"] = 0

        # Behavioral indicators: weight by category severity
        if behavior:
            category_weight = {
                BehaviorCategory.PROCESS_INJECTION: 8,
                BehaviorCategory.PRIVILEGE_ESCALATION: 8,
                BehaviorCategory.PERSISTENCE: 6,
                BehaviorCategory.DEFENSE_EVASION: 6,
                BehaviorCategory.CREDENTIAL_ACCESS: 6,
                BehaviorCategory.COMMAND_AND_CONTROL: 5,
                BehaviorCategory.LATERAL_MOVEMENT: 5,
                BehaviorCategory.DATA_EXFILTRATION: 4,
                BehaviorCategory.FILE_SYSTEM: 2,
                BehaviorCategory.REGISTRY: 2,
                BehaviorCategory.NETWORK: 2,
                BehaviorCategory.CRYPTOGRAPHIC: 2,
                BehaviorCategory.ANTI_ANALYSIS: 4,
            }
            behav_raw = sum(
                category_weight.get(ind.category, 1)
                for ind in behavior.indicators
            )
            breakdown["behavioral"] = min(behav_raw, self._BEHAV_MAX)
        else:
            breakdown["behavioral"] = 0

        # Network IOCs: 1 point per indicator, capped at 10
        if network:
            breakdown["network"] = min(network.total_count, self._NET_MAX)
        else:
            breakdown["network"] = 0

        # Entropy: sections with entropy > 7.0 are likely packed/encrypted
        if pe_entropy:
            high_entropy = sum(1 for s in pe_entropy if s.entropy > 7.0)
            breakdown["entropy"] = min(high_entropy * 3, self._ENTROPY_MAX)
        else:
            breakdown["entropy"] = 0

        total = sum(breakdown.values())
        return min(total, 100), breakdown


# ---------------------------------------------------------------------------
# Report dataclass
# ---------------------------------------------------------------------------

@dataclass
class AnalysisReport:
    """Aggregated result of all Specter static analysis passes."""

    sample_name: str
    sample_sha256: str
    sample_md5: str = ""
    sample_size: int = 0
    analysis_timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    pe_file: Optional[PEFile] = None
    yara_matches: List[YaraMatch] = field(default_factory=list)
    behavior: Optional[BehaviorReport] = None
    strings: Optional[StringExtractionResult] = None
    network: Optional[NetworkExtractionResult] = None
    classification: Optional[ClassificationResult] = None
    fuzzy_digest: Optional[FuzzyDigest] = None
    entropy_results: Optional[List[SectionEntropyResult]] = None

    risk_score: int = 0
    risk_breakdown: Dict[str, int] = field(default_factory=dict)

    analyst_notes: str = ""
    tags: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------

class ReportGenerator:
    """
    Generates JSON and HTML reports from an AnalysisReport.

    Usage::

        rg = ReportGenerator()
        rg.compute_risk(report)
        json_output = rg.to_json(report)
        html_output = rg.to_html(report)
    """

    def __init__(self) -> None:
        self._scorer = RiskScorer()

    def compute_risk(self, report: AnalysisReport) -> None:
        """Populate risk_score and risk_breakdown on the report in place."""
        score, breakdown = self._scorer.score(
            yara_matches=report.yara_matches,
            classification=report.classification,
            behavior=report.behavior,
            network=report.network,
            pe_entropy=report.entropy_results,
        )
        report.risk_score = score
        report.risk_breakdown = breakdown

    # ------------------------------------------------------------------
    # JSON serialisation
    # ------------------------------------------------------------------

    def to_json(self, report: AnalysisReport) -> Dict[str, Any]:
        """Return a fully serialisable dict representing the analysis report."""
        return {
            "schema_version": "1.0",
            "sample": {
                "name": report.sample_name,
                "sha256": report.sample_sha256,
                "md5": report.sample_md5,
                "size_bytes": report.sample_size,
            },
            "analysis_timestamp": report.analysis_timestamp.isoformat(),
            "risk": {
                "score": report.risk_score,
                "breakdown": report.risk_breakdown,
                "verdict": self._risk_verdict(report.risk_score),
            },
            "classification": self._serialize_classification(report.classification),
            "yara_matches": [
                {
                    "rule": m.rule_name,
                    "namespace": m.namespace,
                    "tags": m.tags,
                    "meta": m.meta,
                    "matched_strings": [
                        {"id": s[0], "offset": s[1], "data": s[2].hex()}
                        for s in m.strings
                    ],
                }
                for m in report.yara_matches
            ],
            "behavioral": self._serialize_behavior(report.behavior),
            "network_iocs": self._serialize_network(report.network),
            "pe_header": self._serialize_pe(report.pe_file),
            "entropy": [
                {
                    "section": e.section_name,
                    "entropy": round(e.entropy, 4),
                    "size": e.size,
                    "suspicious": e.entropy > 7.0,
                }
                for e in (report.entropy_results or [])
            ],
            "strings": self._serialize_strings(report.strings),
            "fuzzy_hash": (
                report.fuzzy_digest.to_string()
                if report.fuzzy_digest
                else None
            ),
            "tags": report.tags,
            "analyst_notes": report.analyst_notes,
        }

    def _risk_verdict(self, score: int) -> str:
        if score >= 80:
            return "MALICIOUS"
        if score >= 50:
            return "SUSPICIOUS"
        if score >= 20:
            return "POTENTIALLY_UNWANTED"
        return "CLEAN"

    def _serialize_classification(
        self, c: Optional[ClassificationResult]
    ) -> Optional[Dict[str, Any]]:
        if c is None:
            return None
        return {
            "family": c.family.value,
            "threat_level": c.threat_level.value,
            "confidence": round(c.confidence, 4),
            "matched_rules": c.matched_rules,
            "behavioral_indicators": c.behavioral_indicators,
            "notes": c.notes,
        }

    def _serialize_behavior(
        self, b: Optional[BehaviorReport]
    ) -> Optional[Dict[str, Any]]:
        if b is None:
            return None
        return {
            "risk_level": b.risk_level,
            "indicator_count": len(b.indicators),
            "indicators": [
                {
                    "category": ind.category.value,
                    "description": ind.description,
                    "severity": ind.severity,
                    "evidence": ind.evidence,
                }
                for ind in b.indicators
            ],
            "summary": b.summary,
        }

    def _serialize_network(
        self, n: Optional[NetworkExtractionResult]
    ) -> Optional[Dict[str, Any]]:
        if n is None:
            return None
        return {
            "total_count": n.total_count,
            "indicators": [
                {
                    "type": ind.indicator_type.value,
                    "value": ind.value,
                    "context": ind.context,
                    "confidence": ind.confidence,
                }
                for ind in n.indicators
            ],
        }

    def _serialize_pe(self, pe: Optional[PEFile]) -> Optional[Dict[str, Any]]:
        if pe is None:
            return None
        return {
            "machine": pe.machine_type,
            "timestamp": pe.timestamp,
            "entry_point": hex(pe.entry_point) if pe.entry_point else None,
            "is_dll": pe.is_dll,
            "is_64bit": pe.is_64bit,
            "sections": [
                {
                    "name": s.name,
                    "virtual_size": s.virtual_size,
                    "raw_size": s.raw_size,
                    "characteristics": s.characteristics,
                }
                for s in pe.sections
            ],
            "imports": [
                {"dll": imp.dll_name, "functions": imp.functions}
                for imp in (pe.imports or [])
            ],
        }

    def _serialize_strings(
        self, s: Optional[StringExtractionResult]
    ) -> Optional[Dict[str, Any]]:
        if s is None:
            return None
        return {
            "total_count": s.total_count,
            "interesting_count": len(s.interesting),
            "interesting": [
                {
                    "value": es.value,
                    "encoding": es.encoding,
                    "offset": es.offset,
                    "category": es.category,
                }
                for es in s.interesting[:50]  # cap at 50 for report size
            ],
        }

    # ------------------------------------------------------------------
    # HTML report
    # ------------------------------------------------------------------

    def to_html(self, report: AnalysisReport) -> str:
        """Return a self-contained HTML string for the analysis report."""
        risk_color = self._risk_color(report.risk_score)
        verdict = self._risk_verdict(report.risk_score)
        ts = report.analysis_timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

        sections: List[str] = []

        # Header / summary banner
        sections.append(f"""
<div class="banner" style="background:{risk_color}">
  <div class="banner-title">{html.escape(report.sample_name)}</div>
  <div class="banner-sub">
    SHA-256: <code>{html.escape(report.sample_sha256)}</code>
    &nbsp;&bull;&nbsp; {report.sample_size:,} bytes
    &nbsp;&bull;&nbsp; {html.escape(ts)}
  </div>
  <div class="verdict">{html.escape(verdict)}</div>
</div>""")

        # Risk score gauge
        sections.append(self._html_risk_gauge(report.risk_score, report.risk_breakdown))

        # Classification
        if report.classification:
            sections.append(self._html_classification(report.classification))

        # YARA matches
        if report.yara_matches:
            sections.append(self._html_yara_table(report.yara_matches))

        # Behavioral indicators
        if report.behavior and report.behavior.indicators:
            sections.append(self._html_behavioral(report.behavior))

        # Network IOCs
        if report.network and report.network.indicators:
            sections.append(self._html_network_table(report.network))

        # PE section entropy heatmap
        if report.entropy_results:
            sections.append(self._html_entropy_heatmap(report.entropy_results))

        # Strings
        if report.strings and report.strings.interesting:
            sections.append(self._html_strings_panel(report.strings))

        # Fuzzy hash
        if report.fuzzy_digest:
            fh = html.escape(report.fuzzy_digest.to_string())
            sections.append(f'<div class="section"><h2>Fuzzy Hash</h2><code>{fh}</code></div>')

        # Analyst notes
        if report.analyst_notes:
            sections.append(
                f'<div class="section"><h2>Analyst Notes</h2>'
                f'<p>{html.escape(report.analyst_notes)}</p></div>'
            )

        body = "\n".join(sections)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Specter Report — {html.escape(report.sample_name)}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --code: #f0f6fc;
    --green: #2ea043; --yellow: #d29922; --orange: #da7941; --red: #da3633;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          background: var(--bg); color: var(--text); padding: 24px; font-size: 14px; }}
  h2 {{ font-size: 16px; font-weight: 600; margin-bottom: 12px; color: var(--text); }}
  code {{ font-family: "SF Mono", Consolas, monospace; font-size: 12px;
          background: #1c2128; padding: 2px 6px; border-radius: 4px; color: var(--code); }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ text-align: left; padding: 8px 12px; background: #1c2128;
        color: var(--muted); font-weight: 500; border-bottom: 1px solid var(--border); }}
  td {{ padding: 8px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  tr:hover td {{ background: #1c2128; }}
  .banner {{ border-radius: 8px; padding: 20px 24px; margin-bottom: 20px; color: #fff; }}
  .banner-title {{ font-size: 20px; font-weight: 700; }}
  .banner-sub {{ font-size: 12px; margin-top: 6px; opacity: 0.85; }}
  .verdict {{ display: inline-block; margin-top: 12px; padding: 4px 14px;
              background: rgba(0,0,0,0.25); border-radius: 20px;
              font-size: 13px; font-weight: 700; letter-spacing: 0.05em; }}
  .section {{ background: var(--surface); border: 1px solid var(--border);
              border-radius: 8px; padding: 16px 20px; margin-bottom: 16px; }}
  .gauge-bar {{ height: 12px; border-radius: 6px;
                background: linear-gradient(to right, #2ea043, #d29922, #da7941, #da3633); }}
  .gauge-marker {{ width: 3px; height: 20px; background: #fff;
                   position: relative; top: -16px; border-radius: 2px; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px;
            font-size: 11px; font-weight: 600; }}
  .badge-red {{ background: #da363333; color: #ff8080; }}
  .badge-orange {{ background: #da794133; color: #ffa05a; }}
  .badge-yellow {{ background: #d2992233; color: #e3c060; }}
  .badge-green {{ background: #2ea04333; color: #60d080; }}
</style>
</head>
<body>
{body}
</body>
</html>"""

    def _risk_color(self, score: int) -> str:
        if score >= 80:
            return "#8b0000"
        if score >= 50:
            return "#7a4500"
        if score >= 20:
            return "#5a4a00"
        return "#1a3a1a"

    def _html_risk_gauge(self, score: int, breakdown: Dict[str, int]) -> str:
        marker_left = f"{score}%"
        rows = "".join(
            f"<tr><td>{html.escape(k)}</td>"
            f"<td><div style='width:{v}%;background:#58a6ff;height:8px;border-radius:4px;'></div></td>"
            f"<td style='color:var(--muted);width:40px'>{v}</td></tr>"
            for k, v in breakdown.items()
        )
        return f"""<div class="section">
  <h2>Risk Score: {score}/100</h2>
  <div style="position:relative;margin:8px 0 20px">
    <div class="gauge-bar"></div>
    <div class="gauge-marker" style="margin-left:{marker_left}"></div>
  </div>
  <table>
    <thead><tr><th>Component</th><th>Score</th><th></th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"""

    def _html_classification(self, c: ClassificationResult) -> str:
        conf_pct = round(c.confidence * 100)
        badge_class = {
            "critical": "badge-red", "high": "badge-orange",
            "medium": "badge-yellow", "low": "badge-green", "clean": "badge-green",
        }.get(c.threat_level.value, "badge-yellow")
        return f"""<div class="section">
  <h2>Classification</h2>
  <p>
    <strong>Family:</strong> {html.escape(c.family.value)} &nbsp;
    <span class="badge {badge_class}">{html.escape(c.threat_level.value.upper())}</span>
    &nbsp; Confidence: {conf_pct}%
  </p>
  {'<p style="margin-top:8px">'+html.escape(c.notes)+'</p>' if c.notes else ''}
</div>"""

    def _html_yara_table(self, matches: List[YaraMatch]) -> str:
        rows = "".join(
            f"<tr>"
            f"<td><code>{html.escape(m.rule_name)}</code></td>"
            f"<td>{html.escape(m.namespace)}</td>"
            f"<td>{html.escape(', '.join(m.tags))}</td>"
            f"<td>{len(m.strings)} string(s)</td>"
            f"</tr>"
            for m in matches
        )
        return f"""<div class="section">
  <h2>YARA Matches ({len(matches)})</h2>
  <table>
    <thead><tr><th>Rule</th><th>Namespace</th><th>Tags</th><th>Hits</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"""

    def _html_behavioral(self, b: BehaviorReport) -> str:
        rows = "".join(
            f"<tr>"
            f"<td>{html.escape(ind.category.value)}</td>"
            f"<td>{html.escape(ind.description)}</td>"
            f"<td><span class='badge {self._severity_badge(ind.severity)}'>"
            f"{html.escape(str(ind.severity))}</span></td>"
            f"</tr>"
            for ind in b.indicators
        )
        return f"""<div class="section">
  <h2>Behavioral Indicators ({len(b.indicators)})</h2>
  <table>
    <thead><tr><th>Category</th><th>Description</th><th>Severity</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"""

    def _html_network_table(self, n: NetworkExtractionResult) -> str:
        rows = "".join(
            f"<tr>"
            f"<td>{html.escape(ind.indicator_type.value)}</td>"
            f"<td><code>{html.escape(ind.value)}</code></td>"
            f"<td style='color:var(--muted)'>{html.escape(str(ind.context))}</td>"
            f"</tr>"
            for ind in n.indicators
        )
        return f"""<div class="section">
  <h2>Network Indicators ({n.total_count})</h2>
  <table>
    <thead><tr><th>Type</th><th>Value</th><th>Context</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"""

    def _html_entropy_heatmap(self, sections: List[SectionEntropyResult]) -> str:
        bars = "".join(
            self._entropy_bar(s) for s in sections
        )
        return f"""<div class="section">
  <h2>Section Entropy</h2>
  <div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:8px">{bars}</div>
  <p style="margin-top:10px;color:var(--muted);font-size:12px">
    Entropy &gt;7.0 may indicate packing or encryption.
  </p>
</div>"""

    def _entropy_bar(self, s: SectionEntropyResult) -> str:
        pct = min(round(s.entropy / 8.0 * 100), 100)
        color = (
            "#da3633" if s.entropy > 7.0
            else "#d29922" if s.entropy > 6.0
            else "#2ea043"
        )
        return (
            f"<div style='width:100px;text-align:center'>"
            f"<div style='background:#1c2128;border-radius:4px;height:80px;"
            f"display:flex;align-items:flex-end;overflow:hidden'>"
            f"<div style='width:100%;height:{pct}%;background:{color};'></div></div>"
            f"<div style='font-size:11px;margin-top:4px;color:var(--muted)'>"
            f"{html.escape(s.section_name)}</div>"
            f"<div style='font-size:11px;color:{color}'>{s.entropy:.2f}</div>"
            f"</div>"
        )

    def _html_strings_panel(self, s: StringExtractionResult) -> str:
        rows = "".join(
            f"<tr>"
            f"<td>{html.escape(str(es.offset))}</td>"
            f"<td>{html.escape(es.encoding)}</td>"
            f"<td><code>{html.escape(es.value[:120])}</code></td>"
            f"<td style='color:var(--muted)'>{html.escape(str(es.category))}</td>"
            f"</tr>"
            for es in s.interesting[:30]  # cap display at 30
        )
        return f"""<div class="section">
  <h2>Interesting Strings ({len(s.interesting)} total)</h2>
  <table>
    <thead><tr><th>Offset</th><th>Enc</th><th>Value</th><th>Category</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"""

    def _severity_badge(self, severity: Any) -> str:
        s = str(severity).lower()
        if s in ("critical", "high"):
            return "badge-red"
        if s == "medium":
            return "badge-orange"
        if s == "low":
            return "badge-yellow"
        return "badge-green"
