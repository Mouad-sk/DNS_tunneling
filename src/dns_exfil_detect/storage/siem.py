"""CEF / syslog formatters for SIEM export."""

from __future__ import annotations

from dns_exfil_detect.models import DetectionResult


def to_cef(result: DetectionResult, product: str = "dns-exfil-detect") -> str:
    """ArcSight Common Event Format line for a detection."""
    severity = {"info": 1, "low": 3, "medium": 6, "high": 8, "critical": 10}.get(result.risk_level, 5)
    ml = "nan" if result.ml_score is None else f"{result.ml_score:.4f}"
    extensions = (
        f"src={result.src_ip} "
        f"dhost={result.domain} "
        f"cs1={result.rule_score:.4f} cs1Label=RuleScore "
        f"cs2={ml} cs2Label=MLScore "
        f"cn1={result.raw_query_count} cn1Label=RawQueryCount "
        f"msg={_escape(result.reason)}"
    )
    return (
        f"CEF:0|{product}|dns-tunnel-detect|1.0|DNS-EXFIL|{_escape(result.risk_level)}|"
        f"{severity}|{extensions}"
    )


def to_syslog(result: DetectionResult, product: str = "dns-exfil-detect") -> str:
    """RFC-ish syslog line (no host agent required)."""
    ml = "nan" if result.ml_score is None else f"{result.ml_score:.4f}"
    return (
        f"{result.timestamp.isoformat()} {product} src={result.src_ip} domain={result.domain} "
        f"rule={result.rule_score:.4f} ml={ml} level={result.risk_level} "
        f"queries={result.raw_query_count} reason={result.reason!r}"
    )


def format_event(result: DetectionResult, fmt: str = "cef", product: str = "dns-exfil-detect") -> str:
    if fmt == "syslog":
        return to_syslog(result, product=product)
    return to_cef(result, product=product)


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=")
