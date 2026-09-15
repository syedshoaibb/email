"""
risk_engine.py
---------------
Converts raw geolocation + abuse-reputation data into a single explainable
risk verdict for each IP, plus an overall verdict for the email.

The scoring is intentionally transparent (simple weighted rules, not a
black box) so the Dashboard team can show *why* something was flagged -
that's the "explainable threat evidence" part of the pipeline.
"""

from dataclasses import dataclass, field
from typing import List, Optional

RISK_LEVELS = ["Low", "Medium", "High", "Critical"]


@dataclass
class RiskVerdict:
    ip: str
    score: int  # 0-100
    level: str  # Low / Medium / High / Critical
    reasons: List[str] = field(default_factory=list)


def _level_from_score(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 55:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def score_ip(geo: dict, abuse: dict) -> RiskVerdict:
    """
    Weighted scoring model, 0-100:
      - AbuseIPDB confidence score       -> up to 60 pts (1:1 with their score * 0.6)
      - Report volume                    -> up to 10 pts
      - Known Tor exit node              -> +15 pts
      - Hosting/Datacenter origin         -> +8 pts  (legit mail rarely originates from a DC)
      - Anonymizing proxy flag            -> +12 pts
      - No abuse data available at all    -> small +5 pt uncertainty penalty
    """
    ip = geo.get("ip") or abuse.get("ip") or "unknown"
    score = 0
    reasons = []

    abuse_score = abuse.get("abuse_confidence_score") or 0
    if abuse_score:
        contribution = round(abuse_score * 0.6)
        score += contribution
        reasons.append(f"AbuseIPDB confidence score {abuse_score}/100 (+{contribution})")

    total_reports = abuse.get("total_reports") or 0
    if total_reports:
        contribution = min(10, total_reports)
        score += contribution
        reasons.append(f"{total_reports} community abuse report(s) (+{contribution})")

    if abuse.get("is_tor"):
        score += 15
        reasons.append("Exit node on the Tor network (+15)")

    if geo.get("is_hosting"):
        score += 8
        reasons.append("Address belongs to a hosting/datacenter provider, unusual for personal mail (+8)")

    if geo.get("is_proxy"):
        score += 12
        reasons.append("Flagged as an anonymizing proxy/VPN (+12)")

    if abuse.get("error") and not abuse_score:
        score += 5
        reasons.append("No reputation data available - treated cautiously (+5)")

    score = max(0, min(100, score))
    level = _level_from_score(score)

    if not reasons:
        reasons.append("No adverse indicators found")

    return RiskVerdict(ip=ip, score=score, level=level, reasons=reasons)


def combine_email_verdict(ip_verdicts: List[RiskVerdict], auth_flags: Optional[dict] = None) -> RiskVerdict:
    """
    Rolls up per-IP verdicts into one overall verdict for the email.
    Takes the worst (highest-score) IP as the baseline, then adds
    penalties for failed SPF/DKIM/DMARC if that info was passed in.
    """
    if not ip_verdicts:
        return RiskVerdict(ip="-", score=0, level="Low", reasons=["No public IPs found to evaluate"])

    worst = max(ip_verdicts, key=lambda v: v.score)
    score = worst.score
    reasons = [f"Worst offending IP {worst.ip}: " + "; ".join(worst.reasons)]

    if auth_flags:
        if auth_flags.get("spf") == "fail":
            score += 10
            reasons.append("SPF check failed (+10)")
        if auth_flags.get("dkim") == "fail":
            score += 10
            reasons.append("DKIM check failed (+10)")
        if auth_flags.get("dmarc") == "fail":
            score += 15
            reasons.append("DMARC check failed (+15)")

    score = max(0, min(100, score))
    return RiskVerdict(ip=worst.ip, score=score, level=_level_from_score(score), reasons=reasons)
