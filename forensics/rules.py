from typing import List

from .schemas import (
    AuthenticationAnalysis,
    ForensicFinding,
    RoutingAnalysis,
    SenderAnalysis,
)


def _finding(
    finding_id: str,
    category: str,
    severity: str,
    title: str,
    description: str,
    evidence: str,
    source: str,
) -> ForensicFinding:
    return ForensicFinding(
        finding_id=finding_id,
        category=category,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
        source=source,
    )


def generate_findings(
    sender: SenderAnalysis,
    authentication: AuthenticationAnalysis,
    routing: RoutingAnalysis,
    url_count: int,
    attachment_count: int,
) -> List[ForensicFinding]:

    findings: List[ForensicFinding] = []

    # F001 - Reply-To mismatch
    if (
        sender.from_reply_to_match is False
        and sender.sender_domain
        and sender.reply_to_domain
    ):
        findings.append(
            _finding(
                "F001",
                "Sender",
                "MEDIUM",
                "Reply-To domain differs from sender domain",
                (
                    "The domain in the Reply-To field differs from the "
                    "domain associated with the From address."
                ),
                (
                    f"From domain: {sender.sender_domain}; "
                    f"Reply-To domain: {sender.reply_to_domain}"
                ),
                "From / Reply-To headers",
            )
        )

    # F002 - Return-Path mismatch
    if (
        sender.from_return_path_match is False
        and sender.sender_domain
        and sender.return_path_domain
    ):
        findings.append(
            _finding(
                "F002",
                "Sender",
                "MEDIUM",
                "Return-Path domain differs from sender domain",
                (
                    "The Return-Path domain differs from the domain "
                    "associated with the From address."
                ),
                (
                    f"From domain: {sender.sender_domain}; "
                    f"Return-Path domain: {sender.return_path_domain}"
                ),
                "From / Return-Path headers",
            )
        )

    # F003 - Message-ID mismatch
    if (
        sender.sender_message_id_match is False
        and sender.sender_domain
        and sender.message_id_domain
    ):
        findings.append(
            _finding(
                "F003",
                "Message Identity",
                "LOW",
                "Message-ID domain differs from sender domain",
                (
                    "The domain associated with Message-ID is different "
                    "from the sender domain."
                ),
                (
                    f"Sender domain: {sender.sender_domain}; "
                    f"Message-ID domain: {sender.message_id_domain}"
                ),
                "From / Message-ID headers",
            )
        )

    # Authentication
    if authentication.spf in {
        "FAIL",
        "SOFTFAIL",
        "TEMPERROR",
        "PERMERROR",
    }:
        findings.append(
            _finding(
                "F004",
                "Authentication",
                "HIGH" if authentication.spf == "FAIL" else "MEDIUM",
                f"SPF result: {authentication.spf}",
                "The available authentication evidence indicates an SPF issue.",
                f"SPF: {authentication.spf}",
                "Authentication-Results / Received-SPF",
            )
        )

    if authentication.dkim in {
        "FAIL",
        "TEMPERROR",
        "PERMERROR",
    }:
        findings.append(
            _finding(
                "F005",
                "Authentication",
                "HIGH" if authentication.dkim == "FAIL" else "MEDIUM",
                f"DKIM result: {authentication.dkim}",
                "The available authentication evidence indicates a DKIM issue.",
                f"DKIM: {authentication.dkim}",
                "Authentication-Results",
            )
        )

    if authentication.dmarc in {
        "FAIL",
        "TEMPERROR",
        "PERMERROR",
    }:
        findings.append(
            _finding(
                "F006",
                "Authentication",
                "HIGH" if authentication.dmarc == "FAIL" else "MEDIUM",
                f"DMARC result: {authentication.dmarc}",
                "The available authentication evidence indicates a DMARC issue.",
                f"DMARC: {authentication.dmarc}",
                "Authentication-Results",
            )
        )

    # Missing authentication
    if (
        authentication.spf == "NOT_AVAILABLE"
        and authentication.dkim == "NOT_AVAILABLE"
        and authentication.dmarc == "NOT_AVAILABLE"
    ):
        findings.append(
            _finding(
                "F007",
                "Authentication",
                "INFORMATIONAL",
                "Authentication results are not available",
                (
                    "No usable SPF, DKIM or DMARC result was present "
                    "in the supplied message headers."
                ),
                "SPF/DKIM/DMARC: NOT_AVAILABLE",
                "Authentication headers",
            )
        )

    # Routing
    if routing.hop_count == 0:
        findings.append(
            _finding(
                "F008",
                "Routing",
                "LOW",
                "No Received headers were available",
                (
                    "No Received headers were present, so the message "
                    "delivery path could not be reconstructed."
                ),
                "Received header count: 0",
                "Received headers",
            )
        )

    # URLs
    if url_count > 0:
        findings.append(
            _finding(
                "F009",
                "Content",
                "INFORMATIONAL",
                "URLs were identified in the message",
                (
                    "One or more URLs were extracted from the message. "
                    "Reputation or threat classification is outside M2."
                ),
                f"URL count: {url_count}",
                "Message body",
            )
        )

    # Attachments
    if attachment_count > 0:
        findings.append(
            _finding(
                "F010",
                "Attachment",
                "INFORMATIONAL",
                "Attachments were present",
                (
                    "One or more attachments were present in the message. "
                    "M2 records metadata and hashes but does not execute files."
                ),
                f"Attachment count: {attachment_count}",
                "MIME structure",
            )
        )

    return findings


def build_summary(findings: List[ForensicFinding]) -> dict:
    summary = {
        "total_findings": len(findings),
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
    }

    for finding in findings:
        severity = finding.severity.lower()

        if severity == "high":
            summary["high"] += 1
        elif severity == "medium":
            summary["medium"] += 1
        elif severity == "low":
            summary["low"] += 1
        else:
            summary["informational"] += 1

    return summary