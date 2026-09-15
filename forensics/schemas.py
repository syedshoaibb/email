from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class EmailMetadata(BaseModel):
    from_address: Optional[str] = None
    to: List[str] = Field(default_factory=list)
    cc: List[str] = Field(default_factory=list)
    subject: Optional[str] = None
    date: Optional[str] = None
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    sender: Optional[str] = None
    message_id: Optional[str] = None
    mime_version: Optional[str] = None
    content_type: Optional[str] = None


class AuthenticationResult(BaseModel):
    protocol: str
    result: str
    source: str
    raw: Optional[str] = None


class AuthenticationAnalysis(BaseModel):
    spf: str = "NOT_AVAILABLE"
    dkim: str = "NOT_AVAILABLE"
    dmarc: str = "NOT_AVAILABLE"
    results: List[AuthenticationResult] = Field(default_factory=list)


class SenderAnalysis(BaseModel):
    sender_domain: Optional[str] = None
    reply_to_domain: Optional[str] = None
    return_path_domain: Optional[str] = None
    message_id_domain: Optional[str] = None

    from_reply_to_match: Optional[bool] = None
    from_return_path_match: Optional[bool] = None
    sender_message_id_match: Optional[bool] = None


class ReceivedHop(BaseModel):
    hop_number: int
    raw_header: str
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    ip_addresses: List[str] = Field(default_factory=list)
    timestamp: Optional[str] = None


class RoutingAnalysis(BaseModel):
    hop_count: int = 0
    public_ips: List[str] = Field(default_factory=list)
    hops: List[ReceivedHop] = Field(default_factory=list)


class URLIndicator(BaseModel):
    original_url: str
    scheme: Optional[str] = None
    hostname: Optional[str] = None
    domain: Optional[str] = None
    port: Optional[int] = None
    path: Optional[str] = None


class AttachmentIndicator(BaseModel):
    filename: Optional[str] = None
    content_type: Optional[str] = None
    extension: Optional[str] = None
    size_bytes: int = 0
    sha256: str


class TimelineEvent(BaseModel):
    timestamp: Optional[str] = None
    event_type: str
    description: str
    source: str


class ForensicFinding(BaseModel):
    finding_id: str
    category: str
    severity: str
    title: str
    description: str
    evidence: str
    source: str


class EvidenceSummary(BaseModel):
    total_findings: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0


class ForensicResult(BaseModel):
    case_id: str
    file_name: str
    analysis_timestamp: datetime

    message_metadata: EmailMetadata
    sender_analysis: SenderAnalysis
    authentication: AuthenticationAnalysis
    routing_analysis: RoutingAnalysis

    urls: List[URLIndicator] = Field(default_factory=list)
    attachments: List[AttachmentIndicator] = Field(default_factory=list)
    timeline: List[TimelineEvent] = Field(default_factory=list)

    forensic_findings: List[ForensicFinding] = Field(default_factory=list)
    evidence_summary: EvidenceSummary

    limitations: List[str] = Field(default_factory=list)

    m1_detection: Optional[Dict[str, Any]] = None