import hashlib
import re
import uuid
from datetime import datetime, timezone
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from .rules import build_summary, generate_findings
from .schemas import (
    AttachmentIndicator,
    AuthenticationAnalysis,
    AuthenticationResult,
    EmailMetadata,
    ForensicResult,
    ReceivedHop,
    RoutingAnalysis,
    SenderAnalysis,
    TimelineEvent,
    URLIndicator,
)


URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"]+",
    re.IGNORECASE,
)

IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

AUTH_PATTERN = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*"
    r"(pass|fail|softfail|neutral|none|temperror|permerror)\b",
    re.IGNORECASE,
)


def _clean(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None

    value = str(value).strip()

    return value if value else None


def _extract_domain(value: Optional[str]) -> Optional[str]:
    if not value:
        return None

    match = re.search(
        r"[\w.+-]+@([\w.-]+\.[A-Za-z]{2,})",
        value,
    )

    if not match:
        return None

    return match.group(1).lower()


def _extract_addresses(values: List[str]) -> List[str]:
    if not values:
        return []

    addresses = []

    for _, address in getaddresses(values):
        address = address.strip()

        if address:
            addresses.append(address)

    return addresses


def _normalize_url(url: str) -> str:
    return url.rstrip(".,;:!?)]}>\"'")


def _extract_urls(message: Message) -> List[URLIndicator]:
    raw_urls = set()

    for part in message.walk():

        if part.get_content_disposition() == "attachment":
            continue

        content_type = part.get_content_type()

        try:
            payload = part.get_content()
        except Exception:
            continue

        if not isinstance(payload, str):
            continue

        if content_type == "text/html":
            soup = BeautifulSoup(payload, "html.parser")

            for link in soup.find_all("a", href=True):
                raw_urls.add(link["href"])

            visible_text = soup.get_text(" ")
            raw_urls.update(URL_PATTERN.findall(visible_text))

        elif content_type == "text/plain":
            raw_urls.update(URL_PATTERN.findall(payload))

    results = []
    seen = set()

    for raw_url in raw_urls:

        if not raw_url.lower().startswith(("http://", "https://")):
            continue

        url = _normalize_url(raw_url)

        if url in seen:
            continue

        seen.add(url)

        try:
            parsed = urlsplit(url)
        except ValueError:
            continue

        hostname = parsed.hostname.lower() if parsed.hostname else None

        domain = None

        if hostname:
            parts = hostname.split(".")

            if len(parts) >= 2:
                domain = ".".join(parts[-2:])
            else:
                domain = hostname

        results.append(
            URLIndicator(
                original_url=raw_url,
                scheme=parsed.scheme,
                hostname=hostname,
                domain=domain,
                port=parsed.port,
                path=parsed.path or "/",
            )
        )

    return results


def _extract_attachments(message: Message) -> List[AttachmentIndicator]:
    attachments = []

    for part in message.walk():

        if part.get_content_disposition() != "attachment":
            continue

        payload = part.get_payload(decode=True)

        if payload is None:
            payload = b""

        filename = part.get_filename()
        content_type = part.get_content_type()

        extension = None

        if filename and "." in filename:
            extension = Path(filename).suffix.lower()

        sha256 = hashlib.sha256(payload).hexdigest()

        attachments.append(
            AttachmentIndicator(
                filename=filename,
                content_type=content_type,
                extension=extension,
                size_bytes=len(payload),
                sha256=sha256,
            )
        )

    return attachments


def _parse_authentication(message: Message) -> AuthenticationAnalysis:
    raw_results = message.get_all(
        "Authentication-Results",
        [],
    )

    raw_received_spf = message.get_all(
        "Received-SPF",
        [],
    )

    combined = []

    for item in raw_results:
        combined.append(str(item))

    for item in raw_received_spf:
        combined.append(str(item))

    text = "\n".join(combined)

    parsed = {}

    for match in AUTH_PATTERN.finditer(text):
        protocol = match.group(1).lower()
        result = match.group(2).upper()

        if protocol not in parsed:
            parsed[protocol] = result

    results = []

    for protocol, result in parsed.items():
        results.append(
            AuthenticationResult(
                protocol=protocol.upper(),
                result=result,
                source="Authentication-Results / Received-SPF",
                raw=text,
            )
        )

    return AuthenticationAnalysis(
        spf=parsed.get("spf", "NOT_AVAILABLE"),
        dkim=parsed.get("dkim", "NOT_AVAILABLE"),
        dmarc=parsed.get("dmarc", "NOT_AVAILABLE"),
        results=results,
    )


def _parse_received_headers(
    message: Message,
) -> List[ReceivedHop]:

    received = message.get_all("Received", [])

    hops = []

    for index, raw_header in enumerate(received, start=1):

        raw = str(raw_header)

        timestamp = None

        if ";" in raw:
            possible_date = raw.rsplit(";", 1)[1].strip()

            try:
                timestamp = parsedate_to_datetime(
                    possible_date
                ).isoformat()

            except Exception:
                timestamp = possible_date

        from_host = None
        by_host = None

        from_match = re.search(
            r"\bfrom\s+([^\s(]+)",
            raw,
            re.IGNORECASE,
        )

        by_match = re.search(
            r"\bby\s+([^\s(]+)",
            raw,
            re.IGNORECASE,
        )

        if from_match:
            from_host = from_match.group(1)

        if by_match:
            by_host = by_match.group(1)

        ips = []

        for ip in IP_PATTERN.findall(raw):
            parts = ip.split(".")

            if all(0 <= int(part) <= 255 for part in parts):
                if ip not in ips:
                    ips.append(ip)

        hops.append(
            ReceivedHop(
                hop_number=index,
                raw_header=raw,
                from_host=from_host,
                by_host=by_host,
                ip_addresses=ips,
                timestamp=timestamp,
            )
        )

    return hops


def _public_ips(hops: List[ReceivedHop]) -> List[str]:
    import ipaddress

    result = []

    for hop in hops:
        for ip in hop.ip_addresses:

            try:
                address = ipaddress.ip_address(ip)

                if address.is_global and ip not in result:
                    result.append(ip)

            except ValueError:
                continue

    return result


def _build_timeline(
    message_date: Optional[str],
    hops: List[ReceivedHop],
) -> List[TimelineEvent]:

    events = []

    if message_date:
        events.append(
            TimelineEvent(
                timestamp=message_date,
                event_type="MESSAGE_DATE",
                description="Date value declared by the message.",
                source="Date header",
            )
        )

    for hop in hops:

        if not hop.timestamp:
            continue

        route = "Received hop"

        if hop.from_host and hop.by_host:
            route = f"Message received from {hop.from_host} by {hop.by_host}"

        elif hop.by_host:
            route = f"Message received by {hop.by_host}"

        events.append(
            TimelineEvent(
                timestamp=hop.timestamp,
                event_type="MAIL_TRANSFER",
                description=route,
                source=f"Received header #{hop.hop_number}",
            )
        )

    def sort_key(event: TimelineEvent):
        if not event.timestamp:
            return datetime.max.replace(tzinfo=timezone.utc)

        try:
            dt = datetime.fromisoformat(
                event.timestamp
            )

            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)

            return dt

        except Exception:
            return datetime.max.replace(tzinfo=timezone.utc)

    return sorted(events, key=sort_key)


def _sender_analysis(message: Message) -> SenderAnalysis:
    from_value = _clean(message.get("From"))
    reply_to = _clean(message.get("Reply-To"))
    return_path = _clean(message.get("Return-Path"))
    message_id = _clean(message.get("Message-ID"))

    sender_domain = _extract_domain(from_value)
    reply_to_domain = _extract_domain(reply_to)
    return_path_domain = _extract_domain(return_path)
    message_id_domain = _extract_domain(message_id)

    return SenderAnalysis(
        sender_domain=sender_domain,
        reply_to_domain=reply_to_domain,
        return_path_domain=return_path_domain,
        message_id_domain=message_id_domain,

        from_reply_to_match=(
            sender_domain == reply_to_domain
            if sender_domain and reply_to_domain
            else None
        ),

        from_return_path_match=(
            sender_domain == return_path_domain
            if sender_domain and return_path_domain
            else None
        ),

        sender_message_id_match=(
            sender_domain == message_id_domain
            if sender_domain and message_id_domain
            else None
        ),
    )


def _extract_metadata(message: Message) -> EmailMetadata:
    to_values = message.get_all("To", [])
    cc_values = message.get_all("Cc", [])

    return EmailMetadata(
        from_address=_clean(message.get("From")),
        to=_extract_addresses(to_values),
        cc=_extract_addresses(cc_values),
        subject=_clean(message.get("Subject")),
        date=_clean(message.get("Date")),
        reply_to=_clean(message.get("Reply-To")),
        return_path=_clean(message.get("Return-Path")),
        sender=_clean(message.get("Sender")),
        message_id=_clean(message.get("Message-ID")),
        mime_version=_clean(message.get("MIME-Version")),
        content_type=_clean(message.get("Content-Type")),
    )


def analyze_email(
    email_bytes: bytes,
    file_name: str,
    m1_result: Optional[dict] = None,
) -> ForensicResult:

    case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"

    message = BytesParser(
        policy=policy.default
    ).parsebytes(email_bytes)

    metadata = _extract_metadata(message)

    sender = _sender_analysis(message)

    authentication = _parse_authentication(message)

    hops = _parse_received_headers(message)

    routing = RoutingAnalysis(
        hop_count=len(hops),
        public_ips=_public_ips(hops),
        hops=hops,
    )

    urls = _extract_urls(message)

    attachments = _extract_attachments(message)

    timeline = _build_timeline(
        metadata.date,
        hops,
    )

    findings = generate_findings(
        sender=sender,
        authentication=authentication,
        routing=routing,
        url_count=len(urls),
        attachment_count=len(attachments),
    )

    limitations = []

    if authentication.spf == "NOT_AVAILABLE":
        limitations.append(
            "SPF result was not available in the supplied headers."
        )

    if authentication.dkim == "NOT_AVAILABLE":
        limitations.append(
            "DKIM result was not available in the supplied headers."
        )

    if authentication.dmarc == "NOT_AVAILABLE":
        limitations.append(
            "DMARC result was not available in the supplied headers."
        )

    if not hops:
        limitations.append(
            "No Received headers were available for route reconstruction."
        )

    if urls:
        limitations.append(
            "URL reputation was not evaluated by M2."
        )

    if attachments:
        limitations.append(
            "Attachments were hashed but not executed or sandboxed."
        )

    return ForensicResult(
        case_id=case_id,
        file_name=file_name,
        analysis_timestamp=datetime.now(timezone.utc),
        message_metadata=metadata,
        sender_analysis=sender,
        authentication=authentication,
        routing_analysis=routing,
        urls=urls,
        attachments=attachments,
        timeline=timeline,
        forensic_findings=findings,
        evidence_summary=build_summary(findings),
        limitations=limitations,
        m1_detection=m1_result,
    )