from html import escape

from .schemas import ForensicResult


def _badge_class(value: str) -> str:
    return value.lower().replace(" ", "-")


def _finding_row(finding) -> str:
    return f"""
    <div class="finding">
        <div class="finding-head">
            <span class="severity {_badge_class(finding.severity)}">
                {escape(finding.severity)}
            </span>
            <span class="finding-id">
                {escape(finding.finding_id)}
            </span>
            <strong>{escape(finding.title)}</strong>
        </div>

        <p>{escape(finding.description)}</p>

        <div class="evidence">
            <span>Observed evidence</span>
            <code>{escape(finding.evidence)}</code>
        </div>

        <div class="source">
            Source: {escape(finding.source)}
        </div>
    </div>
    """


def generate_html_report(result: ForensicResult) -> str:
    metadata = result.message_metadata
    sender = result.sender_analysis
    auth = result.authentication
    routing = result.routing_analysis

    findings_html = "".join(
        _finding_row(finding)
        for finding in result.forensic_findings
    )

    if not findings_html:
        findings_html = """
        <div class="empty">
            No forensic findings were generated from the available evidence.
        </div>
        """

    auth_rows = f"""
    <tr><td>SPF</td><td>{escape(auth.spf)}</td></tr>
    <tr><td>DKIM</td><td>{escape(auth.dkim)}</td></tr>
    <tr><td>DMARC</td><td>{escape(auth.dmarc)}</td></tr>
    """

    url_rows = ""

    for url in result.urls:
        url_rows += f"""
        <tr>
            <td>{escape(url.original_url)}</td>
            <td>{escape(url.hostname or "N/A")}</td>
            <td>{escape(url.scheme or "N/A")}</td>
            <td>{escape(url.path or "/")}</td>
        </tr>
        """

    if not url_rows:
        url_rows = """
        <tr>
            <td colspan="4">No URLs extracted.</td>
        </tr>
        """

    attachment_rows = ""

    for attachment in result.attachments:
        attachment_rows += f"""
        <tr>
            <td>{escape(attachment.filename or "N/A")}</td>
            <td>{escape(attachment.content_type or "N/A")}</td>
            <td>{attachment.size_bytes:,}</td>
            <td class="hash">{escape(attachment.sha256)}</td>
        </tr>
        """

    if not attachment_rows:
        attachment_rows = """
        <tr>
            <td colspan="4">No attachments detected.</td>
        </tr>
        """

    route_rows = ""

    for hop in routing.hops:

        ips = ", ".join(hop.ip_addresses) or "None extracted"

        route_rows += f"""
        <tr>
            <td>{hop.hop_number}</td>
            <td>{escape(hop.from_host or "N/A")}</td>
            <td>{escape(hop.by_host or "N/A")}</td>
            <td>{escape(ips)}</td>
            <td>{escape(hop.timestamp or "N/A")}</td>
        </tr>
        """

    if not route_rows:
        route_rows = """
        <tr>
            <td colspan="5">No Received headers available.</td>
        </tr>
        """

    timeline_rows = ""

    for event in result.timeline:
        timeline_rows += f"""
        <tr>
            <td>{escape(event.timestamp or "N/A")}</td>
            <td>{escape(event.event_type)}</td>
            <td>{escape(event.description)}</td>
            <td>{escape(event.source)}</td>
        </tr>
        """

    if not timeline_rows:
        timeline_rows = """
        <tr>
            <td colspan="4">No timeline events available.</td>
        </tr>
        """

    limitation_items = "".join(
        f"<li>{escape(item)}</li>"
        for item in result.limitations
    )

    if not limitation_items:
        limitation_items = "<li>No specific limitations recorded.</li>"

    m1_section = ""

    if result.m1_detection:
        m1 = result.m1_detection

        m1_section = f"""
        <section>
            <div class="section-title">M1 Detection Result</div>

            <div class="summary-grid">
                <div class="metric">
                    <span>Classification</span>
                    <strong>{escape(str(m1.get("classification", "N/A")))}</strong>
                </div>

                <div class="metric">
                    <span>Threat Category</span>
                    <strong>{escape(str(m1.get("threat_category", "N/A")))}</strong>
                </div>

                <div class="metric">
                    <span>Risk Score</span>
                    <strong>{escape(str(m1.get("risk_score", "N/A")))}</strong>
                </div>

                <div class="metric">
                    <span>Confidence</span>
                    <strong>{escape(str(m1.get("confidence", "N/A")))}</strong>
                </div>
            </div>

            <p class="note">
                M1 classification is shown as received from the detection
                module. M2 does not modify or reinterpret the model result.
            </p>
        </section>
        """

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>Email Forensic Examination Report - {escape(result.case_id)}</title>

<style>

:root {{
    --ink: #17202a;
    --muted: #5f6b76;
    --line: #d9dee4;
    --paper: #ffffff;
    --panel: #f5f7f9;
    --dark: #1c2530;
    --high: #b42318;
    --medium: #b54708;
    --low: #175cd3;
    --info: #475467;
}}

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    padding: 0;
    background: #e9edf1;
    color: var(--ink);
    font-family:
        Inter,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        Arial,
        sans-serif;
    line-height: 1.55;
}}

.page {{
    width: 1120px;
    max-width: calc(100% - 40px);
    margin: 30px auto;
    background: var(--paper);
    box-shadow: 0 12px 35px rgba(0,0,0,.08);
}}

.header {{
    padding: 32px 38px;
    background: var(--dark);
    color: white;
}}

.header h1 {{
    margin: 0 0 8px;
    font-size: 26px;
    font-weight: 650;
    letter-spacing: -.3px;
}}

.header p {{
    margin: 4px 0;
    color: #cbd5df;
    font-size: 13px;
}}

.case-bar {{
    padding: 16px 38px;
    border-bottom: 1px solid var(--line);
    background: #fafbfc;
    display: flex;
    justify-content: space-between;
    gap: 20px;
}}

.case-bar span {{
    color: var(--muted);
    font-size: 12px;
}}

.case-bar strong {{
    display: block;
    margin-top: 3px;
    font-size: 14px;
}}

section {{
    padding: 30px 38px;
    border-bottom: 1px solid var(--line);
}}

.section-title {{
    margin-bottom: 17px;
    padding-bottom: 10px;
    border-bottom: 2px solid var(--dark);
    font-size: 17px;
    font-weight: 650;
}}

.summary-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
}}

.metric {{
    padding: 15px;
    background: var(--panel);
    border: 1px solid var(--line);
}}

.metric span {{
    display: block;
    color: var(--muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .5px;
}}

.metric strong {{
    display: block;
    margin-top: 6px;
    font-size: 18px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}}

th {{
    text-align: left;
    background: #f2f4f7;
    color: #344054;
    font-weight: 650;
}}

th, td {{
    border: 1px solid var(--line);
    padding: 10px 11px;
    vertical-align: top;
}}

code {{
    font-family: "Consolas", "Courier New", monospace;
    font-size: 12px;
    word-break: break-word;
}}

.finding {{
    border: 1px solid var(--line);
    padding: 17px;
    margin-bottom: 12px;
    background: #fff;
}}

.finding-head {{
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
}}

.finding-id {{
    color: var(--muted);
    font-size: 11px;
}}

.severity {{
    padding: 3px 7px;
    border-radius: 3px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: .3px;
}}

.high {{
    color: var(--high);
    background: #fef3f2;
}}

.medium {{
    color: var(--medium);
    background: #fffaeb;
}}

.low {{
    color: var(--low);
    background: #eff8ff;
}}

.informational {{
    color: var(--info);
    background: #f2f4f7;
}}

.evidence {{
    margin-top: 12px;
    padding: 11px;
    background: #f8fafc;
    border-left: 3px solid #98a2b3;
}}

.evidence span {{
    display: block;
    margin-bottom: 5px;
    color: var(--muted);
    font-size: 11px;
    text-transform: uppercase;
}}

.source {{
    margin-top: 9px;
    color: var(--muted);
    font-size: 11px;
}}

.hash {{
    word-break: break-all;
    font-family: monospace;
    font-size: 11px;
}}

.note {{
    color: var(--muted);
    font-size: 12px;
}}

.empty {{
    padding: 15px;
    background: var(--panel);
    color: var(--muted);
}}

ul {{
    margin: 0;
    padding-left: 20px;
}}

.footer {{
    padding: 24px 38px;
    color: var(--muted);
    font-size: 11px;
    background: #fafbfc;
}}

@media print {{
    body {{
        background: white;
    }}

    .page {{
        width: 100%;
        max-width: none;
        margin: 0;
        box-shadow: none;
    }}
}}

</style>
</head>

<body>

<div class="page">

<header class="header">
    <h1>Email Forensic Examination Report</h1>
    <p>Evidence extraction and message-header analysis</p>
</header>

<div class="case-bar">
    <div>
        <span>Case ID</span>
        <strong>{escape(result.case_id)}</strong>
    </div>

    <div>
        <span>Source File</span>
        <strong>{escape(result.file_name)}</strong>
    </div>

    <div>
        <span>Analysis Time</span>
        <strong>{escape(result.analysis_timestamp.isoformat())}</strong>
    </div>
</div>

<section>

<div class="section-title">Examination Summary</div>

<div class="summary-grid">

<div class="metric">
    <span>Findings</span>
    <strong>{result.evidence_summary.total_findings}</strong>
</div>

<div class="metric">
    <span>High Severity</span>
    <strong>{result.evidence_summary.high}</strong>
</div>

<div class="metric">
    <span>Medium Severity</span>
    <strong>{result.evidence_summary.medium}</strong>
</div>

<div class="metric">
    <span>Informational</span>
    <strong>{result.evidence_summary.informational}</strong>
</div>

</div>

<p class="note">
This report records observations derived from the supplied email.
It does not, by itself, establish attribution or prove malicious intent.
Threat-intelligence enrichment is handled separately.
</p>

</section>

{m1_section}

<section>

<div class="section-title">Message Metadata</div>

<table>
<tr><th>Field</th><th>Value</th></tr>
<tr><td>From</td><td>{escape(metadata.from_address or "N/A")}</td></tr>
<tr><td>To</td><td>{escape(", ".join(metadata.to) or "N/A")}</td></tr>
<tr><td>Cc</td><td>{escape(", ".join(metadata.cc) or "N/A")}</td></tr>
<tr><td>Subject</td><td>{escape(metadata.subject or "N/A")}</td></tr>
<tr><td>Date</td><td>{escape(metadata.date or "N/A")}</td></tr>
<tr><td>Reply-To</td><td>{escape(metadata.reply_to or "N/A")}</td></tr>
<tr><td>Return-Path</td><td>{escape(metadata.return_path or "N/A")}</td></tr>
<tr><td>Sender</td><td>{escape(metadata.sender or "N/A")}</td></tr>
<tr><td>Message-ID</td><td>{escape(metadata.message_id or "N/A")}</td></tr>
<tr><td>MIME-Version</td><td>{escape(metadata.mime_version or "N/A")}</td></tr>
<tr><td>Content-Type</td><td>{escape(metadata.content_type or "N/A")}</td></tr>
</table>

</section>

<section>

<div class="section-title">Sender Analysis</div>

<table>
<tr><th>Indicator</th><th>Value</th></tr>
<tr><td>Sender domain</td><td>{escape(sender.sender_domain or "N/A")}</td></tr>
<tr><td>Reply-To domain</td><td>{escape(sender.reply_to_domain or "N/A")}</td></tr>
<tr><td>Return-Path domain</td><td>{escape(sender.return_path_domain or "N/A")}</td></tr>
<tr><td>Message-ID domain</td><td>{escape(sender.message_id_domain or "N/A")}</td></tr>
<tr><td>From / Reply-To match</td><td>{escape(str(sender.from_reply_to_match))}</td></tr>
<tr><td>From / Return-Path match</td><td>{escape(str(sender.from_return_path_match))}</td></tr>
<tr><td>Sender / Message-ID match</td><td>{escape(str(sender.sender_message_id_match))}</td></tr>
</table>

</section>

<section>

<div class="section-title">Authentication</div>

<table>
<tr><th>Protocol</th><th>Result</th></tr>
{auth_rows}
</table>

</section>

<section>

<div class="section-title">Message Routing</div>

<table>
<tr>
<th>Hop</th>
<th>From</th>
<th>By</th>
<th>IP Addresses</th>
<th>Timestamp</th>
</tr>
{route_rows}
</table>

<p class="note">
Public IPs extracted:
{escape(", ".join(routing.public_ips) or "None")}
</p>

</section>

<section>

<div class="section-title">Timeline</div>

<table>
<tr>
<th>Timestamp</th>
<th>Event</th>
<th>Description</th>
<th>Source</th>
</tr>
{timeline_rows}
</table>

</section>

<section>

<div class="section-title">URLs</div>

<table>
<tr>
<th>URL</th>
<th>Host</th>
<th>Scheme</th>
<th>Path</th>
</tr>
{url_rows}
</table>

<p class="note">
URL presence is reported as evidence only. Reputation and maliciousness
assessment are not performed by M2.
</p>

</section>

<section>

<div class="section-title">Attachments</div>

<table>
<tr>
<th>Filename</th>
<th>Content Type</th>
<th>Size (bytes)</th>
<th>SHA-256</th>
</tr>
{attachment_rows}
</table>

<p class="note">
Attachments are identified and hashed only. They are not executed.
</p>

</section>

<section>

<div class="section-title">Forensic Findings</div>

{findings_html}

</section>

<section>

<div class="section-title">Limitations</div>

<ul>
{limitation_items}
</ul>

</section>

<footer class="footer">
    Generated by the SIH Email Forensics module.
    Evidence shown in this report is derived from the supplied message.
</footer>

</div>

</body>
</html>
"""

    return html