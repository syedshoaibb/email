import os
import tempfile
import json
import hashlib
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from html import escape

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse

from m1_detector import analyze_eml

# Threat-intelligence integration: M2 provides extracted public IPs,
# then this module enriches them with geolocation/reputation data.
try:
    from threat_intel.ip_intel import enrich_ip
    from threat_intel.risk_engine import score_ip
    THREAT_INTEL_AVAILABLE = True
except ImportError:
    enrich_ip = None
    score_ip = None
    THREAT_INTEL_AVAILABLE = False

# M2 import: support either folder name used in the project.
try:
    from m2_forensics.forensics import analyze_email
    from m2_forensics.report import generate_html_report
except ImportError:
    try:
        from forensics.forensics import analyze_email
        from forensics.report import generate_html_report
    except ImportError:
        analyze_email = None
        generate_html_report = None

app = FastAPI(
    title="SIH26106 Email Threat Detection",
    description="Complete AI email threat detection and forensic analysis",
    version="4.0.0",
)


def to_dict(value):
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if hasattr(value, "dict"):
        return value.dict()
    try:
        return dict(value)
    except Exception:
        return {}


def json_safe(value):
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [json_safe(v) for v in value]
    if hasattr(value, "model_dump"):
        return json_safe(value.model_dump())
    if hasattr(value, "dict"):
        return json_safe(value.dict())
    try:
        json.dumps(value)
        return value
    except TypeError:
        return str(value)


def run_m2(file_bytes, filename, m1_result):
    """
    M2 is deliberately downstream of M1.

    M1 always runs first. Its structured result is passed into M2 so the
    forensic case contains the detection context that triggered/frames the
    investigation. M2 still performs its own evidence extraction and is not
    skipped just because M1 is low risk.
    """
    if analyze_email is None:
        return {
            "status": "unavailable",
            "limitations": ["M2 forensic module could not be imported."],
        }

    try:
        result = analyze_email(
            file_bytes,
            filename,
            m1_result=m1_result,
        )
        return to_dict(result)
    except TypeError:
        # Compatibility with the same positional contract.
        result = analyze_email(file_bytes, filename, m1_result)
        return to_dict(result)


def _extract_public_ips(forensic):
    """Find public IPs already extracted by M2 without assuming one exact schema."""
    candidates = []

    def walk(value):
        if isinstance(value, dict):
            for key, val in value.items():
                k = str(key).lower().replace("-", "_")
                if "public_ip" in k or k in {"public_ips", "received_ips", "ips"}:
                    if isinstance(val, list):
                        candidates.extend(val)
                    elif val:
                        candidates.append(val)
                walk(val)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(forensic or {})

    import ipaddress
    unique = []
    seen = set()
    for item in candidates:
        if isinstance(item, dict):
            item = item.get("ip") or item.get("address") or item.get("value")
        if not item:
            continue
        try:
            ip = str(ipaddress.ip_address(str(item)))
            if not ipaddress.ip_address(ip).is_private and not ipaddress.ip_address(ip).is_loopback:
                if ip not in seen:
                    seen.add(ip)
                    unique.append(ip)
        except ValueError:
            continue
    return unique


async def enrich_with_threat_intel(forensic):
    """Enrich the public IPs already extracted by M2."""
    if not THREAT_INTEL_AVAILABLE:
        return {"status": "unavailable", "ips": [], "overall": None}

    ips = _extract_public_ips(forensic)
    if not ips:
        return {"status": "no_public_ips", "ips": [], "overall": None}

    import httpx
    results = []
    async with httpx.AsyncClient() as client:
        for ip in ips:
            try:
                intel = await enrich_ip(ip, client)
                verdict = score_ip(intel.get("geo", {}), intel.get("abuse", {}))
                results.append({
                    "ip": ip,
                    "geo": intel.get("geo", {}),
                    "abuse": intel.get("abuse", {}),
                    "risk_score": verdict.score,
                    "risk_level": verdict.level,
                    "reasons": verdict.reasons,
                })
            except Exception as exc:
                results.append({
                    "ip": ip,
                    "error": str(exc),
                    "risk_score": 0,
                    "risk_level": "Unknown",
                    "reasons": [],
                })

    valid_scores = [r["risk_score"] for r in results if isinstance(r.get("risk_score"), (int, float))]
    overall_score = max(valid_scores) if valid_scores else 0
    if overall_score >= 80:
        overall_level = "Critical"
    elif overall_score >= 55:
        overall_level = "High"
    elif overall_score >= 25:
        overall_level = "Medium"
    else:
        overall_level = "Low"

    return {
        "status": "success",
        "ips": results,
        "overall": {"score": overall_score, "level": overall_level},
    }


def _m1_context(m1_result):
    """Small, display-safe M1 context shared with M2/M3."""
    m1 = m1_result or {}
    result = m1.get("m1_result") or {}
    final = result.get("final_percentage")
    try:
        final = float(final) if final is not None else 0.0
    except (TypeError, ValueError):
        final = 0.0
    verdict = result.get("verdict", "UNKNOWN")
    return {
        "verdict": verdict,
        "final_threat_probability": round(final, 2),
        "investigation_priority": (
            "HIGH" if final >= 60 or str(verdict).upper() in {"HIGH_RISK", "CRITICAL", "HIGH"} else
            "MEDIUM" if final >= 35 or str(verdict).upper() in {"MEDIUM_RISK", "MEDIUM"} else
            "LOW"
        ),
    }


def build_summary(m1, forensic):
    m1_result = m1.get("m1_result", {})
    header = m1.get("header_model", {})
    text = m1.get("text_model", {})
    rules = m1.get("rule_engine", {})

    final_probability = float(m1_result.get("final_percentage", 0.0))
    safe_probability = max(0.0, 100.0 - final_probability)
    header_probability = float(header.get("class_1_probability", 0.0)) * 100.0
    text_probability = float(text.get("class_1_probability", 0.0)) * 100.0
    rule_probability = float(rules.get("rule_score", 0.0))

    header_conf = max(header_probability / 100.0, 1.0 - header_probability / 100.0)
    text_conf = max(text_probability / 100.0, 1.0 - text_probability / 100.0)
    confidence = ((header_conf + text_conf) / 2.0) * 100.0

    findings = forensic.get("forensic_findings", forensic.get("findings", []))
    return {
        "verdict": m1_result.get("verdict", "UNKNOWN"),
        "final_threat_probability": round(final_probability, 2),
        "safe_probability": round(safe_probability, 2),
        "model_confidence": round(confidence, 2),
        "header_probability": round(header_probability, 2),
        "text_probability": round(text_probability, 2),
        "rule_probability": round(rule_probability, 2),
        "rule_findings_count": len(rules.get("findings", [])),
        "forensic_findings_count": len(findings),
        "url_count": len(forensic.get("urls", [])),
        "attachment_count": len(forensic.get("attachments", [])),
        "timeline_events": len(forensic.get("timeline", [])),
    }




def build_lean_forensic_report(file_bytes, filename, m1_result, forensic_result):
    """Generate a compact evidence report from the submitted .eml only."""
    msg = BytesParser(policy=policy.default).parsebytes(file_bytes)
    forensic = forensic_result or {}
    m1 = m1_result or {}
    summary = build_summary(m1, forensic)

    def text(v, fallback="Not observed"):
        return fallback if v is None or v == "" else str(v)

    def rows(items):
        return "".join(
            f"<tr><th>{escape(str(k))}</th><td>{escape(text(v))}</td></tr>"
            for k, v in items
        )

    def bullets(items):
        if not items:
            return '<div class="muted">None observed.</div>'
        return "<ul>" + "".join(f"<li>{escape(str(i))}</li>" for i in items) + "</ul>"

    sha256 = hashlib.sha256(file_bytes).hexdigest()
    try:
        parsed_date = parsedate_to_datetime(msg.get("Date")).isoformat() if msg.get("Date") else None
    except Exception:
        parsed_date = None

    auth = forensic.get("authentication") or {}
    routing = forensic.get("routing_analysis") or forensic.get("routing") or {}
    urls = forensic.get("urls") or []
    attachments = forensic.get("attachments") or []
    timeline = forensic.get("timeline") or []
    findings = forensic.get("forensic_findings") or forensic.get("findings") or []
    rule_findings = (m1.get("rule_engine") or {}).get("findings") or []

    finding_html = []
    for item in findings:
        if isinstance(item, dict):
            fid = item.get("finding_id") or item.get("id") or item.get("rule_id") or "Finding"
            desc = item.get("description") or item.get("message") or item.get("title") or "Evidence observed."
            sev = item.get("severity") or "info"
        else:
            fid, desc, sev = "Finding", str(item), "info"
        finding_html.append(
            f'<div class="finding"><div class="finding-head"><b>{escape(str(fid))}</b>'
            f'<span class="badge badge-{escape(str(sev).lower())}">{escape(str(sev).upper())}</span></div>'
            f'<div>{escape(str(desc))}</div></div>'
        )

    if not finding_html:
        for item in rule_findings:
            finding_html.append(
                f'<div class="finding"><div class="finding-head"><b>{escape(str(item.get("rule_id", "Rule")))}</b>'
                f'<span class="badge badge-{escape(str(item.get("severity", "info")).lower())}">'
                f'{escape(str(item.get("severity", "info")).upper())}</span></div>'
                f'<div>{escape(str(item.get("description", "Content indicator observed.")))}</div></div>'
            )

    findings_html = "".join(finding_html) or '<div class="muted">No forensic findings reported.</div>'
    url_values = [json.dumps(u, ensure_ascii=False) if isinstance(u, dict) else str(u) for u in urls]

    attachment_values = []
    for item in attachments:
        if isinstance(item, dict):
            name = item.get("filename") or item.get("name") or "Attachment"
            typ = item.get("content_type") or item.get("type") or "Unknown type"
            size = item.get("size")
            suffix = f" — {size} bytes" if size is not None else ""
            attachment_values.append(f"{name} — {typ}{suffix}")
        else:
            attachment_values.append(str(item))

    timeline_values = [json.dumps(t, ensure_ascii=False) if isinstance(t, dict) else str(t) for t in timeline]
    auth_rows = list(auth.items()) if auth else [("Authentication", "Not observed")]
    routing_rows = list(routing.items()) if routing else [("Routing", "Not observed")]

    html = """<!doctype html>
<html><head><meta charset="utf-8"><title>Email Forensic Report</title>
<style>
body{margin:0;background:#f4f7fb;color:#172033;font:14px Arial,Segoe UI,sans-serif}.wrap{max-width:980px;margin:auto;padding:28px}
.header{background:#0f172a;color:#fff;border-radius:14px;padding:22px}.header h1{margin:0 0 6px;font-size:24px}.muted{color:#64748b}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px}.card{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:18px;margin-top:14px}
.metric{font-size:28px;font-weight:800;margin-top:6px}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px 7px;border-bottom:1px solid #edf2f7;vertical-align:top}th{width:32%;color:#64748b;font-weight:600}
.badge{padding:3px 8px;border-radius:999px;font-size:10px;font-weight:700}.badge-high{background:#fee2e2;color:#991b1b}.badge-medium{background:#fef3c7;color:#92400e}.badge-low{background:#dcfce7;color:#166534}.badge-info{background:#e2e8f0;color:#334155}
.finding{border:1px solid #e2e8f0;border-radius:9px;padding:11px;margin:8px 0}.finding-head{display:flex;justify-content:space-between;margin-bottom:5px}ul{margin:8px 0 0 20px;padding:0}li{margin:5px 0;word-break:break-word}
@media(max-width:740px){.grid{grid-template-columns:1fr}.wrap{padding:16px}}
</style></head><body><div class="wrap">
<div class="header"><h1>Email Forensic Report</h1><div>__FILENAME__</div><div style="color:#cbd5e1;margin-top:8px">Evidence generated only from the submitted .eml.</div></div>
<div class="grid"><div class="card"><div class="muted">Threat probability</div><div class="metric">__THREAT__%</div><div>Verdict: <b>__VERDICT__</b></div></div><div class="card"><div class="muted">Safe probability</div><div class="metric">__SAFE__%</div><div>Model confidence: <b>__CONF__%</b></div></div></div>
<div class="card"><h2>Case & Message</h2><table>__MESSAGE_ROWS__</table></div>
<div class="grid"><div class="card"><h2>Authentication</h2><table>__AUTH_ROWS__</table></div><div class="card"><h2>Routing</h2><table>__ROUTING_ROWS__</table></div></div>
<div class="grid"><div class="card"><h2>URLs</h2><div class="muted">__URL_COUNT__ observed</div>__URLS__</div><div class="card"><h2>Attachments</h2><div class="muted">__ATTACH_COUNT__ observed</div>__ATTACHMENTS__</div></div>
<div class="card"><h2>Forensic Findings</h2>__FINDINGS__</div><div class="card"><h2>Timeline</h2>__TIMELINE__</div>
<div class="card"><h2>Evidence Scope</h2><div class="muted">Only observed and parsed evidence from the uploaded message is included. Missing fields are not fabricated.</div></div>
</div></body></html>"""

    return (html
        .replace("__FILENAME__", escape(filename))
        .replace("__THREAT__", f"{summary.get('final_threat_probability',0):.2f}")
        .replace("__SAFE__", f"{summary.get('safe_probability',0):.2f}")
        .replace("__CONF__", f"{summary.get('model_confidence',0):.2f}")
        .replace("__VERDICT__", escape(str(summary.get('verdict','UNKNOWN'))))
        .replace("__MESSAGE_ROWS__", rows([
            ("File", filename), ("SHA-256", sha256), ("From", msg.get("From")), ("To", msg.get("To")),
            ("Subject", msg.get("Subject")), ("Date header", msg.get("Date")), ("Parsed date", parsed_date),
            ("Message-ID", msg.get("Message-ID")), ("Reply-To", msg.get("Reply-To")), ("Return-Path", msg.get("Return-Path"))
        ]))
        .replace("__AUTH_ROWS__", rows(auth_rows))
        .replace("__ROUTING_ROWS__", rows(routing_rows))
        .replace("__URL_COUNT__", str(len(url_values))).replace("__URLS__", bullets(url_values))
        .replace("__ATTACH_COUNT__", str(len(attachment_values))).replace("__ATTACHMENTS__", bullets(attachment_values))
        .replace("__FINDINGS__", findings_html).replace("__TIMELINE__", bullets(timeline_values))
    )


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "system": "SIH26106 Email Threat Detection",
        "m1": True,
        "m2": analyze_email is not None,
        "report": generate_html_report is not None,
        "threat_intelligence": THREAT_INTEL_AVAILABLE,
    }


@app.get("/", response_class=HTMLResponse)
def home():
    return PAGE_HTML


@app.post("/api/analyze")
async def analyze_endpoint(file: UploadFile = File(...)):
    filename = file.filename or ""
    if not filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are supported.")

    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(status_code=400, detail="The uploaded .eml file is empty.")

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".eml", delete=False) as temp:
            temp.write(file_bytes)
            temp_path = temp.name

        print(f"[1/3] M1 analysis: {filename}")
        m1_result = analyze_eml(temp_path)

        print("[2/3] M2 forensic analysis")
        forensic_result = run_m2(file_bytes, filename, m1_result)

        print("[3/4] Threat-intelligence enrichment")
        threat_intel_result = await enrich_with_threat_intel(forensic_result)

        report_html = build_lean_forensic_report(
            file_bytes,
            filename,
            m1_result,
            forensic_result
        )

        summary = build_summary(m1_result, forensic_result)
        summary["threat_intelligence_ip_count"] = len(threat_intel_result.get("ips", []))
        investigation = _m1_context(m1_result)

        response = {
            "status": "success",
            "file": {"filename": filename, "size_bytes": len(file_bytes)},
            "summary": summary,
            "m1": m1_result,
            "m1_context": investigation,
            "forensics": forensic_result,
            "threat_intelligence": {
                **threat_intel_result,
                "triggered_by_m1": True,
                "m1_context": investigation,
            },
            "report_html": report_html,
        }

        print("[3/3] Complete analysis finished")
        return JSONResponse(content=json_safe(response))

    except HTTPException:
        raise
    except Exception as exc:
        print("[ERROR]", repr(exc))
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


PAGE_HTML = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>MailSentinel | Email Security Analysis</title>
<style>
:root{--bg:#0b0c0d;--surface:#111315;--surface2:#17191c;--line:#2b2e32;--text:#f4f1eb;--muted:#96918a;--soft:#c9c3b9;--accent:#c6a56a;--accent2:#e0c58f;--green:#6fc492;--red:#d87a7a;--shadow:0 18px 60px rgba(0,0,0,.28)}
*{box-sizing:border-box}html,body{margin:0;min-height:100%;background:var(--bg);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}button,input{font:inherit}button{cursor:pointer}.hidden{display:none!important}
.entry{min-height:100vh;display:grid;place-items:center;padding:28px;background:radial-gradient(circle at 50% 18%,rgba(198,165,106,.09),transparent 34%),linear-gradient(180deg,#0b0c0d,#090a0b)}
.entry-card{width:min(720px,100%);text-align:center;padding:58px 48px;border:1px solid #292b2e;border-radius:24px;background:rgba(17,19,21,.84);box-shadow:var(--shadow);backdrop-filter:blur(18px)}
.mark{width:52px;height:52px;margin:0 auto 22px;border-radius:15px;display:grid;place-items:center;background:linear-gradient(145deg,#a47e3f,#e0c58f);color:#18120a;font-weight:950;letter-spacing:-.06em}.entry h1{margin:0;font-size:40px;letter-spacing:-.05em}.tagline{margin:11px auto 34px;max-width:560px;color:var(--muted);font-size:14px;line-height:1.7}.drop{border:1px dashed #4a4640;border-radius:18px;padding:36px 24px;background:rgba(255,255,255,.012);transition:.2s}.drop:hover,.drop.over{border-color:var(--accent);background:rgba(198,165,106,.035)}.drop-icon{width:54px;height:54px;margin:0 auto 14px;border-radius:15px;display:grid;place-items:center;background:rgba(198,165,106,.09);font-size:24px}.drop h2{margin:0 0 7px;font-size:18px}.drop p{margin:0;color:var(--muted);font-size:13px}.choose{display:inline-block;margin-top:16px;padding:10px 15px;border-radius:9px;background:#241f17;color:#e6cf9f;font-size:12px;font-weight:800}#fileInput{display:none}.file-name{margin-top:11px;min-height:18px;color:var(--soft);font-size:12px}.entry-actions{display:flex;justify-content:center;gap:10px;margin-top:18px}.btn-primary{border:0;padding:12px 18px;border-radius:10px;background:var(--accent);color:#19140c;font-weight:900}.btn-primary:hover{background:var(--accent2)}.btn-secondary{border:1px solid var(--line);padding:11px 16px;border-radius:10px;background:var(--surface2);color:var(--text);font-weight:800}.loading-entry{display:none;margin-top:18px;color:var(--muted);font-size:12px}.spinner{display:inline-block;width:14px;height:14px;margin-right:7px;border:2px solid #4a4640;border-top-color:var(--accent);border-radius:50%;vertical-align:-2px;animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}.error{display:none;margin-top:14px;padding:11px 13px;border-radius:10px;border:1px solid rgba(216,122,122,.3);background:rgba(216,122,122,.07);color:#efb4b4;font-size:12px;text-align:left}.entry-note{margin-top:24px;color:#706b63;font-size:11px;line-height:1.6}
.app{min-height:100vh;display:none}.app.ready{display:flex}.sidebar{width:246px;min-height:100vh;position:sticky;top:0;align-self:flex-start;background:#0d0f10;border-right:1px solid var(--line);padding:22px 14px;display:flex;flex-direction:column;z-index:15}.brand{display:flex;align-items:center;gap:11px;padding:3px 8px 22px}.brand-mark{width:38px;height:38px;border-radius:11px;display:grid;place-items:center;background:linear-gradient(145deg,#a47e3f,#e0c58f);color:#1b140a;font-size:13px;font-weight:950}.brand-title{font-size:16px;font-weight:900;letter-spacing:-.03em}.brand-sub{display:block;color:#79746d;font-size:10px;margin-top:2px}.nav{display:grid;gap:6px}.nav button{width:100%;border:1px solid transparent;background:transparent;color:#8d8983;padding:12px 11px;border-radius:10px;text-align:left;display:flex;align-items:center;gap:10px;font-size:12px;font-weight:750}.nav button:hover{background:#17191b;color:#fff}.nav button.active{background:rgba(198,165,106,.08);border-color:rgba(198,165,106,.22);color:#fff;box-shadow:inset 2px 0 0 var(--accent)}.side-note{margin-top:auto;color:#6f6a63;font-size:10px;line-height:1.65;padding:13px 9px;border-top:1px solid #222528}.main{min-width:0;flex:1}.top{height:70px;position:sticky;top:0;z-index:10;display:flex;align-items:center;justify-content:space-between;padding:0 28px;background:rgba(11,12,13,.92);backdrop-filter:blur(18px);border-bottom:1px solid var(--line)}.top-title{font-size:13px;color:var(--soft);font-weight:800}.status{display:flex;align-items:center;gap:7px;padding:7px 10px;border:1px solid #26322b;border-radius:999px;background:rgba(111,196,146,.05);color:#9bd4b1;font-size:10px;font-weight:850}.status i{width:6px;height:6px;border-radius:50%;background:var(--green);box-shadow:0 0 10px rgba(111,196,146,.65)}.content{padding:28px;max-width:1260px;margin:auto}.view{display:none}.view.active{display:block}.page-heading{display:flex;justify-content:space-between;align-items:flex-end;gap:18px;margin-bottom:20px}.page-heading h2{margin:0;font-size:28px;letter-spacing:-.04em}.page-heading p{margin:6px 0 0;color:var(--muted);font-size:12px}
.card{background:linear-gradient(180deg,#121416,#101214);border:1px solid var(--line);border-radius:18px;box-shadow:0 10px 34px rgba(0,0,0,.16)}.panel{padding:19px}.panel h3{margin:0;font-size:15px;letter-spacing:-.02em}.sub{margin:5px 0 15px;color:#77736d;font-size:11px;line-height:1.45}.hero{padding:26px;background:radial-gradient(circle at 80% 30%,rgba(198,165,106,.08),transparent 28%),linear-gradient(135deg,#171513,#121416 62%);margin-bottom:14px}.hero-row{display:flex;justify-content:space-between;align-items:center;gap:20px;flex-wrap:wrap}.eyebrow{font-size:9px;font-weight:900;letter-spacing:.15em;color:#847c70}.hero h1{font-size:32px;margin:6px 0 4px;letter-spacing:-.04em}.hero-file{font-size:11px;color:var(--muted)}.risk-box{text-align:right}.risk-label{font-size:9px;color:#77736d;letter-spacing:.12em;font-weight:900}.risk{font-size:46px;font-weight:950;color:#e7d4ad;letter-spacing:-.05em;margin-top:2px}.risk-badge{margin-top:5px}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:11px;margin-bottom:14px}.metric{padding:16px}.metric small{display:block;color:#7a756e;text-transform:uppercase;font-size:9px;letter-spacing:.1em}.metric strong{display:block;font-size:23px;margin-top:5px;letter-spacing:-.03em}.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}.signal{margin:12px 0}.signal-top{display:flex;justify-content:space-between;font-size:11px;margin-bottom:5px}.track{height:7px;border-radius:99px;background:#25282b;overflow:hidden}.fill{height:100%;width:0;background:var(--accent);transition:width .55s ease}.table{width:100%;border-collapse:collapse;font-size:11px}.table th,.table td{padding:9px 7px;border-bottom:1px solid #272a2d;text-align:left;vertical-align:top}.table th{width:30%;color:#7c756b;font-weight:750}.empty{color:#77736d;font-size:11px;padding:5px 0;line-height:1.6}.finding{padding:12px;border:1px solid #2a2d30;background:#151719;border-radius:12px;margin-bottom:8px}.finding-top{display:flex;justify-content:space-between;gap:12px;align-items:center}.finding-title{font-size:11px;font-weight:850}.finding-desc{margin-top:6px;color:#aaa49c;font-size:11px;line-height:1.55}.finding-evidence{margin-top:7px;color:#7f8da0;font-size:10px}.badge{display:inline-flex;align-items:center;padding:4px 8px;border-radius:999px;font-size:8px;letter-spacing:.06em;font-weight:900}.low{background:rgba(111,196,146,.11);color:#80d6a0}.medium{background:rgba(216,170,99,.12);color:#e8bd79}.high{background:rgba(216,122,122,.12);color:#ef9696}.unknown{background:#25282b;color:#9da6b1}.ti-top{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:12px}.mini{padding:13px;border:1px solid #2b2e31;border-radius:12px;background:#151719}.mini small{display:block;color:#726d66;font-size:8px;font-weight:900;letter-spacing:.11em}.mini strong{display:block;margin-top:5px;font-size:17px}.ip{padding:17px;border:1px solid #2d3033;border-radius:14px;background:linear-gradient(180deg,#16181a,#121416);margin-bottom:11px}.ip-head{display:flex;justify-content:space-between;align-items:center;gap:12px}.ip-title{font-size:16px;font-weight:900;letter-spacing:-.02em}.ip-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:13px}.ip-item{padding:10px;border:1px solid #292c2f;background:#1a1c1f;border-radius:9px}.ip-item span{display:block;color:#716d66;font-size:8px;text-transform:uppercase;letter-spacing:.09em}.ip-item b{display:block;margin-top:3px;font-size:11px;word-break:break-word}.actions{display:flex;gap:8px;flex-wrap:wrap}.btn{border:1px solid var(--line);background:#17191b;color:var(--text);padding:10px 13px;border-radius:9px;font-size:11px;font-weight:800}.btn:hover{background:#202326}.btn.gold{background:#c6a56a;color:#1a140b;border-color:#c6a56a}.report-frame{width:100%;height:910px;border:0;background:#fff;border-radius:14px}.mobile-btn{display:none}
@media(max-width:980px){.sidebar{width:215px}.metrics{grid-template-columns:repeat(2,1fr)}.ip-grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:760px){.sidebar{position:fixed;left:-235px;transition:left .22s;box-shadow:20px 0 50px rgba(0,0,0,.3)}.sidebar.open{left:0}.mobile-btn{display:block;border:1px solid var(--line);background:var(--surface);color:#fff;border-radius:8px;padding:7px 9px}.top{padding:0 16px}.content{padding:18px}.grid2{grid-template-columns:1fr}.page-heading{align-items:flex-start;flex-direction:column}}
@media(max-width:560px){.entry-card{padding:38px 20px}.entry h1{font-size:32px}.metrics,.ti-top,.ip-grid{grid-template-columns:1fr}.risk-box{text-align:left}.hero h1{font-size:26px}}
</style>
</head>
<body>
<section class="entry" id="entryScreen"><div class="entry-card"><div class="mark">MS</div><h1>MailSentinel</h1><p class="tagline">A focused email security workspace for threat assessment, forensic evidence, and IP intelligence — starting from one <b>.eml</b> file.</p><div class="drop" id="dropZone"><div class="drop-icon">✉</div><h2>Upload an email for analysis</h2><p>Drop a complete <b>.eml</b> file here, or select one from your computer.</p><label class="choose" for="fileInput">Choose .eml file</label><input id="fileInput" type="file" accept=".eml"><div class="file-name" id="fileName">No file selected</div></div><div class="entry-actions"><button class="btn-primary" id="analyzeBtn">Analyze Email</button><button class="btn-secondary" id="clearBtn">Clear</button></div><div class="loading-entry" id="loading"><span class="spinner"></span>Parsing email and building the investigation workspace…</div><div class="error" id="errorBox"></div><div class="entry-note">The workspace is populated from the uploaded email and available enrichment only. Missing evidence is shown as unavailable.</div></div></section>
<section class="app" id="appShell"><aside class="sidebar" id="sidebar"><div class="brand"><div class="brand-mark">MS</div><div><div class="brand-title">MailSentinel</div><span class="brand-sub">Email Security Workspace</span></div></div><nav class="nav"><button class="active" data-page="overview">◉ <span>Overview</span></button><button data-page="forensics">◈ <span>Forensic Report</span></button><button data-page="geo">⌖ <span>Geolocation</span></button><button data-page="indicators">◌ <span>Indicators</span></button><button data-page="report">▤ <span>Report View</span></button></nav><div class="side-note">Analysis is grounded in the submitted <b>.eml</b> and enrichment results. No missing evidence is invented.</div></aside><div class="main"><header class="top"><button class="mobile-btn" id="menuBtn">☰</button><div class="top-title" id="pageTitle">Overview</div><div class="status"><i></i>Analysis ready</div></header><main class="content">
<section class="view active" id="view-overview"><div class="page-heading"><div><h2>Overview</h2><p>Threat assessment and the most relevant evidence from the submitted email.</p></div></div><div class="hero card"><div class="hero-row"><div><div class="eyebrow">FINAL ASSESSMENT</div><h1 id="verdict">—</h1><div class="hero-file" id="heroFile">—</div></div><div class="risk-box"><div class="risk-label">THREAT PROBABILITY</div><div class="risk" id="threatScore">0.00%</div><div class="risk-badge" id="riskBadge"></div></div></div></div><div class="metrics"><div class="metric card"><small>Safe probability</small><strong id="safeScore">—</strong></div><div class="metric card"><small>Model confidence</small><strong id="confidence">—</strong></div><div class="metric card"><small>Forensic findings</small><strong id="findingCount">0</strong></div><div class="metric card"><small>Public IPs enriched</small><strong id="ipCount">0</strong></div></div><div class="grid2"><section class="card panel"><h3>Detection signals</h3><div class="sub">The current prototype's detection outputs.</div><div class="signal"><div class="signal-top"><span>Header analysis</span><span id="headerP">0%</span></div><div class="track"><div class="fill" id="headerBar"></div></div></div><div class="signal"><div class="signal-top"><span>Message content</span><span id="textP">0%</span></div><div class="track"><div class="fill" id="textBar"></div></div></div><div class="signal"><div class="signal-top"><span>Content rules</span><span id="ruleP">0%</span></div><div class="track"><div class="fill" id="ruleBar"></div></div></div></section><section class="card panel"><h3>Message</h3><div class="sub">Core fields from the uploaded email.</div><table class="table"><tr><th>From</th><td id="from">—</td></tr><tr><th>To</th><td id="to">—</td></tr><tr><th>Subject</th><td id="subject">—</td></tr><tr><th>Date</th><td id="date">—</td></tr></table></section></div><section class="card panel"><h3>Investigate further</h3><div class="sub">Each section focuses on one type of evidence.</div><div class="actions"><button class="btn gold" data-go="forensics">Open Forensic Report</button><button class="btn" data-go="geo">Open Geolocation</button><button class="btn" data-go="indicators">Open Indicators</button></div></section></section>
<section class="view" id="view-forensics"><div class="page-heading"><div><h2>Forensic Report</h2><p>Structured evidence extracted from the same email.</p></div><div class="actions"><button class="btn" id="forensicPrint">Print</button></div></div><div id="forensicContent"></div></section>
<section class="view" id="view-geo"><div class="page-heading"><div><h2>Geolocation</h2><p>Network and reputation context for public IP addresses found in the email.</p></div></div><div id="geoContent"></div></section>
<section class="view" id="view-indicators"><div class="page-heading"><div><h2>Indicators</h2><p>Content findings, URLs, attachments and timeline evidence.</p></div></div><div id="indicatorContent"></div></section>
<section class="view" id="view-report"><div class="page-heading"><div><h2>Report View</h2><p>Printable report generated from the same submitted email.</p></div><div class="actions"><button class="btn" id="reportPrint">Print / Save PDF</button><button class="btn" id="jsonBtn">View JSON</button></div></div><section class="card panel" style="padding:8px"><div id="reportShell"><div class="empty" style="padding:18px">Report unavailable until analysis is complete.</div></div></section></section>
</main></div></section>
<div class="toast" id="toast"></div>
<script>
const $=id=>document.getElementById(id);let selectedFile=null,latest=null;
function esc(v){return String(v??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;')}function val(v){return v===null||v===undefined||v===''?'Not observed':String(v)}function pct(v){return Number(v||0).toFixed(2)+'%'}function badge(v){const s=String(v||'unknown').toLowerCase();const c=['low','medium','high'].includes(s)?s:'unknown';return '<span class="badge '+c+'">'+esc(s.toUpperCase())+'</span>'}function notify(m){const t=$('toast');t.textContent=m;t.style.display='block';clearTimeout(window.__toast);window.__toast=setTimeout(()=>t.style.display='none',2200)}function showError(m){$('errorBox').textContent=m;$('errorBox').style.display='block'}function clearError(){$('errorBox').textContent='';$('errorBox').style.display='none'}
function chooseFile(f){clearError();if(!f){selectedFile=null;$('fileName').textContent='No file selected';return}if(!f.name.toLowerCase().endsWith('.eml')){selectedFile=null;$('fileName').textContent='Only .eml files are supported';showError('Please select a valid .eml file.');return}selectedFile=f;$('fileName').textContent='Selected: '+f.name}
function setPage(page){document.querySelectorAll('.nav button').forEach(b=>b.classList.toggle('active',b.dataset.page===page));document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));$('view-'+page).classList.add('active');$('pageTitle').textContent=page==='geo'?'Geolocation':page==='forensics'?'Forensic Report':page==='indicators'?'Indicators':page==='report'?'Report View':'Overview';$('sidebar').classList.remove('open');window.scrollTo({top:0,behavior:'smooth'})}
document.querySelectorAll('.nav button').forEach(b=>b.addEventListener('click',()=>setPage(b.dataset.page)));document.querySelectorAll('[data-go]').forEach(b=>b.addEventListener('click',()=>setPage(b.dataset.go)));$('menuBtn').addEventListener('click',()=>$('sidebar').classList.toggle('open'));$('fileInput').addEventListener('change',e=>chooseFile(e.target.files[0]));$('dropZone').addEventListener('click',e=>{if(!e.target.closest('label'))$('fileInput').click()});$('dropZone').addEventListener('dragover',e=>{e.preventDefault();$('dropZone').classList.add('over')});$('dropZone').addEventListener('dragleave',()=> $('dropZone').classList.remove('over'));$('dropZone').addEventListener('drop',e=>{e.preventDefault();$('dropZone').classList.remove('over');const f=e.dataTransfer.files[0];chooseFile(f);if(f){try{const dt=new DataTransfer();dt.items.add(f);$('fileInput').files=dt.files}catch(_){}}});$('clearBtn').addEventListener('click',()=>{selectedFile=null;$('fileInput').value='';$('fileName').textContent='No file selected';clearError();notify('Selection cleared')});
$('analyzeBtn').addEventListener('click',async()=>{clearError();if(!selectedFile){showError('Select a .eml file first.');return}const fd=new FormData();fd.append('file',selectedFile);$('analyzeBtn').disabled=true;$('loading').style.display='block';try{const r=await fetch('/api/analyze',{method:'POST',body:fd});const d=await r.json();if(!r.ok)throw new Error(d.detail||'Analysis failed');latest=d;render(d);$('entryScreen').classList.add('hidden');$('appShell').classList.add('ready');setPage('overview');notify('Analysis complete')}catch(e){console.error(e);showError(e.message||'Analysis failed')}finally{$('analyzeBtn').disabled=false;$('loading').style.display='none'}});
function setBar(bar,label,v){const n=Math.max(0,Math.min(100,Number(v||0)));$(label).textContent=pct(n);$(bar).style.width=n+'%'}function dictRows(obj){const rows=Object.entries(obj||{});if(!rows.length)return '<div class="empty">Not observed.</div>';return '<table class="table">'+rows.map(([k,v])=>'<tr><th>'+esc(k)+'</th><td>'+esc(typeof v==='object'?JSON.stringify(v):val(v))+'</td></tr>').join('')+'</table>'}
function render(d){const s=d.summary||{},m=d.m1||{},f=d.forensics||{},meta=f.message_metadata||{},ti=d.threat_intelligence||{};$('verdict').textContent=val(s.verdict);$('heroFile').textContent=val(d.file?.filename);$('threatScore').textContent=pct(s.final_threat_probability);$('riskBadge').innerHTML=badge(s.verdict||'Unknown');$('safeScore').textContent=pct(s.safe_probability);$('confidence').textContent=pct(s.model_confidence);$('findingCount').textContent=String(s.forensic_findings_count??0);$('ipCount').textContent=String((ti.ips||[]).length);setBar('headerBar','headerP',s.header_probability);setBar('textBar','textP',s.text_probability);setBar('ruleBar','ruleP',s.rule_probability);$('from').textContent=val(meta.from_address);$('to').textContent=Array.isArray(meta.to)?(meta.to.join(', ')||'Not observed'):val(meta.to);$('subject').textContent=val(meta.subject);$('date').textContent=val(meta.date);renderForensics(f);renderGeo(ti);renderIndicators(f,m);$('reportShell').innerHTML=d.report_html?'<iframe class="report-frame"></iframe>':'<div class="empty" style="padding:18px">Detailed report unavailable.</div>';if(d.report_html)$('reportShell').querySelector('iframe').srcdoc=d.report_html}
function renderForensics(f){const m=f.message_metadata||{},a=f.authentication||{},r=f.routing_analysis||{},findings=f.forensic_findings||[];let h='<div class="grid2"><section class="card panel"><h3>Message details</h3><div class="sub">Observed message metadata.</div>'+dictRows({'From':m.from_address,'To':Array.isArray(m.to)?m.to.join(', '):m.to,'Cc':Array.isArray(m.cc)?m.cc.join(', '):m.cc,'Subject':m.subject,'Date':m.date,'Reply-To':m.reply_to,'Return-Path':m.return_path,'Message-ID':m.message_id})+'</section><section class="card panel"><h3>Authentication</h3><div class="sub">Results available in the supplied headers.</div>'+dictRows({'SPF':a.spf,'DKIM':a.dkim,'DMARC':a.dmarc})+'</section></div>';h+='<section class="card panel" style="margin-bottom:14px"><h3>Routing</h3><div class="sub">Received headers, hop count and extracted public addresses.</div>'+dictRows({'Hop count':r.hop_count,'Public IPs':r.public_ips,'Received hops':r.hops})+'</section>';h+='<section class="card panel"><h3>Forensic findings</h3><div class="sub">Only deterministic evidence observed during parsing.</div>'+(findings.length?findings.map(x=>'<div class="finding"><div class="finding-top"><div class="finding-title">'+esc(x.finding_id||'Finding')+' · '+esc(x.title||x.category||'Evidence')+'</div>'+badge(x.severity)+'</div><div class="finding-desc">'+esc(x.description||'')+'</div>'+(x.evidence?'<div class="finding-evidence"><b>Evidence:</b> '+esc(x.evidence)+'</div>':'')+'</div>').join(''):'<div class="empty">No forensic findings were reported.</div>')+'</section>';$('forensicContent').innerHTML=h}
function renderGeo(ti){const ctx=ti.m1_context||{},items=ti.ips||[],ov=ti.overall||{};let h='<div class="card panel"><div class="ti-top"><div class="mini"><small>INVESTIGATION PRIORITY</small><strong>'+(ctx.investigation_priority?badge(ctx.investigation_priority):'—')+'</strong></div><div class="mini"><small>PUBLIC IPS ENRICHED</small><strong>'+items.length+'</strong></div><div class="mini"><small>OVERALL IP RISK</small><strong>'+(ov.level?esc(String(ov.score??0))+' · '+badge(ov.level):'—')+'</strong></div></div>';if(!items.length){h+='<div class="empty">'+(ti.status==='no_public_ips'?'No public IP address was extracted from this email, so no geolocation lookup was performed.':'Threat intelligence is unavailable for this email.')+'</div></div>';$('geoContent').innerHTML=h;return}h+='</div>';h+=items.map(x=>{const g=x.geo||{},a=x.abuse||{};const item=(k,v)=>'<div class="ip-item"><span>'+esc(k)+'</span><b>'+esc(val(v))+'</b></div>';return '<section class="ip"><div class="ip-head"><div class="ip-title">'+esc(x.ip||'Unknown IP')+'</div>'+badge(x.risk_level||'Unknown')+'</div><div class="ip-grid">'+item('Country',g.country)+item('Region',g.region)+item('City',g.city)+item('ISP',g.isp)+item('Organization',g.org)+item('ASN',g.asn)+item('Proxy',g.is_proxy)+item('Hosting',g.is_hosting)+item('TOR',a.is_tor)+item('Abuse score',a.abuse_confidence_score)+item('Reports',a.total_reports)+item('IP risk',x.risk_score)+'</div>'+(x.reasons?.length?'<div class="finding-desc" style="margin-top:12px"><b>Risk context:</b> '+esc(x.reasons.join(' · '))+'</div>':'')+(x.error?'<div class="finding-desc" style="color:#ef9696"><b>Lookup error:</b> '+esc(x.error)+'</div>':'')+'</section>'}).join('');$('geoContent').innerHTML=h}
function renderIndicators(f,m){const rules=m.rule_engine||{},urls=f.urls||[],att=f.attachments||[],timeline=f.timeline||[],rf=rules.findings||[];let h='<section class="card panel" style="margin-bottom:14px"><h3>Content findings</h3><div class="sub">Indicators raised from message content.</div>'+(rf.length?rf.map(x=>'<div class="finding"><div class="finding-top"><div class="finding-title">'+esc(x.rule_id||'Rule')+' · '+esc(x.category||'Indicator')+'</div>'+badge(x.severity)+'</div><div class="finding-desc">'+esc(x.description||'')+'</div>'+(x.matches?.length?'<div class="finding-evidence">'+esc(x.matches.join(', '))+'</div>':'')+'</div>').join(''):'<div class="empty">No content findings were reported.</div>')+'</section>';h+='<div class="grid2"><section class="card panel"><h3>URLs</h3><div class="sub">Links extracted from the message.</div>'+(urls.length?'<table class="table"><tr><th>URL</th><th>Domain</th><th>Path</th></tr>'+urls.map(x=>'<tr><td style="word-break:break-all">'+esc(x.original_url)+'</td><td>'+esc(x.domain||'Not observed')+'</td><td>'+esc(x.path||'/')+'</td></tr>').join('')+'</table>':'<div class="empty">No URLs detected.</div>')+'</section><section class="card panel"><h3>Attachments</h3><div class="sub">Detected files and hashes.</div>'+(att.length?'<table class="table"><tr><th>Filename</th><th>Type</th><th>Size</th></tr>'+att.map(x=>'<tr><td>'+esc(x.filename||'Not observed')+'</td><td>'+esc(x.content_type||'Not observed')+'</td><td>'+esc(x.size_bytes??0)+' bytes</td></tr>').join('')+'</table>':'<div class="empty">No attachments detected.</div>')+'</section></div>';h+='<section class="card panel"><h3>Timeline</h3><div class="sub">Events reconstructed from message headers.</div>'+(timeline.length?'<table class="table"><tr><th>Time</th><th>Event</th><th>Description</th></tr>'+timeline.map(x=>'<tr><td>'+esc(x.timestamp||'Not observed')+'</td><td>'+esc(x.event_type||'Event')+'</td><td>'+esc(x.description||'')+'</td></tr>').join('')+'</table>':'<div class="empty">No timeline events extracted.</div>')+'</section>';$('indicatorContent').innerHTML=h}
$('forensicPrint').addEventListener('click',()=>window.print());$('reportPrint').addEventListener('click',()=>{if(!latest?.report_html){notify('Run an analysis first');return}const w=window.open('','_blank');w.document.write(latest.report_html);w.document.close();setTimeout(()=>w.print(),450)});$('jsonBtn').addEventListener('click',()=>{if(!latest){notify('Run an analysis first');return}const w=window.open('','_blank');w.document.write('<!doctype html><html><body style="margin:0;background:#0b0c0d;color:#eee;font-family:Consolas,monospace;padding:24px"><pre style="white-space:pre-wrap;word-break:break-word">'+esc(JSON.stringify(latest,null,2))+'</pre></body></html>');w.document.close()});
</script>
</body></html>
'''


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="127.0.0.1", port=8000, reload=True)
