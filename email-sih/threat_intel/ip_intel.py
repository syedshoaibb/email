"""
ip_intel.py
-----------
Enrichment layer: given a public IP, fetch

  1. Geolocation / ASN / ISP info      -> ip-api.com (free tier, no key)
  2. Abuse reputation                  -> AbuseIPDB v2 /check (needs API key)

Results are cached in-memory for the life of the process so repeated
lookups (e.g. multiple emails from the same sending server) don't burn
API quota. Swap `_CACHE` for Redis in production.

Set the AbuseIPDB key via env var: ABUSEIPDB_API_KEY
"""

import os
import time
import httpx
from dataclasses import dataclass, asdict
from typing import Optional

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
GEO_URL = "http://ip-api.com/json/{ip}"
GEO_FIELDS = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"

_CACHE: dict[str, dict] = {}
_CACHE_TTL_SECONDS = 60 * 30  # 30 min


def _cache_get(key: str) -> Optional[dict]:
    entry = _CACHE.get(key)
    if not entry:
        return None
    if time.time() - entry["_ts"] > _CACHE_TTL_SECONDS:
        _CACHE.pop(key, None)
        return None
    return entry["data"]


def _cache_set(key: str, data: dict):
    _CACHE[key] = {"_ts": time.time(), "data": data}


@dataclass
class GeoInfo:
    ip: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    is_proxy: bool = False
    is_hosting: bool = False
    is_mobile: bool = False
    error: Optional[str] = None


@dataclass
class AbuseInfo:
    ip: str
    abuse_confidence_score: int = 0
    total_reports: int = 0
    num_distinct_users: int = 0
    last_reported_at: Optional[str] = None
    is_whitelisted: Optional[bool] = None
    is_tor: bool = False
    usage_type: Optional[str] = None
    domain: Optional[str] = None
    error: Optional[str] = None


async def get_geolocation(ip: str, client: httpx.AsyncClient) -> GeoInfo:
    cached = _cache_get(f"geo:{ip}")
    if cached:
        return GeoInfo(**cached)

    try:
        resp = await client.get(GEO_URL.format(ip=ip), params={"fields": GEO_FIELDS}, timeout=8)
        data = resp.json()
        if data.get("status") != "success":
            info = GeoInfo(ip=ip, error=data.get("message", "lookup failed"))
        else:
            info = GeoInfo(
                ip=ip,
                country=data.get("country"),
                country_code=data.get("countryCode"),
                region=data.get("regionName"),
                city=data.get("city"),
                lat=data.get("lat"),
                lon=data.get("lon"),
                isp=data.get("isp"),
                org=data.get("org"),
                asn=data.get("as"),
                is_proxy=bool(data.get("proxy")),
                is_hosting=bool(data.get("hosting")),
                is_mobile=bool(data.get("mobile")),
            )
    except Exception as e:
        info = GeoInfo(ip=ip, error=str(e))

    _cache_set(f"geo:{ip}", asdict(info))
    return info


async def get_abuse_reputation(ip: str, client: httpx.AsyncClient) -> AbuseInfo:
    cached = _cache_get(f"abuse:{ip}")
    if cached:
        return AbuseInfo(**cached)

    if not ABUSEIPDB_API_KEY:
        info = AbuseInfo(ip=ip, error="ABUSEIPDB_API_KEY not configured")
        _cache_set(f"abuse:{ip}", asdict(info))
        return info

    try:
        resp = await client.get(
            ABUSEIPDB_URL,
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=8,
        )
        payload = resp.json().get("data", {})
        if not payload:
            info = AbuseInfo(ip=ip, error=resp.text[:200])
        else:
            info = AbuseInfo(
                ip=ip,
                abuse_confidence_score=payload.get("abuseConfidenceScore", 0),
                total_reports=payload.get("totalReports", 0),
                num_distinct_users=payload.get("numDistinctUsers", 0),
                last_reported_at=payload.get("lastReportedAt"),
                is_whitelisted=payload.get("isWhitelisted"),
                is_tor=payload.get("isTor", False),
                usage_type=payload.get("usageType"),
                domain=payload.get("domain"),
            )
    except Exception as e:
        info = AbuseInfo(ip=ip, error=str(e))

    _cache_set(f"abuse:{ip}", asdict(info))
    return info


async def enrich_ip(ip: str, client: httpx.AsyncClient) -> dict:
    """Runs both lookups concurrently and returns a combined dict."""
    import asyncio

    geo, abuse = await asyncio.gather(
        get_geolocation(ip, client),
        get_abuse_reputation(ip, client),
    )
    return {"geo": asdict(geo), "abuse": asdict(abuse)}
