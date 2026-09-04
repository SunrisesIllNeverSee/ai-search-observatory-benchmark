#!/usr/bin/env python3
"""Traffic adapter for the AI Search Observatory Benchmark.

Pulls real traffic/visitor data from three sources:
1. Vercel CLI — request counts for Vercel-hosted projects
2. Cloudflare API — request/visitor counts for Cloudflare-managed zones
3. PostHog — web analytics overview, top pages, referring domains

PostHog is supported via two modes:
  a) Direct API mode — set POSTHOG_PERSONAL_API_KEY and POSTHOG_PROJECT_ID
     env vars. The adapter calls the PostHog REST API directly.
  b) Cache file mode — if a JSON file is passed via --posthog-file (or the
     default data/_posthog_cache.json exists), the adapter reads pre-fetched
     data from it. This is useful when an orchestrating agent fetches PostHog
     data via MCP and writes it to the cache file before running the adapter.

Writes results into data/external_metrics.json so the benchmark uses
real traffic numbers instead of nulls.

Usage:
    python3 scripts/traffic_adapter.py
    python3 scripts/traffic_adapter.py --posthog-file /path/to/posthog.json
    POSTHOG_PERSONAL_API_KEY=xxx POSTHOG_PROJECT_ID=123 python3 scripts/traffic_adapter.py

Reads Cloudflare OAuth token from wrangler config. Uses vercel CLI
(assumes authenticated).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone, timedelta

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
SITES_CFG = ROOT / "config" / "sites.json"

# Map site IDs to their hosting platform
VERCEL_PROJECTS = {
    "signomy-xyz": "agent-universe",
    "signalaf-com": "sigrank-app",
    "mos2es-xyz": "application-hub",
}

CLOUDFLARE_ZONES = {
    "mos2es-org": "d3fa790d740b94fea2395cd6348162fc",
    "sigeconomy-com": "451ccf3ac9ae20feb61820442a6233b8",
}

# PostHog tracks signalaf.com (the sigrank-app project)
POSTHOG_SITE = "signalaf-com"

# PostHog API endpoints
POSTHOG_API_BASE = "https://us.posthog.com"
POSTHOG_DEFAULT_CACHE = DATA / "_posthog_cache.json"


def get_vercel_request_count(project: str, days: int = 30) -> dict:
    """Pull request count from Vercel CLI metrics."""
    try:
        result = subprocess.run(
            ["vercel", "metrics", "vercel.request.count", "-p", project,
             "--since", f"{days}d", "-g", "1d", "--format", "json"],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout
        # Strip CLI header lines before JSON
        json_start = output.find("{")
        if json_start < 0:
            return {}
        data = json.loads(output[json_start:])
        summary = data.get("summary", [{}])[0]
        total = summary.get("vercel_request_count_sum", 0)
        return {"requests_30d": total, "daily_avg": total // days if days else 0}
    except Exception as e:
        print(f"  Vercel error for {project}: {e}", file=sys.stderr)
        return {}


def get_cloudflare_analytics(zone_id: str, days: int = 30) -> dict:
    """Pull analytics from Cloudflare GraphQL API."""
    config_path = Path.home() / "Library/Preferences/.wrangler/config/default.toml"
    if not config_path.exists():
        return {}
    token = None
    for line in config_path.read_text().splitlines():
        if line.startswith("oauth_token"):
            token = line.split('"')[1]
            break
    if not token:
        return {}

    until = datetime.now(timezone.utc)
    since = until - timedelta(days=days)
    since_str = since.strftime("%Y-%m-%d")
    until_str = until.strftime("%Y-%m-%d")

    query = json.dumps({
        "query": f'query {{ viewer {{ zones(filter: {{zoneTag: "{zone_id}"}}) {{ httpRequests1dGroups(limit: {days}, filter: {{date_geq: "{since_str}", date_leq: "{until_str}"}}) {{ sum {{ requests bytes }} uniq {{ uniques }} }} }} }} }}'
    }).encode()

    req = urllib.request.Request(
        "https://api.cloudflare.com/client/v4/graphql",
        data=query,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        zones = data.get("data", {}).get("viewer", {}).get("zones", [])
        if not zones:
            return {}
        groups = zones[0].get("httpRequests1dGroups", [])
        total_req = sum(g["sum"]["requests"] for g in groups)
        total_bytes = sum(g["sum"]["bytes"] for g in groups)
        total_uniq = sum(g["uniq"]["uniques"] for g in groups)
        return {
            "requests_30d": total_req,
            "unique_visitors_30d": total_uniq,
            "bandwidth_30d_mb": round(total_bytes / 1e6, 1),
            "daily_avg_requests": total_req // days if days else 0,
            "daily_avg_uniques": total_uniq // days if days else 0,
        }
    except Exception as e:
        print(f"  Cloudflare error for {zone_id}: {e}", file=sys.stderr)
        return {}


# ---------------------------------------------------------------------------
# PostHog adapter — direct API mode + cache file fallback
# ---------------------------------------------------------------------------

def _posthog_api_request(api_key: str, project_id: str, query_body: dict) -> dict | None:
    """Call the PostHog query API and return the response JSON, or None on error."""
    url = f"{POSTHOG_API_BASE}/api/projects/{project_id}/query/"
    payload = json.dumps(query_body).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"  PostHog API HTTP {e.code}: {e.read().decode()[:200]}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  PostHog API error: {e}", file=sys.stderr)
        return None


def fetch_posthog_via_api(api_key: str, project_id: str, days: int = 30) -> dict:
    """Fetch PostHog web analytics via the REST API.

    Returns a dict in the cache-file format:
    {visitors_30d, pageviews_30d, sessions_30d, avg_session_duration_s,
     bounce_rate_pct, top_pages: [...], referring_domains: [...]}
    """
    date_from = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")

    # 1. Web overview query — visitors, pageviews, sessions, bounce rate, session duration
    overview_body = {
        "kind": "WebOverviewQuery",
        "dateRange": {"date_from": date_from},
    }
    overview_resp = _posthog_api_request(api_key, project_id, overview_body)
    if not overview_resp or "results" not in overview_resp:
        return {}

    result = {}
    for metric in overview_resp["results"]:
        key = metric.get("key", "")
        val = metric.get("value")
        if val is None:
            continue
        if key == "visitors":
            result["visitors_30d"] = int(val)
        elif key == "views":
            result["pageviews_30d"] = int(val)
        elif key == "sessions":
            result["sessions_30d"] = int(val)
        elif key == "session duration":
            result["avg_session_duration_s"] = round(float(val), 1)
        elif key == "bounce rate":
            result["bounce_rate_pct"] = round(float(val), 1)

    # 2. Top pages breakdown
    pages_body = {
        "kind": "WebStatsTableQuery",
        "breakdownBy": "Page",
        "dateRange": {"date_from": date_from},
        "limit": 15,
    }
    pages_resp = _posthog_api_request(api_key, project_id, pages_body)
    if pages_resp and "results" in pages_resp:
        top_pages = []
        for row in pages_resp["results"]:
            # Format: [path, [visitors, prev], [views, prev], share, ...]
            path = row[0]
            visitors = row[1][0] if isinstance(row[1], list) else row[1]
            views = row[2][0] if isinstance(row[2], list) else row[2]
            top_pages.append({"path": path, "visitors": visitors, "views": views})
        result["top_pages"] = top_pages

    # 3. Referring domains breakdown
    ref_body = {
        "kind": "WebStatsTableQuery",
        "breakdownBy": "InitialReferringDomain",
        "dateRange": {"date_from": date_from},
        "limit": 15,
    }
    ref_resp = _posthog_api_request(api_key, project_id, ref_body)
    if ref_resp and "results" in ref_resp:
        ref_domains = []
        for row in ref_resp["results"]:
            domain = row[0]
            visitors = row[1][0] if isinstance(row[1], list) else row[1]
            views = row[2][0] if isinstance(row[2], list) else row[2]
            ref_domains.append({"domain": domain, "visitors": visitors, "views": views})
        result["referring_domains"] = ref_domains

    return result


def get_posthog_analytics(posthog_file: Path | None = None) -> dict:
    """Pull web analytics from PostHog.

    Tries direct API mode first (if POSTHOG_PERSONAL_API_KEY is set),
    then falls back to the cache file.
    """
    # Mode 1: Direct API call
    api_key = os.environ.get("POSTHOG_PERSONAL_API_KEY")
    project_id = os.environ.get("POSTHOG_PROJECT_ID")
    if api_key and project_id:
        print("  PostHog: fetching via REST API ...", flush=True)
        data = fetch_posthog_via_api(api_key, project_id)
        if data:
            # Write to cache for future use
            cache_path = posthog_file or POSTHOG_DEFAULT_CACHE
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(json.dumps(data, indent=2))
            return data
        print("  PostHog: API call failed, falling back to cache ...", file=sys.stderr)

    # Mode 2: Cache file
    cache_path = posthog_file or POSTHOG_DEFAULT_CACHE
    if cache_path.exists():
        print(f"  PostHog: reading from cache {cache_path.name} ...", flush=True)
        return json.loads(cache_path.read_text())
    return {}


def main():
    ap = argparse.ArgumentParser(description="Traffic adapter for AI Search Observatory")
    ap.add_argument("--posthog-file", type=Path, default=None,
                    help="Path to a PostHog JSON cache file (alternative to POSTHOG_PERSONAL_API_KEY)")
    args = ap.parse_args()

    sites = json.loads(SITES_CFG.read_text())["sites"]
    metrics_path = DATA / "external_metrics.json"
    metrics = json.loads(metrics_path.read_text()) if metrics_path.exists() else {"sites": {}}

    # PostHog data (via API or cache)
    posthog_data = get_posthog_analytics(args.posthog_file)

    for site in sites:
        sid = site["id"]
        domain = site["domain"]
        print(f"Fetching traffic data for {domain} ...", flush=True)

        site_data = metrics.get("sites", {}).get(sid, {})
        traffic = {}

        # Vercel
        if sid in VERCEL_PROJECTS:
            proj = VERCEL_PROJECTS[sid]
            print(f"  Vercel project: {proj}", flush=True)
            vdata = get_vercel_request_count(proj)
            if vdata:
                traffic["vercel"] = vdata
                # Use Vercel request count as referral_traffic proxy
                site_data["referral_traffic"] = vdata.get("requests_30d", 0)

        # Cloudflare
        if sid in CLOUDFLARE_ZONES:
            zid = CLOUDFLARE_ZONES[sid]
            print(f"  Cloudflare zone: {zid[:12]}...", flush=True)
            cdata = get_cloudflare_analytics(zid)
            if cdata:
                traffic["cloudflare"] = cdata
                site_data["referral_traffic"] = cdata.get("requests_30d", 0)

        # PostHog (only for the tracked site)
        if sid == POSTHOG_SITE and posthog_data:
            traffic["posthog"] = posthog_data
            # PostHog gives us the most accurate visitor/session data
            site_data["referral_traffic"] = posthog_data.get("pageviews_30d", 0)

        site_data["_traffic_sources"] = traffic

        # Print summary
        if traffic:
            parts = []
            for src, d in traffic.items():
                req = d.get("requests_30d", d.get("pageviews_30d", "?"))
                parts.append(f"{src}={req}")
            print(f"  Traffic: {', '.join(parts)}", flush=True)
        else:
            print(f"  No traffic source configured", flush=True)

        metrics["sites"][sid] = site_data

    metrics["_traffic_fetched_at"] = datetime.now(timezone.utc).isoformat()
    metrics_path.write_text(json.dumps(metrics, indent=2))
    print(f"\nWrote traffic data to {metrics_path}")


if __name__ == "__main__":
    main()
