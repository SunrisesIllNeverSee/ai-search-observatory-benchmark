#!/usr/bin/env python3
"""Semrush adapter for the AI Search Observatory Benchmark.

Pulls real backlink and domain data from the Semrush MCP API and writes
it into data/external_metrics.json so the benchmark uses real numbers
instead of nulls.

Usage:
    SEMRUSH_API_KEY=your_key python3 scripts/semrush_adapter.py

Reads the API key from the SEMRUSH_API_KEY environment variable.
Never writes the key to any file.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
SITES_CFG = ROOT / "config" / "sites.json"
MCP_URL = "https://mcp.semrush.com/v2/mcp"
_mcp_id = 0


def _next_id():
    global _mcp_id
    _mcp_id += 1
    return _mcp_id


def mcp_call(api_key, method, params):
    """Call a Semrush MCP tool and return the text content."""
    payload = json.dumps({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": params,
        "id": _next_id(),
    }).encode()
    req = urllib.request.Request(
        MCP_URL,
        data=payload,
        headers={
            "Authorization": f"Apikey {api_key}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}: {e.read().decode()[:200]}"
    except Exception as e:
        return f"ERROR: {e}"

    if "error" in body:
        return f"ERROR: {body['error']}"
    if "result" in body and "content" in body["result"]:
        for item in body["result"]["content"]:
            if item.get("type") == "text":
                return item["text"]
    return "NO CONTENT"


def parse_csv(text):
    """Parse Semrush semicolon-delimited response into list of dicts."""
    lines = text.strip().split("\n")
    if len(lines) < 2:
        return []
    headers = lines[0].split(";")
    rows = []
    for line in lines[1:]:
        vals = line.split(";")
        if len(vals) == len(headers):
            rows.append(dict(zip(headers, vals)))
    return rows


def fetch_backlinks_overview(api_key, domain):
    """Returns dict: total, domains_num, ips_num, follows_num, nofollows_num, etc."""
    result = mcp_call(api_key, "tools/call", {
        "name": "execute_report",
        "arguments": {
            "report": "backlinks_overview",
            "params": {"target": domain, "target_type": "root_domain"}
        }
    })
    rows = parse_csv(result)
    return rows[0] if rows else {}


def fetch_referring_domains(api_key, domain, limit=50):
    """Returns list of referring domain dicts."""
    result = mcp_call(api_key, "tools/call", {
        "name": "execute_report",
        "arguments": {
            "report": "backlinks_refdomains",
            "params": {
                "target": domain,
                "target_type": "root_domain",
                "display_limit": limit,
                "display_sort": "backlinks_num_desc",
            }
        }
    })
    return parse_csv(result)


def fetch_domain_rank(api_key, domain):
    """Returns dict: rank, organic_keywords, organic_traffic, etc. or empty."""
    result = mcp_call(api_key, "tools/call", {
        "name": "execute_report",
        "arguments": {
            "report": "domain_rank",
            "params": {"target": domain, "database": "us"}
        }
    })
    if "ERROR" in result or "NOTHING FOUND" in result:
        return {}
    rows = parse_csv(result)
    return rows[0] if rows else {}


def fetch_organic_keywords(api_key, domain, limit=20):
    """Returns list of organic keyword dicts the domain ranks for."""
    result = mcp_call(api_key, "tools/call", {
        "name": "execute_report",
        "arguments": {
            "report": "resource_organic",
            "params": {"target": domain, "database": "us", "display_limit": limit}
        }
    })
    if "ERROR" in result or "NOTHING FOUND" in result:
        return []
    return parse_csv(result)


def fetch_backlink_competitors(api_key, domain, limit=10):
    """Returns list of backlink competitor domains."""
    result = mcp_call(api_key, "tools/call", {
        "name": "execute_report",
        "arguments": {
            "report": "backlinks_competitors",
            "params": {
                "target": domain,
                "target_type": "root_domain",
                "display_limit": limit,
            }
        }
    })
    if "ERROR" in result or "NOTHING FOUND" in result:
        return []
    return parse_csv(result)


def main():
    api_key = os.environ.get("SEMRUSH_API_KEY")
    if not api_key:
        print("ERROR: Set SEMRUSH_API_KEY environment variable.")
        sys.exit(1)

    sites = json.loads(SITES_CFG.read_text())["sites"]
    metrics = json.loads((DATA / "external_metrics.json").read_text())

    for site in sites:
        sid = site["id"]
        domain = site["domain"]
        print(f"Fetching Semrush data for {domain} ...", flush=True)

        bl = fetch_backlinks_overview(api_key, domain)
        ref_domains = fetch_referring_domains(api_key, domain)
        rank = fetch_domain_rank(api_key, domain)
        organic_kw = fetch_organic_keywords(api_key, domain)
        competitors = fetch_backlink_competitors(api_key, domain)

        site_data = metrics.get("sites", {}).get(sid, {})

        # Backlink metrics
        site_data["referring_domains"] = int(bl.get("domains_num", 0)) if bl.get("domains_num") else 0
        site_data["linked_mentions"] = int(bl.get("total", 0)) if bl.get("total") else 0
        site_data["unlinked_mentions"] = int(bl.get("nofollows_num", 0)) if bl.get("nofollows_num") else 0

        # Domain rank (organic search visibility)
        if rank:
            site_data["source_visibility"] = int(rank.get("Organic Keywords", 0)) if rank.get("Organic Keywords") else 0
            site_data["share_of_voice"] = int(rank.get("Organic Traffic", 0)) if rank.get("Organic Traffic") else 0
        else:
            site_data["source_visibility"] = 0
            site_data["share_of_voice"] = 0

        # Store detailed Semrush evidence
        site_data["_semrush_referring_domains"] = [
            {"domain": r.get("domain", ""), "backlinks": r.get("backlinks_num", "0"),
             "authority_score": r.get("domain_score", "0")}
            for r in ref_domains[:20]
        ]
        site_data["_semrush_backlinks_total"] = int(bl.get("total", 0)) if bl.get("total") else 0
        site_data["_semrush_authority_score"] = int(bl.get("score", 0)) if bl.get("score") else 0
        site_data["_semrush_follow_links"] = int(bl.get("follows_num", 0)) if bl.get("follows_num") else 0
        site_data["_semrush_nofollow_links"] = int(bl.get("nofollows_num", 0)) if bl.get("nofollows_num") else 0
        site_data["_semrush_referring_ips"] = int(bl.get("ips_num", 0)) if bl.get("ips_num") else 0

        # Organic keywords
        site_data["_semrush_organic_keywords"] = [
            {"keyword": kw.get("Keyword", ""), "position": kw.get("Position", ""),
             "volume": kw.get("Search Volume", ""), "url": kw.get("Url", "")}
            for kw in organic_kw[:20]
        ]

        # Backlink competitors
        site_data["_semrush_backlink_competitors"] = [
            {"domain": c.get("neighbour", ""), "similarity": c.get("similarity", ""),
             "common_refdomains": c.get("common_refdomains", "")}
            for c in competitors[:10]
        ]

        metrics["sites"][sid] = site_data
        kw_count = len(organic_kw)
        comp_count = len(competitors)
        print(f"  {bl.get('total', '?')} backlinks, {bl.get('domains_num', '?')} ref domains, "
              f"auth {bl.get('score', '?')}, {kw_count} organic keywords, {comp_count} competitors",
              flush=True)

    metrics["_semrush_fetched_at"] = __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc).isoformat()

    (DATA / "external_metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"\nWrote real Semrush data to {DATA / 'external_metrics.json'}")


if __name__ == "__main__":
    main()
