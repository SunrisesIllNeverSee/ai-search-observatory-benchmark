#!/usr/bin/env python3
"""AI Search Observatory Benchmark — v0.2

v0.2 hardening additions:
- Evidence Coverage + Measurement Confidence + coverage threshold gate
- Multi-page crawl (sitemap URL parsing + inspection)
- Semantic JSON-LD validation (not just json.loads)
- Framework/Schema profile + version marker reading from HTML meta tags
- Search Authority adapter (replaces manual ai_responses.json)
- Per-metric/family comparison (not just combined score)
- Regression thresholds and alerts
- Ello Control observation publishing (satellite inbox)
- Scheduling support (launchd plist install)
"""
from __future__ import annotations

import argparse, json, os, re, ssl, sys, time, hashlib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parent
CONFIG = ROOT / "config"
DATA = ROOT / "data"
RUNS = ROOT / "runs"

# Ello Control satellite inbox (for observation publishing)
ELLO_CONTROL_PATH = Path(os.environ.get(
    "ELLO_CONTROL_PATH",
    str(Path.home() / "Developer" / "_control" / "ello-repo-control")
))
ELLO_SATELLITE_INBOX = ELLO_CONTROL_PATH / "artifacts" / "satellite_inbox"

# Search Authority path (for SA adapter)
SA_PATH = Path(os.environ.get(
    "SEARCH_AUTHORITY_PATH",
    str(Path.home() / "Developer" / "_control" / "search-authority")
))

# v0.2 coverage threshold — combined score is NOT authoritative below this
COVERAGE_THRESHOLD = 60.0

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

def load_json(path, default=None):
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        return default if default is not None else {}

def dump_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=False))

class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title = ""
        self._in_title = False
        self.h1 = []
        self.headings = []
        self.links = []
        self.meta = {}
        self.canonical = None
        self.jsonld = []
        self._jsonld = False
        self._jsonld_buf = []
        self.text_parts = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        d = {k:(v or "") for k,v in attrs}
        tag = tag.lower()
        if tag in ("script","style","noscript"):
            self._skip += 1
        if tag == "title":
            self._in_title = True
        if tag in ("h1","h2","h3"):
            self.headings.append(tag)
        if tag == "a" and d.get("href"):
            self.links.append(d["href"])
        if tag == "meta":
            key = (d.get("name") or d.get("property") or "").lower()
            if key:
                self.meta[key] = d.get("content","")
        if tag == "link" and d.get("rel","").lower() == "canonical":
            self.canonical = d.get("href")
        if tag == "script" and d.get("type","").lower() == "application/ld+json":
            self._jsonld = True
            self._jsonld_buf = []

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        if tag == "script" and self._jsonld:
            self.jsonld.append("".join(self._jsonld_buf).strip())
            self._jsonld = False
        if tag in ("script","style","noscript") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        if self._jsonld:
            self._jsonld_buf.append(data)
        if not self._skip:
            txt = " ".join(data.split())
            if txt:
                self.text_parts.append(txt)

def header_get(headers, name):
    """Case-insensitive HTTP header lookup (HTTP headers are case-insensitive)."""
    name_l = name.lower()
    for k, v in (headers or {}).items():
        if k.lower() == name_l:
            return v
    return None

def fetch(url, timeout, user_agent):
    req = Request(url, headers={"User-Agent": user_agent, "Accept":"text/html,application/xhtml+xml,*/*;q=0.8"})
    try:
        with urlopen(req, timeout=timeout, context=ssl.create_default_context()) as r:
            body = r.read(2_000_000)
            return {"ok":True, "status":r.getcode(), "url":r.geturl(),
                    "headers":dict(r.headers.items()),
                    "body":body.decode("utf-8","replace")}
    except HTTPError as e:
        body = e.read(300_000).decode("utf-8","replace") if hasattr(e, "read") else ""
        return {"ok":False, "status":e.code, "url":url, "headers":dict(e.headers.items()) if e.headers else {}, "body":body, "error":str(e)}
    except Exception as e:
        return {"ok":False, "status":None, "url":url, "headers":{}, "body":"", "error":repr(e)}

def robot_rules(text):
    """Parse robots.txt into ``[(agents, rules)]`` groups per RFC 9309 §2.2.1.

    Groups are separated by blank lines. Consecutive ``User-agent`` lines
    belong to the same group; a ``User-agent`` line appearing after rules
    have been collected starts a new group. Empty named groups (a
    ``User-agent`` with no following ``Allow``/``Disallow``) are preserved
    so :func:`crawler_blocked` can honor group precedence.
    """
    groups = []
    current_agents = []
    current_rules = []
    for raw in text.splitlines():
        line = raw.split("#",1)[0].strip()
        if not line:
            # Blank line separates groups (RFC 9309 §2.2.1). Flush even an
            # empty named group so its precedence is preserved.
            if current_agents or current_rules:
                groups.append((current_agents, current_rules))
                current_agents = []
                current_rules = []
            continue
        if ":" not in line:
            continue
        k,v = [x.strip() for x in line.split(":",1)]
        kl = k.lower()
        if kl == "user-agent":
            # A User-agent line after rules have been collected starts a
            # new group (handles files that omit blank-line separators).
            if current_rules:
                groups.append((current_agents, current_rules))
                current_agents = []
                current_rules = []
            current_agents.append(v)
        elif kl in ("disallow","allow"):
            current_rules.append((kl,v))
        elif kl == "sitemap":
            pass
    if current_agents or current_rules:
        groups.append((current_agents, current_rules))
    return groups

def crawler_blocked(text, bot):
    """Return True if `bot` is disallowed from `/` per RFC 9309 group precedence.

    A named bot's own group (even if empty) takes precedence over the `*`
    group. Within the selected group, ``Allow: /`` wins over ``Disallow: /``
    on a tie (RFC 9309 §2.2.2).
    """
    bot_l = bot.lower()
    groups = robot_rules(text)
    specific_rules = None
    wildcard_rules = None
    for agents, rules in groups:
        agent_names = [a.strip().lower() for a in agents]
        if bot_l in agent_names:
            specific_rules = rules
            break
        if "*" in agent_names and wildcard_rules is None:
            wildcard_rules = rules
    rules = specific_rules if specific_rules is not None else wildcard_rules
    if rules is None:
        return False
    has_disallow_root = any(kind == "disallow" and path == "/" for kind, path in rules)
    has_allow_root = any(kind == "allow" and path == "/" for kind, path in rules)
    return has_disallow_root and not has_allow_root

def parse_jsonld(blobs):
    parsed, errors = [], []
    for b in blobs:
        if not b:
            continue
        try:
            parsed.append(json.loads(b))
        except Exception as e:
            errors.append(str(e))
    return parsed, errors

def schema_types(parsed):
    out = set()
    def walk(x):
        if isinstance(x, dict):
            t = x.get("@type")
            if isinstance(t, str): out.add(t)
            elif isinstance(t, list): out.update(str(i) for i in t)
            for v in x.values(): walk(v)
        elif isinstance(x, list):
            for v in x: walk(v)
    walk(parsed)
    return sorted(out)

# ============================================================================
# v0.2: Semantic JSON-LD validation
# ============================================================================

# Minimal required-property sets for common schema.org types.
# This is NOT a full schema.org validator — it catches the most common
# semantic errors: missing required fields, wrong value types, and
# @context pointing at the wrong vocabulary.
SCHEMA_REQUIRED_PROPS = {
    "Organization": {"name"},
    "Person": {"name"},
    "WebSite": {"name", "url"},
    "WebPage": {"name"},
    "Article": {"headline", "author", "datePublished"},
    "ScholarlyArticle": {"headline", "author", "datePublished"},
    "Dataset": {"name"},
    "SoftwareApplication": {"name"},
    "WebApplication": {"name"},
    "Brand": {"name"},
    "Service": {"name"},
    "FAQPage": {"mainEntity"},
    "Question": {"name", "acceptedAnswer"},
    "Answer": {"text"},
    "Offer": {"price", "priceCurrency"},
    "ItemList": {"itemListElement"},
    "SearchAction": {"target", "query-input"},
    "ContactPoint": {"contactType"},
    "PostalAddress": {"addressCountry", "addressLocality"},
    "CreativeWork": {"name"},
    "DefinedTerm": {"name"},
    "DataDownload": {"name"},
    "PropertyValue": {"name"},
    "Thing": {"name"},
    "ListItem": {"position"},
}

def validate_jsonld_semantic(parsed_blocks):
    """Validate JSON-LD blocks semantically beyond just json.loads().

    Checks:
    - @context is present and points at schema.org (if @type is a schema.org type)
    - Required properties per @type are present
    - @type values are non-empty strings
    - @id, if present, is a valid http(s) URL

    Returns (valid_count, errors) where errors is a list of dicts:
    {"type": ..., "error": ..., "detail": ...}
    """
    errors = []
    valid_count = 0

    def check_block(block, path=""):
        nonlocal valid_count
        if isinstance(block, list):
            for i, item in enumerate(block):
                check_block(item, f"{path}[{i}]")
            return
        if not isinstance(block, dict):
            return

        # Snapshot error count BEFORE this block's own checks so a block
        # with any error (missing required prop, invalid @id, empty @type,
        # unexpected @context, or errors from nested objects) is not
        # counted as valid.
        block_errors_before = len(errors)

        stype = block.get("@type")
        if stype is None:
            # Graph container or @graph — recurse
            if "@graph" in block:
                check_block(block["@graph"], path + ".@graph")
            return

        # Normalize @type to list for checking
        types = [stype] if isinstance(stype, str) else (stype if isinstance(stype, list) else [])

        # Check @context
        context = block.get("@context", "")
        if context and isinstance(context, str):
            if "schema.org" not in context and "www.w3.org" not in context:
                errors.append({
                    "type": ".".join(types),
                    "error": "unexpected_context",
                    "detail": f"@context points to '{context}', expected schema.org or w3.org"
                })

        # Check required properties per type
        for t in types:
            required = SCHEMA_REQUIRED_PROPS.get(t)
            if required:
                missing = required - set(block.keys())
                if missing:
                    errors.append({
                        "type": t,
                        "error": "missing_required_property",
                        "detail": f"Missing: {', '.join(sorted(missing))}"
                    })

        # Check @type is non-empty
        if isinstance(stype, str) and not stype.strip():
            errors.append({
                "type": "(empty)",
                "error": "empty_type",
                "detail": "@type is an empty string"
            })

        # Check @id is an http(s) URL if present
        sid = block.get("@id")
        if sid and isinstance(sid, str):
            parsed = urlparse(sid)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                errors.append({
                    "type": ".".join(types),
                    "error": "invalid_id",
                    "detail": f"@id '{sid}' is not a valid http(s) URL"
                })

        # Recurse into nested objects
        for k, v in block.items():
            if k.startswith("@"):
                continue
            if isinstance(v, dict):
                check_block(v, f"{path}.{k}")
            elif isinstance(v, list):
                for i, item in enumerate(v):
                    if isinstance(item, dict):
                        check_block(item, f"{path}.{k}[{i}]")

        # Count as valid only if no errors were added for this block
        # (its own checks or its nested objects).
        if len(errors) == block_errors_before:
            valid_count += 1

    for block in parsed_blocks:
        check_block(block)

    return valid_count, errors

# ============================================================================
# v0.2: Framework/Schema profile + version marker reading
# ============================================================================

def read_framework_markers(parser):
    """Read framework/schema profile and version markers from HTML meta tags.

    Expected meta tags:
    - <meta name="ello-framework-profile" content="full-moses">
    - <meta name="ello-framework-version" content="0.1.0">
    - <meta name="ello-schema-profile" content="json-ld-v1">
    - <meta name="ello-schema-version" content="1.2.0">
    - <meta name="ello-canon-version" content="1.2.0">

    Also checks for <link rel="ello-framework" href="..."> if present.
    """
    return {
        "framework_profile": parser.meta.get("ello-framework-profile"),
        "framework_version": parser.meta.get("ello-framework-version"),
        "schema_profile": parser.meta.get("ello-schema-profile"),
        "schema_version": parser.meta.get("ello-schema-version"),
        "canon_version": parser.meta.get("ello-canon-version"),
    }

# ============================================================================
# v0.2: Sitemap URL parsing and multi-page crawl
# ============================================================================

def parse_sitemap_urls(sitemap_body):
    """Parse sitemap.xml and return list of URLs.

    Handles both <urlset> (URL sitemaps) and <sitemapindex> (sitemap of sitemaps).
    For sitemapindex, returns the child sitemap URLs (caller can recurse).
    """
    if not sitemap_body:
        return []
    try:
        root = ET.fromstring(sitemap_body)
    except ET.ParseError:
        return []

    # Strip namespace for easier matching
    def localname(tag):
        return tag.split("}")[-1] if "}" in tag else tag

    urls = []
    for elem in root:
        tag = localname(elem.tag)
        if tag == "url":
            for child in elem:
                if localname(child.tag) == "loc" and child.text:
                    urls.append(child.text.strip())
        elif tag == "sitemap":
            for child in elem:
                if localname(child.tag) == "loc" and child.text:
                    urls.append(child.text.strip())
    return urls

def crawl_pages(base, sitemap_urls, cfg, max_pages=5):
    """Crawl up to max_pages pages from the sitemap.

    Returns a list of per-page results:
    [{"url": ..., "status": ..., "title": ..., "has_jsonld": bool,
      "schema_types": [...], "canonical": ..., "framework_markers": {...}}]
    """
    ua, timeout = cfg["user_agent"], cfg["timeout_seconds"]
    pages = []
    # Filter to same-domain, non-asset URLs
    host = urlparse(base).netloc.lower()
    candidates = []
    for url in sitemap_urls:
        p = urlparse(url)
        if p.netloc.lower() != host:
            continue
        if p.path.endswith((".jpg", ".png", ".gif", ".svg", ".css", ".js", ".pdf")):
            continue
        candidates.append(url)
        if len(candidates) >= max_pages:
            break

    for url in candidates:
        resp = fetch(url, timeout, ua)
        page = {"url": url, "status": resp.get("status"), "ok": resp.get("ok")}
        if resp.get("body"):
            parser = PageParser()
            try:
                parser.feed(resp["body"])
            except Exception:
                pass
            page["title"] = parser.title.strip()
            page["has_jsonld"] = bool(parser.jsonld)
            parsed_ld, _ = parse_jsonld(parser.jsonld)
            page["schema_types"] = schema_types(parsed_ld)
            page["canonical"] = parser.canonical
            page["framework_markers"] = read_framework_markers(parser)
            page["visible_text_chars"] = len(" ".join(parser.text_parts))
        pages.append(page)
    return pages

# ============================================================================
# v0.2: Evidence Coverage + Measurement Confidence
# ============================================================================

# Evidence source quality weights (higher = more trustworthy)
EVIDENCE_QUALITY = {
    "live_crawl": 1.0,      # Direct HTTP fetch — highest confidence
    "sitemap_crawl": 0.9,   # Crawled via sitemap
    "adapter": 0.8,         # Pulled from Semrush/PostHog/SA adapter
    "manual": 0.5,          # Manually edited evidence file
    "inferred": 0.3,        # Inferred from other signals
    "none": 0.0,            # No evidence — unknown
}

def compute_evidence_coverage(steps):
    """Compute evidence coverage: what fraction of playbook steps have real evidence.

    A step is 'covered' if its status is not 'unknown'.
    Returns (coverage_pct, covered_count, total_count).
    """
    total = len(steps)
    covered = sum(1 for s in steps.values() if s.get("status") not in (None, "unknown"))
    pct = round(100 * covered / total, 1) if total else 0.0
    return pct, covered, total

def compute_measurement_confidence(steps, auto, pages_crawled, authority_obs):
    """Compute measurement confidence: how trustworthy is the evidence?

    Weighted by evidence source quality. A step backed by live crawl
    scores higher than one backed by manual entry.

    The `auto` dict provides crawl-derived quality signals:
    - jsonld_semantically_valid: JSON-LD passed semantic validation (not just parse)
    - framework_markers: framework/schema markers were found in HTML meta tags

    Returns confidence_pct (0-100).
    """
    total_weight = 0
    earned_weight = 0

    for n, step in steps.items():
        status = step.get("status")
        if status in (None, "unknown"):
            total_weight += 1.0  # counts as zero earned
            continue

        # Determine evidence source quality for this step
        evidence = step.get("evidence", [])
        ev_str = " ".join(evidence).lower()

        if "live crawl" in ev_str or "homepage" in ev_str or "robots.txt" in ev_str:
            quality = EVIDENCE_QUALITY["live_crawl"]
        elif "sitemap" in ev_str or "internal links" in ev_str:
            quality = EVIDENCE_QUALITY["sitemap_crawl"]
        elif "external_metrics" in ev_str or "ai_responses" in ev_str:
            # If authority observations exist, this is adapter-backed
            quality = EVIDENCE_QUALITY["adapter"] if authority_obs > 0 else EVIDENCE_QUALITY["manual"]
        elif "manual" in ev_str:
            quality = EVIDENCE_QUALITY["manual"]
        elif "benchmark run history" in ev_str:
            quality = EVIDENCE_QUALITY["inferred"]
        elif "config" in ev_str:
            quality = EVIDENCE_QUALITY["manual"]
        elif "semantically validated" in ev_str:
            # v0.2: JSON-LD that passed semantic validation is high-quality evidence
            quality = EVIDENCE_QUALITY["live_crawl"]
        else:
            quality = EVIDENCE_QUALITY["inferred"]

        # Status scaling: complete=1.0, partial=0.5, missing=0.0
        status_scale = {"complete": 1.0, "partial": 0.5, "missing": 0.0,
                       "not_applicable": 1.0}.get(status, 0.0)

        total_weight += 1.0
        earned_weight += quality * status_scale

    # Bonus for multi-page crawl (up to 10% boost)
    crawl_bonus = min(len(pages_crawled) * 0.02, 0.10)

    # v0.2: Quality bonuses from crawl-derived signals in `auto`
    quality_bonus = 0.0
    if auto.get("jsonld_semantically_valid"):
        quality_bonus += 0.03  # semantic validation is higher-quality evidence
    fw_markers = auto.get("framework_markers", {})
    if any(v is not None for v in fw_markers.values()):
        quality_bonus += 0.02  # framework markers found = richer crawl evidence

    confidence = round(100 * (earned_weight / total_weight + crawl_bonus + quality_bonus), 1) if total_weight else 0.0
    return min(confidence, 100.0)

def is_authoritative(coverage_pct, confidence_pct):
    """Determine whether the combined score is authoritative.

    Combined score is NOT authoritative if:
    - Evidence coverage is below COVERAGE_THRESHOLD
    - Measurement confidence is below COVERAGE_THRESHOLD
    """
    return coverage_pct >= COVERAGE_THRESHOLD and confidence_pct >= COVERAGE_THRESHOLD

def status_score(status):
    return {"complete":100,"partial":50,"missing":0,"unknown":None,"not_applicable":None}.get(status)

def avg(vals):
    xs = [x for x in vals if isinstance(x,(int,float))]
    return round(sum(xs)/len(xs),1) if xs else None

def pct(num, den):
    return round(100*num/den,1) if den else None

def evaluate_authority(site_id, ai_data):
    obs = [o for o in ai_data.get("observations",[]) if o.get("site_id")==site_id]
    if not obs:
        return {
            "observations":0,
            "canonical_accuracy_rate":None,
            "claim_match_rate":None,
            "unsupported_claim_rate":None,
            "contradiction_rate":None,
            "stale_information_rate":None,
            "correct_source_attribution_rate":None
        }
    total = len(obs)
    def count(v): return sum(1 for o in obs if o.get("classification")==v)
    src_known = [o for o in obs if o.get("source_attribution_correct") is not None]
    return {
        "observations": total,
        "canonical_accuracy_rate": pct(sum(1 for o in obs if o.get("classification") in ("match","accurate")), total),
        "claim_match_rate": pct(count("match"), total),
        "unsupported_claim_rate": pct(count("unsupported"), total),
        "contradiction_rate": pct(count("contradiction"), total),
        "stale_information_rate": pct(count("stale"), total),
        "correct_source_attribution_rate": pct(sum(1 for o in src_known if o.get("source_attribution_correct") is True), len(src_known))
    }

def classify_step(n, auto, external, manual, authority, history_count):
    m = manual.get(str(n), {})
    if m.get("status"):
        return {"status":m["status"],"evidence":m.get("evidence",[])}

    if n == 1:
        present = any(external.get(k) is not None for k in ("share_of_voice","source_visibility","referral_traffic","ai_visibility"))
        return {"status":"complete" if present else "unknown","evidence":["external_metrics"]}
    if n == 2:
        return {"status":"complete","evidence":["config/benchmark.json targets"]}
    if n == 3:
        return {"status":"complete" if auto["crawler_access_ok"] else "missing","evidence":["robots.txt"]}
    if n == 4:
        checks = [auto["homepage_200"], auto["real_404"], auto["sitemap_present"]]
        return {"status":"complete" if all(checks) else ("partial" if any(checks) else "missing"),"evidence":["live crawl"]}
    if n == 5:
        return {"status":"complete" if authority["observations"]>=5 else ("partial" if authority["observations"] else "unknown"),"evidence":["data/ai_responses.json"]}
    if n == 6:
        return {"status":"complete" if external.get("top_cited_pages") else "unknown","evidence":["external_metrics.top_cited_pages"]}
    if n == 7:
        vals = [external.get("linked_mentions"),external.get("unlinked_mentions"),external.get("referring_domains")]
        return {"status":"complete" if any(v is not None for v in vals) else "unknown","evidence":["external_metrics"]}
    if n == 8:
        checks = [auto["title_present"],auto["meta_description_present"],auto["has_h1"],auto["canonical_present"]]
        return {"status":"complete" if all(checks) else ("partial" if any(checks) else "missing"),"evidence":["homepage"]}
    if n == 9:
        # v0.2: Semantic validation is part of the scoring, not just diagnostics.
        # complete = JSON-LD present, parseable, AND semantically valid
        # partial  = JSON-LD present and parseable but semantically invalid
        # missing  = no JSON-LD or unparseable
        if auto["jsonld_present"] and auto["jsonld_parseable"] and auto.get("jsonld_semantically_valid"):
            return {"status":"complete","evidence":["JSON-LD (semantically validated)"]}
        if auto["jsonld_present"] and auto["jsonld_parseable"]:
            return {"status":"partial","evidence":["JSON-LD (parseable but semantically invalid)"]}
        if auto["jsonld_present"]:
            return {"status":"partial","evidence":["JSON-LD (present but unparseable)"]}
        return {"status":"missing","evidence":[]}
    if n == 10:
        checks = [auto["sitemap_present"],auto["internal_links_count"]>=3]
        return {"status":"complete" if all(checks) else ("partial" if any(checks) else "missing"),"evidence":["sitemap/internal links"]}
    if n == 11:
        return {"status":"partial" if auto["freshness_signal_present"] else "unknown","evidence":["Last-Modified/date metadata"]}
    if n == 12:
        return {"status":"unknown","evidence":[]}
    if n == 13:
        return {"status":"unknown","evidence":[]}
    if n == 14:
        return {"status":"complete" if (external.get("tracked_prompts") or 0)>0 else "unknown","evidence":["tracked prompts"]}
    if n == 15:
        checks = [auto["heading_structure_ok"],auto["visible_text_chars"]>=800]
        return {"status":"complete" if all(checks) else ("partial" if any(checks) else "missing"),"evidence":["HTML structure"]}
    if n == 16:
        checks = [auto["author_signal"],auto["external_links_count"]>0]
        return {"status":"complete" if all(checks) else ("partial" if any(checks) else "unknown"),"evidence":["author/source signals"]}
    if n == 17:
        return {"status":"complete" if (external.get("repurposed_assets") or 0)>0 else "unknown","evidence":["external_metrics.repurposed_assets"]}
    if n == 18:
        return {"status":"complete" if (external.get("referring_domains") or 0)>0 else "unknown","evidence":["external_metrics.referring_domains"]}
    if n == 19:
        return {"status":"partial" if authority["observations"] else "unknown","evidence":["AI response audit"]}
    if n == 20:
        return {"status":"complete" if (external.get("forum_contributions") or 0)>0 else "unknown","evidence":["external_metrics.forum_contributions"]}
    if n == 21:
        return {"status":"complete" if history_count >= 2 else "unknown","evidence":["benchmark run history"]}
    if n == 22:
        return {"status":"complete" if history_count >= 3 else ("partial" if history_count>=1 else "unknown"),"evidence":["benchmark run history"]}
    return {"status":"unknown","evidence":[]}

STEP_NAMES = {
1:"Benchmark current visibility",2:"Set AI visibility targets",3:"Check AI crawler access",4:"Audit crawl/index issues",
5:"Audit what AI says and truthfulness",6:"Audit top AI-cited pages",7:"Audit brand mentions",
8:"Optimize key pages for AI citations",9:"Implement technical/schema foundations",10:"Build crawlable site structure",
11:"Refresh outdated content",12:"Create citeable content formats",13:"Build content hubs",
14:"Map AI prompts/questions",15:"Structure content for AI retrieval",16:"Improve E-E-A-T",
17:"Repurpose across platforms",18:"Build links and brand mentions",19:"Correct third-party misinformation",
20:"Contribute to relevant forums",21:"Review progress against goals",22:"Repeat cycle / maintain momentum"
}

def audit_site(site, cfg, external, ai_data, manual, history_count):
    base = f'{site.get("scheme","https")}://{site["domain"]}'
    ua, timeout = cfg["user_agent"], cfg["timeout_seconds"]
    home = fetch(base + "/", timeout, ua)
    robots = fetch(base + "/robots.txt", timeout, ua)
    sitemap = fetch(base + "/sitemap.xml", timeout, ua)
    llms = fetch(base + "/llms.txt", timeout, ua)
    missing_path = f"/__ello_audit_missing_{hashlib.sha1(str(time.time()).encode()).hexdigest()[:10]}"
    miss = fetch(base + missing_path, timeout, ua)

    parser = PageParser()
    if home.get("body"):
        try: parser.feed(home["body"])
        except Exception: pass

    parsed_ld, ld_errors = parse_jsonld(parser.jsonld)
    types = schema_types(parsed_ld)
    host = urlparse(base).netloc.lower()
    internal, external_links = [], []
    for href in parser.links:
        u = urljoin(base, href)
        p = urlparse(u)
        if p.scheme not in ("http","https"): continue
        if p.netloc.lower() == host: internal.append(u)
        else: external_links.append(u)

    robots_body = robots.get("body","") if robots.get("status")==200 else ""
    blocked = {bot:crawler_blocked(robots_body, bot) for bot in cfg["ai_crawlers"]}
    crawler_ok = robots.get("status") in (200,404) and not any(blocked.values())

    visible_text = " ".join(parser.text_parts)
    meta_keys = set(parser.meta)
    freshness = any(k in meta_keys for k in ("article:published_time","article:modified_time","date","last-modified")) or bool(header_get(home.get("headers",{}), "Last-Modified"))
    author_signal = ("author" in meta_keys
                     or bool(re.search(r"\bwritten by\b", visible_text, re.IGNORECASE))
                     or bool(re.search(r"\bby [A-Z][a-zA-Z.'-]+ [A-Z][a-zA-Z.'-]+\b", visible_text)))

    # v0.2: Semantic JSON-LD validation
    ld_valid_count, ld_semantic_errors = validate_jsonld_semantic(parsed_ld)
    ld_semantically_valid = bool(parser.jsonld) and not ld_errors and not ld_semantic_errors

    # v0.2: Framework/Schema profile + version markers from HTML meta tags
    fw_markers = read_framework_markers(parser)
    # Fall back to config-declared profile if meta tags are absent
    framework_profile = fw_markers["framework_profile"] or site.get("framework_profile")

    # v0.2: Parse sitemap and crawl additional pages
    sitemap_urls = []
    pages_crawled = []
    if sitemap.get("status") == 200 and sitemap.get("body"):
        sitemap_urls = parse_sitemap_urls(sitemap["body"])
        max_pages = cfg.get("max_crawl_pages", 5)
        if sitemap_urls and max_pages > 0:
            pages_crawled = crawl_pages(base, sitemap_urls, cfg, max_pages)

    # Aggregate multi-page schema coverage
    pages_with_jsonld = sum(1 for p in pages_crawled if p.get("has_jsonld"))
    pages_with_canonical = sum(1 for p in pages_crawled if p.get("canonical"))
    all_schema_types = set(types)
    for p in pages_crawled:
        all_schema_types.update(p.get("schema_types", []))

    auto = {
        "homepage_status":home.get("status"),
        "homepage_200":home.get("status")==200,
        "robots_status":robots.get("status"),
        "crawler_blocks":blocked,
        "crawler_access_ok":crawler_ok,
        "sitemap_status":sitemap.get("status"),
        "sitemap_present":sitemap.get("status")==200,
        "sitemap_url_count":len(sitemap_urls),
        "llms_txt_status":llms.get("status"),
        "llms_txt_present":llms.get("status")==200,
        "missing_path_status":miss.get("status"),
        "real_404":miss.get("status") in (404,410),
        "title_present":bool(parser.title.strip()),
        "meta_description_present":bool(parser.meta.get("description")),
        "canonical_present":bool(parser.canonical),
        "has_h1":"h1" in parser.headings,
        "heading_structure_ok":"h1" in parser.headings and any(h in ("h2","h3") for h in parser.headings),
        "visible_text_chars":len(visible_text),
        "internal_links_count":len(set(internal)),
        "external_links_count":len(set(external_links)),
        "jsonld_present":bool(parser.jsonld),
        "jsonld_parseable":bool(parser.jsonld) and not ld_errors,
        "jsonld_semantically_valid":ld_semantically_valid,
        "jsonld_blocks":len(parser.jsonld),
        "jsonld_errors":ld_errors,
        "jsonld_semantic_errors":ld_semantic_errors,
        "jsonld_valid_count":ld_valid_count,
        "schema_types":types,
        "all_schema_types":sorted(all_schema_types),
        "freshness_signal_present":freshness,
        "author_signal":author_signal,
        # v0.2 multi-page crawl data
        "pages_crawled_count":len(pages_crawled),
        "pages_with_jsonld":pages_with_jsonld,
        "pages_with_canonical":pages_with_canonical,
        "pages_crawled":pages_crawled,
        # v0.2 framework/schema markers
        "framework_markers":fw_markers,
    }

    authority = evaluate_authority(site["id"], ai_data)
    site_manual = manual.get("sites",{}).get(site["id"],{})
    steps = {}
    for n in range(1,23):
        steps[str(n)] = {"name":STEP_NAMES[n], **classify_step(n, auto, external, site_manual, authority, history_count)}

    # Family scores use subsets of playbook steps + raw metrics where available.
    family_steps = {
        "visibility":[1,6,14,21],
        "technical":[3,4,8,9,10],
        "content":[11,12,13,15,16],
        "authority":[5,19],
        "offsite":[7,17,18,20]
    }
    family_scores = {}
    for fam, nums in family_steps.items():
        family_scores[fam] = avg([status_score(steps[str(n)]["status"]) for n in nums])

    # If authority observations exist, use their accuracy directly as part of authority family.
    if authority["canonical_accuracy_rate"] is not None:
        family_scores["authority"] = avg([family_scores["authority"], authority["canonical_accuracy_rate"]])

    weighted = []
    weight_total = 0
    for fam,w in cfg["weights"].items():
        sc = family_scores.get(fam)
        if sc is not None:
            weighted.append(sc*w)
            weight_total += w
    combined = round(sum(weighted)/weight_total,1) if weight_total else None

    # v0.2: Evidence coverage + measurement confidence
    coverage_pct, covered_count, total_count = compute_evidence_coverage(steps)
    confidence_pct = compute_measurement_confidence(steps, auto, pages_crawled, authority["observations"])
    authoritative = is_authoritative(coverage_pct, confidence_pct)

    # v0.2: Diagnostic dimensions — now with real framework/schema markers
    framework_status = "complete" if (framework_profile and fw_markers["framework_version"]) else (
        "partial" if framework_profile else "missing"
    )
    schema_status = ("complete" if (auto["jsonld_present"] and auto["jsonld_parseable"] and ld_semantically_valid)
                     else ("partial" if auto["jsonld_present"] else "missing"))
    diagnostics = {
        "framework": {
            "profile": framework_profile,
            "version": fw_markers["framework_version"],
            "status": framework_status,
            "markers_found": any(v is not None for v in fw_markers.values()),
        },
        "schema": {
            "present": auto["jsonld_present"],
            "parseable": auto["jsonld_parseable"],
            "semantically_valid": ld_semantically_valid,
            "types": types,
            "all_schema_types": sorted(all_schema_types),
            "status": schema_status,
            "semantic_errors": ld_semantic_errors,
            "schema_profile": fw_markers["schema_profile"],
            "schema_version": fw_markers["schema_version"],
        },
        "crawl": {
            "sitemap_urls": len(sitemap_urls),
            "pages_crawled": len(pages_crawled),
            "pages_with_jsonld": pages_with_jsonld,
            "pages_with_canonical": pages_with_canonical,
        }
    }

    return {
        "site":site,
        "observed_at":now_iso(),
        "technical":auto,
        "external_metrics":external,
        "authority_metrics":authority,
        "playbook_steps":steps,
        "family_scores":family_scores,
        "diagnostics":diagnostics,
        "combined_score":combined,
        # v0.2 confidence metadata
        "evidence_coverage": {
            "coverage_pct": coverage_pct,
            "covered_steps": covered_count,
            "total_steps": total_count,
        },
        "measurement_confidence": confidence_pct,
        "authoritative": authoritative,
        "benchmark_version": cfg.get("version", "unknown"),
    }

def list_run_dirs():
    if not RUNS.exists(): return []
    return sorted([p for p in RUNS.iterdir() if p.is_dir() and (p/"summary.json").exists()])

def md_score(v):
    return "—" if v is None else f"{v:.1f}"

def build_markdown(result):
    lines = [
        "# AI Search Observatory — Scorecard",
        "",
        f"Observed: `{result['observed_at']}`",
        f"Benchmark version: `{result.get('benchmark_version', 'unknown')}`",
        "",
        "## Estate Summary",
        "",
        "| Site | Combined | Coverage | Confidence | Authoritative | Visibility | Technical | Content | Authority | Off-site |",
        "|---|---:|---:|---:|:---:|---:|---:|---:|---:|---:|"
    ]
    for r in result["sites"]:
        f = r["family_scores"]
        cov = r.get("evidence_coverage", {}).get("coverage_pct", 0)
        conf = r.get("measurement_confidence", 0)
        auth = "YES" if r.get("authoritative") else "**NO**"
        lines.append(f"| {r['site']['domain']} | {md_score(r['combined_score'])} | {md_score(cov)} | {md_score(conf)} | {auth} | {md_score(f['visibility'])} | {md_score(f['technical'])} | {md_score(f['content'])} | {md_score(f['authority'])} | {md_score(f['offsite'])} |")
    lines += ["", f"> **Coverage threshold:** {COVERAGE_THRESHOLD}% — combined scores below this threshold are NOT authoritative.", ""]

    # v0.2: Confidence report
    lines += ["## Evidence Coverage & Confidence", "",
              "| Site | Coverage | Covered Steps | Confidence | Authoritative |",
              "|---|---:|---:|---:|:---:|"]
    for r in result["sites"]:
        cov = r.get("evidence_coverage", {})
        auth = "YES" if r.get("authoritative") else "**NO**"
        lines.append(f"| {r['site']['domain']} | {md_score(cov.get('coverage_pct',0))}% | {cov.get('covered_steps',0)}/{cov.get('total_steps',0)} | {md_score(r.get('measurement_confidence',0))} | {auth} |")
    lines += [""]

    lines += ["## Diagnostic Dimensions", "",
              "Reported alongside the weighted score but not part of it.", "",
              "| Site | Framework | Profile | FW Version | Schema | Semantic | Schema types | Pages crawled |",
              "|---|---|---|---|---|---|---|---:|"]
    for r in result["sites"]:
        d = r["diagnostics"]
        fw = d["framework"]
        sc = d["schema"]
        cr = d.get("crawl", {})
        sem_ok = "PASS" if sc.get("semantically_valid") else ("FAIL" if sc.get("present") else "—")
        lines.append(f"| {r['site']['domain']} | **{fw['status']}** | `{fw['profile'] or '—'}` | `{fw.get('version') or '—'}` | **{sc['status']}** | {sem_ok} | `{', '.join(sc['types']) if sc['types'] else 'none'}` | {cr.get('pages_crawled', 0)} |")
    lines += ["", "## Site Details", ""]
    for r in result["sites"]:
        lines += [f"### {r['site']['domain']}", ""]
        t = r["technical"]
        a = r["authority_metrics"]
        ext = r.get("external_metrics", {})
        lines += [
            f"- Homepage: `{t['homepage_status']}`",
            f"- Real 404: `{t['real_404']}`",
            f"- AI crawler access OK: `{t['crawler_access_ok']}`",
            f"- Sitemap: `{t['sitemap_present']}` ({t.get('sitemap_url_count', 0)} URLs)",
            f"- Pages crawled: `{t.get('pages_crawled_count', 0)}`",
            f"- llms.txt: `{t['llms_txt_present']}`",
            f"- JSON-LD present / parseable / semantic: `{t['jsonld_present']}` / `{t['jsonld_parseable']}` / `{t.get('jsonld_semantically_valid', '—')}`",
            f"- Schema types: `{', '.join(t['schema_types']) if t['schema_types'] else 'none detected'}`",
            f"- Framework markers: `{t.get('framework_markers', {})}`",
            f"- Canonical accuracy rate: `{a['canonical_accuracy_rate'] if a['canonical_accuracy_rate'] is not None else 'unknown'}`",
            "",
            "#### Semrush Metrics",
            "",
            f"- Backlinks: `{ext.get('_semrush_backlinks_total', '—')}`",
            f"- Referring domains: `{ext.get('referring_domains', '—')}`",
            f"- Follow / Nofollow: `{ext.get('_semrush_follow_links', '—')}` / `{ext.get('_semrush_nofollow_links', '—')}`",
            f"- Referring IPs: `{ext.get('_semrush_referring_ips', '—')}`",
            f"- Authority score: `{ext.get('_semrush_authority_score', '—')}`",
            f"- Organic keywords: `{ext.get('source_visibility', '—')}`",
            f"- Organic traffic (est): `{ext.get('share_of_voice', '—')}`",
        ]
        # Traffic data from Vercel/Cloudflare/PostHog
        traffic = ext.get("_traffic_sources", {})
        if traffic:
            lines += ["", "#### Traffic Analytics", ""]
            for src, td in traffic.items():
                lines.append(f"##### {src.title()}")
                lines.append("")
                if src == "vercel":
                    lines.append(f"- Requests (30d): `{td.get('requests_30d', '—')}`")
                    lines.append(f"- Daily avg: `{td.get('daily_avg', '—')}`")
                elif src == "cloudflare":
                    lines.append(f"- Requests (30d): `{td.get('requests_30d', '—')}`")
                    lines.append(f"- Unique visitors (30d): `{td.get('unique_visitors_30d', '—')}`")
                    lines.append(f"- Bandwidth (30d): `{td.get('bandwidth_30d_mb', '—')} MB`")
                    lines.append(f"- Daily avg requests: `{td.get('daily_avg_requests', '—')}`")
                    lines.append(f"- Daily avg uniques: `{td.get('daily_avg_uniques', '—')}`")
                elif src == "posthog":
                    lines.append(f"- Visitors (30d): `{td.get('visitors_30d', '—')}`")
                    lines.append(f"- Pageviews (30d): `{td.get('pageviews_30d', '—')}`")
                    lines.append(f"- Sessions (30d): `{td.get('sessions_30d', '—')}`")
                    lines.append(f"- Avg session duration: `{td.get('avg_session_duration_s', '—')}s`")
                    lines.append(f"- Bounce rate: `{td.get('bounce_rate_pct', '—')}%`")
                    # Top pages
                    top_pages = td.get("top_pages", [])
                    if top_pages:
                        lines += ["", "| Page | Visitors | Views |", "|---|---:|---:|"]
                        for p in top_pages[:10]:
                            lines.append(f"| `{p['path']}` | {p['visitors']} | {p['views']} |")
                    # Referring domains
                    ref_doms = td.get("referring_domains", [])
                    if ref_doms:
                        lines += ["", "| Referring Domain | Visitors | Views |", "|---|---:|---:|"]
                        for rd in ref_doms[:10]:
                            lines.append(f"| `{rd['domain']}` | {rd['visitors']} | {rd['views']} |")
                lines.append("")
        # Organic keyword details
        organic_kw = ext.get("_semrush_organic_keywords", [])
        if organic_kw:
            lines += ["", "##### Organic Keywords", "",
                      "| Keyword | Position | Volume | URL |",
                      "|---|---:|---:|---|"]
            for kw in organic_kw[:10]:
                lines.append(f"| `{kw.get('keyword','')}` | {kw.get('position','—')} | {kw.get('volume','—')} | `{kw.get('url','')}` |")
        # Top referring domains
        ref_domains = ext.get("_semrush_referring_domains", [])
        if ref_domains:
            lines += ["", "##### Top Referring Domains", "",
                      "| Domain | Backlinks | Authority |",
                      "|---|---:|---:|"]
            for rd in ref_domains[:10]:
                lines.append(f"| `{rd.get('domain','')}` | {rd.get('backlinks','—')} | {rd.get('authority_score','—')} |")
        # Backlink competitors
        competitors = ext.get("_semrush_backlink_competitors", [])
        if competitors:
            lines += ["", "##### Backlink Competitors", "",
                      "| Competitor | Similarity | Shared ref domains |",
                      "|---|---:|---:|"]
            for c in competitors[:5]:
                lines.append(f"| `{c.get('domain','')}` | {c.get('similarity','—')} | {c.get('common_refdomains','—')} |")
        lines += ["",
            "| # | Playbook step | Status |",
            "|---:|---|---|"
        ]
        for n in range(1,23):
            s = r["playbook_steps"][str(n)]
            lines.append(f"| {n} | {s['name']} | **{s['status']}** |")
        lines += [""]
    lines += [
        "## Interpretation",
        "",
        "- `unknown` means the benchmark lacks evidence; it does **not** mean failure or success.",
        "- Technical readiness and AI-search visibility remain distinct.",
        f"- **Coverage threshold:** Combined scores are NOT authoritative below {COVERAGE_THRESHOLD}% evidence coverage or measurement confidence.",
        "- `Authoritative: NO` means the combined score should not be cited as a definitive measurement.",
        "- Semantic JSON-LD validation checks required properties per schema.org type, not just JSON parseability.",
        "- Framework/Schema version markers are read from `<meta name='ello-framework-profile'>` etc. in HTML.",
        "- Multi-page crawl inspects up to 5 sitemap URLs beyond the homepage for schema/canonical coverage.",
        "- Run `benchmark.py publish` to write observations to Ello Control satellite inbox.",
        "- Run `sa_adapter.py` to pull Search Authority canon for AI-response verification.",
    ]
    return "\n".join(lines) + "\n"

def command_run(semrush=False, sa=False, traffic=False, posthog_file=None):
    cfg = load_json(CONFIG/"benchmark.json")
    sites_cfg = load_json(CONFIG/"sites.json", {"sites":[]})
    if semrush:
        import subprocess, os
        key = os.environ.get("SEMRUSH_API_KEY")
        if not key:
            print("ERROR: --semrush requires SEMRUSH_API_KEY environment variable.")
            return
        print("Fetching fresh Semrush data ...", flush=True)
        subprocess.run([sys.executable, str(ROOT/"scripts"/"semrush_adapter.py")],
                       env={**os.environ, "SEMRUSH_API_KEY": key}, check=True)
        print()
    if sa:
        import subprocess
        sa_script = ROOT / "scripts" / "sa_adapter.py"
        if sa_script.exists():
            print("Pulling Search Authority canon ...", flush=True)
            subprocess.run([sys.executable, str(sa_script)], check=True)
            print()
        else:
            print("WARNING: sa_adapter.py not found — skipping SA pull.")
    if traffic:
        import subprocess
        traffic_script = ROOT / "scripts" / "traffic_adapter.py"
        if traffic_script.exists():
            print("Fetching traffic data (Vercel/Cloudflare/PostHog) ...", flush=True)
            cmd = [sys.executable, str(traffic_script)]
            if posthog_file:
                cmd += ["--posthog-file", str(posthog_file)]
            subprocess.run(cmd, check=True)
            print()
        else:
            print("WARNING: traffic_adapter.py not found — skipping traffic pull.")
    metrics = load_json(DATA/"external_metrics.json", {"sites":{}})
    ai_data = load_json(DATA/"ai_responses.json", {"observations":[]})
    manual = load_json(DATA/"manual_evidence.json", {"sites":{}})
    history_count = len(list_run_dirs())
    results = []
    for site in sites_cfg["sites"]:
        ext = metrics.get("sites",{}).get(site["id"],{})
        print(f"Auditing {site['domain']} ...", flush=True)
        results.append(audit_site(site,cfg,ext,ai_data,manual,history_count))
    result = {
        "benchmark_version":cfg.get("version"),
        "observed_at":now_iso(),
        "sites":results
    }
    out = RUNS/stamp()
    out.mkdir(parents=True, exist_ok=True)
    dump_json(out/"summary.json", result)
    dump_json(out/"evidence.json", {"sites":[{"site":r["site"],"technical":r["technical"],"authority_metrics":r["authority_metrics"],"diagnostics":r["diagnostics"],"evidence_coverage":r.get("evidence_coverage"),"measurement_confidence":r.get("measurement_confidence")} for r in results]})
    (out/"scorecard.md").write_text(build_markdown(result))
    with (RUNS/"history.jsonl").open("a") as f:
        f.write(json.dumps({"run":out.name,"observed_at":result["observed_at"],
                            "scores":{r["site"]["id"]:r["combined_score"] for r in results},
                            "family_scores":{r["site"]["id"]:r["family_scores"] for r in results},
                            "coverage":{r["site"]["id"]:r.get("evidence_coverage",{}).get("coverage_pct",0) for r in results},
                            "confidence":{r["site"]["id"]:r.get("measurement_confidence",0) for r in results}})+"\n")
    print(f"\nWrote {out}")
    print(out/"scorecard.md")

    # v0.2: Check regression thresholds
    alerts = check_regression_thresholds(result, cfg)
    if alerts:
        print("\n" + "="*60)
        print("REGRESSION ALERTS")
        print("="*60)
        for a in alerts:
            print(f"  [{a['severity'].upper()}] {a['site']}: {a['message']}")
        print("="*60)

def command_compare():
    runs = list_run_dirs()
    if len(runs) < 2:
        print("Need at least two completed runs to compare.")
        return
    a,b = [load_json(p/"summary.json") for p in runs[-2:]]
    amap = {x["site"]["id"]:x for x in a["sites"]}
    bmap = {x["site"]["id"]:x for x in b["sites"]}
    print(f"Comparing {runs[-2].name} -> {runs[-1].name}\n")

    # v0.2: Per-metric comparison, not just combined score
    families = ["visibility", "technical", "content", "authority", "offsite"]
    header = f"{'SITE':25} {'COMBINED':>10} {'COVERAGE':>10} {'CONFIDENCE':>10}"
    for fam in families:
        header += f" {fam[:4].upper():>8}"
    print(header)
    print("-" * len(header))

    for sid, new in bmap.items():
        old = amap.get(sid, {})
        old_combined = old.get("combined_score")
        new_combined = new.get("combined_score")
        old_cov = old.get("evidence_coverage", {}).get("coverage_pct", 0)
        new_cov = new.get("evidence_coverage", {}).get("coverage_pct", 0)
        old_conf = old.get("measurement_confidence", 0)
        new_conf = new.get("measurement_confidence", 0)

        def fmt_delta(old_v, new_v):
            if old_v is None and new_v is None: return "—"
            if old_v is None: return f"+{new_v}"
            if new_v is None: return f"{old_v}→—"
            delta = round(new_v - old_v, 1)
            sign = "+" if delta >= 0 else ""
            return f"{new_v} ({sign}{delta})"

        row = f"{new['site']['domain']:25} {fmt_delta(old_combined, new_combined):>10} {fmt_delta(old_cov, new_cov):>10} {fmt_delta(old_conf, new_conf):>10}"
        for fam in families:
            old_fam = old.get("family_scores", {}).get(fam)
            new_fam = new.get("family_scores", {}).get(fam)
            row += f" {fmt_delta(old_fam, new_fam):>8}"
        print(row)

def check_regression_thresholds(result, cfg):
    """Check for regressions against configured thresholds.

    Config example:
    "regression_thresholds": {
        "combined_score_max_drop": 5.0,
        "coverage_min": 60.0,
        "confidence_min": 50.0
    }
    """
    thresholds = cfg.get("regression_thresholds", {})
    if not thresholds:
        return []

    alerts = []
    runs = list_run_dirs()
    if len(runs) < 2:
        return alerts

    prev = load_json(runs[-2] / "summary.json")
    prev_map = {x["site"]["id"]: x for x in prev.get("sites", [])}

    for r in result["sites"]:
        sid = r["site"]["id"]
        domain = r["site"]["domain"]
        prev_r = prev_map.get(sid, {})

        # Combined score regression
        max_drop = thresholds.get("combined_score_max_drop")
        if max_drop and prev_r.get("combined_score") is not None and r.get("combined_score") is not None:
            drop = prev_r["combined_score"] - r["combined_score"]
            if drop > max_drop:
                alerts.append({
                    "severity": "warning",
                    "site": domain,
                    "message": f"Combined score dropped {drop:.1f} points (threshold: {max_drop})"
                })

        # Coverage regression
        cov_min = thresholds.get("coverage_min")
        if cov_min:
            cov = r.get("evidence_coverage", {}).get("coverage_pct", 0)
            if cov < cov_min:
                alerts.append({
                    "severity": "info",
                    "site": domain,
                    "message": f"Evidence coverage {cov}% below threshold {cov_min}% — score NOT authoritative"
                })

        # Confidence regression
        conf_min = thresholds.get("confidence_min")
        if conf_min:
            conf = r.get("measurement_confidence", 0)
            if conf < conf_min:
                alerts.append({
                    "severity": "info",
                    "site": domain,
                    "message": f"Measurement confidence {conf}% below threshold {conf_min}%"
                })

        # Per-family regression
        fam_threshold = thresholds.get("family_max_drop")
        if fam_threshold:
            for fam, new_score in r.get("family_scores", {}).items():
                old_score = prev_r.get("family_scores", {}).get(fam)
                if old_score is not None and new_score is not None:
                    drop = old_score - new_score
                    if drop > fam_threshold:
                        alerts.append({
                            "severity": "warning",
                            "site": domain,
                            "message": f"{fam} score dropped {drop:.1f} points (threshold: {fam_threshold})"
                        })

    return alerts

# ============================================================================
# v0.2: Ello Control observation publishing
# ============================================================================

def command_publish():
    """Publish latest run observations to Ello Control satellite inbox."""
    runs = list_run_dirs()
    if not runs:
        print("No runs to publish.")
        return

    latest = load_json(runs[-1] / "summary.json")
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # Write to Ello Control satellite inbox
    inbox_dir = ELLO_SATELLITE_INBOX / "ai_search_observatory" / "observations"
    inbox_dir.mkdir(parents=True, exist_ok=True)

    obs_file = inbox_dir / f"obs_{ts}.json"
    observation = {
        "record_id": f"obs_{ts}",
        "repo_id": "ai_search_observatory",
        "record_type": "observation",
        "created_at": now_iso(),
        "observed_at": latest.get("observed_at"),
        "benchmark_version": latest.get("benchmark_version"),
        "run_dir": runs[-1].name,
        "sites": [],
    }

    for r in latest["sites"]:
        site_obs = {
            "site_id": r["site"]["id"],
            "domain": r["site"]["domain"],
            "combined_score": r.get("combined_score"),
            "authoritative": r.get("authoritative", False),
            "evidence_coverage": r.get("evidence_coverage", {}).get("coverage_pct", 0),
            "measurement_confidence": r.get("measurement_confidence", 0),
            "family_scores": r.get("family_scores", {}),
            "diagnostics": {
                "framework": r.get("diagnostics", {}).get("framework", {}).get("status"),
                "schema": r.get("diagnostics", {}).get("schema", {}).get("status"),
                "schema_semantically_valid": r.get("diagnostics", {}).get("schema", {}).get("semantically_valid"),
                "pages_crawled": r.get("diagnostics", {}).get("crawl", {}).get("pages_crawled", 0),
            },
            "technical": {
                "homepage_status": r.get("technical", {}).get("homepage_status"),
                "sitemap_present": r.get("technical", {}).get("sitemap_present"),
                "sitemap_url_count": r.get("technical", {}).get("sitemap_url_count", 0),
                "jsonld_present": r.get("technical", {}).get("jsonld_present"),
                "jsonld_semantically_valid": r.get("technical", {}).get("jsonld_semantically_valid"),
                "llms_txt_present": r.get("technical", {}).get("llms_txt_present"),
                "crawler_access_ok": r.get("technical", {}).get("crawler_access_ok"),
                "framework_markers": r.get("technical", {}).get("framework_markers"),
            },
        }
        observation["sites"].append(site_obs)

    dump_json(obs_file, observation)
    print(f"Published to Ello Control: {obs_file}")
    print(f"  {len(observation['sites'])} sites observed")

    # Also append to history
    history_file = inbox_dir / "history.jsonl"
    with history_file.open("a") as f:
        f.write(json.dumps({
            "run": runs[-1].name,
            "observed_at": observation["observed_at"],
            "published_at": observation["created_at"],
            "sites": {s["domain"]: s["combined_score"] for s in observation["sites"]},
        }) + "\n")

# ============================================================================
# v0.2: Scheduling — install/verify launchd plist
# ============================================================================

def command_schedule(action="status"):
    """Install, verify, or remove the launchd scheduling plist."""
    plist_label = "com.ellocello.ai-search-observatory"
    plist_path = Path.home() / "Library" / "LaunchAgents" / f"{plist_label}.plist"
    template = ROOT / "scripts" / "com.ellocello.ai-search-observatory.plist.example"

    if action == "status":
        # Check if installed
        import subprocess
        result = subprocess.run(["launchctl", "list"], capture_output=True, text=True)
        installed = plist_label in result.stdout
        print(f"Scheduler status:")
        print(f"  Label: {plist_label}")
        print(f"  Installed: {'YES' if installed else 'NO'}")
        print(f"  Plist path: {plist_path}")
        print(f"  Plist exists: {plist_path.exists()}")
        if installed:
            print(f"  Status: loaded")
        else:
            print(f"  Status: not loaded")
        if not installed:
            print(f"\n  To install: python3 benchmark.py schedule install")

    elif action == "install":
        if not template.exists():
            print(f"ERROR: Template not found: {template}")
            return
        # Read template and replace placeholders
        content = template.read_text()
        content = content.replace("REPLACE_WITH_ABSOLUTE_PATH", str(ROOT))
        plist_path.parent.mkdir(parents=True, exist_ok=True)
        plist_path.write_text(content)
        print(f"Wrote plist to {plist_path}")
        import subprocess
        result = subprocess.run(["launchctl", "load", str(plist_path)], capture_output=True, text=True)
        if result.returncode == 0:
            print("Loaded launchd job — weekly benchmark scheduled (Monday 8:00 AM)")
        else:
            print(f"Failed to load: {result.stderr}")
        print(f"Verify with: python3 benchmark.py schedule status")

    elif action == "uninstall":
        import subprocess
        if plist_path.exists():
            subprocess.run(["launchctl", "unload", str(plist_path)], capture_output=True)
            plist_path.unlink()
            print(f"Unloaded and removed {plist_path}")
        else:
            print("No plist found to uninstall.")

def command_init_evidence():
    for name, skeleton in [
        ("external_metrics.json", {"sites":{}}),
        ("ai_responses.json", {"observations":[]}),
        ("manual_evidence.json", {"sites":{}})
    ]:
        p = DATA/name
        if p.exists():
            print(f"exists: {p}")
        else:
            dump_json(p,skeleton)
            print(f"created: {p}")

def main():
    ap = argparse.ArgumentParser(description="AI Search Observatory Benchmark v0.2")
    sub = ap.add_subparsers(dest="cmd", required=True)
    run_p = sub.add_parser("run", help="Run live audit for configured sites")
    run_p.add_argument("--semrush", action="store_true",
                       help="Fetch fresh Semrush data before running (requires SEMRUSH_API_KEY)")
    run_p.add_argument("--sa", action="store_true",
                       help="Pull Search Authority canon before running")
    run_p.add_argument("--traffic", action="store_true",
                       help="Fetch traffic data (Vercel/Cloudflare/PostHog) before running")
    run_p.add_argument("--posthog-file", type=str, default=None,
                       help="Path to a PostHog JSON cache file for use with --traffic")
    sub.add_parser("compare", help="Compare the two most recent runs (per-metric)")
    sub.add_parser("init-evidence", help="Create missing external evidence files")
    sub.add_parser("publish", help="Publish latest run to Ello Control satellite inbox")
    sched_p = sub.add_parser("schedule", help="Manage launchd scheduling")
    sched_p.add_argument("action", choices=["status", "install", "uninstall"], default="status", nargs="?")
    args = ap.parse_args()
    if args.cmd=="run": command_run(semrush=args.semrush, sa=args.sa, traffic=args.traffic, posthog_file=args.posthog_file)
    elif args.cmd=="compare": command_compare()
    elif args.cmd=="init-evidence": command_init_evidence()
    elif args.cmd=="publish": command_publish()
    elif args.cmd=="schedule": command_schedule(args.action)

if __name__ == "__main__":
    main()
