# AI Search Observatory Benchmark

A repeatable benchmark for measuring AI-search readiness **and** actual AI-search outcomes.

**Current version: v0.2.0**

It maps directly to the 22-step six-month AI-search playbook while adding four estate-specific layers:

1. **Ello Control** — what site/repo exists, where it lives, and which profile/version it runs.
2. **Search Authority** — whether AI responses match, distort, omit, contradict, or invent canonical claims.
3. **Framework** — whether the site's structured public knowledge model is present/current.
4. **Schema** — whether machine-readable metadata is present, valid enough to parse, and traceable.

## v0.2 hardening

v0.2 adds:

- **Evidence Coverage** — what % of playbook steps have real evidence (not `unknown`)
- **Measurement Confidence** — weighted by evidence source quality (live crawl > adapter > manual > none)
- **Coverage threshold gate** — combined score is NOT authoritative below 60% coverage or confidence
- **Multi-page crawl** — parses sitemap.xml, crawls up to 5 pages beyond homepage
- **Semantic JSON-LD validation** — checks required properties per schema.org type, not just `json.loads()`
- **Framework/Schema markers** — reads `<meta name="ello-framework-profile">` etc. from HTML
- **Search Authority adapter** — `scripts/sa_adapter.py` pulls canon entities and generates observations
- **Semrush adapter** — `scripts/semrush_adapter.py` pulls backlink/domain data via Semrush MCP API
- **PostHog adapter** — `scripts/traffic_adapter.py` pulls web analytics via PostHog REST API or cache file
- **Per-metric comparison** — compares individual family scores across runs, not just combined
- **Regression thresholds** — config-driven alerts for score drops, coverage, and confidence
- **Ello Control publishing** — `benchmark.py publish` writes to satellite inbox
- **Scheduling** — `benchmark.py schedule install` sets up weekly launchd job

## Important scoring rule

Technical readiness and actual AI visibility are scored separately.

A site can be:

- 95/100 technically ready
- 10/100 visible in AI search

and the benchmark will show that rather than averaging the distinction away.

**v0.2 addition:** A site can score 90/100 combined but be marked `Authoritative: NO` if evidence coverage or measurement confidence is below 60%. The combined score is not presented as authoritative without sufficient evidence.

## Quick start

```bash
cd ai_search_observatory_benchmark

# Run benchmark (with SA canon pull)
python3 benchmark.py run --sa

# Run with Semrush data (requires API key)
SEMRUSH_API_KEY=xxx python3 benchmark.py run --semrush --sa

# Run with traffic data (Vercel/Cloudflare/PostHog)
python3 benchmark.py run --traffic --sa

# Run with traffic data + custom PostHog cache file
python3 benchmark.py run --traffic --posthog-file /path/to/posthog.json --sa

# Run with PostHog via direct API (requires personal API key)
POSTHOG_PERSONAL_API_KEY=xxx POSTHOG_PROJECT_ID=123 python3 benchmark.py run --traffic --sa

# Compare last two runs (per-metric)
python3 benchmark.py compare

# Publish to Ello Control
python3 benchmark.py publish

# Schedule weekly run
python3 benchmark.py schedule install
python3 benchmark.py schedule status
```

Outputs are written to:

```text
runs/<timestamp>/
├── summary.json
├── scorecard.md
└── evidence.json
```

To compare against the previous run:

```bash
python3 benchmark.py compare
```

To create/update external evidence templates:

```bash
python3 benchmark.py init-evidence
```

## External evidence

Some playbook steps cannot be inferred reliably from a website crawl alone.

Populate:

```text
data/external_metrics.json
data/ai_responses.json
data/manual_evidence.json
```

These can later be populated automatically by Semrush/API adapters, Search Authority evaluators, or other monitoring systems.

## Recommended operating model

```text
live sites
   ↓
benchmark crawl
   ↓
technical + framework/schema evidence
   ↓
external AI visibility evidence
   ↓
Search Authority accuracy evidence
   ↓
scorecard + history
   ↓
Ello Control observation record
```

Run manually first. The package includes an optional launchd template for recurring observation once the protocol is trusted.
