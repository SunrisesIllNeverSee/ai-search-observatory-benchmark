# Benchmark Specification

## Core score families

| Family | Weight | Meaning |
|---|---:|---|
| AI Visibility Outcomes | 30% | Share of voice, source visibility, AI visibility, referral traffic, citation presence |
| Technical / Crawlability | 20% | robots, indexing surface, real 404, sitemap, canonical tags, server-visible content |
| Content / Retrieval | 20% | headings, direct-answer structure, prompt coverage, freshness, hubs |
| Authority / Accuracy | 20% | canonical accuracy, contradiction, unsupported claims, stale information, source attribution |
| Off-site / Distribution | 10% | backlinks, brand mentions, forum presence, repurposing |

The benchmark additionally reports Framework and Schema implementation coverage as diagnostic dimensions.

## 22-step mapping

1. Baseline current AI visibility
2. Set AI visibility targets
3. Check AI crawler access
4. Audit crawling/indexing
5. Audit what AI says and whether it is true
6. Audit top pages responsible for AI responses
7. Audit brand mentions
8. Optimize key pages for AI citations
9. Implement schema / technical foundations
10. Build crawlable site structure
11. Refresh outdated content
12. Create citeable content formats
13. Build content hubs
14. Find prompts/questions to answer
15. Structure content for AI retrieval
16. Improve E-E-A-T / authority signals
17. Repurpose across platforms
18. Build links and mentions
19. Correct third-party misinformation
20. Participate in relevant forums
21. Review progress against goals
22. Repeat the cycle / maintain momentum

## Estate-specific authority metrics

- AI Mention Rate
- AI Citation Rate
- Canonical Accuracy Rate
- Claim Match Rate
- Unsupported Claim Rate
- Contradiction Rate
- Stale Information Rate
- Correct Source Attribution Rate

## Estate-specific technical metrics

- AI crawler accessibility
- Real HTTP 404 compliance
- Sitemap availability
- Canonical URL coverage
- Server-visible content
- Schema presence
- Schema parseability
- Framework profile declaration
- Framework version declaration
- Schema profile/version declaration
- llms.txt availability
- provenance/authority markers

## Status values

- `complete`
- `partial`
- `missing`
- `unknown`
- `not_applicable`

`unknown` must never silently count as complete.
