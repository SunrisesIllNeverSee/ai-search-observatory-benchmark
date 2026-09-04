# Integration Contract

## Ello Control

May consume:

- latest run timestamp
- per-domain score
- framework/schema profile observations
- crawl/404/robots/schema drift
- stale/unresolved evidence status

Suggested observation type:

```yaml
record_type: ai_search_benchmark
site_id: signalaf-com
observed_at: ...
benchmark_version: 0.1.0
combined_score: 64.2
technical_score: 83.0
visibility_score: 25.0
```

Ello Control must not interpret a visibility score as canonical truth.

## Search Authority

May produce `data/ai_responses.json` observations.

Search Authority owns classification against canon:

- match
- partial
- unsupported
- contradiction
- stale
- unknown

The benchmark computes rates from those classifications.

## Framework

Should eventually expose a version/profile declaration that the benchmark can read.

## Schema

Should eventually expose:

- schema profile/version
- generated_at
- source_system
- canon_backed
- authority approval references where applicable

## GTM / Semrush adapter

Populate outcome metrics in `data/external_metrics.json`.

Do not fake missing API data as zero.
