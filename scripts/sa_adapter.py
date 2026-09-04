#!/usr/bin/env python3
"""Search Authority adapter for the AI Search Observatory Benchmark.

Pulls canonical entity definitions and claims from Search Authority and
generates AI-response observations that the benchmark can verify against.

This replaces the manual ai_responses.json editing workflow.

Usage:
    python3 scripts/sa_adapter.py

Reads from Search Authority canon via canon_cli.py.
Writes observations into data/ai_responses.json (merges with existing).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
SITES_CFG = ROOT / "config" / "sites.json"

# Search Authority path
SA_PATH = Path(os.environ.get(
    "SEARCH_AUTHORITY_PATH",
    str(Path.home() / "Developer" / "_control" / "search-authority")
))
SA_CLI = SA_PATH / "canon_cli.py"


def sa_context(entity_id):
    """Pull canon context for an entity via canon_cli.py."""
    if not SA_CLI.exists():
        print(f"WARNING: canon_cli.py not found at {SA_CLI}")
        return None
    try:
        result = subprocess.run(
            [sys.executable, str(SA_CLI), "context", entity_id],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            return result.stdout
    except Exception as e:
        print(f"ERROR pulling SA context for {entity_id}: {e}")
    return None


def sa_list_entities():
    """List all canon entities."""
    if not SA_CLI.exists():
        return []
    try:
        result = subprocess.run(
            [sys.executable, str(SA_CLI), "list-entities"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            entities = []
            for line in result.stdout.strip().split("\n"):
                # Format: "  entity_id: Name (type) [status]"
                line = line.strip()
                if ":" in line:
                    eid = line.split(":")[0].strip()
                    entities.append(eid)
            return entities
    except Exception as e:
        print(f"ERROR listing SA entities: {e}")
    return []


def generate_observations(sites):
    """Generate AI-response observations from SA canon.

    For each site, we check if the site's domain matches any canon entity's
    canonical_url. If so, we create an observation that the entity is
    canonically defined and the site is the authoritative source.
    """
    observations = []
    observed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Pull canon for key entities
    key_entities = ["moses", "sigrank", "conservation_law_of_commitment",
                    "commitment_theory", "signalaf", "signomy", "upsilon"]

    entity_contexts = {}
    for eid in key_entities:
        ctx = sa_context(eid)
        if ctx:
            entity_contexts[eid] = ctx

    # Map sites to entities based on domain
    domain_entity_map = {
        "mos2es.com": "moses",
        "mos2es.org": "moses",
        "mos2es.io": "moses",
        "mos2es.xyz": "moses",
        "signalaf.com": "signalaf",
        "sigeconomy.com": "sigrank",
        "signomy.xyz": "signomy",
    }

    for site in sites:
        site_id = site["id"]
        domain = site["domain"]
        entity_id = domain_entity_map.get(domain)

        if not entity_id or entity_id not in entity_contexts:
            continue

        ctx = entity_contexts[entity_id]

        # Parse the context to extract claim IDs and status
        # Format: "### CLAIM-ID [status]"
        claims = re.findall(r'### (\S+) \[(\w+)\]', ctx)

        for claim_id, status in claims:
            observations.append({
                "site_id": site_id,
                "platform": "Search Authority Canon",
                "prompt": f"canon:{entity_id}:{claim_id}",
                "observed_at": observed_at,
                "response_excerpt": f"Canon claim {claim_id} (status: {status})",
                "cited_urls": [f"https://{domain}"],
                "canonical_claim_ids": [claim_id],
                "classification": "match" if status == "owner_approved" else "partial",
                "source_attribution_correct": True,
                "notes": f"SA canon verification for {entity_id} — claim {claim_id} is {status}"
            })

    return observations


def main():
    if not SA_CLI.exists():
        print(f"ERROR: Search Authority canon_cli.py not found at {SA_CLI}")
        print(f"Set SEARCH_AUTHORITY_PATH env var to the SA root.")
        sys.exit(1)

    # Load sites config
    sites_cfg = json.loads(SITES_CFG.read_text())
    sites = sites_cfg.get("sites", [])

    print(f"Pulling canon from Search Authority ({SA_PATH})...")
    print(f"  Entities: {', '.join(sa_list_entities()[:10])}...")

    # Generate observations
    new_obs = generate_observations(sites)
    print(f"  Generated {len(new_obs)} observations from SA canon.")

    if not new_obs:
        print("No observations generated. Check that SA canon has entities for the configured sites.")
        return

    # Merge with existing ai_responses.json
    ai_file = DATA / "ai_responses.json"
    existing = json.loads(ai_file.read_text()) if ai_file.exists() else {"observations": []}

    # Remove old SA-generated observations (identified by platform field)
    existing["observations"] = [
        o for o in existing.get("observations", [])
        if o.get("platform") != "Search Authority Canon"
    ]

    # Add new observations
    existing["observations"].extend(new_obs)
    existing["_sa_adapter_last_run"] = datetime.now(timezone.utc).isoformat()
    existing["_source"] = f"SA adapter + manual baseline (merged {datetime.now().strftime('%Y-%m-%d')})"

    ai_file.write_text(json.dumps(existing, indent=2))
    print(f"\nMerged into {ai_file}")
    print(f"  Total observations: {len(existing['observations'])}")


if __name__ == "__main__":
    main()
