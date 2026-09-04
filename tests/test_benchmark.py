"""Test suite for the AI Search Observatory Benchmark.

Covers:
- robots.txt parsing and RFC 9309 crawler-blocked semantics
- HTTP header case-insensitivity
- author-signal heuristic precision
- authority/accuracy rate computation
- status scoring and family-score aggregation
- classify_step logic for representative playbook steps
- markdown scorecard generation (including diagnostic dimensions)
- compare/init-evidence commands
"""
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

# Make benchmark.py importable regardless of cwd.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import benchmark as bm


# ---------------------------------------------------------------------------
# robots.txt parsing
# ---------------------------------------------------------------------------

class TestRobotRules:
    def test_basic_groups(self):
        text = "User-agent: *\nDisallow: /\n\nUser-agent: GoodBot\nAllow: /\n"
        groups = bm.robot_rules(text)
        assert len(groups) == 2
        assert ["*"] == [a.strip() for a in groups[0][0]]
        assert ["goodbot"] == [a.strip().lower() for a in groups[1][0]]

    def test_multiple_agents_in_group(self):
        text = "User-agent: a\nUser-agent: b\nDisallow: /\n"
        groups = bm.robot_rules(text)
        assert len(groups) == 1
        agents = [a.strip().lower() for a in groups[0][0]]
        assert agents == ["a", "b"]

    def test_comments_and_blank_lines_ignored(self):
        text = "# comment\n\nUser-agent: *\nDisallow: /  # block all\n"
        groups = bm.robot_rules(text)
        assert len(groups) == 1
        assert groups[0][1] == [("disallow", "/")]

    def test_empty_text(self):
        assert bm.robot_rules("") == []

    def test_sitemap_directive_ignored(self):
        text = "User-agent: *\nDisallow: /\nSitemap: https://x.com/s.xml\n"
        groups = bm.robot_rules(text)
        assert len(groups) == 1
        assert all(r[0] in ("disallow", "allow") for r in groups[0][1])

    def test_blank_line_separates_groups(self):
        """RFC 9309 §2.2.1: groups are separated by blank lines."""
        text = "User-agent: A\nDisallow: /a\n\nUser-agent: B\nDisallow: /b\n"
        groups = bm.robot_rules(text)
        assert len(groups) == 2
        assert [a.lower() for a in groups[0][0]] == ["a"]
        assert groups[0][1] == [("disallow", "/a")]
        assert [a.lower() for a in groups[1][0]] == ["b"]
        assert groups[1][1] == [("disallow", "/b")]

    def test_empty_named_group_preserved(self):
        """An empty named group (UA with no rules) must be kept as a distinct
        group so crawler_blocked can honor its precedence over ``*``."""
        text = "User-agent: GPTBot\n\nUser-agent: *\nDisallow: /\n"
        groups = bm.robot_rules(text)
        assert len(groups) == 2
        assert [a.lower() for a in groups[0][0]] == ["gptbot"]
        assert groups[0][1] == []  # empty rules
        assert [a.lower() for a in groups[1][0]] == ["*"]
        assert groups[1][1] == [("disallow", "/")]

    def test_user_agent_after_rules_starts_new_group(self):
        """Without a blank line, a UA line after rules still starts a new group."""
        text = "User-agent: A\nDisallow: /a\nUser-agent: B\nDisallow: /b\n"
        groups = bm.robot_rules(text)
        assert len(groups) == 2

    def test_multiple_blank_lines_between_groups(self):
        text = "User-agent: A\nDisallow: /a\n\n\nUser-agent: B\nDisallow: /b\n"
        groups = bm.robot_rules(text)
        assert len(groups) == 2


# ---------------------------------------------------------------------------
# crawler_blocked — RFC 9309 group specificity
# ---------------------------------------------------------------------------

class TestCrawlerBlocked:
    def test_wildcard_block(self):
        text = "User-agent: *\nDisallow: /\n"
        assert bm.crawler_blocked(text, "GPTBot") is True
        assert bm.crawler_blocked(text, "Googlebot") is True

    def test_named_bot_overrides_wildcard_block(self):
        """A named bot's own (empty) group takes precedence over * block."""
        text = "User-agent: *\nDisallow: /\n\nUser-agent: GPTBot\n"
        assert bm.crawler_blocked(text, "GPTBot") is False
        assert bm.crawler_blocked(text, "Googlebot") is True

    def test_named_bot_explicitly_blocked(self):
        text = "User-agent: *\nDisallow: /\n\nUser-agent: GPTBot\nDisallow: /\n"
        assert bm.crawler_blocked(text, "GPTBot") is True

    def test_allow_overrides_disallow_on_tie(self):
        """Allow: / wins over Disallow: / on equal specificity (RFC 9309 §2.2.2)."""
        text = "User-agent: *\nDisallow: /\nAllow: /\n"
        assert bm.crawler_blocked(text, "GPTBot") is False

    def test_no_rules_means_allowed(self):
        text = "User-agent: *\n"
        assert bm.crawler_blocked(text, "GPTBot") is False

    def test_no_applicable_group(self):
        text = "User-agent: BadBot\nDisallow: /\n"
        assert bm.crawler_blocked(text, "GPTBot") is False

    def test_empty_disallow_means_allowed(self):
        text = "User-agent: *\nDisallow:\n"
        assert bm.crawler_blocked(text, "GPTBot") is False

    def test_case_insensitive_agent_match(self):
        text = "User-agent: *\nDisallow: /\n\nUser-agent: gptbot\n"
        assert bm.crawler_blocked(text, "GPTBot") is False

    def test_specific_path_does_not_block_root(self):
        text = "User-agent: *\nDisallow: /private\n"
        assert bm.crawler_blocked(text, "GPTBot") is False

    def test_empty_named_group_before_wildcard_block(self):
        """Empty named group separated by blank line from * block must
        take precedence — the pattern sites use to allow a specific AI
        crawler while blocking the wildcard."""
        text = "User-agent: GPTBot\n\nUser-agent: *\nDisallow: /\n"
        assert bm.crawler_blocked(text, "GPTBot") is False
        assert bm.crawler_blocked(text, "Googlebot") is True

    def test_empty_named_group_after_wildcard_block(self):
        """Same precedence regardless of group ordering in the file."""
        text = "User-agent: *\nDisallow: /\n\nUser-agent: GPTBot\n"
        assert bm.crawler_blocked(text, "GPTBot") is False
        assert bm.crawler_blocked(text, "Googlebot") is True

    def test_consecutive_user_agents_share_rules(self):
        """Consecutive UA lines (no blank line) belong to one group and
        share the same rules — both bots are blocked here."""
        text = "User-agent: GPTBot\nUser-agent: *\nDisallow: /\n"
        assert bm.crawler_blocked(text, "GPTBot") is True
        assert bm.crawler_blocked(text, "Googlebot") is True


# ---------------------------------------------------------------------------
# header_get — case-insensitive HTTP header lookup
# ---------------------------------------------------------------------------

class TestHeaderGet:
    def test_exact_case(self):
        assert bm.header_get({"Last-Modified": "x"}, "Last-Modified") == "x"

    def test_lowercase_header(self):
        assert bm.header_get({"last-modified": "x"}, "Last-Modified") == "x"

    def test_mixed_case(self):
        assert bm.header_get({"Last-modified": "x"}, "last-Modified") == "x"

    def test_missing(self):
        assert bm.header_get({"content-type": "x"}, "Last-Modified") is None

    def test_none_headers(self):
        assert bm.header_get(None, "Last-Modified") is None


# ---------------------------------------------------------------------------
# author_signal heuristic (tested via regex directly)
# ---------------------------------------------------------------------------

import re as _re

AUTHOR_WRITTEN_BY = _re.compile(r"\bwritten by\b", _re.IGNORECASE)
AUTHOR_BY_NAME = _re.compile(r"\bby [A-Z][a-zA-Z.'-]+ [A-Z][a-zA-Z.'-]+\b")


class TestAuthorSignalRegex:
    def test_written_by_matches(self):
        assert AUTHOR_WRITTEN_BY.search("This article was written by Jane Smith.")

    def test_written_by_case_insensitive(self):
        assert AUTHOR_WRITTEN_BY.search("WRITTEN BY the team")

    def test_by_firstname_lastname_matches(self):
        assert AUTHOR_BY_NAME.search("by Jane Smith today")

    def test_by_single_name_does_not_match(self):
        assert not AUTHOR_BY_NAME.search("by the way")

    def test_standby_does_not_match(self):
        assert not AUTHOR_BY_NAME.search("standby mode")

    def test_nearby_does_not_match(self):
        assert not AUTHOR_BY_NAME.search("nearby restaurant")

    def test_by_the_way_does_not_match(self):
        assert not AUTHOR_BY_NAME.search("by the way this is cool")


# ---------------------------------------------------------------------------
# evaluate_authority — rate computation
# ---------------------------------------------------------------------------

class TestEvaluateAuthority:
    def test_no_observations(self):
        result = bm.evaluate_authority("site-1", {"observations": []})
        assert result["observations"] == 0
        assert result["canonical_accuracy_rate"] is None
        assert result["claim_match_rate"] is None

    def test_all_matches(self):
        obs = [{"site_id": "s", "classification": "match", "source_attribution_correct": True}] * 5
        result = bm.evaluate_authority("s", {"observations": obs})
        assert result["observations"] == 5
        assert result["canonical_accuracy_rate"] == 100.0
        assert result["claim_match_rate"] == 100.0
        assert result["contradiction_rate"] == 0.0

    def test_mixed_classifications(self):
        obs = [
            {"site_id": "s", "classification": "match"},
            {"site_id": "s", "classification": "contradiction"},
            {"site_id": "s", "classification": "unsupported"},
            {"site_id": "s", "classification": "stale"},
            {"site_id": "s", "classification": "accurate"},
        ]
        result = bm.evaluate_authority("s", {"observations": obs})
        assert result["observations"] == 5
        assert result["canonical_accuracy_rate"] == 40.0  # match + accurate
        assert result["claim_match_rate"] == 20.0
        assert result["unsupported_claim_rate"] == 20.0
        assert result["contradiction_rate"] == 20.0
        assert result["stale_information_rate"] == 20.0

    def test_filters_by_site_id(self):
        obs = [
            {"site_id": "s1", "classification": "match"},
            {"site_id": "s2", "classification": "contradiction"},
        ]
        result = bm.evaluate_authority("s1", {"observations": obs})
        assert result["observations"] == 1
        assert result["claim_match_rate"] == 100.0

    def test_source_attribution_only_known(self):
        obs = [
            {"site_id": "s", "classification": "match", "source_attribution_correct": True},
            {"site_id": "s", "classification": "match"},  # no attribution field
            {"site_id": "s", "classification": "match", "source_attribution_correct": False},
        ]
        result = bm.evaluate_authority("s", {"observations": obs})
        # Only 2 observations have source_attribution_correct set
        assert result["correct_source_attribution_rate"] == 50.0

    def test_accurate_counts_as_canonical_accuracy(self):
        obs = [{"site_id": "s", "classification": "accurate"}]
        result = bm.evaluate_authority("s", {"observations": obs})
        assert result["canonical_accuracy_rate"] == 100.0


# ---------------------------------------------------------------------------
# status_score / avg / pct
# ---------------------------------------------------------------------------

class TestScoringHelpers:
    def test_status_score(self):
        assert bm.status_score("complete") == 100
        assert bm.status_score("partial") == 50
        assert bm.status_score("missing") == 0
        assert bm.status_score("unknown") is None
        assert bm.status_score("not_applicable") is None

    def test_avg(self):
        assert bm.avg([100, 50]) == 75.0
        assert bm.avg([100, None, 50]) == 75.0
        assert bm.avg([]) is None
        assert bm.avg([None, None]) is None

    def test_pct(self):
        assert bm.pct(1, 4) == 25.0
        assert bm.pct(0, 0) is None


# ---------------------------------------------------------------------------
# classify_step — representative steps
# ---------------------------------------------------------------------------

def make_auto(**overrides):
    base = {
        "homepage_200": True, "real_404": True, "sitemap_present": True,
        "crawler_access_ok": True, "title_present": True,
        "meta_description_present": True, "has_h1": True,
        "canonical_present": True, "jsonld_present": True,
        "jsonld_parseable": True, "jsonld_semantically_valid": True,
        "internal_links_count": 5,
        "heading_structure_ok": True, "visible_text_chars": 1200,
        "author_signal": True, "external_links_count": 3,
        "freshness_signal_present": True,
    }
    base.update(overrides)
    return base

def make_external(**overrides):
    base = {
        "share_of_voice": None, "source_visibility": None,
        "referral_traffic": None, "ai_visibility": None,
        "top_cited_pages": [], "linked_mentions": None,
        "unlinked_mentions": None, "referring_domains": None,
        "tracked_prompts": 0, "forum_contributions": 0,
        "repurposed_assets": 0,
    }
    base.update(overrides)
    return base

def make_authority(**overrides):
    base = {
        "observations": 0, "canonical_accuracy_rate": None,
        "claim_match_rate": None, "unsupported_claim_rate": None,
        "contradiction_rate": None, "stale_information_rate": None,
        "correct_source_attribution_rate": None,
    }
    base.update(overrides)
    return base


class TestClassifyStep:
    def test_step1_unknown_when_no_external(self):
        auto = make_auto()
        ext = make_external()
        result = bm.classify_step(1, auto, ext, {}, make_authority(), 0)
        assert result["status"] == "unknown"

    def test_step1_complete_when_external_present(self):
        auto = make_auto()
        ext = make_external(share_of_voice=10)
        result = bm.classify_step(1, auto, ext, {}, make_authority(), 0)
        assert result["status"] == "complete"

    def test_step3_complete_when_crawler_ok(self):
        result = bm.classify_step(3, make_auto(), make_external(), {}, make_authority(), 0)
        assert result["status"] == "complete"

    def test_step3_missing_when_crawler_blocked(self):
        result = bm.classify_step(3, make_auto(crawler_access_ok=False), make_external(), {}, make_authority(), 0)
        assert result["status"] == "missing"

    def test_step4_partial_when_some_checks_fail(self):
        result = bm.classify_step(4, make_auto(real_404=False), make_external(), {}, make_authority(), 0)
        assert result["status"] == "partial"

    def test_step5_partial_with_some_observations(self):
        auth = make_authority(observations=3)
        result = bm.classify_step(5, make_auto(), make_external(), {}, auth, 0)
        assert result["status"] == "partial"

    def test_step5_complete_with_five_or_more_observations(self):
        auth = make_authority(observations=5)
        result = bm.classify_step(5, make_auto(), make_external(), {}, auth, 0)
        assert result["status"] == "complete"

    def test_step9_complete_when_jsonld_present_parseable_and_semantically_valid(self):
        result = bm.classify_step(9, make_auto(), make_external(), {}, make_authority(), 0)
        assert result["status"] == "complete"

    def test_step9_partial_when_jsonld_present_parseable_but_semantically_invalid(self):
        result = bm.classify_step(9, make_auto(jsonld_semantically_valid=False), make_external(), {}, make_authority(), 0)
        assert result["status"] == "partial"

    def test_step9_partial_when_jsonld_present_but_unparseable(self):
        result = bm.classify_step(9, make_auto(jsonld_parseable=False, jsonld_semantically_valid=False), make_external(), {}, make_authority(), 0)
        assert result["status"] == "partial"

    def test_step9_missing_when_no_jsonld(self):
        result = bm.classify_step(9, make_auto(jsonld_present=False, jsonld_parseable=False, jsonld_semantically_valid=False), make_external(), {}, make_authority(), 0)
        assert result["status"] == "missing"

    def test_step11_unknown_when_no_freshness(self):
        result = bm.classify_step(11, make_auto(freshness_signal_present=False), make_external(), {}, make_authority(), 0)
        assert result["status"] == "unknown"

    def test_step21_unknown_with_no_history(self):
        result = bm.classify_step(21, make_auto(), make_external(), {}, make_authority(), 0)
        assert result["status"] == "unknown"

    def test_step21_complete_with_two_runs(self):
        result = bm.classify_step(21, make_auto(), make_external(), {}, make_authority(), 2)
        assert result["status"] == "complete"

    def test_step22_partial_with_one_run(self):
        result = bm.classify_step(22, make_auto(), make_external(), {}, make_authority(), 1)
        assert result["status"] == "partial"

    def test_manual_override_takes_precedence(self):
        manual = {"sites": {"s1": {"16": {"status": "complete", "evidence": ["manual"]}}}}
        result = bm.classify_step(16, make_auto(), make_external(), manual["sites"]["s1"], make_authority(), 0)
        assert result["status"] == "complete"
        assert result["evidence"] == ["manual"]


# ---------------------------------------------------------------------------
# build_markdown — scorecard generation
# ---------------------------------------------------------------------------

class TestBuildMarkdown:
    def _make_result(self):
        return {
            "observed_at": "2026-01-01T00:00:00Z",
            "sites": [{
                "site": {"id": "s1", "domain": "example.com", "framework_profile": "full-moses"},
                "observed_at": "2026-01-01T00:00:00Z",
                "technical": {
                    "homepage_status": 200, "real_404": True, "crawler_access_ok": True,
                    "sitemap_present": True, "llms_txt_present": False,
                    "jsonld_present": True, "jsonld_parseable": True,
                    "schema_types": ["Organization", "WebSite"],
                },
                "external_metrics": {},
                "authority_metrics": {
                    "observations": 0, "canonical_accuracy_rate": None,
                    "claim_match_rate": None, "unsupported_claim_rate": None,
                    "contradiction_rate": None, "stale_information_rate": None,
                    "correct_source_attribution_rate": None,
                },
                "playbook_steps": {str(n): {"name": bm.STEP_NAMES[n], "status": "unknown", "evidence": []}
                                   for n in range(1, 23)},
                "family_scores": {"visibility": None, "technical": 80.0, "content": None,
                                  "authority": None, "offsite": None},
                "diagnostics": {
                    "framework": {"profile": "full-moses", "status": "complete"},
                    "schema": {"present": True, "parseable": True,
                               "types": ["Organization", "WebSite"], "status": "complete"},
                },
                "combined_score": 64.0,
            }],
        }

    def test_generates_markdown(self):
        md = bm.build_markdown(self._make_result())
        assert "# AI Search Observatory — Scorecard" in md
        assert "example.com" in md

    def test_includes_diagnostic_dimensions(self):
        md = bm.build_markdown(self._make_result())
        assert "## Diagnostic Dimensions" in md
        assert "Framework" in md
        assert "full-moses" in md
        assert "Organization" in md

    def test_includes_playbook_steps(self):
        md = bm.build_markdown(self._make_result())
        assert "Playbook step" in md
        # All 22 step names should appear
        for n in range(1, 23):
            assert bm.STEP_NAMES[n] in md


# ---------------------------------------------------------------------------
# PageParser — HTML parsing
# ---------------------------------------------------------------------------

class TestPageParser:
    def test_parses_title_and_headings(self):
        html = "<html><head><title>Test</title></head><body><h1>Main</h1><h2>Sub</h2></body></html>"
        p = bm.PageParser()
        p.feed(html)
        assert p.title == "Test"
        assert "h1" in p.headings
        assert "h2" in p.headings

    def test_parses_canonical(self):
        html = '<html><head><link rel="canonical" href="https://x.com/"/></head></html>'
        p = bm.PageParser()
        p.feed(html)
        assert p.canonical == "https://x.com/"

    def test_parses_meta_description(self):
        html = '<html><head><meta name="description" content="A site"/></head></html>'
        p = bm.PageParser()
        p.feed(html)
        assert p.meta.get("description") == "A site"

    def test_parses_jsonld(self):
        html = '<html><head><script type="application/ld+json">{"@type":"Organization"}</script></head></html>'
        p = bm.PageParser()
        p.feed(html)
        assert len(p.jsonld) == 1

    def test_skips_script_style_text(self):
        html = '<body><script>var x = 1;</script><p>visible text</p><style>body{}</style></body>'
        p = bm.PageParser()
        p.feed(html)
        joined = " ".join(p.text_parts)
        assert "visible text" in joined
        assert "var x" not in joined
        assert "body{}" not in joined

    def test_parses_links(self):
        html = '<body><a href="/about">About</a><a href="https://ext.com">Ext</a></body>'
        p = bm.PageParser()
        p.feed(html)
        assert "/about" in p.links
        assert "https://ext.com" in p.links


# ---------------------------------------------------------------------------
# parse_jsonld / schema_types
# ---------------------------------------------------------------------------

class TestJsonLd:
    def test_parse_valid(self):
        parsed, errors = bm.parse_jsonld(['{"@type":"Organization"}'])
        assert len(parsed) == 1
        assert errors == []

    def test_parse_invalid(self):
        parsed, errors = bm.parse_jsonld(['{invalid json}'])
        assert parsed == []
        assert len(errors) == 1

    def test_parse_empty_blobs(self):
        parsed, errors = bm.parse_jsonld(['', None])
        assert parsed == []
        assert errors == []

    def test_schema_types_str(self):
        parsed, errors = bm.parse_jsonld(['{"@type":"Organization"}'])
        types = bm.schema_types(parsed)
        assert "Organization" in types

    def test_schema_types_list(self):
        parsed, _ = bm.parse_jsonld(['{"@type":["Organization","WebSite"]}'])
        types = bm.schema_types(parsed)
        assert "Organization" in types
        assert "WebSite" in types

    def test_schema_types_nested(self):
        parsed, _ = bm.parse_jsonld(['{"@type":"WebSite","potentialAction":{"@type":"SearchAction"}}'])
        types = bm.schema_types(parsed)
        assert "WebSite" in types
        assert "SearchAction" in types


# ---------------------------------------------------------------------------
# init-evidence command
# ---------------------------------------------------------------------------

class TestInitEvidence:
    def test_creates_missing_files(self, tmp_path, monkeypatch):
        monkeypatch.setattr(bm, "DATA", tmp_path)
        bm.command_init_evidence()
        assert (tmp_path / "external_metrics.json").exists()
        assert (tmp_path / "ai_responses.json").exists()
        assert (tmp_path / "manual_evidence.json").exists()
        data = json.loads((tmp_path / "external_metrics.json").read_text())
        assert data == {"sites": {}}

    def test_does_not_overwrite_existing(self, tmp_path, monkeypatch):
        monkeypatch.setattr(bm, "DATA", tmp_path)
        existing = {"sites": {"s1": {"share_of_voice": 42}}}
        (tmp_path / "external_metrics.json").write_text(json.dumps(existing))
        bm.command_init_evidence()
        data = json.loads((tmp_path / "external_metrics.json").read_text())
        assert data == existing  # unchanged


# ---------------------------------------------------------------------------
# v0.2: Semantic JSON-LD validation
# ---------------------------------------------------------------------------

class TestSemanticJsonLd:
    def test_valid_organization(self):
        blocks = [{"@type": "Organization", "name": "Test Org", "@context": "https://schema.org"}]
        valid, errors = bm.validate_jsonld_semantic(blocks)
        assert valid == 1
        assert errors == []

    def test_missing_required_name(self):
        blocks = [{"@type": "Organization", "@context": "https://schema.org"}]
        valid, errors = bm.validate_jsonld_semantic(blocks)
        assert errors[0]["error"] == "missing_required_property"
        assert "name" in errors[0]["detail"]
        # Regression: a block with errors must NOT be counted as valid
        assert valid == 0

    def test_missing_required_for_article(self):
        blocks = [{"@type": "Article", "@context": "https://schema.org"}]
        valid, errors = bm.validate_jsonld_semantic(blocks)
        missing_props = [e for e in errors if e["error"] == "missing_required_property"]
        assert len(missing_props) >= 1
        assert "headline" in missing_props[0]["detail"]
        # Regression: a block with errors must NOT be counted as valid
        assert valid == 0

    def test_unexpected_context(self):
        blocks = [{"@type": "Organization", "name": "X", "@context": "https://example.com"}]
        valid, errors = bm.validate_jsonld_semantic(blocks)
        ctx_errors = [e for e in errors if e["error"] == "unexpected_context"]
        assert len(ctx_errors) == 1
        # Regression: a block with errors must NOT be counted as valid
        assert valid == 0

    def test_nested_objects_validated(self):
        blocks = [{
            "@type": "WebSite", "name": "Test", "url": "https://x.com",
            "@context": "https://schema.org",
            "potentialAction": {"@type": "SearchAction"}  # missing target + query-input
        }]
        valid, errors = bm.validate_jsonld_semantic(blocks)
        sa_errors = [e for e in errors if e["type"] == "SearchAction"]
        assert len(sa_errors) >= 1
        # Regression: parent is valid but nested has errors — neither counts
        assert valid == 0

    def test_graph_container_recursed(self):
        blocks = [{
            "@context": "https://schema.org",
            "@graph": [{"@type": "Organization", "name": "OK"}]
        }]
        valid, errors = bm.validate_jsonld_semantic(blocks)
        assert valid >= 1

    def test_empty_type_flagged(self):
        blocks = [{"@type": "", "@context": "https://schema.org"}]
        valid, errors = bm.validate_jsonld_semantic(blocks)
        type_errors = [e for e in errors if e["error"] == "empty_type"]
        assert len(type_errors) == 1
        # Regression: a block with errors must NOT be counted as valid
        assert valid == 0

    def test_no_type_skips_required_check(self):
        blocks = [{"@context": "https://schema.org", "name": "X"}]
        valid, errors = bm.validate_jsonld_semantic(blocks)
        # No @type means no required-property check
        assert all(e["error"] != "missing_required_property" for e in errors)

    # --- @id validation ---

    def test_valid_https_id_accepted(self):
        blocks = [{"@type": "Organization", "name": "X", "@context": "https://schema.org",
                   "@id": "https://example.com/org"}]
        valid, errors = bm.validate_jsonld_semantic(blocks)
        id_errors = [e for e in errors if e["error"] == "invalid_id"]
        assert id_errors == []
        assert valid == 1

    def test_valid_http_id_accepted(self):
        blocks = [{"@type": "Organization", "name": "X", "@context": "https://schema.org",
                   "@id": "http://example.com/org"}]
        valid, errors = bm.validate_jsonld_semantic(blocks)
        id_errors = [e for e in errors if e["error"] == "invalid_id"]
        assert id_errors == []
        assert valid == 1

    def test_urn_id_flagged(self):
        blocks = [{"@type": "Organization", "name": "X", "@context": "https://schema.org",
                   "@id": "urn:uuid:123"}]
        valid, errors = bm.validate_jsonld_semantic(blocks)
        id_errors = [e for e in errors if e["error"] == "invalid_id"]
        assert len(id_errors) == 1
        assert "urn:uuid:123" in id_errors[0]["detail"]
        # Regression: a block with errors must NOT be counted as valid
        assert valid == 0

    def test_bare_string_id_flagged(self):
        blocks = [{"@type": "Organization", "name": "X", "@context": "https://schema.org",
                   "@id": "not-a-url"}]
        valid, errors = bm.validate_jsonld_semantic(blocks)
        id_errors = [e for e in errors if e["error"] == "invalid_id"]
        assert len(id_errors) == 1
        # Regression: a block with errors must NOT be counted as valid
        assert valid == 0

    def test_relative_path_id_flagged(self):
        blocks = [{"@type": "Organization", "name": "X", "@context": "https://schema.org",
                   "@id": "/relative/path"}]
        valid, errors = bm.validate_jsonld_semantic(blocks)
        id_errors = [e for e in errors if e["error"] == "invalid_id"]
        assert len(id_errors) == 1
        # Regression: a block with errors must NOT be counted as valid
        assert valid == 0

    def test_mailto_id_flagged(self):
        blocks = [{"@type": "Organization", "name": "X", "@context": "https://schema.org",
                   "@id": "mailto:foo@bar.com"}]
        valid, errors = bm.validate_jsonld_semantic(blocks)
        id_errors = [e for e in errors if e["error"] == "invalid_id"]
        assert len(id_errors) == 1
        # Regression: a block with errors must NOT be counted as valid
        assert valid == 0

    def test_no_id_no_error(self):
        blocks = [{"@type": "Organization", "name": "X", "@context": "https://schema.org"}]
        valid, errors = bm.validate_jsonld_semantic(blocks)
        id_errors = [e for e in errors if e["error"] == "invalid_id"]
        assert id_errors == []
        assert valid == 1


# ---------------------------------------------------------------------------
# v0.2: Framework/Schema marker reading
# ---------------------------------------------------------------------------

class TestFrameworkMarkers:
    def test_reads_framework_profile(self):
        html = '<html><head><meta name="ello-framework-profile" content="full-moses"></head></html>'
        p = bm.PageParser()
        p.feed(html)
        markers = bm.read_framework_markers(p)
        assert markers["framework_profile"] == "full-moses"

    def test_reads_all_markers(self):
        html = ('<head>'
                '<meta name="ello-framework-profile" content="full-moses">'
                '<meta name="ello-framework-version" content="0.1.0">'
                '<meta name="ello-schema-version" content="1.2.0">'
                '<meta name="ello-canon-version" content="1.2.0">'
                '</head>')
        p = bm.PageParser()
        p.feed(html)
        markers = bm.read_framework_markers(p)
        assert markers["framework_profile"] == "full-moses"
        assert markers["framework_version"] == "0.1.0"
        assert markers["schema_version"] == "1.2.0"
        assert markers["canon_version"] == "1.2.0"

    def test_no_markers_returns_none(self):
        html = '<html><head><title>Test</title></head></html>'
        p = bm.PageParser()
        p.feed(html)
        markers = bm.read_framework_markers(p)
        assert markers["framework_profile"] is None
        assert markers["framework_version"] is None


# ---------------------------------------------------------------------------
# v0.2: Sitemap URL parsing
# ---------------------------------------------------------------------------

class TestSitemapParsing:
    def test_parse_urlset(self):
        xml = '<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://x.com/</loc></url><url><loc>https://x.com/about</loc></url></urlset>'
        urls = bm.parse_sitemap_urls(xml)
        assert len(urls) == 2
        assert "https://x.com/" in urls
        assert "https://x.com/about" in urls

    def test_parse_sitemapindex(self):
        xml = '<?xml version="1.0"?><sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>https://x.com/sitemap1.xml</loc></sitemap></sitemapindex>'
        urls = bm.parse_sitemap_urls(xml)
        assert len(urls) == 1
        assert "https://x.com/sitemap1.xml" in urls

    def test_empty_body(self):
        assert bm.parse_sitemap_urls("") == []

    def test_invalid_xml(self):
        assert bm.parse_sitemap_urls("not xml") == []

    def test_no_loc_elements(self):
        xml = '<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><priority>1.0</priority></url></urlset>'
        assert bm.parse_sitemap_urls(xml) == []


# ---------------------------------------------------------------------------
# v0.2: Evidence Coverage + Measurement Confidence
# ---------------------------------------------------------------------------

class TestEvidenceCoverage:
    def test_all_covered(self):
        steps = {str(n): {"status": "complete"} for n in range(1, 23)}
        pct, covered, total = bm.compute_evidence_coverage(steps)
        assert pct == 100.0
        assert covered == 22
        assert total == 22

    def test_all_unknown(self):
        steps = {str(n): {"status": "unknown"} for n in range(1, 23)}
        pct, covered, total = bm.compute_evidence_coverage(steps)
        assert pct == 0.0
        assert covered == 0

    def test_mixed(self):
        steps = {str(n): {"status": "complete" if n <= 11 else "unknown"} for n in range(1, 23)}
        pct, covered, total = bm.compute_evidence_coverage(steps)
        assert pct == 50.0
        assert covered == 11


class TestMeasurementConfidence:
    def test_high_confidence_with_live_crawl(self):
        steps = {str(n): {"status": "complete", "evidence": ["live crawl"]} for n in range(1, 23)}
        conf = bm.compute_measurement_confidence(steps, {}, [], 5)
        assert conf > 80.0

    def test_low_confidence_with_unknowns(self):
        steps = {str(n): {"status": "unknown", "evidence": []} for n in range(1, 23)}
        conf = bm.compute_measurement_confidence(steps, {}, [], 0)
        assert conf < 20.0

    def test_crawl_bonus(self):
        # Use partial steps so base confidence isn't already 100
        steps = {str(n): {"status": "partial", "evidence": ["live crawl"]} for n in range(1, 23)}
        conf_no_crawl = bm.compute_measurement_confidence(steps, {}, [], 0)
        conf_with_crawl = bm.compute_measurement_confidence(steps, {}, [1, 2, 3, 4, 5], 0)
        assert conf_with_crawl > conf_no_crawl

    def test_quality_bonus_from_semantic_validation(self):
        """auto dict with jsonld_semantically_valid should boost confidence."""
        steps = {str(n): {"status": "partial", "evidence": ["live crawl"]} for n in range(1, 23)}
        auto_no_semantic = {}
        auto_with_semantic = {"jsonld_semantically_valid": True}
        conf_no = bm.compute_measurement_confidence(steps, auto_no_semantic, [], 0)
        conf_yes = bm.compute_measurement_confidence(steps, auto_with_semantic, [], 0)
        assert conf_yes > conf_no

    def test_quality_bonus_from_framework_markers(self):
        """auto dict with framework_markers should boost confidence."""
        steps = {str(n): {"status": "partial", "evidence": ["live crawl"]} for n in range(1, 23)}
        auto_no_markers = {}
        auto_with_markers = {"framework_markers": {"framework_profile": "full-moses"}}
        conf_no = bm.compute_measurement_confidence(steps, auto_no_markers, [], 0)
        conf_yes = bm.compute_measurement_confidence(steps, auto_with_markers, [], 0)
        assert conf_yes > conf_no

    def test_semantically_validated_evidence_quality(self):
        """Steps with 'semantically validated' evidence get live_crawl quality."""
        steps = {str(n): {"status": "complete", "evidence": ["JSON-LD (semantically validated)"]} for n in range(1, 23)}
        conf = bm.compute_measurement_confidence(steps, {}, [], 0)
        # live_crawl quality (1.0) * complete (1.0) = 100% earned, plus bonuses
        assert conf > 90.0


class TestIsAuthoritative:
    def test_above_threshold(self):
        assert bm.is_authoritative(80.0, 70.0) is True

    def test_below_coverage_threshold(self):
        assert bm.is_authoritative(50.0, 80.0) is False

    def test_below_confidence_threshold(self):
        assert bm.is_authoritative(80.0, 40.0) is False

    def test_both_below(self):
        assert bm.is_authoritative(30.0, 30.0) is False

    def test_at_threshold(self):
        assert bm.is_authoritative(60.0, 60.0) is True


# ---------------------------------------------------------------------------
# Regression: valid_count must not count blocks that have their own errors.
# Bug: block_errors_before was captured AFTER the block's own checks ran,
# so blocks with missing required props / invalid @id / empty @type /
# unexpected @context were incorrectly counted as valid. The snapshot must
# be captured BEFORE any error checks for the block.
# ---------------------------------------------------------------------------

class TestValidCountRegression:
    def test_missing_required_prop_not_counted_valid(self):
        """Block with missing required property must not increment valid_count."""
        blocks = [{"@type": "Organization", "@context": "https://schema.org"}]
        valid, errors = bm.validate_jsonld_semantic(blocks)
        assert len(errors) == 1
        assert valid == 0

    def test_invalid_id_not_counted_valid(self):
        """Block with invalid @id must not increment valid_count."""
        blocks = [{"@type": "Organization", "name": "X",
                   "@context": "https://schema.org", "@id": "urn:foo"}]
        valid, errors = bm.validate_jsonld_semantic(blocks)
        assert len(errors) == 1
        assert valid == 0

    def test_empty_type_not_counted_valid(self):
        """Block with empty @type must not increment valid_count."""
        blocks = [{"@type": "", "@context": "https://schema.org"}]
        valid, errors = bm.validate_jsonld_semantic(blocks)
        assert len(errors) >= 1
        assert valid == 0

    def test_unexpected_context_not_counted_valid(self):
        """Block with unexpected @context must not increment valid_count."""
        blocks = [{"@type": "Organization", "name": "X",
                   "@context": "https://example.com"}]
        valid, errors = bm.validate_jsonld_semantic(blocks)
        assert len(errors) == 1
        assert valid == 0

    def test_nested_invalid_increments_neither(self):
        """Parent valid + nested invalid → valid_count stays 0 (parent's
        nested-object errors disqualify the parent too)."""
        blocks = [{
            "@type": "WebSite", "name": "T", "url": "https://x.com",
            "@context": "https://schema.org",
            "potentialAction": {"@type": "SearchAction"}  # missing target + query-input
        }]
        valid, errors = bm.validate_jsonld_semantic(blocks)
        assert len(errors) >= 1
        assert valid == 0

    def test_both_parent_and_nested_valid_count_both(self):
        """Parent valid + nested valid → valid_count == 2."""
        blocks = [{
            "@type": "WebSite", "name": "T", "url": "https://x.com",
            "@context": "https://schema.org",
            "potentialAction": {"@type": "SearchAction", "target": "x",
                                "query-input": "y", "@context": "https://schema.org"}
        }]
        valid, errors = bm.validate_jsonld_semantic(blocks)
        assert errors == []
        assert valid == 2

    def test_mixed_blocks_count_only_valid_ones(self):
        """One valid block + one invalid block → valid_count == 1."""
        blocks = [
            {"@type": "Organization", "name": "OK", "@context": "https://schema.org"},
            {"@type": "Organization", "@context": "https://schema.org"},  # missing name
        ]
        valid, errors = bm.validate_jsonld_semantic(blocks)
        assert len(errors) == 1
        assert valid == 1

    def test_graph_with_valid_child_counts_child(self):
        """@graph container with a valid child → valid_count == 1 (child only)."""
        blocks = [{
            "@context": "https://schema.org",
            "@graph": [{"@type": "Organization", "name": "OK",
                        "@context": "https://schema.org"}]
        }]
        valid, errors = bm.validate_jsonld_semantic(blocks)
        assert errors == []
        assert valid == 1

    def test_graph_with_invalid_child_counts_neither(self):
        """@graph container with an invalid child → valid_count == 0."""
        blocks = [{
            "@context": "https://schema.org",
            "@graph": [{"@type": "Organization", "@context": "https://schema.org"}]  # missing name
        }]
        valid, errors = bm.validate_jsonld_semantic(blocks)
        assert len(errors) == 1
        assert valid == 0
