"""Tests for ai_audit.report — EU AI Act Compliance Report Generator."""

import json

from ai_audit.dashboard import ComplianceSummary
from ai_audit.report import ComplianceReportGenerator


def _certified_summary(receipts: int = 500) -> ComplianceSummary:
    return ComplianceSummary(
        sprt_status="CERTIFIED",
        compliance_confidence=0.95,
        check_fire_rates={"safety": 0.01, "routing": 0.0},
        total_receipts=receipts,
        chain_integrity=True,
    )


def _flagged_summary() -> ComplianceSummary:
    return ComplianceSummary(
        sprt_status="FLAGGED",
        compliance_confidence=0.40,
        check_fire_rates={"critical_safety": 0.25},
        total_receipts=200,
        chain_integrity=False,
    )


_FAKE_KEY = "a" * 64  # 64 hex chars (32-byte key)


# ---------------------------------------------------------------------------
# AuditReport construction
# ---------------------------------------------------------------------------

def test_report_contains_all_articles():
    gen = ComplianceReportGenerator(_certified_summary(), _FAKE_KEY)
    assert set(gen.report.articles.keys()) == {
        "Art. 9", "Art. 12", "Art. 13", "Art. 17", "Art. 18"
    }


def test_report_id_format():
    gen = ComplianceReportGenerator(_certified_summary(), _FAKE_KEY)
    assert gen.report.report_id.startswith("AUDIT-EUAI-")


def test_fingerprint_is_16_chars():
    gen = ComplianceReportGenerator(_certified_summary(), _FAKE_KEY)
    assert len(gen.report.signing_key_fingerprint) == 16


def test_fingerprint_deterministic():
    g1 = ComplianceReportGenerator(_certified_summary(), _FAKE_KEY)
    g2 = ComplianceReportGenerator(_certified_summary(), _FAKE_KEY)
    assert g1.report.signing_key_fingerprint == g2.report.signing_key_fingerprint


# ---------------------------------------------------------------------------
# Article scores — CERTIFIED path
# ---------------------------------------------------------------------------

def test_art12_pass_when_chain_intact():
    gen = ComplianceReportGenerator(_certified_summary(), _FAKE_KEY)
    assert gen.report.articles["Art. 12"].score == 1.0
    assert gen.report.articles["Art. 12"].status == "PASS"
    assert gen.report.articles["Art. 12"].confidence == 1.0


def test_art12_fail_when_chain_broken():
    gen = ComplianceReportGenerator(_flagged_summary(), _FAKE_KEY)
    assert gen.report.articles["Art. 12"].score == 0.0
    assert gen.report.articles["Art. 12"].status == "FAIL"


def test_art9_high_score_certified():
    gen = ComplianceReportGenerator(_certified_summary(), _FAKE_KEY)
    assert gen.report.articles["Art. 9"].score >= 0.85
    assert gen.report.articles["Art. 9"].status == "PASS"


def test_art9_low_score_flagged():
    gen = ComplianceReportGenerator(_flagged_summary(), _FAKE_KEY)
    # FLAGGED base score 0.3 - 0.25 critical fires = 0.05
    assert gen.report.articles["Art. 9"].score < 0.60
    assert gen.report.articles["Art. 9"].status == "FAIL"


def test_art17_pass_certified():
    gen = ComplianceReportGenerator(_certified_summary(), _FAKE_KEY)
    assert gen.report.articles["Art. 17"].score == 0.95
    assert gen.report.articles["Art. 17"].status == "PASS"


def test_art18_fail_when_chain_broken():
    gen = ComplianceReportGenerator(_flagged_summary(), _FAKE_KEY)
    assert gen.report.articles["Art. 18"].score == 0.2
    assert gen.report.articles["Art. 18"].status == "FAIL"


def test_status_thresholds():
    """_status helper: >=0.85 → PASS, >=0.60 → WARN, <0.60 → FAIL."""
    gen = ComplianceReportGenerator(_certified_summary(), _FAKE_KEY)
    assert gen._status(0.85) == "PASS"
    assert gen._status(0.84) == "WARN"
    assert gen._status(0.60) == "WARN"
    assert gen._status(0.59) == "FAIL"


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------

def test_to_json_valid():
    gen = ComplianceReportGenerator(_certified_summary(), _FAKE_KEY)
    data = json.loads(gen.to_json())
    assert data["sprt_status"] == "CERTIFIED"
    assert "Art. 12" in data["articles"]
    assert data["chain_intact"] is True


def test_to_json_deterministic_keys():
    gen = ComplianceReportGenerator(_certified_summary(), _FAKE_KEY)
    data = json.loads(gen.to_json())
    assert "report_id" in data
    assert "global_confidence" in data
    assert "signing_key_fingerprint" in data


# ---------------------------------------------------------------------------
# Markdown export
# ---------------------------------------------------------------------------

def test_to_markdown_contains_header():
    gen = ComplianceReportGenerator(_certified_summary(), _FAKE_KEY)
    md = gen.to_markdown()
    assert "# EU AI Act Compliance Audit Report" in md


def test_to_markdown_contains_all_articles():
    gen = ComplianceReportGenerator(_certified_summary(), _FAKE_KEY)
    md = gen.to_markdown()
    for art in ["Art. 9", "Art. 12", "Art. 13", "Art. 17", "Art. 18"]:
        assert art in md


def test_to_markdown_contains_fingerprint():
    gen = ComplianceReportGenerator(_certified_summary(), _FAKE_KEY)
    md = gen.to_markdown()
    assert gen.report.signing_key_fingerprint in md


def test_to_markdown_flagged_shows_critical():
    gen = ComplianceReportGenerator(_flagged_summary(), _FAKE_KEY)
    md = gen.to_markdown()
    assert "NEIN" in md or "KRITISCH" in md


# ---------------------------------------------------------------------------
# HTML export
# ---------------------------------------------------------------------------

def test_to_html_is_valid_html():
    gen = ComplianceReportGenerator(_certified_summary(), _FAKE_KEY)
    html = gen.to_html()
    assert html.startswith("<!DOCTYPE html>")
    assert "</html>" in html


def test_to_html_no_external_resources():
    """No CDN or external resource references — must be air-gap safe."""
    gen = ComplianceReportGenerator(_certified_summary(), _FAKE_KEY)
    html = gen.to_html()
    assert "https://" not in html
    assert "http://" not in html
    assert "cdn." not in html


def test_to_html_contains_articles():
    gen = ComplianceReportGenerator(_certified_summary(), _FAKE_KEY)
    html = gen.to_html()
    for art in ["Art. 9", "Art. 12", "Art. 13", "Art. 17", "Art. 18"]:
        assert art in html


def test_to_html_contains_fingerprint():
    gen = ComplianceReportGenerator(_certified_summary(), _FAKE_KEY)
    html = gen.to_html()
    assert gen.report.signing_key_fingerprint in html


# ---------------------------------------------------------------------------
# Public API completeness
# ---------------------------------------------------------------------------

def test_public_api_report_symbols():
    import ai_audit

    for sym in ["ArticleScore", "AuditReport", "ComplianceReportGenerator"]:
        assert hasattr(ai_audit, sym), f"Missing from public API: {sym}"
