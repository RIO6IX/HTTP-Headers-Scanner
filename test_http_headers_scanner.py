from __future__ import annotations

import httpx

from http_headers_scanner import (
    RULES,
    HeaderFinding,
    HeaderRule,
    ScanReport,
    evaluate_header,
    report_to_dict,
    scan,
)


def test_evaluate_header_reports_missing_header() -> None:
    rule = HeaderRule(
        header="Strict-Transport-Security",
        severity="high",
        description="HSTS",
        recommendation="Add HSTS",
        must_match=r"\bmax-age\s*=\s*[1-9][0-9]*\b",
    )

    finding = evaluate_header(rule, {})

    assert finding.status == "missing"
    assert finding.actual_value is None


def test_evaluate_header_accepts_case_insensitive_names() -> None:
    rule = HeaderRule(
        header="X-Content-Type-Options",
        severity="medium",
        description="No sniffing",
        recommendation="Add nosniff",
        must_match=r"\bnosniff\b",
    )

    finding = evaluate_header(rule, {"x-content-type-options": "nosniff"})

    assert finding.status == "ok"
    assert finding.actual_value == "nosniff"


def test_evaluate_header_reports_weak_value() -> None:
    rule = HeaderRule(
        header="Strict-Transport-Security",
        severity="high",
        description="HSTS",
        recommendation="Add HSTS",
        must_match=r"\bmax-age\s*=\s*[1-9][0-9]*\b",
    )

    finding = evaluate_header(rule, {"Strict-Transport-Security": "max-age=0"})

    assert finding.status == "weak"


def test_report_score_and_grade_for_perfect_findings() -> None:
    findings = [
        HeaderFinding(rule=rule, status="ok", actual_value="present", note="Present")
        for rule in RULES
    ]
    report = ScanReport(
        url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        findings=findings,
    )

    assert report.score == 100
    assert report.grade == "A"


def test_scan_uses_httpx_and_grades_response(monkeypatch) -> None:
    def fake_get(*args, **kwargs) -> httpx.Response:  # noqa: ANN002, ANN003
        assert args == ("https://safe.example",)
        assert kwargs["follow_redirects"] is True
        return httpx.Response(
            status_code=200,
            request=httpx.Request("GET", "https://safe.example"),
            headers={
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            },
        )

    monkeypatch.setattr("http_headers_scanner.httpx.get", fake_get)

    report = scan("https://safe.example")

    assert report.status_code == 200
    assert report.score == 100
    assert report.grade == "A"


def test_report_to_dict_includes_author_credit() -> None:
    findings = [
        HeaderFinding(rule=rule, status="missing", actual_value=None, note="Missing")
        for rule in RULES
    ]
    report = ScanReport(
        url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        findings=findings,
    )

    data = report_to_dict(report)

    assert data["author"] == "Chanuka Isuru Sampath (RIO6IX)"
    assert data["grade"] == "F"
