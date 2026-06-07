"""Scan a URL and grade its HTTP security response headers."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from typing import Literal

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

AUTHOR = "Chanuka Isuru Sampath (RIO6IX)"
DEFAULT_USER_AGENT = "http-headers-scanner/1.0 (+https://github.com/RIO6IX)"

Severity = Literal["high", "medium", "low"]
Status = Literal["ok", "weak", "missing"]


@dataclass(frozen=True, slots=True)
class HeaderRule:
    """A single security header rule."""

    header: str
    severity: Severity
    description: str
    recommendation: str
    must_match: str | None = None


@dataclass(frozen=True, slots=True)
class HeaderFinding:
    """The result of evaluating one header rule."""

    rule: HeaderRule
    status: Status
    actual_value: str | None
    note: str


@dataclass(frozen=True, slots=True)
class ScanReport:
    """The complete scanner result for a URL."""

    url: str
    final_url: str
    status_code: int
    findings: list[HeaderFinding]

    @property
    def score(self) -> int:
        total = sum(SEVERITY_POINTS[rule.severity] for rule in RULES)
        if total == 0:
            return 0

        earned = 0.0
        for finding in self.findings:
            full_points = SEVERITY_POINTS[finding.rule.severity]
            if finding.status == "ok":
                earned += full_points
            elif finding.status == "weak":
                earned += full_points / 2

        return int((earned / total) * 100 + 0.5)

    @property
    def grade(self) -> str:
        score = self.score
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"


RULES: list[HeaderRule] = [
    HeaderRule(
        header="Strict-Transport-Security",
        severity="high",
        description="Forces browsers to use HTTPS for future requests.",
        recommendation=(
            "Add: Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains; preload"
        ),
        must_match=r"\bmax-age\s*=\s*[1-9][0-9]*\b",
    ),
    HeaderRule(
        header="Content-Security-Policy",
        severity="high",
        description="Restricts where scripts, styles, images, and other resources can load from.",
        recommendation=(
            "Add a CSP such as: Content-Security-Policy: default-src 'self'; "
            "script-src 'self'"
        ),
    ),
    HeaderRule(
        header="X-Content-Type-Options",
        severity="medium",
        description="Prevents browsers from MIME-sniffing a response away from its declared type.",
        recommendation="Add: X-Content-Type-Options: nosniff",
        must_match=r"\bnosniff\b",
    ),
    HeaderRule(
        header="X-Frame-Options",
        severity="medium",
        description="Prevents other sites from framing the page and clickjacking users.",
        recommendation="Add: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN",
        must_match=r"^(DENY|SAMEORIGIN)$",
    ),
    HeaderRule(
        header="Referrer-Policy",
        severity="low",
        description="Controls how much referrer information is sent to other sites.",
        recommendation="Add: Referrer-Policy: strict-origin-when-cross-origin",
    ),
    HeaderRule(
        header="Permissions-Policy",
        severity="low",
        description="Restricts access to browser features such as camera, microphone, and location.",
        recommendation=(
            "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"
        ),
    ),
]

SEVERITY_POINTS: dict[Severity, int] = {
    "high": 30,
    "medium": 15,
    "low": 5,
}

STATUS_COLORS: dict[Status, str] = {
    "ok": "green",
    "weak": "yellow",
    "missing": "red",
}

GRADE_COLORS: dict[str, str] = {
    "A": "bright_green",
    "B": "green",
    "C": "yellow",
    "D": "red",
    "F": "bright_red",
}

RIO6IX_BANNER = r"""
 ____  ___  ___   __   _ __  __
|  _ \|_ _|/ _ \ / /_ / |\ \/ /
| |_) || || | | | '_ \| | \  /
|  _ < | || |_| | (_) | | /  \
|_| \_\___|\___/ \___/|_|/_/\_\
"""


def _render_banner(console: Console) -> None:
    console.print(f"[bold green]{RIO6IX_BANNER}[/bold green]")
    console.print(
        "[green]:: HTTP SECURITY HEADERS SCANNER ::[/green] "
        f"[dim]credit: {AUTHOR}[/dim]\n"
    )


def evaluate_header(
    rule: HeaderRule,
    response_headers: dict[str, str],
) -> HeaderFinding:
    """Apply one rule to a response header dictionary."""

    target = rule.header.lower()
    actual_value: str | None = None

    for name, value in response_headers.items():
        if name.lower() == target:
            actual_value = value.strip()
            break

    if actual_value is None:
        return HeaderFinding(
            rule=rule,
            status="missing",
            actual_value=None,
            note=f"Header {rule.header} is not set",
        )

    if rule.must_match is None:
        return HeaderFinding(
            rule=rule,
            status="ok",
            actual_value=actual_value,
            note="Present",
        )

    if re.search(rule.must_match, actual_value, re.IGNORECASE):
        return HeaderFinding(
            rule=rule,
            status="ok",
            actual_value=actual_value,
            note=f"Present and matches {rule.must_match}",
        )

    return HeaderFinding(
        rule=rule,
        status="weak",
        actual_value=actual_value,
        note=f"Present but weak value: {actual_value}",
    )


def scan(
    url: str,
    *,
    timeout: float = 10.0,
    user_agent: str = DEFAULT_USER_AGENT,
) -> ScanReport:
    """Fetch a URL and produce a security header report."""

    response = httpx.get(
        url,
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": user_agent},
    )
    response_headers = dict(response.headers)
    findings = [evaluate_header(rule, response_headers) for rule in RULES]

    return ScanReport(
        url=url,
        final_url=str(response.url),
        status_code=response.status_code,
        findings=findings,
    )


def report_to_dict(report: ScanReport) -> dict[str, object]:
    """Convert a report to a JSON-friendly dictionary."""

    return {
        "url": report.url,
        "final_url": report.final_url,
        "status_code": report.status_code,
        "score": report.score,
        "grade": report.grade,
        "author": AUTHOR,
        "findings": [asdict(finding) for finding in report.findings],
    }


def _render_report(report: ScanReport, console: Console) -> None:
    table = Table(
        title=f"Headers for {report.final_url} (HTTP {report.status_code})",
        show_lines=False,
    )
    table.add_column("Header", style="bold")
    table.add_column("Status")
    table.add_column("Severity")
    table.add_column("Value", overflow="fold", max_width=42)
    table.add_column("Note", overflow="fold", max_width=44)

    for finding in report.findings:
        color = STATUS_COLORS[finding.status]
        table.add_row(
            finding.rule.header,
            f"[{color}]{finding.status}[/{color}]",
            finding.rule.severity,
            finding.actual_value or "-",
            finding.note,
        )

    console.print(table)

    if report.final_url.startswith("http://"):
        console.print(
            "[yellow]Note:[/yellow] this response was served over plain HTTP. "
            "Browsers ignore HSTS unless it is received over HTTPS."
        )

    grade_color = GRADE_COLORS[report.grade]
    console.print(
        Panel(
            f"[bold {grade_color}]Grade: {report.grade}[/bold {grade_color}]\n"
            f"Score: {report.score} / 100\n"
            f"Credit: {AUTHOR}",
            title="Result",
            border_style=grade_color,
        )
    )

    actionable = [finding for finding in report.findings if finding.status != "ok"]
    if actionable:
        console.print("\n[bold]Recommendations:[/bold]")
        for finding in actionable:
            console.print(f"- [bold]{finding.rule.header}[/bold]: {finding.rule.recommendation}")


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="headers",
        description="Scan a URL for HTTP security headers and grade the result A-F.",
    )
    parser.add_argument("url", help="Full URL to scan, including http:// or https://.")
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Seconds to wait before giving up on the request.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON instead of the terminal report.",
    )
    return parser


def main() -> int:
    parser = _build_argument_parser()
    args = parser.parse_args()
    console = Console()

    try:
        if not args.json:
            _render_banner(console)
        report = scan(args.url, timeout=args.timeout)
    except httpx.RequestError as exc:
        console.print(f"[red]Request failed:[/red] {type(exc).__name__}: {exc}")
        return 2

    if args.json:
        console.print(json.dumps(report_to_dict(report), indent=2))
    else:
        _render_report(report, console)

    if report.grade in ("A", "B"):
        return 0
    if report.grade in ("C", "D"):
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
