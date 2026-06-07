# 00 - Overview

HTTP Headers Scanner is a small command line tool that visits a website, reads the HTTP response headers, and grades the site's basic browser security controls.

It does not exploit anything. It does not crawl the whole website. It makes one request and answers one practical question:

> Is this site sending the security headers a modern browser expects?

## Why It Matters

When a browser asks a website for a page, the server returns the page plus metadata called response headers. Some of those headers are security instructions. They tell the browser things like:

- Only talk to this site over HTTPS.
- Do not allow this page inside another site's iframe.
- Do not guess a file type if the server already declared one.
- Only load scripts from approved places.
- Do not leak full URLs to third-party sites.
- Block unused browser features such as camera, microphone, and location.

If these headers are missing or weak, attacks like SSL stripping, clickjacking, MIME sniffing, XSS, referer leakage, and browser feature abuse become easier.

## What The Scanner Checks

| Header | Severity | Main Risk |
| --- | --- | --- |
| `Strict-Transport-Security` | high | SSL stripping and HTTPS downgrade attacks |
| `Content-Security-Policy` | high | XSS through untrusted scripts |
| `X-Content-Type-Options` | medium | MIME sniffing |
| `X-Frame-Options` | medium | Clickjacking |
| `Referrer-Policy` | low | Sensitive URL leakage |
| `Permissions-Policy` | low | Browser feature abuse |

## Scoring

Each rule has a severity:

| Severity | Points |
| --- | --- |
| high | 30 |
| medium | 15 |
| low | 5 |

Each finding has a status:

| Status | Score Impact |
| --- | --- |
| `ok` | full points |
| `weak` | half points |
| `missing` | zero points |

The score becomes a grade:

| Score | Grade |
| --- | --- |
| 90-100 | A |
| 80-89 | B |
| 70-79 | C |
| 60-69 | D |
| 0-59 | F |

## Quick Start

From PowerShell in the project folder:

```powershell
python -m pip install -e ".[dev]"
python http_headers_scanner.py https://example.com
```

For JSON output:

```powershell
python http_headers_scanner.py https://example.com --json
```

To run tests:

```powershell
python -m pytest
```

## Demo URLs

```powershell
python http_headers_scanner.py https://github.com
python http_headers_scanner.py https://example.com
python http_headers_scanner.py https://web.dev --timeout 5
python http_headers_scanner.py http://neverssl.com
```

The exact grade can change over time because websites update their headers, but these are useful sites for seeing different scanner paths.

## What This Project Does Not Do

- It is not a vulnerability scanner.
- It does not crawl every page.
- It does not perform deep CSP analysis.
- It does not check TLS cipher suites or certificates.
- It does not decide whether a missing header is acceptable for a specific business context.

This is a learning-scale scanner. Its job is to make the core security-header idea clear.

## Extension Ideas

- Add more headers such as `Cross-Origin-Opener-Policy`, `Cross-Origin-Embedder-Policy`, and `Cross-Origin-Resource-Policy`.
- Add a web UI with a URL input and scan result cards.
- Add a deeper CSP analyzer that flags `unsafe-inline` and wildcard script sources.
- Scan multiple URLs in one run.
- Store scan history in SQLite.
- Build a FastAPI wrapper so other tools can call it.
