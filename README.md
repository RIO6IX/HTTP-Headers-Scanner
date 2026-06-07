# HTTP Headers Scanner

HTTP Headers Scanner checks a website's HTTP security headers and identifies missing or weak controls such as CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.

Created with credit to **Chanuka Isuru Sampath (RIO6IX)**.

This is a quick overview. More learning notes are in the `learn/` folder.

## Note

This project is built as a beginner-friendly security tool. The core scanner is one readable Python file, with tests and documentation that explain the security ideas behind each header.

## What It Does

- Performs one polite HTTP request to the URL you provide and inspects the response headers.
- Grades six security-critical headers against a weighted rubric.
- Reports each finding as `ok`, `weak`, or `missing`.
- Computes a `0` to `100` score and maps it to an `A` through `F` letter grade.
- Catches broken values like `Strict-Transport-Security: max-age=0` and flags them as weak.
- Follows redirects and grades the final URL, the one your browser would actually land on.
- Prints a colored Rich table, a RIO6IX banner, a grade panel, and recommendations.
- Supports `--json` output for scripts and future dashboards.
- Returns meaningful exit codes for CI pipelines.

## The Headers It Grades

| Header | Severity | What It Helps Stop |
| --- | --- | --- |
| `Strict-Transport-Security` | high | SSL stripping on untrusted Wi-Fi |
| `Content-Security-Policy` | high | XSS through injected scripts |
| `X-Content-Type-Options` | medium | MIME sniffing of uploaded files |
| `X-Frame-Options` | medium | Clickjacking through hidden iframes |
| `Referrer-Policy` | low | Leaking sensitive URLs through the `Referer` header |
| `Permissions-Policy` | low | Browser feature abuse by third-party scripts |

## Quick Start

From PowerShell in this folder:

```powershell
python -m pip install -e ".[dev]"
python http_headers_scanner.py https://example.com
```

If you installed the package, you can also use the command entry point:

```powershell
headers https://example.com
```

## Usage

```powershell
python http_headers_scanner.py https://github.com
python http_headers_scanner.py https://example.com --timeout 5
python http_headers_scanner.py https://example.com --json
```

Always include the `http://` or `https://` scheme. The scanner does not guess bare hostnames like `github.com`, because guessing the wrong scheme is exactly the kind of downgrade problem HSTS exists to prevent.

## Demo URLs

Try these to see different results:

| URL | Likely Grade | Why |
| --- | --- | --- |
| `https://github.com` | A | Strong modern header setup |
| `https://web.dev` | A | Google developer site with modern controls |
| `https://www.mozilla.org` | A | Mozilla generally ships strong browser security headers |
| `https://example.com` | B/C | Useful baseline site, usually missing some optional controls |
| `http://neverssl.com` | F | Intentionally plain HTTP with no modern security headers |

## Sample Output

The normal terminal output includes:

- A green `RIO6IX` banner.
- A table of checked headers.
- A grade panel with score and author credit.
- Recommendations for every non-ok finding.

Example:

```text
:: HTTP SECURITY HEADERS SCANNER :: credit: Chanuka Isuru Sampath (RIO6IX)

Headers for https://example.com/ (HTTP 200)
Header                       Status    Severity    Note
Strict-Transport-Security    ok        high        Present and matches ...
Content-Security-Policy      missing   high        Header Content-Security-Policy is not set

Result
Grade: B
Score: 85 / 100
```

## Exit Codes

| Grade | Exit Code | Meaning |
| --- | --- | --- |
| A, B | `0` | Good baseline |
| C, D | `1` | Worth investigating |
| F or network error | `2` | Hard fail |

## Tooling

```powershell
just
just test
just run -- https://example.com
python -m pytest
```

`just` is optional. If you do not have it installed, use the direct Python commands above.

## Requirements

- Python 3.11 or newer.
- Internet access when scanning real URLs.
- `httpx` and `rich`, installed through `pip install -e ".[dev]"`.
- `pytest` for tests.

## Learn

The `learn/` folder contains beginner-friendly notes:

| File | Topic |
| --- | --- |
| `learn/00-OVERVIEW.md` | Project overview, security context, quick start, and extension ideas |
| `learn/ABOUT.md` | Author credit and social links |

## Real-World Context

This scanner is a teaching-scale version of tools such as:

- Mozilla Observatory
- securityheaders.com
- nmap's `http-security-headers` script

Those tools go deeper, especially for CSP and TLS analysis. This project focuses on making the core idea readable and hackable.

## About

See [learn/ABOUT.md](learn/ABOUT.md) for author links and project credit.
