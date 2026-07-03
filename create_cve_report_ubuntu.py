"""
Generate a summary CVE report for Ubuntu for the current year.

Uses the Ubuntu Security API (https://ubuntu.com/security/cves.json)
to fetch CVE data and produce a severity breakdown, top affected packages,
and a list of critical/high CVEs.

Output formats: plain text (.txt), HTML (.html), and Markdown (.md).

Usage:
    python create_cve_report_ubuntu.py
    python create_cve_report_ubuntu.py --year 2025
    python create_cve_report_ubuntu.py --output-dir /tmp/reports
"""

import argparse
import html as html_mod
import os
import sys
import time
from datetime import datetime
from io import StringIO

try:
    import requests
except ImportError:
    print("Error: 'requests' library is required. Install it with: pip install requests")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Progress bar
# ---------------------------------------------------------------------------

class ProgressBar:
    """Simple terminal progress bar without external dependencies."""

    def __init__(self, total, prefix="", width=40):
        self.total = total
        self.prefix = prefix
        self.width = width
        self.current = 0
        self.start_time = time.time()

    def update(self, amount=1):
        self.current += amount
        self._render()

    def _render(self):
        if self.total <= 0:
            return
        fraction = min(self.current / self.total, 1.0)
        filled = int(self.width * fraction)
        bar = "█" * filled + "░" * (self.width - filled)
        elapsed = time.time() - self.start_time
        rate = self.current / elapsed if elapsed > 0 else 0
        eta = (self.total - self.current) / rate if rate > 0 else 0
        pct = fraction * 100
        sys.stderr.write(
            f"\r  {self.prefix} |{bar}| {pct:5.1f}% "
            f"({self.current}/{self.total}) "
            f"[{elapsed:.0f}s elapsed, ~{eta:.0f}s remaining]"
        )
        sys.stderr.flush()

    def finish(self):
        self._render()
        sys.stderr.write("\n")
        sys.stderr.flush()


# ---------------------------------------------------------------------------
# Data fetching
# ---------------------------------------------------------------------------

def fetch_ubuntu_cves(year, max_results=2000):
    """Fetch CVEs from the Ubuntu Security API for a given year.

    Args:
        year: The year to query CVEs for.
        max_results: Maximum number of CVEs to retrieve.

    Returns:
        A list of CVE dictionaries, or None on failure.
    """
    base_url = "https://ubuntu.com/security/cves.json"
    page_size = 20  # API limit is max 20 per request
    offset = 0
    all_cves = []

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Accept": "application/json",
    }

    # First request to discover total count
    params = {"q": f"CVE-{year}", "limit": page_size, "offset": 0, "order": "newest"}
    try:
        response = requests.get(base_url, params=params, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"  Error on initial request: {e}", file=sys.stderr)
        return None

    total_available = data.get("total_results", max_results)
    total_to_fetch = min(total_available, max_results)

    cves_first = data.get("cves", [])
    for cve in cves_first:
        if f"CVE-{year}" in cve.get("id", ""):
            all_cves.append(cve)

    if len(cves_first) < page_size:
        return all_cves

    offset += page_size
    total_pages = (total_to_fetch + page_size - 1) // page_size
    progress = ProgressBar(total_to_fetch, prefix="Fetching CVEs")
    progress.update(len(cves_first))

    while offset < total_to_fetch:
        params = {
            "q": f"CVE-{year}",
            "limit": page_size,
            "offset": offset,
            "order": "newest",
        }

        try:
            response = requests.get(base_url, params=params, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.Timeout:
            time.sleep(2)
            try:
                response = requests.get(base_url, params=params, headers=headers, timeout=60)
                response.raise_for_status()
                data = response.json()
            except requests.exceptions.RequestException as e:
                print(f"\n  Error: Retry failed at offset {offset}: {e}", file=sys.stderr)
                break
        except requests.exceptions.HTTPError as e:
            print(f"\n  Error: HTTP {response.status_code} at offset {offset}: {e}", file=sys.stderr)
            break
        except requests.exceptions.RequestException as e:
            print(f"\n  Error: {e}", file=sys.stderr)
            break

        cves = data.get("cves", [])
        if not cves:
            break

        for cve in cves:
            if f"CVE-{year}" in cve.get("id", ""):
                all_cves.append(cve)

        progress.update(len(cves))

        if len(cves) < page_size:
            break

        offset += page_size
        time.sleep(0.5)

    progress.finish()
    return all_cves


# ---------------------------------------------------------------------------
# Ubuntu codename to version mapping
# ---------------------------------------------------------------------------

CODENAME_TO_VERSION = {
    "trusty": "14.04 LTS",
    "xenial": "16.04 LTS",
    "bionic": "18.04 LTS",
    "focal": "20.04 LTS",
    "jammy": "22.04 LTS",
    "noble": "24.04 LTS",
    "resolute": "26.04 LTS",
    "questing": "25.10",
    "oracular": "24.10",
    "plucky": "25.04",
    "kinetic": "22.10",
    "lunar": "23.04",
    "mantic": "23.10",
}


def _get_affected_releases(cve):
    """Extract the list of affected Ubuntu releases from a CVE entry.

    Returns a sorted list of version strings like ['20.04 LTS', '22.04 LTS'].
    A release is considered affected if its status is not 'DNE' (does not exist)
    and not 'not-affected'.
    """
    affected = set()
    skip_statuses = {"dne", "not-affected", "does-not-exist"}

    for pkg in cve.get("packages", []):
        for rel in pkg.get("statuses", []):
            codename = rel.get("release_codename", "").lower()
            status = rel.get("status", "").lower()
            if codename in ("upstream",):
                continue
            if status in skip_statuses:
                continue
            version = CODENAME_TO_VERSION.get(codename, codename)
            affected.add(version)

    # Sort by numeric version
    def sort_key(v):
        try:
            return float(v.split()[0])
        except (ValueError, IndexError):
            return 99.0

    return sorted(affected, key=sort_key)


# ---------------------------------------------------------------------------
# Report data extraction (shared by all formatters)
# ---------------------------------------------------------------------------

def _extract_report_data(cves):
    """Extract structured data from CVE list for report generation."""
    severity_counts = {
        "critical": 0, "high": 0, "medium": 0,
        "low": 0, "negligible": 0, "unknown": 0,
    }
    statuses = {}
    package_counts = {}

    for cve in cves:
        priority = (cve.get("priority") or "unknown").lower()
        if priority in severity_counts:
            severity_counts[priority] += 1
        else:
            severity_counts["unknown"] += 1

        status = (cve.get("status") or "unknown").lower()
        statuses[status] = statuses.get(status, 0) + 1

        for pkg in cve.get("packages", []):
            pkg_name = pkg.get("name", "unknown")
            package_counts[pkg_name] = package_counts.get(pkg_name, 0) + 1

    sorted_packages = sorted(package_counts.items(), key=lambda x: x[1], reverse=True)

    critical_high = [
        cve for cve in cves
        if (cve.get("priority") or "").lower() in ("critical", "high")
    ]
    critical_high.sort(
        key=lambda c: (0 if (c.get("priority") or "").lower() == "critical" else 1,
                       c.get("id", ""))
    )

    return {
        "total": len(cves),
        "severity_counts": severity_counts,
        "statuses": statuses,
        "sorted_packages": sorted_packages,
        "critical_high": critical_high,
    }


# ---------------------------------------------------------------------------
# Plain-text report
# ---------------------------------------------------------------------------

def generate_report_txt(year, cves):
    """Generate plain-text CVE summary report."""
    if not cves:
        return f"Ubuntu CVE Summary Report - {year}\n\nNo CVEs found for this period.\n"

    d = _extract_report_data(cves)
    total = d["total"]
    severity_counts = d["severity_counts"]
    statuses = d["statuses"]
    sorted_packages = d["sorted_packages"]
    critical_high = d["critical_high"]

    o = StringIO()

    def out(text=""):
        o.write(text + "\n")

    out("=" * 70)
    out(f"  Ubuntu CVE Summary Report - {year}")
    out("=" * 70)
    out(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    out(f"  Source:    Ubuntu Security API (https://ubuntu.com/security/cves)")
    out("=" * 70)

    # Severity
    out(f"\n{'─' * 70}")
    out("  SEVERITY BREAKDOWN")
    out(f"{'─' * 70}")
    out(f"  {'Severity':<15} {'Count':>8}  {'Percentage':>10}  {'Bar'}")
    out(f"  {'-' * 55}")
    for sev in ["critical", "high", "medium", "low", "negligible", "unknown"]:
        count = severity_counts[sev]
        if count > 0:
            pct = (count / total) * 100
            bar = "█" * int(pct / 2)
            out(f"  {sev.capitalize():<15} {count:>8}  {pct:>9.1f}%  {bar}")
    out(f"  {'-' * 55}")
    out(f"  {'TOTAL':<15} {total:>8}")

    # Status
    if statuses:
        out(f"\n{'─' * 70}")
        out("  STATUS BREAKDOWN")
        out(f"{'─' * 70}")
        out(f"  {'Status':<25} {'Count':>8}  {'Percentage':>10}")
        out(f"  {'-' * 48}")
        for status, count in sorted(statuses.items(), key=lambda x: x[1], reverse=True):
            pct = (count / total) * 100
            out(f"  {status.capitalize():<25} {count:>8}  {pct:>9.1f}%")

    # Packages
    out(f"\n{'─' * 70}")
    out("  TOP 25 AFFECTED PACKAGES")
    out(f"{'─' * 70}")
    out(f"  {'#':<4} {'Package':<40} {'CVE Count':>10}")
    out(f"  {'-' * 58}")
    for i, (pkg_name, count) in enumerate(sorted_packages[:25], 1):
        out(f"  {i:<4} {pkg_name:<40} {count:>10}")

    # Critical/High
    out(f"\n{'─' * 70}")
    out(f"  CRITICAL & HIGH SEVERITY CVEs ({len(critical_high)} total)")
    out(f"{'─' * 70}")

    display_limit = 30
    for cve in critical_high[:display_limit]:
        cve_id = cve.get("id", "N/A")
        priority = (cve.get("priority") or "N/A").upper()
        published = cve.get("published", "N/A")
        description = cve.get("description", "No description available.")
        cve_packages = [p.get("name", "") for p in cve.get("packages", [])]
        pkg_str = ", ".join(cve_packages[:5])
        if len(cve_packages) > 5:
            pkg_str += f" (+{len(cve_packages) - 5} more)"
        if len(description) > 150:
            description = description[:147] + "..."
        affected = _get_affected_releases(cve)
        affected_str = ", ".join(affected) if affected else "N/A"
        out(f"\n  [{priority}] {cve_id}")
        out(f"    Published: {published}")
        out(f"    Packages:  {pkg_str}")
        out(f"    Affected:  Ubuntu {affected_str}")
        out(f"    {description}")

    if len(critical_high) > display_limit:
        out(f"\n  ... and {len(critical_high) - display_limit} more critical/high CVEs")

    # Executive summary
    out(f"\n{'═' * 70}")
    out("  EXECUTIVE SUMMARY")
    out(f"{'═' * 70}")
    out(f"  Year:                          {year}")
    out(f"  Total CVEs analyzed:           {total}")
    out(f"  Critical severity:             {severity_counts['critical']}")
    out(f"  High severity:                 {severity_counts['high']}")
    out(f"  Medium severity:               {severity_counts['medium']}")
    out(f"  Low severity:                  {severity_counts['low']}")
    out(f"  Negligible:                    {severity_counts['negligible']}")
    out(f"  Unique packages affected:      {len(sorted_packages)}")
    out(f"  Most affected package:         {sorted_packages[0][0] if sorted_packages else 'N/A'}"
        f" ({sorted_packages[0][1] if sorted_packages else 0} CVEs)")
    out(f"{'═' * 70}")
    out(f"  Report URL: https://ubuntu.com/security/cves?q=CVE-{year}")
    out(f"{'═' * 70}")

    return o.getvalue()


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

def generate_report_md(year, cves):
    """Generate Markdown CVE summary report."""
    if not cves:
        return f"# Ubuntu CVE Summary Report - {year}\n\nNo CVEs found for this period.\n"

    d = _extract_report_data(cves)
    total = d["total"]
    severity_counts = d["severity_counts"]
    statuses = d["statuses"]
    sorted_packages = d["sorted_packages"]
    critical_high = d["critical_high"]

    o = StringIO()

    def out(text=""):
        o.write(text + "\n")

    out(f"# Ubuntu CVE Summary Report - {year}")
    out()
    out(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
    out(f"**Source:** [Ubuntu Security API](https://ubuntu.com/security/cves)")
    out()

    # Severity
    out("## Severity Breakdown")
    out()
    out("| Severity | Count | Percentage |")
    out("|----------|------:|-----------:|")
    for sev in ["critical", "high", "medium", "low", "negligible", "unknown"]:
        count = severity_counts[sev]
        if count > 0:
            pct = (count / total) * 100
            out(f"| {sev.capitalize()} | {count} | {pct:.1f}% |")
    out(f"| **TOTAL** | **{total}** | |")
    out()

    # Status
    if statuses:
        out("## Status Breakdown")
        out()
        out("| Status | Count | Percentage |")
        out("|--------|------:|-----------:|")
        for status, count in sorted(statuses.items(), key=lambda x: x[1], reverse=True):
            pct = (count / total) * 100
            out(f"| {status.capitalize()} | {count} | {pct:.1f}% |")
        out()

    # Packages
    out("## Top 25 Affected Packages")
    out()
    out("| # | Package | CVE Count |")
    out("|---|---------|----------:|")
    for i, (pkg_name, count) in enumerate(sorted_packages[:25], 1):
        out(f"| {i} | {pkg_name} | {count} |")
    out()

    # Critical/High
    out(f"## Critical & High Severity CVEs ({len(critical_high)} total)")
    out()

    display_limit = 30
    for cve in critical_high[:display_limit]:
        cve_id = cve.get("id", "N/A")
        priority = (cve.get("priority") or "N/A").upper()
        published = cve.get("published", "N/A")
        description = cve.get("description", "No description available.")
        cve_packages = [p.get("name", "") for p in cve.get("packages", [])]
        pkg_str = ", ".join(cve_packages[:5])
        if len(cve_packages) > 5:
            pkg_str += f" (+{len(cve_packages) - 5} more)"
        if len(description) > 200:
            description = description[:197] + "..."
        affected = _get_affected_releases(cve)
        affected_str = ", ".join(affected) if affected else "N/A"

        out(f"### [{priority}] {cve_id}")
        out()
        out(f"- **Published:** {published}")
        out(f"- **Packages:** {pkg_str}")
        out(f"- **Affected Ubuntu versions:** {affected_str}")
        out(f"- {description}")
        out()

    if len(critical_high) > display_limit:
        out(f"*... and {len(critical_high) - display_limit} more critical/high CVEs*")
        out()

    # Executive summary
    out("## Executive Summary")
    out()
    out(f"| Metric | Value |")
    out(f"|--------|-------|")
    out(f"| Year | {year} |")
    out(f"| Total CVEs analyzed | {total} |")
    out(f"| Critical severity | {severity_counts['critical']} |")
    out(f"| High severity | {severity_counts['high']} |")
    out(f"| Medium severity | {severity_counts['medium']} |")
    out(f"| Low severity | {severity_counts['low']} |")
    out(f"| Negligible | {severity_counts['negligible']} |")
    out(f"| Unique packages affected | {len(sorted_packages)} |")
    out(f"| Most affected package | {sorted_packages[0][0] if sorted_packages else 'N/A'}"
        f" ({sorted_packages[0][1] if sorted_packages else 0} CVEs) |")
    out()
    out(f"**Full list:** <https://ubuntu.com/security/cves?q=CVE-{year}>")
    out()

    return o.getvalue()


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

def generate_report_html(year, cves):
    """Generate HTML CVE summary report."""
    if not cves:
        return (f"<html><head><title>Ubuntu CVE Report {year}</title></head>"
                f"<body><h1>Ubuntu CVE Summary Report - {year}</h1>"
                f"<p>No CVEs found for this period.</p></body></html>")

    d = _extract_report_data(cves)
    total = d["total"]
    severity_counts = d["severity_counts"]
    statuses = d["statuses"]
    sorted_packages = d["sorted_packages"]
    critical_high = d["critical_high"]

    esc = html_mod.escape
    o = StringIO()

    def out(text=""):
        o.write(text + "\n")

    out("<!DOCTYPE html>")
    out("<html lang=\"en\">")
    out("<head>")
    out(f"  <meta charset=\"utf-8\">")
    out(f"  <title>Ubuntu CVE Report {year}</title>")
    out("  <style>")
    out("    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI',"
        " Roboto, sans-serif; margin: 2em; color: #333; }")
    out("    h1 { color: #E95420; }")
    out("    h2 { border-bottom: 2px solid #E95420; padding-bottom: 0.3em; }")
    out("    table { border-collapse: collapse; width: 100%; margin: 1em 0; }")
    out("    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }")
    out("    th { background: #f5f5f5; }")
    out("    tr:nth-child(even) { background: #fafafa; }")
    out("    .critical { color: #d32f2f; font-weight: bold; }")
    out("    .high { color: #e65100; font-weight: bold; }")
    out("    .medium { color: #f9a825; }")
    out("    .low { color: #388e3c; }")
    out("    .summary-box { background: #f9f9f9; border: 1px solid #ddd;"
        " padding: 1em; border-radius: 6px; }")
    out("    .cve-card { border: 1px solid #eee; padding: 1em;"
        " margin: 0.5em 0; border-radius: 4px; }")
    out("    .footer { margin-top: 2em; color: #666; font-size: 0.9em; }")
    out("  </style>")
    out("</head>")
    out("<body>")

    out(f"<h1>Ubuntu CVE Summary Report &ndash; {year}</h1>")
    out(f"<p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>")
    out(f"<strong>Source:</strong> <a href=\"https://ubuntu.com/security/cves\">"
        f"Ubuntu Security API</a></p>")

    # Severity table
    out("<h2>Severity Breakdown</h2>")
    out("<table>")
    out("<tr><th>Severity</th><th>Count</th><th>Percentage</th><th>Bar</th></tr>")
    for sev in ["critical", "high", "medium", "low", "negligible", "unknown"]:
        count = severity_counts[sev]
        if count > 0:
            pct = (count / total) * 100
            bar_width = int(pct * 2)
            out(f'<tr><td class="{sev}">{sev.capitalize()}</td>'
                f'<td>{count}</td><td>{pct:.1f}%</td>'
                f'<td><div style="background:#E95420;height:14px;'
                f'width:{bar_width}px;border-radius:2px;"></div></td></tr>')
    out(f"<tr><th>TOTAL</th><th>{total}</th><th></th><th></th></tr>")
    out("</table>")

    # Status table
    if statuses:
        out("<h2>Status Breakdown</h2>")
        out("<table>")
        out("<tr><th>Status</th><th>Count</th><th>Percentage</th></tr>")
        for status, count in sorted(statuses.items(), key=lambda x: x[1], reverse=True):
            pct = (count / total) * 100
            out(f"<tr><td>{esc(status.capitalize())}</td>"
                f"<td>{count}</td><td>{pct:.1f}%</td></tr>")
        out("</table>")

    # Packages table
    out("<h2>Top 25 Affected Packages</h2>")
    out("<table>")
    out("<tr><th>#</th><th>Package</th><th>CVE Count</th></tr>")
    for i, (pkg_name, count) in enumerate(sorted_packages[:25], 1):
        out(f"<tr><td>{i}</td><td>{esc(pkg_name)}</td><td>{count}</td></tr>")
    out("</table>")

    # Critical/High CVEs
    out(f"<h2>Critical &amp; High Severity CVEs ({len(critical_high)} total)</h2>")

    display_limit = 30
    for cve in critical_high[:display_limit]:
        cve_id = cve.get("id", "N/A")
        priority = (cve.get("priority") or "N/A").lower()
        published = cve.get("published", "N/A")
        description = cve.get("description", "No description available.")
        cve_packages = [p.get("name", "") for p in cve.get("packages", [])]
        pkg_str = ", ".join(cve_packages[:5])
        if len(cve_packages) > 5:
            pkg_str += f" (+{len(cve_packages) - 5} more)"
        if len(description) > 200:
            description = description[:197] + "..."
        affected = _get_affected_releases(cve)
        affected_str = ", ".join(affected) if affected else "N/A"

        out(f'<div class="cve-card">')
        out(f'  <strong class="{priority}">[{priority.upper()}]</strong> '
            f'<a href="https://ubuntu.com/security/{cve_id}">{esc(cve_id)}</a><br>')
        out(f"  <strong>Published:</strong> {esc(published)}<br>")
        out(f"  <strong>Packages:</strong> {esc(pkg_str)}<br>")
        out(f"  <strong>Affected Ubuntu versions:</strong> {esc(affected_str)}<br>")
        out(f"  <em>{esc(description)}</em>")
        out(f"</div>")

    if len(critical_high) > display_limit:
        out(f"<p><em>... and {len(critical_high) - display_limit} more critical/high CVEs</em></p>")

    # Executive summary box
    out('<h2>Executive Summary</h2>')
    out('<div class="summary-box">')
    out(f"<p><strong>Year:</strong> {year}<br>")
    out(f"<strong>Total CVEs analyzed:</strong> {total}<br>")
    out(f"<strong>Critical severity:</strong> {severity_counts['critical']}<br>")
    out(f"<strong>High severity:</strong> {severity_counts['high']}<br>")
    out(f"<strong>Medium severity:</strong> {severity_counts['medium']}<br>")
    out(f"<strong>Low severity:</strong> {severity_counts['low']}<br>")
    out(f"<strong>Negligible:</strong> {severity_counts['negligible']}<br>")
    out(f"<strong>Unique packages affected:</strong> {len(sorted_packages)}<br>")
    out(f"<strong>Most affected package:</strong> "
        f"{esc(sorted_packages[0][0]) if sorted_packages else 'N/A'}"
        f" ({sorted_packages[0][1] if sorted_packages else 0} CVEs)</p>")
    out("</div>")

    out(f'<p class="footer">Full list: '
        f'<a href="https://ubuntu.com/security/cves?q=CVE-{year}">'
        f'https://ubuntu.com/security/cves?q=CVE-{year}</a></p>')
    out("</body>")
    out("</html>")

    return o.getvalue()


# ---------------------------------------------------------------------------
# Full CVE list (all CVEs, separate files)
# ---------------------------------------------------------------------------

def generate_full_list_txt(year, cves):
    """Generate a plain-text file listing every CVE with details."""
    o = StringIO()

    def out(text=""):
        o.write(text + "\n")

    out("=" * 70)
    out(f"  Ubuntu Full CVE List - {year} ({len(cves)} CVEs)")
    out("=" * 70)
    out(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    out(f"  Source:    Ubuntu Security API (https://ubuntu.com/security/cves)")
    out("=" * 70)

    for cve in cves:
        cve_id = cve.get("id", "N/A")
        priority = (cve.get("priority") or "N/A").upper()
        published = cve.get("published", "N/A")
        status = (cve.get("status") or "N/A").capitalize()
        description = cve.get("description", "No description available.").strip()
        cve_packages = [p.get("name", "") for p in cve.get("packages", [])]
        pkg_str = ", ".join(cve_packages[:10])
        if len(cve_packages) > 10:
            pkg_str += f" (+{len(cve_packages) - 10} more)"
        affected = _get_affected_releases(cve)
        affected_str = ", ".join(affected) if affected else "N/A"
        if len(description) > 300:
            description = description[:297] + "..."

        out(f"\n{'─' * 70}")
        out(f"  [{priority}] {cve_id}  (Status: {status})")
        out(f"    Published: {published}")
        out(f"    Packages:  {pkg_str}")
        out(f"    Affected:  Ubuntu {affected_str}")
        out(f"    {description}")

    out(f"\n{'═' * 70}")
    out(f"  Total: {len(cves)} CVEs")
    out(f"{'═' * 70}")

    return o.getvalue()


def generate_full_list_md(year, cves):
    """Generate a Markdown file listing every CVE with details."""
    o = StringIO()

    def out(text=""):
        o.write(text + "\n")

    out(f"# Ubuntu Full CVE List - {year}")
    out()
    out(f"**Total CVEs:** {len(cves)}  ")
    out(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
    out(f"**Source:** [Ubuntu Security API](https://ubuntu.com/security/cves)")
    out()
    out("---")
    out()

    for cve in cves:
        cve_id = cve.get("id", "N/A")
        priority = (cve.get("priority") or "N/A").upper()
        published = cve.get("published", "N/A")
        status = (cve.get("status") or "N/A").capitalize()
        description = cve.get("description", "No description available.").strip()
        cve_packages = [p.get("name", "") for p in cve.get("packages", [])]
        pkg_str = ", ".join(cve_packages[:10])
        if len(cve_packages) > 10:
            pkg_str += f" (+{len(cve_packages) - 10} more)"
        affected = _get_affected_releases(cve)
        affected_str = ", ".join(affected) if affected else "N/A"
        if len(description) > 300:
            description = description[:297] + "..."

        out(f"## [{priority}] {cve_id}")
        out()
        out(f"- **Status:** {status}")
        out(f"- **Published:** {published}")
        out(f"- **Packages:** {pkg_str}")
        out(f"- **Affected Ubuntu versions:** {affected_str}")
        out(f"- {description}")
        out()

    return o.getvalue()


def generate_full_list_html(year, cves):
    """Generate an HTML file listing every CVE in a table with severity filter."""
    esc = html_mod.escape
    o = StringIO()

    def out(text=""):
        o.write(text + "\n")

    out("<!DOCTYPE html>")
    out("<html lang=\"en\">")
    out("<head>")
    out("  <meta charset=\"utf-8\">")
    out(f"  <title>Ubuntu Full CVE List {year}</title>")
    out("  <style>")
    out("    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI',"
        " Roboto, sans-serif; margin: 2em; color: #333; }")
    out("    h1 { color: #E95420; }")
    out("    table { border-collapse: collapse; width: 100%; margin: 1em 0; }")
    out("    th, td { border: 1px solid #ddd; padding: 6px 8px;"
        " text-align: left; vertical-align: top; }")
    out("    th { background: #f5f5f5; position: sticky; top: 0; }")
    out("    tr:nth-child(even) { background: #fafafa; }")
    out("    .critical { color: #d32f2f; font-weight: bold; }")
    out("    .high { color: #e65100; font-weight: bold; }")
    out("    .medium { color: #f9a825; }")
    out("    .low { color: #388e3c; }")
    out("    .negligible { color: #666; }")
    out("    td.desc { max-width: 400px; font-size: 0.9em; }")
    out("    .footer { margin-top: 1em; color: #666; font-size: 0.9em; }")
    out("    .filter-bar { margin: 1em 0; padding: 1em; background: #f9f9f9;"
        " border: 1px solid #ddd; border-radius: 6px;"
        " display: flex; align-items: center; gap: 1em; flex-wrap: wrap; }")
    out("    .filter-bar label { font-weight: bold; }")
    out("    .filter-bar select { padding: 6px 12px; border-radius: 4px;"
        " border: 1px solid #ccc; font-size: 1em; }")
    out("    .filter-bar .count { color: #666; font-size: 0.9em; }")
    out("  </style>")
    out("</head>")
    out("<body>")
    out(f"<h1>Ubuntu Full CVE List &ndash; {year} ({len(cves)} CVEs)</h1>")
    out(f"<p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        f" | <strong>Source:</strong> "
        f"<a href=\"https://ubuntu.com/security/cves\">Ubuntu Security API</a></p>")

    # Filter bar
    out('<div class="filter-bar">')
    out('  <label for="severity-filter">Filter by severity:</label>')
    out('  <select id="severity-filter" onchange="filterBySeverity()">')
    out('    <option value="all">All</option>')
    out('    <option value="critical">Critical</option>')
    out('    <option value="high">High</option>')
    out('    <option value="medium">Medium</option>')
    out('    <option value="low">Low</option>')
    out('    <option value="negligible">Negligible</option>')
    out('    <option value="unknown">Unknown</option>')
    out('  </select>')
    out('  <span class="count" id="visible-count"></span>')
    out('</div>')

    out('<table id="cve-table">')
    out("<tr><th>CVE ID</th><th>Severity</th><th>Status</th>"
        "<th>Published</th><th>Packages</th>"
        "<th>Affected Versions</th><th>Description</th></tr>")

    for cve in cves:
        cve_id = cve.get("id", "N/A")
        priority = (cve.get("priority") or "unknown").lower()
        priority_label = priority.upper()
        status = (cve.get("status") or "N/A").capitalize()
        published = cve.get("published", "N/A")
        description = cve.get("description", "").strip()
        cve_packages = [p.get("name", "") for p in cve.get("packages", [])]
        pkg_str = ", ".join(cve_packages[:5])
        if len(cve_packages) > 5:
            pkg_str += f" (+{len(cve_packages) - 5} more)"
        affected = _get_affected_releases(cve)
        affected_str = ", ".join(affected) if affected else "N/A"
        if len(description) > 200:
            description = description[:197] + "..."

        out(f'<tr data-severity="{priority}">'
            f'<td><a href="https://ubuntu.com/security/{cve_id}">{esc(cve_id)}</a></td>'
            f'<td class="{priority}">{priority_label}</td>'
            f'<td>{esc(status)}</td>'
            f'<td>{esc(published)}</td>'
            f'<td>{esc(pkg_str)}</td>'
            f'<td>{esc(affected_str)}</td>'
            f'<td class="desc">{esc(description)}</td>'
            f'</tr>')

    out("</table>")
    out(f'<p class="footer">Total: {len(cves)} CVEs | '
        f'<a href="https://ubuntu.com/security/cves?q=CVE-{year}">View on Ubuntu.com</a></p>')

    # JavaScript for filtering
    out("<script>")
    out("function filterBySeverity() {")
    out("  var sel = document.getElementById('severity-filter').value;")
    out("  var rows = document.querySelectorAll('#cve-table tr[data-severity]');")
    out("  var visible = 0;")
    out("  rows.forEach(function(row) {")
    out("    if (sel === 'all' || row.getAttribute('data-severity') === sel) {")
    out("      row.style.display = '';")
    out("      visible++;")
    out("    } else {")
    out("      row.style.display = 'none';")
    out("    }")
    out("  });")
    out("  document.getElementById('visible-count').textContent =")
    out(f"    'Showing ' + visible + ' of {len(cves)} CVEs';")
    out("}")
    out(f"document.getElementById('visible-count').textContent ="
        f" 'Showing {len(cves)} of {len(cves)} CVEs';")
    out("</script>")

    out("</body>")
    out("</html>")

    return o.getvalue()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate a Ubuntu CVE summary report for a given year."
    )
    parser.add_argument(
        "--year", type=int, default=datetime.now().year,
        help="Year to generate the report for (default: current year)"
    )
    parser.add_argument(
        "--output-dir", "-o", type=str, default=".",
        help="Directory to write report files to (default: current directory)"
    )
    parser.add_argument(
        "--max-results", type=int, default=1000,
        help="Maximum number of CVEs to fetch (default: 1000)"
    )
    parser.add_argument(
        "--full", action="store_true", default=False,
        help="Generate the full CVE list (fetches ALL CVEs, ignores --max-results)"
    )
    args = parser.parse_args()

    year = args.year

    # --full overrides --max-results to unlimited
    if args.full:
        max_results = 999999
    else:
        max_results = args.max_results

    print(f"Fetching Ubuntu CVEs for {year}...")
    if args.full:
        print("(Full mode: fetching ALL available CVEs — this may take several minutes)\n")
    else:
        print(f"(Fetching up to {max_results} CVEs — use --full for the complete list)\n")

    cves = fetch_ubuntu_cves(year, max_results=max_results)

    if cves is None:
        print("Failed to fetch CVE data. Please check your internet connection.")
        sys.exit(1)

    print(f"\nRetrieved {len(cves)} CVEs for {year}.\n")

    # Generate summary reports (always)
    report_txt = generate_report_txt(year, cves)
    report_md = generate_report_md(year, cves)
    report_html = generate_report_html(year, cves)

    # Ensure output directory exists
    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)

    basename = f"ubuntu_cve_report_{year}"
    files_written = []

    for ext, content in [(".txt", report_txt), (".md", report_md), (".html", report_html)]:
        filepath = os.path.join(output_dir, basename + ext)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        files_written.append(filepath)

    # Generate full CVE list only when --full is specified
    if args.full:
        full_txt = generate_full_list_txt(year, cves)
        full_md = generate_full_list_md(year, cves)
        full_html = generate_full_list_html(year, cves)

        fullname = f"ubuntu_cve_full_list_{year}"
        for ext, content in [(".txt", full_txt), (".md", full_md), (".html", full_html)]:
            filepath = os.path.join(output_dir, fullname + ext)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            files_written.append(filepath)

    print("Reports saved:")
    for fp in files_written:
        print(f"  - {fp}")

    # Also print the text report to stdout
    print()
    print(report_txt)


if __name__ == "__main__":
    main()
