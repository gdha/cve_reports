"""
Generate a summary CVE report for Ubuntu for the current year.

Uses the Ubuntu Security API (https://ubuntu.com/security/cves.json)
to fetch CVE data and produce a severity breakdown, top affected packages,
and a list of critical/high CVEs.

Usage:
    python create_cve_report_ubuntu.py
    python create_cve_report_ubuntu.py --output report.txt
    python create_cve_report_ubuntu.py --year 2025
"""

import argparse
import sys
import time
from datetime import datetime
from io import StringIO

try:
    import requests
except ImportError:
    print("Error: 'requests' library is required. Install it with: pip install requests")
    sys.exit(1)


def fetch_ubuntu_cves(year, max_results=1000):
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

    while offset < max_results:
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
            print(f"  Warning: Request timed out at offset {offset}. Retrying...")
            time.sleep(2)
            try:
                response = requests.get(base_url, params=params, headers=headers, timeout=60)
                response.raise_for_status()
                data = response.json()
            except requests.exceptions.RequestException as e:
                print(f"  Error: Retry failed: {e}")
                break
        except requests.exceptions.HTTPError as e:
            print(f"  Error: HTTP {response.status_code} at offset {offset}: {e}")
            break
        except requests.exceptions.RequestException as e:
            print(f"  Error: {e}")
            break

        cves = data.get("cves", [])
        if not cves:
            break

        # Filter to only include CVEs from the requested year
        for cve in cves:
            cve_id = cve.get("id", "")
            if f"CVE-{year}" in cve_id:
                all_cves.append(cve)

        # If fewer results than page_size, we've reached the end
        if len(cves) < page_size:
            break

        offset += page_size
        # Be polite to the API
        time.sleep(0.5)

    return all_cves


def generate_report(year, cves):
    """Generate a formatted CVE summary report.

    Args:
        year: The year of the report.
        cves: List of CVE dictionaries from the Ubuntu API.

    Returns:
        The report as a string.
    """
    output = StringIO()

    def out(text=""):
        output.write(text + "\n")

    out("=" * 70)
    out(f"  Ubuntu CVE Summary Report - {year}")
    out("=" * 70)
    out(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    out(f"  Source:    Ubuntu Security API (https://ubuntu.com/security/cves)")
    out("=" * 70)

    if not cves:
        out("\n  No CVEs found for this period.")
        return output.getvalue()

    # Severity breakdown
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "negligible": 0,
        "unknown": 0,
    }

    statuses = {}
    package_counts = {}

    for cve in cves:
        # Count by priority/severity
        priority = (cve.get("priority") or "unknown").lower()
        if priority in severity_counts:
            severity_counts[priority] += 1
        else:
            severity_counts["unknown"] += 1

        # Count by status
        status = (cve.get("status") or "unknown").lower()
        statuses[status] = statuses.get(status, 0) + 1

        # Count affected packages
        packages = cve.get("packages", [])
        for pkg in packages:
            pkg_name = pkg.get("name", "unknown")
            package_counts[pkg_name] = package_counts.get(pkg_name, 0) + 1

    total = len(cves)

    # Severity summary
    out(f"\n{'─' * 70}")
    out(f"  SEVERITY BREAKDOWN")
    out(f"{'─' * 70}")
    out(f"  {'Severity':<15} {'Count':>8}  {'Percentage':>10}  {'Bar'}")
    out(f"  {'-' * 55}")

    for severity in ["critical", "high", "medium", "low", "negligible", "unknown"]:
        count = severity_counts[severity]
        if count > 0:
            pct = (count / total) * 100
            bar = "█" * int(pct / 2)
            out(f"  {severity.capitalize():<15} {count:>8}  {pct:>9.1f}%  {bar}")

    out(f"  {'-' * 55}")
    out(f"  {'TOTAL':<15} {total:>8}")

    # Status summary
    if statuses:
        out(f"\n{'─' * 70}")
        out(f"  STATUS BREAKDOWN")
        out(f"{'─' * 70}")
        out(f"  {'Status':<25} {'Count':>8}  {'Percentage':>10}")
        out(f"  {'-' * 48}")
        for status, count in sorted(statuses.items(), key=lambda x: x[1], reverse=True):
            pct = (count / total) * 100
            out(f"  {status.capitalize():<25} {count:>8}  {pct:>9.1f}%")

    # Top affected packages
    sorted_packages = sorted(package_counts.items(), key=lambda x: x[1], reverse=True)
    out(f"\n{'─' * 70}")
    out(f"  TOP 25 AFFECTED PACKAGES")
    out(f"{'─' * 70}")
    out(f"  {'#':<4} {'Package':<40} {'CVE Count':>10}")
    out(f"  {'-' * 58}")
    for i, (pkg_name, count) in enumerate(sorted_packages[:25], 1):
        out(f"  {i:<4} {pkg_name:<40} {count:>10}")

    # Critical and High severity CVEs
    critical_high = [
        cve for cve in cves
        if (cve.get("priority") or "").lower() in ("critical", "high")
    ]

    out(f"\n{'─' * 70}")
    out(f"  CRITICAL & HIGH SEVERITY CVEs ({len(critical_high)} total)")
    out(f"{'─' * 70}")

    # Sort by priority (critical first), then by ID
    critical_high.sort(
        key=lambda c: (0 if (c.get("priority") or "").lower() == "critical" else 1,
                       c.get("id", ""))
    )

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

        # Truncate description
        if len(description) > 150:
            description = description[:147] + "..."

        out(f"\n  [{priority}] {cve_id}")
        out(f"    Published: {published}")
        out(f"    Packages:  {pkg_str}")
        out(f"    {description}")

    if len(critical_high) > display_limit:
        out(f"\n  ... and {len(critical_high) - display_limit} more critical/high CVEs")

    # Final summary box
    out(f"\n{'═' * 70}")
    out(f"  EXECUTIVE SUMMARY")
    out(f"{'═' * 70}")
    out(f"  Year:                          {year}")
    out(f"  Total CVEs analyzed:           {total}")
    out(f"  Critical severity:             {severity_counts['critical']}")
    out(f"  High severity:                 {severity_counts['high']}")
    out(f"  Medium severity:               {severity_counts['medium']}")
    out(f"  Low severity:                  {severity_counts['low']}")
    out(f"  Negligible:                    {severity_counts['negligible']}")
    out(f"  Unique packages affected:      {len(package_counts)}")
    out(f"  Most affected package:         {sorted_packages[0][0] if sorted_packages else 'N/A'}"
        f" ({sorted_packages[0][1] if sorted_packages else 0} CVEs)")
    out(f"{'═' * 70}")
    out(f"  Report URL: https://ubuntu.com/security/cves?q=CVE-{year}")
    out(f"{'═' * 70}")

    return output.getvalue()


def main():
    parser = argparse.ArgumentParser(
        description="Generate a Ubuntu CVE summary report for a given year."
    )
    parser.add_argument(
        "--year", type=int, default=datetime.now().year,
        help="Year to generate the report for (default: current year)"
    )
    parser.add_argument(
        "--output", "-o", type=str, default=None,
        help="Write report to file instead of stdout"
    )
    parser.add_argument(
        "--max-results", type=int, default=1000,
        help="Maximum number of CVEs to fetch (default: 1000)"
    )
    args = parser.parse_args()

    year = args.year
    print(f"Fetching Ubuntu CVEs for {year}...")
    print(f"(This may take a moment depending on the number of CVEs)\n")

    cves = fetch_ubuntu_cves(year, max_results=args.max_results)

    if cves is None:
        print("Failed to fetch CVE data. Please check your internet connection.")
        sys.exit(1)

    print(f"Retrieved {len(cves)} CVEs for {year}.\n")

    report = generate_report(year, cves)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"Report written to: {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()
