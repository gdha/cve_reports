#!/usr/bin/env python3
"""
Generate a summary CVE report for Linux distributions for a given year.

Supported distributions: Ubuntu, RHEL (Red Hat Enterprise Linux).

Uses distro-specific security APIs to fetch CVE data and produce a severity
breakdown, top affected packages, and a list of critical/high CVEs.

Output formats: plain text (.txt), HTML (.html), and Markdown (.md).

Usage:
    python create_cve_report.py --distro ubuntu
    python create_cve_report.py --distro rhel
    python create_cve_report.py --distro rhel --year 2025 --full
    python create_cve_report.py --distro ubuntu --output-dir /tmp/reports
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


# ===========================================================================
# Progress bar
# ===========================================================================

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


# ===========================================================================
# Normalized CVE structure
# ===========================================================================
# Each fetcher normalizes its API response into this common format:
#
# {
#     "id": "CVE-YYYY-NNNNN",
#     "priority": "critical|high|medium|low|negligible|unknown",
#     "status": "active|fixed|...",
#     "published": "YYYY-MM-DD...",
#     "description": "...",
#     "packages": [{"name": "pkg"}],
#     "affected_versions": ["RHEL 8", "RHEL 9", ...],
# }


# ===========================================================================
# Ubuntu fetcher
# ===========================================================================

UBUNTU_CODENAME_TO_VERSION = {
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


def _ubuntu_get_affected(cve_raw):
    """Extract affected Ubuntu releases from raw API CVE entry."""
    affected = set()
    skip_statuses = {"dne", "not-affected", "does-not-exist"}

    for pkg in cve_raw.get("packages", []):
        for rel in pkg.get("statuses", []):
            codename = rel.get("release_codename", "").lower()
            status = rel.get("status", "").lower()
            if codename in ("upstream",):
                continue
            if status in skip_statuses:
                continue
            version = UBUNTU_CODENAME_TO_VERSION.get(codename, codename)
            affected.add(version)

    def sort_key(v):
        try:
            return float(v.split()[0])
        except (ValueError, IndexError):
            return 99.0

    return sorted(affected, key=sort_key)


def _ubuntu_normalize(cve_raw):
    """Normalize a single Ubuntu API CVE entry to common format."""
    packages = [{"name": p.get("name", "unknown")} for p in cve_raw.get("packages", [])]
    return {
        "id": cve_raw.get("id", "N/A"),
        "priority": (cve_raw.get("priority") or "unknown").lower(),
        "status": (cve_raw.get("status") or "unknown").lower(),
        "published": cve_raw.get("published", "N/A"),
        "description": cve_raw.get("description", "").strip(),
        "packages": packages,
        "affected_versions": _ubuntu_get_affected(cve_raw),
    }


def fetch_ubuntu_cves(year, max_results=1000):
    """Fetch CVEs from the Ubuntu Security API for a given year."""
    base_url = "https://ubuntu.com/security/cves.json"
    page_size = 20
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
            all_cves.append(_ubuntu_normalize(cve))

    if len(cves_first) < page_size:
        return all_cves

    offset = page_size
    progress = ProgressBar(total_to_fetch, prefix="Fetching CVEs")
    progress.update(len(cves_first))

    while offset < total_to_fetch:
        params = {"q": f"CVE-{year}", "limit": page_size, "offset": offset, "order": "newest"}
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
                all_cves.append(_ubuntu_normalize(cve))

        progress.update(len(cves))
        if len(cves) < page_size:
            break
        offset += page_size
        time.sleep(0.5)

    progress.finish()
    return all_cves


# ===========================================================================
# RHEL fetcher
# ===========================================================================

# Red Hat severity names mapped to our normalized priority levels
RHEL_SEVERITY_MAP = {
    "critical": "critical",
    "important": "high",
    "moderate": "medium",
    "low": "low",
}


def _rhel_get_affected(cve_raw):
    """Extract affected RHEL versions from a CVE list entry with package_state."""
    affected = set()
    skip_states = {"not affected", "fix deferred", "will not fix"}

    for ps in cve_raw.get("package_state") or []:
        fix_state = (ps.get("fix_state") or "").lower()
        product = ps.get("product_name", "")
        if fix_state in skip_states:
            continue
        # Only include RHEL products
        if "Red Hat Enterprise Linux" in product:
            # Extract version number, e.g. "Red Hat Enterprise Linux 9" -> "RHEL 9"
            parts = product.replace("Red Hat Enterprise Linux", "").strip()
            if parts:
                affected.add(f"RHEL {parts}")

    def sort_key(v):
        try:
            return float(v.split()[-1])
        except (ValueError, IndexError):
            return 99.0

    return sorted(affected, key=sort_key)


def _rhel_normalize(cve_raw):
    """Normalize a single RHEL API CVE list entry to common format."""
    severity = (cve_raw.get("severity") or "unknown").lower()
    priority = RHEL_SEVERITY_MAP.get(severity, "unknown")

    # Extract packages from package_state or affected_packages
    packages = []
    seen_pkgs = set()
    for ps in cve_raw.get("package_state") or []:
        pkg_name = ps.get("package_name", "")
        # Strip module prefix like "redhat-ds:11/"
        if "/" in pkg_name:
            pkg_name = pkg_name.split("/", 1)[1]
        if pkg_name and pkg_name not in seen_pkgs:
            packages.append({"name": pkg_name})
            seen_pkgs.add(pkg_name)
    for pkg in cve_raw.get("affected_packages") or []:
        if isinstance(pkg, str) and pkg not in seen_pkgs:
            packages.append({"name": pkg})
            seen_pkgs.add(pkg)

    # Description from bugzilla_description (list API doesn't have full details)
    description = cve_raw.get("bugzilla_description", "")

    return {
        "id": cve_raw.get("CVE", "N/A"),
        "priority": priority,
        "status": "with advisory" if cve_raw.get("advisories") else "active",
        "published": cve_raw.get("public_date", "N/A"),
        "description": description.strip(),
        "packages": packages,
        "affected_versions": _rhel_get_affected(cve_raw),
    }


def fetch_rhel_cves(year, max_results=1000):
    """Fetch CVEs from the Red Hat Security Data API for a given year."""
    base_url = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
    per_page = 1000  # Red Hat allows up to 1000 per page
    page = 1
    all_cves = []

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Accept": "application/json",
    }

    # First request to get total count estimate
    params = {
        "after": f"{year}-01-01",
        "before": f"{year}-12-31",
        "per_page": min(per_page, max_results),
        "page": 1,
        "include_package_state": "true",
    }

    try:
        response = requests.get(base_url, params=params, headers=headers, timeout=60)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"  Error on initial request: {e}", file=sys.stderr)
        return None

    if not isinstance(data, list):
        print(f"  Error: Unexpected response format", file=sys.stderr)
        return None

    for cve in data:
        all_cves.append(_rhel_normalize(cve))

    # If first page is full, there may be more
    if len(data) < per_page or len(all_cves) >= max_results:
        return all_cves[:max_results]

    # Estimate: Red Hat API doesn't return total count, so we paginate until empty
    print(f"  First page: {len(data)} CVEs, fetching more...", file=sys.stderr)
    progress = ProgressBar(max_results, prefix="Fetching CVEs")
    progress.update(len(data))
    page = 2

    while len(all_cves) < max_results:
        params["page"] = page
        try:
            response = requests.get(base_url, params=params, headers=headers, timeout=60)
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.RequestException as e:
            print(f"\n  Error on page {page}: {e}", file=sys.stderr)
            break

        if not data:
            break

        for cve in data:
            all_cves.append(_rhel_normalize(cve))

        progress.update(len(data))

        if len(data) < per_page:
            break

        page += 1
        time.sleep(0.3)

    if page > 1:
        progress.finish()

    return all_cves[:max_results]


# ===========================================================================
# Debian fetcher
# ===========================================================================

DEBIAN_CODENAME_TO_VERSION = {
    "sid": "Sid (unstable)",
    "trixie": "13 (Trixie)",
    "bookworm": "12 (Bookworm)",
    "bullseye": "11 (Bullseye)",
    "buster": "10 (Buster)",
    "stretch": "9 (Stretch)",
    "jessie": "8 (Jessie)",
    "forky": "14 (Forky)",
}

# Map Debian urgency to normalized priority
DEBIAN_URGENCY_MAP = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "unimportant": "negligible",
    "not yet assigned": "unknown",
    "end-of-life": "negligible",
}


def _debian_get_priority(cve_data, releases):
    """Determine the highest urgency across all affected releases."""
    priority_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3,
                     "negligible": 4, "unknown": 5}
    best = "unknown"
    for rel_name, rel_info in releases.items():
        urgency = (rel_info.get("urgency") or "not yet assigned").lower()
        # Some urgency values have suffixes like "low*" or contain extra text
        urgency = urgency.rstrip("*").strip()
        normalized = DEBIAN_URGENCY_MAP.get(urgency, "unknown")
        if priority_rank.get(normalized, 5) < priority_rank.get(best, 5):
            best = normalized
    return best


def _debian_get_affected(releases):
    """Extract affected Debian releases (status != 'resolved' and != 'undetermined')."""
    affected = []
    skip_statuses = {"resolved", "undetermined"}

    for rel_name, rel_info in releases.items():
        status = (rel_info.get("status") or "").lower()
        if status in skip_statuses:
            continue
        version = DEBIAN_CODENAME_TO_VERSION.get(rel_name, rel_name.capitalize())
        affected.append(version)

    # Sort by version number
    def sort_key(v):
        try:
            return float(v.split()[0])
        except (ValueError, IndexError):
            # Sid/unstable goes last
            if "unstable" in v.lower() or "sid" in v.lower():
                return 99.0
            return 50.0

    return sorted(affected, key=sort_key)


def fetch_debian_cves(year, max_results=1000):
    """Fetch CVEs from the Debian Security Tracker JSON for a given year.

    Downloads the full JSON dataset and filters by year client-side.
    The download is ~75MB so this takes a while on the first call.
    """
    url = "https://security-tracker.debian.org/tracker/data/json"

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Accept": "application/json",
    }

    print("  Downloading Debian Security Tracker data (~75MB)...", file=sys.stderr)
    try:
        response = requests.get(url, headers=headers, timeout=180, stream=True)
        response.raise_for_status()

        # Download with progress
        total_size = int(response.headers.get("content-length", 0))
        if total_size > 0:
            progress = ProgressBar(total_size, prefix="Downloading")
        chunks = []
        downloaded = 0
        for chunk in response.iter_content(chunk_size=1024 * 256):
            chunks.append(chunk)
            downloaded += len(chunk)
            if total_size > 0:
                progress.current = downloaded
                progress._render()
        if total_size > 0:
            progress.finish()

        raw = b"".join(chunks)
        data = __import__("json").loads(raw)
    except requests.exceptions.RequestException as e:
        print(f"  Error downloading Debian data: {e}", file=sys.stderr)
        return None

    # Invert from package-centric to CVE-centric
    year_prefix = f"CVE-{year}"
    cve_map = {}  # cve_id -> {description, packages, releases_union}

    print(f"  Filtering CVEs for {year}...", file=sys.stderr)

    for pkg_name, pkg_cves in data.items():
        for cve_id, cve_info in pkg_cves.items():
            if not cve_id.startswith(year_prefix):
                continue

            if cve_id not in cve_map:
                cve_map[cve_id] = {
                    "description": cve_info.get("description", ""),
                    "packages": [],
                    "releases": {},
                }

            cve_map[cve_id]["packages"].append({"name": pkg_name})

            # Merge release info (union across packages)
            for rel_name, rel_info in (cve_info.get("releases") or {}).items():
                if rel_name not in cve_map[cve_id]["releases"]:
                    cve_map[cve_id]["releases"][rel_name] = rel_info
                else:
                    # Keep the "worse" status (open > resolved)
                    existing = cve_map[cve_id]["releases"][rel_name]
                    if (rel_info.get("status", "").lower() == "open" and
                            existing.get("status", "").lower() != "open"):
                        cve_map[cve_id]["releases"][rel_name] = rel_info

    # Normalize into common format
    all_cves = []
    for cve_id in sorted(cve_map.keys(), reverse=True):
        entry = cve_map[cve_id]
        releases = entry["releases"]
        priority = _debian_get_priority(entry, releases)
        affected = _debian_get_affected(releases)

        all_cves.append({
            "id": cve_id,
            "priority": priority,
            "status": "open" if any(
                r.get("status", "").lower() == "open"
                for r in releases.values()
            ) else "resolved",
            "published": "N/A",  # Debian tracker doesn't provide publish dates
            "description": entry["description"].strip(),
            "packages": entry["packages"],
            "affected_versions": affected,
        })

        if len(all_cves) >= max_results:
            break

    return all_cves


# ===========================================================================
# Distro registry
# ===========================================================================

DISTRO_CONFIG = {
    "ubuntu": {
        "name": "Ubuntu",
        "fetcher": fetch_ubuntu_cves,
        "source_url": "https://ubuntu.com/security/cves",
        "cve_url_template": "https://ubuntu.com/security/{cve_id}",
        "brand_color": "#E95420",
        "version_label": "Ubuntu versions",
    },
    "rhel": {
        "name": "Red Hat Enterprise Linux",
        "fetcher": fetch_rhel_cves,
        "source_url": "https://access.redhat.com/security/security-updates/cve",
        "cve_url_template": "https://access.redhat.com/security/cve/{cve_id}",
        "brand_color": "#CC0000",
        "version_label": "RHEL versions",
    },
    "debian": {
        "name": "Debian",
        "fetcher": fetch_debian_cves,
        "source_url": "https://security-tracker.debian.org/tracker",
        "cve_url_template": "https://security-tracker.debian.org/tracker/{cve_id}",
        "brand_color": "#A80030",
        "version_label": "Debian versions",
    },
}


# ===========================================================================
# Report data extraction (shared by all formatters)
# ===========================================================================

def _extract_report_data(cves):
    """Extract structured data from normalized CVE list for report generation."""
    severity_counts = {
        "critical": 0, "high": 0, "medium": 0,
        "low": 0, "negligible": 0, "unknown": 0,
    }
    statuses = {}
    package_counts = {}

    for cve in cves:
        priority = cve.get("priority", "unknown")
        if priority in severity_counts:
            severity_counts[priority] += 1
        else:
            severity_counts["unknown"] += 1

        status = cve.get("status", "unknown")
        statuses[status] = statuses.get(status, 0) + 1

        for pkg in cve.get("packages", []):
            pkg_name = pkg.get("name", "unknown")
            package_counts[pkg_name] = package_counts.get(pkg_name, 0) + 1

    sorted_packages = sorted(package_counts.items(), key=lambda x: x[1], reverse=True)

    critical_high = [
        cve for cve in cves
        if cve.get("priority", "") in ("critical", "high")
    ]
    critical_high.sort(
        key=lambda c: (0 if c.get("priority") == "critical" else 1, c.get("id", ""))
    )

    return {
        "total": len(cves),
        "severity_counts": severity_counts,
        "statuses": statuses,
        "sorted_packages": sorted_packages,
        "critical_high": critical_high,
    }


# ===========================================================================
# Plain-text report
# ===========================================================================

def generate_report_txt(year, cves, distro_cfg):
    """Generate plain-text CVE summary report."""
    distro_name = distro_cfg["name"]
    source_url = distro_cfg["source_url"]
    version_label = distro_cfg["version_label"]

    if not cves:
        return f"{distro_name} CVE Summary Report - {year}\n\nNo CVEs found.\n"

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
    out(f"  {distro_name} CVE Summary Report - {year}")
    out("=" * 70)
    out(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    out(f"  Source:    {source_url}")
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
        cve_id = cve["id"]
        priority = cve["priority"].upper()
        published = cve["published"]
        description = cve["description"]
        pkg_names = [p["name"] for p in cve["packages"][:5]]
        pkg_str = ", ".join(pkg_names)
        if len(cve["packages"]) > 5:
            pkg_str += f" (+{len(cve['packages']) - 5} more)"
        if len(description) > 150:
            description = description[:147] + "..."
        affected = cve.get("affected_versions", [])
        affected_str = ", ".join(affected) if affected else "N/A"
        out(f"\n  [{priority}] {cve_id}")
        out(f"    Published:  {published}")
        out(f"    Packages:   {pkg_str}")
        out(f"    Affected:   {affected_str}")
        out(f"    {description}")

    if len(critical_high) > display_limit:
        out(f"\n  ... and {len(critical_high) - display_limit} more critical/high CVEs")

    # Executive summary
    out(f"\n{'═' * 70}")
    out("  EXECUTIVE SUMMARY")
    out(f"{'═' * 70}")
    out(f"  Distribution:                  {distro_name}")
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

    return o.getvalue()


# ===========================================================================
# Markdown report
# ===========================================================================

def generate_report_md(year, cves, distro_cfg):
    """Generate Markdown CVE summary report."""
    distro_name = distro_cfg["name"]
    source_url = distro_cfg["source_url"]
    version_label = distro_cfg["version_label"]

    if not cves:
        return f"# {distro_name} CVE Summary Report - {year}\n\nNo CVEs found.\n"

    d = _extract_report_data(cves)
    total = d["total"]
    severity_counts = d["severity_counts"]
    statuses = d["statuses"]
    sorted_packages = d["sorted_packages"]
    critical_high = d["critical_high"]

    o = StringIO()

    def out(text=""):
        o.write(text + "\n")

    out(f"# {distro_name} CVE Summary Report - {year}")
    out()
    out(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
    out(f"**Source:** [{distro_name} Security]({source_url})")
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
        cve_id = cve["id"]
        priority = cve["priority"].upper()
        published = cve["published"]
        description = cve["description"]
        pkg_names = [p["name"] for p in cve["packages"][:5]]
        pkg_str = ", ".join(pkg_names)
        if len(cve["packages"]) > 5:
            pkg_str += f" (+{len(cve['packages']) - 5} more)"
        if len(description) > 200:
            description = description[:197] + "..."
        affected = cve.get("affected_versions", [])
        affected_str = ", ".join(affected) if affected else "N/A"

        out(f"### [{priority}] {cve_id}")
        out()
        out(f"- **Published:** {published}")
        out(f"- **Packages:** {pkg_str}")
        out(f"- **Affected {version_label}:** {affected_str}")
        out(f"- {description}")
        out()

    if len(critical_high) > display_limit:
        out(f"*... and {len(critical_high) - display_limit} more critical/high CVEs*")
        out()

    # Executive summary
    out("## Executive Summary")
    out()
    out("| Metric | Value |")
    out("|--------|-------|")
    out(f"| Distribution | {distro_name} |")
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

    return o.getvalue()


# ===========================================================================
# HTML report
# ===========================================================================

def generate_report_html(year, cves, distro_cfg):
    """Generate HTML CVE summary report."""
    distro_name = distro_cfg["name"]
    source_url = distro_cfg["source_url"]
    cve_url_tpl = distro_cfg["cve_url_template"]
    brand_color = distro_cfg["brand_color"]
    version_label = distro_cfg["version_label"]

    if not cves:
        return (f"<html><head><title>{distro_name} CVE Report {year}</title></head>"
                f"<body><h1>{distro_name} CVE Summary Report - {year}</h1>"
                f"<p>No CVEs found.</p></body></html>")

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
    out("  <meta charset=\"utf-8\">")
    out(f"  <title>{esc(distro_name)} CVE Report {year}</title>")
    out("  <style>")
    out("    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI',"
        " Roboto, sans-serif; margin: 2em; color: #333; }")
    out(f"    h1 {{ color: {brand_color}; }}")
    out(f"    h2 {{ border-bottom: 2px solid {brand_color}; padding-bottom: 0.3em; }}")
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

    out(f"<h1>{esc(distro_name)} CVE Summary Report &ndash; {year}</h1>")
    out(f"<p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>")
    out(f"<strong>Source:</strong> <a href=\"{esc(source_url)}\">"
        f"{esc(distro_name)} Security</a></p>")

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
                f'<td><div style="background:{brand_color};height:14px;'
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
        cve_id = cve["id"]
        priority = cve["priority"]
        published = cve["published"]
        description = cve["description"]
        pkg_names = [p["name"] for p in cve["packages"][:5]]
        pkg_str = ", ".join(pkg_names)
        if len(cve["packages"]) > 5:
            pkg_str += f" (+{len(cve['packages']) - 5} more)"
        if len(description) > 200:
            description = description[:197] + "..."
        affected = cve.get("affected_versions", [])
        affected_str = ", ".join(affected) if affected else "N/A"
        cve_url = cve_url_tpl.format(cve_id=cve_id)

        out(f'<div class="cve-card">')
        out(f'  <strong class="{priority}">[{priority.upper()}]</strong> '
            f'<a href="{esc(cve_url)}">{esc(cve_id)}</a><br>')
        out(f"  <strong>Published:</strong> {esc(published)}<br>")
        out(f"  <strong>Packages:</strong> {esc(pkg_str)}<br>")
        out(f"  <strong>Affected {esc(version_label)}:</strong> {esc(affected_str)}<br>")
        out(f"  <em>{esc(description)}</em>")
        out(f"</div>")

    if len(critical_high) > display_limit:
        out(f"<p><em>... and {len(critical_high) - display_limit} more</em></p>")

    # Executive summary
    out('<h2>Executive Summary</h2>')
    out('<div class="summary-box">')
    out(f"<p><strong>Distribution:</strong> {esc(distro_name)}<br>")
    out(f"<strong>Year:</strong> {year}<br>")
    out(f"<strong>Total CVEs analyzed:</strong> {total}<br>")
    out(f"<strong>Critical:</strong> {severity_counts['critical']}<br>")
    out(f"<strong>High:</strong> {severity_counts['high']}<br>")
    out(f"<strong>Medium:</strong> {severity_counts['medium']}<br>")
    out(f"<strong>Low:</strong> {severity_counts['low']}<br>")
    out(f"<strong>Unique packages:</strong> {len(sorted_packages)}<br>")
    out(f"<strong>Most affected:</strong> "
        f"{esc(sorted_packages[0][0]) if sorted_packages else 'N/A'}"
        f" ({sorted_packages[0][1] if sorted_packages else 0} CVEs)</p>")
    out("</div>")
    out(f'<p class="footer"><a href="{esc(source_url)}">{esc(source_url)}</a></p>')
    out("</body></html>")

    return o.getvalue()


# ===========================================================================
# Full CVE list (all CVEs, separate files)
# ===========================================================================

def generate_full_list_txt(year, cves, distro_cfg):
    """Generate plain-text full CVE list."""
    distro_name = distro_cfg["name"]
    source_url = distro_cfg["source_url"]
    version_label = distro_cfg["version_label"]

    o = StringIO()

    def out(text=""):
        o.write(text + "\n")

    out("=" * 70)
    out(f"  {distro_name} Full CVE List - {year} ({len(cves)} CVEs)")
    out("=" * 70)
    out(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    out(f"  Source:    {source_url}")
    out("=" * 70)

    for cve in cves:
        cve_id = cve["id"]
        priority = cve["priority"].upper()
        published = cve["published"]
        status = cve["status"].capitalize()
        description = cve["description"]
        pkg_names = [p["name"] for p in cve["packages"][:10]]
        pkg_str = ", ".join(pkg_names)
        if len(cve["packages"]) > 10:
            pkg_str += f" (+{len(cve['packages']) - 10} more)"
        affected = cve.get("affected_versions", [])
        affected_str = ", ".join(affected) if affected else "N/A"
        if len(description) > 300:
            description = description[:297] + "..."

        out(f"\n{'─' * 70}")
        out(f"  [{priority}] {cve_id}  (Status: {status})")
        out(f"    Published:  {published}")
        out(f"    Packages:   {pkg_str}")
        out(f"    Affected:   {affected_str}")
        out(f"    {description}")

    out(f"\n{'═' * 70}")
    out(f"  Total: {len(cves)} CVEs")
    out(f"{'═' * 70}")

    return o.getvalue()


def generate_full_list_md(year, cves, distro_cfg):
    """Generate Markdown full CVE list."""
    distro_name = distro_cfg["name"]
    source_url = distro_cfg["source_url"]
    version_label = distro_cfg["version_label"]

    o = StringIO()

    def out(text=""):
        o.write(text + "\n")

    out(f"# {distro_name} Full CVE List - {year}")
    out()
    out(f"**Total CVEs:** {len(cves)}  ")
    out(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
    out(f"**Source:** [{distro_name} Security]({source_url})")
    out()
    out("---")
    out()

    for cve in cves:
        cve_id = cve["id"]
        priority = cve["priority"].upper()
        published = cve["published"]
        status = cve["status"].capitalize()
        description = cve["description"]
        pkg_names = [p["name"] for p in cve["packages"][:10]]
        pkg_str = ", ".join(pkg_names)
        if len(cve["packages"]) > 10:
            pkg_str += f" (+{len(cve['packages']) - 10} more)"
        affected = cve.get("affected_versions", [])
        affected_str = ", ".join(affected) if affected else "N/A"
        if len(description) > 300:
            description = description[:297] + "..."

        out(f"## [{priority}] {cve_id}")
        out()
        out(f"- **Status:** {status}")
        out(f"- **Published:** {published}")
        out(f"- **Packages:** {pkg_str}")
        out(f"- **Affected {version_label}:** {affected_str}")
        out(f"- {description}")
        out()

    return o.getvalue()


def generate_full_list_html(year, cves, distro_cfg):
    """Generate HTML full CVE list with severity filter."""
    distro_name = distro_cfg["name"]
    source_url = distro_cfg["source_url"]
    cve_url_tpl = distro_cfg["cve_url_template"]
    brand_color = distro_cfg["brand_color"]
    version_label = distro_cfg["version_label"]

    esc = html_mod.escape
    o = StringIO()

    def out(text=""):
        o.write(text + "\n")

    out("<!DOCTYPE html>")
    out("<html lang=\"en\">")
    out("<head>")
    out("  <meta charset=\"utf-8\">")
    out(f"  <title>{esc(distro_name)} Full CVE List {year}</title>")
    out("  <style>")
    out("    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI',"
        " Roboto, sans-serif; margin: 2em; color: #333; }")
    out(f"    h1 {{ color: {brand_color}; }}")
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
    out(f"<h1>{esc(distro_name)} Full CVE List &ndash; {year} ({len(cves)} CVEs)</h1>")
    out(f"<p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        f" | <strong>Source:</strong> "
        f"<a href=\"{esc(source_url)}\">{esc(distro_name)} Security</a></p>")

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
        f"<th>Published</th><th>Packages</th>"
        f"<th>Affected {esc(version_label)}</th><th>Description</th></tr>")

    for cve in cves:
        cve_id = cve["id"]
        priority = cve["priority"]
        status = cve["status"].capitalize()
        published = cve["published"]
        description = cve["description"]
        pkg_names = [p["name"] for p in cve["packages"][:5]]
        pkg_str = ", ".join(pkg_names)
        if len(cve["packages"]) > 5:
            pkg_str += f" (+{len(cve['packages']) - 5} more)"
        affected = cve.get("affected_versions", [])
        affected_str = ", ".join(affected) if affected else "N/A"
        if len(description) > 200:
            description = description[:197] + "..."
        cve_url = cve_url_tpl.format(cve_id=cve_id)

        out(f'<tr data-severity="{priority}">'
            f'<td><a href="{esc(cve_url)}">{esc(cve_id)}</a></td>'
            f'<td class="{priority}">{priority.upper()}</td>'
            f'<td>{esc(status)}</td>'
            f'<td>{esc(published)}</td>'
            f'<td>{esc(pkg_str)}</td>'
            f'<td>{esc(affected_str)}</td>'
            f'<td class="desc">{esc(description)}</td>'
            f'</tr>')

    out("</table>")
    out(f'<p class="footer">Total: {len(cves)} CVEs | '
        f'<a href="{esc(source_url)}">View on {esc(distro_name)}</a></p>')

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
    out("</body></html>")

    return o.getvalue()


# ===========================================================================
# Main
# ===========================================================================

def main():
    distro_choices = list(DISTRO_CONFIG.keys())

    parser = argparse.ArgumentParser(
        description="Generate a CVE summary report for a Linux distribution."
    )
    parser.add_argument(
        "--distro", "-d", type=str, required=True, choices=distro_choices,
        help=f"Linux distribution ({', '.join(distro_choices)})"
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

    distro = args.distro
    distro_cfg = DISTRO_CONFIG[distro]
    year = args.year

    # --full overrides --max-results to unlimited
    if args.full:
        max_results = 999999
    else:
        max_results = args.max_results

    print(f"Fetching {distro_cfg['name']} CVEs for {year}...")
    if args.full:
        print("(Full mode: fetching ALL available CVEs — this may take several minutes)\n")
    else:
        print(f"(Fetching up to {max_results} CVEs — use --full for the complete list)\n")

    fetcher = distro_cfg["fetcher"]
    cves = fetcher(year, max_results=max_results)

    if cves is None:
        print("Failed to fetch CVE data. Please check your internet connection.")
        sys.exit(1)

    print(f"\nRetrieved {len(cves)} CVEs for {year}.\n")

    # Generate summary reports (always)
    report_txt = generate_report_txt(year, cves, distro_cfg)
    report_md = generate_report_md(year, cves, distro_cfg)
    report_html = generate_report_html(year, cves, distro_cfg)

    # Ensure output directory exists
    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)

    basename = f"{distro}_cve_report_{year}"
    files_written = []

    for ext, content in [(".txt", report_txt), (".md", report_md), (".html", report_html)]:
        filepath = os.path.join(output_dir, basename + ext)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        files_written.append(filepath)

    # Generate full CVE list only when --full is specified
    if args.full:
        full_txt = generate_full_list_txt(year, cves, distro_cfg)
        full_md = generate_full_list_md(year, cves, distro_cfg)
        full_html = generate_full_list_html(year, cves, distro_cfg)

        fullname = f"{distro}_cve_full_list_{year}"
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
