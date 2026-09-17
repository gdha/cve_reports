# CVE Reports

Command-line tools to generate CVE summary reports for Linux distributions. Fetches data from official security APIs and outputs reports in plain text, Markdown, and HTML.

## Scripts

| Script | Description |
|---|---|
| `create_cve_report.py` | Unified tool supporting Ubuntu, RHEL, and Debian |
| `create_cve_report_ubuntu.py` | Legacy Ubuntu-only script |

## Requirements

- Python 3.8+
- `requests` (`pip install requests`)

---

## `create_cve_report.py`

### Supported Distributions

- **Ubuntu** — Ubuntu Security API
- **RHEL** — Red Hat Security Data API
- **Debian** — Debian Security Tracker

### Quick Start

```bash
# RHEL report for current year
python create_cve_report.py -d rhel

# Ubuntu full report for 2025
python create_cve_report.py -d ubuntu --year 2025 --full

# Debian, limited to 100 CVEs, output to a specific directory
python create_cve_report.py -d debian --max-results 100 -o /tmp/reports

# Only critical and high CVEs for Ubuntu
python create_cve_report.py -d ubuntu --severity critical,high

# Only core OS packages for RHEL
python create_cve_report.py -d rhel --filter core

# Add a one-line-per-CVE detail table to the summary report
python create_cve_report.py -d ubuntu --detail
```

### Options

```
--distro, -d        Distribution: ubuntu, rhel, debian (required)
--year              Year to report on (default: current year)
--output-dir, -o    Output directory (default: .)
--max-results       Max CVEs to fetch (default: 1000)
--full              Fetch all CVEs and generate full list files
--filter, -f        Package category filter: all (default), core, apps
--severity, -s      Severity filter, comma-separated (default: all)
                    Values: critical, high, medium, low, negligible, unknown
--detail            Add a one-line-per-CVE description table to the summary report
```

### Example

```
$ python create_cve_report.py -d rhel --max-results 50

Fetching Red Hat Enterprise Linux CVEs for 2026...
(Fetching up to 50 CVEs — use --full for the complete list)

Retrieved 50 CVEs for 2026.

Reports saved:
  - ./rhel_cve_report_2026.txt
  - ./rhel_cve_report_2026.md
  - ./rhel_cve_report_2026.html
```

With `--full`, additional files are generated:

```
rhel_cve_full_list_2026.txt
rhel_cve_full_list_2026.md
rhel_cve_full_list_2026.html
```

The HTML full list includes a severity filter dropdown for interactive browsing.

When `--filter` or `--severity` is used, the selected values are appended to the
output filenames. For example:

```text
ubuntu_cve_report_2026_core_critical_high.md
```

### Notes

- RHEL is the fastest (1000 CVEs/page). Ubuntu is slower (20/page with rate limiting). Debian downloads the full tracker (~75 MB) once per run.
- Debian uses its own triage urgency rather than CVSS severity, so most CVEs appear as "negligible" or "unknown".
- A progress bar is shown during lengthy fetches.

---

## `create_cve_report_ubuntu.py`

Legacy Ubuntu-only script. Fetches CVE data from the [Ubuntu Security API](https://ubuntu.com/security/cves.json) and produces a summary report for a given year.

### Usage

```bash
# Report for the current year
python create_cve_report_ubuntu.py

# Report for a specific year
python create_cve_report_ubuntu.py --year 2025

# Write reports to a custom output directory
python create_cve_report_ubuntu.py --output-dir /tmp/reports

# Fetch all CVEs for the year
python create_cve_report_ubuntu.py --full
```

### Options

```
--year              Year to report on (default: current year)
--output-dir, -o    Output directory (default: .)
--max-results       Max CVEs to fetch (default: 1000)
--full              Fetch all CVEs and generate full list files
```

### Supported Ubuntu Releases

| Codename | Version    |
|----------|------------|
| trusty   | 14.04 LTS  |
| xenial   | 16.04 LTS  |
| bionic   | 18.04 LTS  |
| focal    | 20.04 LTS  |
| kinetic  | 22.10      |
| jammy    | 22.04 LTS  |
| lunar    | 23.04      |
| mantic   | 23.10      |
| noble    | 24.04 LTS  |
| oracular | 24.10      |
| plucky   | 25.04      |
| questing | 25.10      |
| resolute | 26.04 LTS  |

---

## License

GPL v3
