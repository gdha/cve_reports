# CVE Reports

Command-line tool to generate CVE summary reports for Linux distributions. Fetches data from official security APIs and outputs reports in plain text, Markdown, and HTML.

## Supported Distributions

- **Ubuntu** — Ubuntu Security API
- **RHEL** — Red Hat Security Data API
- **Debian** — Debian Security Tracker

## Requirements

- Python 3.8+
- `requests` (`pip install requests`)

## Quick Start

```bash
# RHEL report for current year
./create_cve_report.py -d rhel

# Ubuntu full report for 2025
./create_cve_report.py -d ubuntu --year 2025 --full

# Debian, limited to 100 CVEs, output to a specific directory
./create_cve_report.py -d debian --max-results 100 -o /tmp/reports
```

## Options

```
--distro, -d       Distribution: ubuntu, rhel, debian (required)
--year             Year to report on (default: current year)
--output-dir, -o   Output directory (default: .)
--max-results      Max CVEs to fetch (default: 1000)
--full             Fetch all CVEs and generate full list files
```

## Example

```
$ ./create_cve_report.py -d rhel --max-results 50

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

## Notes

- RHEL is the fastest (1000 CVEs/page). Ubuntu is slower (20/page with rate limiting). Debian downloads the full tracker (~75MB) once per run.
- Debian uses its own triage urgency rather than CVSS severity, so most CVEs appear as "negligible" or "unknown".
- A progress bar is shown during lengthy fetches.

## License

GPL v3
=======
A collection of scripts to generate CVE (Common Vulnerabilities and Exposures) summary reports for Ubuntu.

## Scripts

### `create_cve_report_ubuntu.py`

Fetches CVE data from the [Ubuntu Security API](https://ubuntu.com/security/cves.json) and produces a summary report for a given year, including:

- Severity breakdown (Critical / High / Medium / Low / Negligible / Unknown)
- Top affected packages
- Detailed list of Critical and High CVEs with affected Ubuntu releases

**Output formats:** plain text (`.txt`), HTML (`.html`), and Markdown (`.md`)

#### Requirements

```bash
pip install requests
```

#### Usage

```bash
# Report for the current year
python create_cve_report_ubuntu.py

# Report for a specific year
python create_cve_report_ubuntu.py --year 2025

# Write reports to a custom output directory
python create_cve_report_ubuntu.py --output-dir /tmp/reports
```

#### Supported Ubuntu Releases

The script recognises the following Ubuntu codenames:

| Codename  | Version    |
|-----------|------------|
| trusty    | 14.04 LTS  |
| xenial    | 16.04 LTS  |
| bionic    | 18.04 LTS  |
| focal     | 20.04 LTS  |
| jammy     | 22.04 LTS  |
| noble     | 24.04 LTS  |
| oracular  | 24.10      |
| plucky    | 25.04      |
| questing  | 25.10      |
| resolute  | 26.04 LTS  |

## License

See [LICENSE](LICENSE) if present, or check the repository for licensing details.
