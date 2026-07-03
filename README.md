# CVE Reports

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
