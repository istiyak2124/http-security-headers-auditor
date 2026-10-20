# HTTP Security Headers Auditor

A Python-based cybersecurity tool that audits HTTP security headers, identifies missing or potentially misconfigured headers, and provides actionable security recommendations.

## Features

- Audit important HTTP security headers.
- Identify missing headers and basic configuration issues.
- Classify findings by severity.
- Provide remediation recommendations.
- Generate JSON security reports.
- Include automated tests using pytest.

## Security Headers Checked

The project plans to check the following headers:

- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`
- `Permissions-Policy`

## Technology Stack

- **Language:** Python 3.12+
- **HTTP Client:** Requests
- **Testing:** pytest
- **Version Control:** Git and GitHub

## Project Status

**Under development.**

Features will be implemented and tested incrementally.

## Installation

Clone the repository:

```bash
git clone https://github.com/istiyak2124/http-security-headers-auditor.git
cd http-security-headers-auditor
```

Create and activate a virtual environment.

**Windows PowerShell:**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the project and development dependencies:

```powershell
python -m pip install -e ".[dev]"
```

## Usage

The command-line interface and auditing features are under development.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.