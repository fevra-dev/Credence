# Credence - How to Run and Use Guide

A comprehensive guide to installing, configuring, and using Credence for scanning web targets for exposed sensitive files.

---

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Basic Usage](#basic-usage)
4. [Advanced Usage](#advanced-usage)
5. [Output Formats](#output-formats)
6. [Configuration Options](#configuration-options)
7. [Examples](#examples)
8. [Troubleshooting](#troubleshooting)
9. [Best Practices](#best-practices)

---

## Installation

### Prerequisites

- Python 3.9 or higher
- pip (Python package manager)
- Internet connection (for downloading dependencies)

### Step 1: Clone or Download the Repository

```bash
# If you have the repository
cd /path/to/Credence

# Or clone from GitHub (when published)
git clone https://github.com/fevra-dev/Credence.git
cd credence
```

### Step 2: Install Dependencies

```bash
# Install required packages
pip3 install -r requirements.txt

# Or install with user flag if you don't have admin access
pip3 install --user -r requirements.txt
```

### Step 3: Install Credence (Optional)

```bash
# Install in editable mode (recommended for development)
pip3 install -e .

# Or install as a regular package
pip3 install .
```

**Note:** If you encounter permission errors, you can run Credence directly without installing (see [Running Without Installation](#running-without-installation)).

---

## Quick Start

### Running Without Installation

You can run Credence directly as a Python module without installing it:

```bash
# Basic scan
python3 -m credence.cli example.com

# Using the wrapper script
./credence.sh example.com
```

### Your First Scan

```bash
# Scan a single target
python3 -m credence.cli example.com

# Scan multiple targets
python3 -m credence.cli example.com example.org https://target.io
```

---

## Basic Usage

### Command Syntax

```bash
python3 -m credence.cli [OPTIONS] [TARGETS]...
```

### Required Arguments

- **TARGETS**: One or more target URLs to scan
  - Can be provided as command-line arguments
  - Or loaded from a file using `-f/--file` option

### Basic Examples

```bash
# Scan a single domain
python3 -m credence.cli example.com

# Scan multiple domains
python3 -m credence.cli example.com example.org subdomain.example.com

# Scan with HTTPS (auto-added if no scheme specified)
python3 -m credence.cli https://example.com

# Scan from a file
python3 -m credence.cli -f targets.txt
```

### Target File Format

Create a text file with one target per line:

```text
# targets.txt
example.com
https://example.org
subdomain.target.io
# Comments are ignored
another-target.com
```

Then scan with:
```bash
python3 -m credence.cli -f targets.txt
```

---

## Advanced Usage

### Concurrency Control

Adjust the number of concurrent requests for faster scanning:

```bash
# High concurrency (faster, but may trigger rate limits)
python3 -m credence.cli -f targets.txt -c 100

# Low concurrency (slower, but more respectful)
python3 -m credence.cli -f targets.txt -c 10

# Default is 50 concurrent requests
```

### Timeout Configuration

Set custom timeout values:

```bash
# Short timeout (5 seconds)
python3 -m credence.cli example.com -t 5

# Long timeout (30 seconds for slow servers)
python3 -m credence.cli example.com -t 30

# Default is 10 seconds
```

### Custom User-Agent

Use a custom User-Agent string:

```bash
# Mimic a browser
python3 -m credence.cli example.com --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Custom scanner identifier
python3 -m credence.cli example.com --user-agent "MySecurityScanner/1.0"
```

### Follow Redirects

By default, Credence does not follow redirects. Enable redirect following:

```bash
python3 -m credence.cli example.com --follow-redirects
```

**Note:** Not following redirects helps detect redirect-based false positives (e.g., `.git/config` redirecting to `/login`).

---

## Output Formats

### Console Output (Default)

Colored, human-readable output:

```bash
python3 -m credence.cli example.com
```

**Output:**
```
🔍 Credence - Sensitive File Scanner

────────────────────────────────────────────────────────────
🎯 https://example.com
────────────────────────────────────────────────────────────

[CRITICAL] .git/config
  URL: https://example.com/.git/config
  Evidence: Found signature: [core]
  Status: 200 | Size: 1234 bytes

════════════════════════════════════════════════════════════
Summary: 1 targets scanned | 1 vulnerable | 1 findings
Duration: 2.45s
════════════════════════════════════════════════════════════
```

### JSON Output

Structured JSON for automation and parsing:

```bash
python3 -m credence.cli example.com -o json
```

**Output:**
```json
{
  "targets_scanned": 1,
  "targets_vulnerable": 1,
  "total_findings": 1,
  "critical_count": 1,
  "high_count": 0,
  "medium_count": 0,
  "low_count": 0,
  "scan_start": "2025-12-06T22:30:00.000000",
  "scan_end": "2025-12-06T22:30:02.450000",
  "scan_duration_ms": 2450,
  "target_reports": [
    {
      "target": "https://example.com",
      "total_paths_checked": 67,
      "vulnerable_count": 1,
      "findings": [
        {
          "url": "https://example.com/.git/config",
          "path": ".git/config",
          "target": "https://example.com",
          "status_code": 200,
          "vulnerable": true,
          "severity": "CRITICAL",
          "category": "git",
          "description": "Git repository configuration exposed",
          "evidence": "Found signature: [core]",
          "response_length": 1234,
          "content_type": "text/plain"
        }
      ],
      "errors": [],
      "scan_duration_ms": 2450
    }
  ]
}
```

### CSV Output

Spreadsheet-friendly format:

```bash
python3 -m credence.cli example.com -o csv
```

**Output:**
```csv
target,url,path,severity,category,description,status_code,evidence,response_length
https://example.com,https://example.com/.git/config,.git/config,CRITICAL,git,Git repository configuration exposed,200,Found signature: [core],1234
```

### Saving Output to File

```bash
# Save JSON output
python3 -m credence.cli -f targets.txt -o json --out-file results.json

# Save CSV output
python3 -m credence.cli -f targets.txt -o csv --out-file results.csv

# Save console output
python3 -m credence.cli -f targets.txt --out-file results.txt
```

---

## Configuration Options

### All Available Options

```bash
python3 -m credence.cli --help
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--file` | `-f` | File containing targets (one per line) | - |
| `--output` | `-o` | Output format: console, json, csv | console |
| `--out-file` | - | Write output to file | stdout |
| `--concurrency` | `-c` | Max concurrent requests | 50 |
| `--timeout` | `-t` | Request timeout in seconds | 10 |
| `--quiet` | `-q` | Only show vulnerable targets | false |
| `--verbose` | `-v` | Enable verbose logging | false |
| `--no-color` | - | Disable colored output | false |
| `--user-agent` | - | Custom User-Agent string | Credence/1.0 |
| `--follow-redirects` | - | Follow HTTP redirects | false |
| `--version` | - | Show version and exit | - |
| `--help` | `-h` | Show help message | - |

---

## Examples

### Example 1: Basic Single Target Scan

```bash
python3 -m credence.cli example.com
```

**Use Case:** Quick check of a single target

### Example 2: Batch Scanning with File Input

```bash
# Create targets file
echo -e "example.com\nexample.org\nsubdomain.example.com" > targets.txt

# Scan all targets
python3 -m credence.cli -f targets.txt
```

**Use Case:** Scanning multiple targets from a list

### Example 3: High-Speed Scanning

```bash
python3 -m credence.cli -f targets.txt -c 100 -t 5
```

**Use Case:** Fast scanning of many targets with short timeout

### Example 4: CI/CD Integration

```bash
# Scan and exit with code 1 if vulnerabilities found
python3 -m credence.cli -f targets.txt -o json --out-file results.json

# Check exit code
if [ $? -eq 1 ]; then
    echo "Vulnerabilities found! Check results.json"
    exit 1
fi
```

**Use Case:** Automated security checks in CI/CD pipelines

### Example 5: Quiet Mode for Clean Output

```bash
python3 -m credence.cli -f targets.txt -q
```

**Use Case:** Only show targets with vulnerabilities (cleaner output)

### Example 6: Verbose Logging for Debugging

```bash
python3 -m credence.cli example.com -v
```

**Use Case:** Debugging connection issues or understanding scan behavior

### Example 7: Export Results for Analysis

```bash
# Generate JSON report
python3 -m credence.cli -f targets.txt -o json --out-file scan_results.json

# Generate CSV for spreadsheet analysis
python3 -m credence.cli -f targets.txt -o csv --out-file scan_results.csv
```

**Use Case:** Sharing results with team or importing into other tools

### Example 8: Custom Configuration

```bash
python3 -m credence.cli \
    -f targets.txt \
    -c 75 \
    -t 15 \
    --user-agent "MyCompany-SecurityScanner/1.0" \
    -o json \
    --out-file results.json \
    -v
```

**Use Case:** Customized scanning with specific requirements

---

## Exit Codes

Credence uses exit codes for automation and CI/CD integration:

| Exit Code | Meaning |
|-----------|---------|
| `0` | No vulnerabilities found (clean scan) |
| `1` | Vulnerabilities found |
| `2` | Execution error (invalid input, file errors, etc.) |

### Using Exit Codes in Scripts

```bash
#!/bin/bash

python3 -m credence.cli -f targets.txt

case $? in
    0)
        echo "✅ No vulnerabilities found"
        ;;
    1)
        echo "⚠️  Vulnerabilities detected!"
        exit 1
        ;;
    2)
        echo "❌ Error during scan"
        exit 1
        ;;
esac
```

---

## Troubleshooting

### Common Issues and Solutions

#### Issue: "ModuleNotFoundError: No module named 'click'"

**Solution:** Install dependencies
```bash
pip3 install -r requirements.txt
```

#### Issue: "Permission denied" during installation

**Solution:** Use `--user` flag or run without installing
```bash
# Option 1: Install with user flag
pip3 install --user -e .

# Option 2: Run without installing
python3 -m credence.cli example.com
```

#### Issue: "Connection timeout" errors

**Solution:** Increase timeout value
```bash
python3 -m credence.cli example.com -t 30
```

#### Issue: Too many false positives

**Solution:** Credence uses signature-based validation to reduce false positives. If you still see issues:
- Check the evidence field in the output
- Use verbose mode to see what's being detected: `-v`
- False positives are filtered automatically, but custom 404 pages may still trigger

#### Issue: Rate limiting or blocked requests

**Solution:** Reduce concurrency and add delays
```bash
# Lower concurrency
python3 -m credence.cli -f targets.txt -c 10

# Use custom User-Agent
python3 -m credence.cli -f targets.txt --user-agent "Mozilla/5.0..."
```

#### Issue: SSL certificate errors

**Solution:** Credence disables SSL verification by default for scanning. If you need to verify SSL:
- This would require modifying the scanner code
- For security scanning, disabling verification is often acceptable

---

## Best Practices

### 1. Start with Low Concurrency

When scanning new targets, start with lower concurrency to avoid rate limiting:

```bash
python3 -m credence.cli -f targets.txt -c 10
```

### 2. Use Appropriate Timeouts

Adjust timeouts based on target responsiveness:

```bash
# Fast targets
python3 -m credence.cli -f targets.txt -t 5

# Slow targets
python3 -m credence.cli -f targets.txt -t 30
```

### 3. Save Results for Analysis

Always save results when scanning multiple targets:

```bash
python3 -m credence.cli -f targets.txt -o json --out-file results_$(date +%Y%m%d).json
```

### 4. Use Quiet Mode for Automation

In scripts and CI/CD, use quiet mode for cleaner output:

```bash
python3 -m credence.cli -f targets.txt -q -o json --out-file results.json
```

### 5. Verify Findings

Always manually verify critical findings:

1. Check the URL in a browser
2. Review the evidence provided
3. Confirm the severity matches the exposure

### 6. Respect Rate Limits

- Don't use excessive concurrency (keep it under 100)
- Add delays between scans if needed
- Use appropriate User-Agent strings

### 7. Organize Target Files

Keep target files organized:

```bash
# Production targets
production_targets.txt

# Staging targets
staging_targets.txt

# Test targets
test_targets.txt
```

### 8. Regular Scanning

Set up regular scans for your infrastructure:

```bash
# Daily scan script
#!/bin/bash
python3 -m credence.cli -f production_targets.txt \
    -o json \
    --out-file "scans/scan_$(date +%Y%m%d).json" \
    -q
```

---

## Integration Examples

### GitHub Actions

```yaml
name: Security Scan

on:
  schedule:
    - cron: '0 0 * * *'  # Daily
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run Credence
        run: |
          python3 -m credence.cli -f targets.txt \
            -o json \
            --out-file results.json
      - name: Upload results
        uses: actions/upload-artifact@v2
        with:
          name: scan-results
          path: results.json
```

### Cron Job

```bash
# Add to crontab (crontab -e)
0 2 * * * cd /path/to/credence && python3 -m credence.cli -f targets.txt -o json --out-file /var/log/credence/scan_$(date +\%Y\%m\%d).json -q
```

### Python Script Integration

```python
#!/usr/bin/env python3
"""Example integration script."""

import subprocess
import json
import sys

def run_scan(targets_file):
    """Run Credence and return results."""
    result = subprocess.run(
        [
            "python3", "-m", "credence.cli",
            "-f", targets_file,
            "-o", "json",
            "-q"
        ],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 2:
        print(f"Error: {result.stderr}")
        return None
    
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None

if __name__ == "__main__":
    report = run_scan("targets.txt")
    
    if report and report["total_findings"] > 0:
        print(f"⚠️  Found {report['total_findings']} vulnerabilities!")
        for target_report in report["target_reports"]:
            for finding in target_report["findings"]:
                print(f"  - {finding['url']} ({finding['severity']})")
        sys.exit(1)
    else:
        print("✅ No vulnerabilities found")
        sys.exit(0)
```

---

## What Credence Scans For

Credence checks for 67+ sensitive paths across 7 categories:

### Critical Findings
- **Git Repository Files**: `.git/config`, `.git/HEAD`, `.git/index`
- **Environment Files**: `.env`, `.env.production`, `.env.backup`
- **Configuration Files**: `wp-config.php`, `config.yml`, `secrets.yml`
- **Backup Files**: `backup.sql`, `dump.sql`, `backup.zip`

### High Severity
- **Version Control**: `.svn/entries`, `.svn/wc.db`
- **Config Files**: `config.php`, `settings.py`, `database.yml`

### Medium Severity
- **Debug Files**: `phpinfo.php`, `debug.log`, `error.log`
- **API Documentation**: `swagger.json`, `openapi.json`

### Low Severity
- **Metadata Files**: `.DS_Store`, `Thumbs.db`
- **Dependency Files**: `package.json`, `requirements.txt`

---

## Security and Ethics

### ⚠️ Important: Responsible Use

Credence is a security tool designed for:

- ✅ **Authorized penetration testing**
- ✅ **Bug bounty programs** (in-scope targets only)
- ✅ **Security audits** with permission
- ✅ **Validating your own infrastructure**

### ❌ Do NOT use for:

- Unauthorized scanning
- Accessing systems without permission
- Any illegal activities

**Always obtain proper authorization before scanning any target.**

---

## Getting Help

### Check the Help

```bash
python3 -m credence.cli --help
```

### Verbose Mode

Enable verbose logging to see detailed information:

```bash
python3 -m credence.cli example.com -v
```

### Common Commands Reference

```bash
# Version
python3 -m credence.cli --version

# Help
python3 -m credence.cli --help

# Basic scan
python3 -m credence.cli example.com

# File input
python3 -m credence.cli -f targets.txt

# JSON output
python3 -m credence.cli example.com -o json

# Save to file
python3 -m credence.cli example.com -o json --out-file results.json
```

---

## Additional Resources

- **README.md**: Project overview and features
- **LICENSE**: MIT License details
- **Source Code**: Check the `credence/` directory for implementation details

---

## Version Information

Current version: **1.0.0**

Check version:
```bash
python3 -m credence.cli --version
```

---

**Happy Scanning! 🔍**

Remember: Always scan responsibly and with proper authorization.

