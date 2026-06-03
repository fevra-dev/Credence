# Credence × GitHub Code Scanning

Credence emits SARIF 2.1.0 (vendored schema validated) so its findings show up
natively in GitHub Code Scanning. This page covers the end-to-end setup.

## What you get

- Findings as Code Scanning alerts in the PR "Security" tab
- Inline annotations on the lines where credentials or supply-chain risks live
- MITRE ATLAS and OWASP LLM Top 10 taxonomy references on every alert
- Verification status (`verified-live` / `verified-dead` / `verification-error`)
  as alert tags — filter the dashboard by tag

## Setup (5 minutes)

1. **Enable Code Scanning** on your repo:
   Settings → Security → Code security and analysis → Code scanning → Set up
   advanced.

2. **Add the Credence workflow**. Copy `.github/workflows/credence-scan.yml`
   from this repo into your own.

3. **Push**. On the next PR or push to main, Credence runs and uploads SARIF.

4. **Review alerts**. Open the "Security" tab on your repo. New alerts appear
   under "Code scanning alerts".

## Filtering by verification status

Credence v0.3 emits SARIF `properties.tags` entries:

- `verified-live` — credential confirmed active by the provider
- `verified-dead` — credential rejected by the provider
- `verification-error` — couldn't reach the provider (network / 5xx / timeout)

Use these in Code Scanning's filter UI to focus on the highest-confidence
alerts. Example: `tag:verified-live` to see only credentials that are
confirmed exploitable today.

## Sample SARIF output

```json
{
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Credence",
          "version": "0.3.0",
          "informationUri": "https://github.com/fevra-dev/Credence"
        }
      },
      "results": [
        {
          "ruleId": "credential-exposure",
          "level": "error",
          "message": {"text": "OpenAI API key exposed and confirmed live"},
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {"uri": ".env"},
              "region": {"startLine": 14}
            }
          }],
          "properties": {
            "attack_class": "LLM06",
            "atlas_technique": "AML.T0019",
            "verification_status": "verified",
            "tags": ["verified-live"]
          }
        }
      ]
    }
  ]
}
```

## Troubleshooting

- **No alerts appearing?** Check the workflow run logs — Code Scanning requires
  `security-events: write` permission, which the sample workflow sets.
- **Too many alerts?** Use `--severity-threshold HIGH` in the scan step to drop
  MEDIUM/LOW findings before SARIF upload.
- **SARIF rejected by GitHub?** Credence validates its own output against the
  vendored 2.1.0 schema in `tests/fixtures/sarif-schema-2.1.0.json`. If GitHub
  rejects it, file an issue with the offending finding's JSON snippet.
