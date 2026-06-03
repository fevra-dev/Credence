"""Colored console output reporter."""

import click

from ..models import ScanReport, ScanResult, Severity, TargetReport
from .base import BaseReporter


class ConsoleReporter(BaseReporter):
    """Console reporter with colored output."""

    SEVERITY_COLORS = {
        Severity.CRITICAL: ("red", True),  # (color, bold)
        Severity.HIGH: ("red", False),
        Severity.MEDIUM: ("yellow", False),
        Severity.LOW: ("green", False),
        Severity.INFO: ("blue", False),
    }

    def severity_style(self, severity: Severity) -> str:
        """Get styled severity string."""
        color, bold = self.SEVERITY_COLORS[severity]
        if self.no_color:
            return severity.value
        return click.style(severity.value, fg=color, bold=bold)

    def generate(self, report: ScanReport) -> str:
        """Generate console output."""
        lines = []

        if not self.quiet:
            lines.append("")
            lines.append(click.style("🔍 Credence - Sensitive File Scanner", bold=True))
            lines.append("")

        # Process each target
        for target_report in report.target_reports:
            if self.quiet and target_report.vulnerable_count == 0:
                continue

            lines.extend(self._format_target(target_report))

        # Summary
        if not self.quiet:
            lines.append("")
            lines.append("═" * 60)

            summary_parts = [
                f"{report.targets_scanned} targets scanned",
                f"{report.targets_vulnerable} vulnerable",
                f"{report.total_findings} findings",
            ]

            if report.critical_count > 0:
                critical_str = (
                    click.style(
                        f"{report.critical_count} critical",
                        fg="red",
                        bold=True,
                    )
                    if not self.no_color
                    else f"{report.critical_count} critical"
                )
                summary_parts.append(critical_str)

            lines.append(f"Summary: {' | '.join(summary_parts)}")
            lines.append(f"Duration: {report.scan_duration_ms / 1000:.2f}s")
            lines.append("═" * 60)

        return "\n".join(lines)

    def _format_target(self, target_report: TargetReport) -> list:
        """Format a single target's results."""
        lines = []

        if not self.quiet:
            lines.append("")
            lines.append("─" * 60)
            lines.append(f"🎯 {target_report.target}")
            lines.append("─" * 60)

        if target_report.vulnerable_count == 0:
            if not self.quiet:
                success = click.style("✓ No vulnerabilities found", fg="green")
                lines.append(
                    success if not self.no_color else "✓ No vulnerabilities found"
                )
            return lines

        # Show findings
        for finding in target_report.findings:
            lines.extend(self._format_finding(finding))

        return lines

    def _format_finding(self, finding: ScanResult) -> list:
        """Format a single finding."""
        lines = []

        severity_str = self.severity_style(finding.severity)
        lines.append("")
        lines.append(f"[{severity_str}] {finding.path}")
        lines.append(f"  URL: {finding.url}")
        lines.append(f"  Evidence: {finding.evidence}")
        lines.append(
            f"  Status: {finding.status_code} | Size: {finding.response_length} bytes"
        )

        if finding.attack_class or finding.atlas_technique:
            parts = []
            if finding.attack_class:
                parts.append(f"OWASP {finding.attack_class}")
            if finding.atlas_technique:
                parts.append(f"ATLAS {finding.atlas_technique}")
            compliance_str = " · ".join(parts)
            if self.no_color:
                lines.append(f"  Compliance: {compliance_str}")
            else:
                lines.append(
                    click.style(f"  Compliance: {compliance_str}", fg="cyan")
                )

        # Verification tag (only when not skipped)
        status = getattr(finding, "verification_status", "skipped")
        if status == "verified":
            lines.append("  [VERIFIED]")
        elif status == "dead":
            lines.append("  [DEAD]")
        elif status == "error":
            detail = getattr(finding, "verification_detail", "") or "?"
            lines.append(f"  [ERROR: {detail}]")
        elif status == "unverifiable":
            lines.append("  [UNVERIFIABLE]")

        return lines

