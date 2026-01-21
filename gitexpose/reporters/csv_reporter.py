"""CSV output reporter."""

import csv
import io

from ..models import ScanReport
from .base import BaseReporter


class CSVReporter(BaseReporter):
    """CSV output reporter."""

    def generate(self, report: ScanReport) -> str:
        """Generate CSV output."""
        output = io.StringIO()

        writer = csv.writer(output)

        # Header
        writer.writerow(
            [
                "target",
                "url",
                "path",
                "severity",
                "category",
                "description",
                "status_code",
                "evidence",
                "response_length",
            ]
        )

        # Data rows
        for target_report in report.target_reports:
            for finding in target_report.findings:
                writer.writerow(
                    [
                        finding.target,
                        finding.url,
                        finding.path,
                        finding.severity.value,
                        finding.category.value,
                        finding.description,
                        finding.status_code,
                        finding.evidence,
                        finding.response_length,
                    ]
                )

        return output.getvalue()

