"""JSON output reporter."""

import json
from dataclasses import asdict

from ..models import Category, ScanReport, Severity
from .base import BaseReporter


class JSONReporter(BaseReporter):
    """JSON output reporter."""

    def generate(self, report: ScanReport) -> str:
        """Generate JSON output."""

        def serialize(obj):
            """Custom serializer for enums."""
            if isinstance(obj, (Severity, Category)):
                return obj.value
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

        # Convert to dict
        report_dict = asdict(report)

        # Serialize to JSON
        return json.dumps(report_dict, default=serialize, indent=2)

