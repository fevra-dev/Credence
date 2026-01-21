"""HTML report generator with charts and visualizations."""

from datetime import datetime
from pathlib import Path

from ..models import ScanReport


class HTMLReporter:
    """Generate beautiful HTML reports"""

    def generate(self, report: ScanReport, output_file: Path = None) -> str:
        """Generate HTML report"""

        # Calculate severity counts
        severity_counts = {
            'critical': report.critical_count,
            'high': report.high_count,
            'medium': report.medium_count,
            'low': report.low_count
        }

        # Get all findings
        all_findings = []
        for target_report in report.target_reports:
            for finding in target_report.findings:
                all_findings.append({
                    'target': target_report.target,
                    'finding': finding
                })

        html = self._render_template(report, severity_counts, all_findings)

        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html)

        return html

    def _render_template(self, report: ScanReport, severity_counts: dict, findings: list) -> str:
        """Render the HTML template"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GitExpose Security Scan Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            padding: 2rem;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 1rem;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }}
        
        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 3rem 2rem;
            text-align: center;
        }}
        
        header h1 {{
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }}
        
        header p {{
            opacity: 0.9;
            font-size: 1.1rem;
        }}
        
        .content {{
            padding: 2rem;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 3rem;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 2rem;
            border-radius: 0.75rem;
            text-align: center;
            transition: transform 0.2s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        
        .stat-value {{
            font-size: 3rem;
            font-weight: 700;
            color: #667eea;
            margin-bottom: 0.5rem;
        }}
        
        .stat-label {{
            color: #64748b;
            text-transform: uppercase;
            font-size: 0.875rem;
            letter-spacing: 0.05em;
            font-weight: 600;
        }}
        
        .chart-container {{
            background: #f8fafc;
            padding: 2rem;
            border-radius: 0.75rem;
            margin-bottom: 3rem;
        }}
        
        .findings-section {{
            margin-top: 2rem;
        }}
        
        .findings-section h2 {{
            font-size: 2rem;
            color: #1e293b;
            margin-bottom: 1.5rem;
            padding-bottom: 0.5rem;
            border-bottom: 3px solid #667eea;
        }}
        
        .finding {{
            background: white;
            border: 1px solid #e2e8f0;
            border-left: 4px solid;
            border-radius: 0.5rem;
            padding: 1.5rem;
            margin-bottom: 1rem;
            transition: box-shadow 0.2s;
        }}
        
        .finding:hover {{
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }}
        
        .finding.critical {{
            border-left-color: #dc2626;
            background: linear-gradient(90deg, #fef2f2 0%, white 10%);
        }}
        
        .finding.high {{
            border-left-color: #ea580c;
            background: linear-gradient(90deg, #fff7ed 0%, white 10%);
        }}
        
        .finding.medium {{
            border-left-color: #ca8a04;
            background: linear-gradient(90deg, #fefce8 0%, white 10%);
        }}
        
        .finding.low {{
            border-left-color: #2563eb;
            background: linear-gradient(90deg, #eff6ff 0%, white 10%);
        }}
        
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 1rem;
        }}
        
        .finding-title {{
            font-size: 1.25rem;
            font-weight: 600;
            color: #1e293b;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 0.375rem 0.75rem;
            border-radius: 0.375rem;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        .severity-badge.critical {{
            background: #dc2626;
            color: white;
        }}
        
        .severity-badge.high {{
            background: #ea580c;
            color: white;
        }}
        
        .severity-badge.medium {{
            background: #ca8a04;
            color: white;
        }}
        
        .severity-badge.low {{
            background: #2563eb;
            color: white;
        }}
        
        .finding-url {{
            color: #6366f1;
            word-break: break-all;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            margin-bottom: 1rem;
        }}
        
        .finding-description {{
            color: #64748b;
            line-height: 1.6;
            margin-bottom: 1rem;
        }}
        
        .evidence {{
            background: #1e293b;
            color: #e2e8f0;
            padding: 1rem;
            border-radius: 0.5rem;
            font-family: 'Courier New', monospace;
            font-size: 0.875rem;
            overflow-x: auto;
            margin-top: 1rem;
        }}
        
        .meta-info {{
            display: flex;
            gap: 2rem;
            color: #64748b;
            font-size: 0.875rem;
            margin-top: 1rem;
        }}
        
        .meta-item {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        
        .no-findings {{
            text-align: center;
            padding: 4rem 2rem;
            color: #64748b;
        }}
        
        .no-findings svg {{
            width: 4rem;
            height: 4rem;
            margin-bottom: 1rem;
            color: #10b981;
        }}
        
        footer {{
            background: #f8fafc;
            padding: 2rem;
            text-align: center;
            color: #64748b;
            font-size: 0.875rem;
        }}
        
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            
            .finding {{
                page-break-inside: avoid;
            }}
        }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 GitExpose Security Scan Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>
        
        <div class="content">
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-value">{report.targets_scanned}</div>
                    <div class="stat-label">Targets Scanned</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{report.targets_vulnerable}</div>
                    <div class="stat-label">Vulnerable Targets</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{report.total_findings}</div>
                    <div class="stat-label">Total Findings</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{report.scan_duration_ms / 1000:.2f}s</div>
                    <div class="stat-label">Scan Duration</div>
                </div>
            </div>
            
            {self._render_chart_section(severity_counts)}
            
            {self._render_findings_section(findings)}
        </div>
        
        <footer>
            <p>Generated by <strong>GitExpose</strong> - A security scanner for exposed sensitive files</p>
            <p>Report any false positives to improve detection accuracy</p>
        </footer>
    </div>
    
    <script>
        {self._render_chart_script(severity_counts)}
    </script>
</body>
</html>"""

    def _render_chart_section(self, severity_counts: dict) -> str:
        """Render the chart section"""
        if sum(severity_counts.values()) == 0:
            return ""

        return """
            <div class="chart-container">
                <canvas id="severityChart" height="100"></canvas>
            </div>
        """

    def _render_chart_script(self, severity_counts: dict) -> str:
        """Render the Chart.js script"""
        if sum(severity_counts.values()) == 0:
            return ""

        return f"""
        const ctx = document.getElementById('severityChart');
        if (ctx) {{
            new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{{
                        label: 'Findings by Severity',
                        data: [{severity_counts['critical']}, {severity_counts['high']}, {severity_counts['medium']}, {severity_counts['low']}],
                        backgroundColor: [
                            '#dc2626',
                            '#ea580c',
                            '#ca8a04',
                            '#2563eb'
                        ],
                        borderWidth: 0
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{
                        legend: {{
                            display: false
                        }},
                        title: {{
                            display: true,
                            text: 'Findings by Severity Level',
                            font: {{
                                size: 18,
                                weight: 'bold'
                            }}
                        }}
                    }},
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            ticks: {{
                                stepSize: 1
                            }}
                        }}
                    }}
                }}
            }});
        }}
        """

    def _render_findings_section(self, findings: list) -> str:
        """Render findings section"""
        if not findings:
            return """
            <div class="findings-section">
                <div class="no-findings">
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <h2>No Vulnerabilities Found</h2>
                    <p>All scanned targets appear to be secure.</p>
                </div>
            </div>
            """

        findings_html = ['<div class="findings-section">', '<h2>Security Findings</h2>']

        for item in findings:
            target = item['target']
            finding = item['finding']

            findings_html.append(f"""
            <div class="finding {finding.severity.value.lower()}">
                <div class="finding-header">
                    <div class="finding-title">{finding.path}</div>
                    <span class="severity-badge {finding.severity.value.lower()}">{finding.severity.value}</span>
                </div>
                <div class="finding-url">{finding.url}</div>
                <div class="finding-description">{finding.description}</div>
                {f'<div class="evidence"><strong>Evidence:</strong> {finding.evidence}</div>' if finding.evidence else ''}
                <div class="meta-info">
                    <div class="meta-item">
                        <strong>Status:</strong> {finding.status_code}
                    </div>
                    <div class="meta-item">
                        <strong>Size:</strong> {finding.response_length:,} bytes
                    </div>
                    <div class="meta-item">
                        <strong>Category:</strong> {finding.category.value}
                    </div>
                </div>
            </div>
            """)

        findings_html.append('</div>')
        return '\n'.join(findings_html)
