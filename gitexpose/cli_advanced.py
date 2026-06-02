#!/usr/bin/env python3
"""
GitExpose Advanced CLI

Unified command-line interface integrating all advanced security scanning
capabilities including:

- React2Shell Detection (CVE-2025-55182)
- ML Model Supply Chain Scanning
- LLM/RAG Infrastructure Exposure
- Invisible Unicode Detection
- MCP Server Mode

Author: GitExpose Security Research
"""

import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import click

from . import __version__
from .cli_gating import SEVERITY_ORDER, add_fail_on_arg, exit_code_for

# Rich console for beautiful output (optional but recommended)
try:
    from rich import print as rprint
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
    from rich.table import Table
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None


def print_banner():
    """Print GitExpose banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ██████╗ ██╗████████╗███████╗██╗  ██╗██████╗  ██████╗ ███████╗  ║
║  ██╔════╝ ██║╚══██╔══╝██╔════╝╚██╗██╔╝██╔══██╗██╔═══██╗██╔════╝  ║
║  ██║  ███╗██║   ██║   █████╗   ╚███╔╝ ██████╔╝██║   ██║███████╗  ║
║  ██║   ██║██║   ██║   ██╔══╝   ██╔██╗ ██╔═══╝ ██║   ██║╚════██║  ║
║  ╚██████╔╝██║   ██║   ███████╗██╔╝ ██╗██║     ╚██████╔╝███████║  ║
║   ╚═════╝ ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝  ║
║                                                                   ║
║           Advanced Security Scanner v3.0 - 2025 Edition           ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
    """
    if RICH_AVAILABLE:
        console.print(banner, style="bold blue")
    else:
        print(banner)


def print_section(title: str):
    """Print section header"""
    if RICH_AVAILABLE:
        console.print(f"\n[bold cyan]{'━' * 60}[/]")
        console.print(f"[bold white]  {title}[/]")
        console.print(f"[bold cyan]{'━' * 60}[/]\n")
    else:
        print(f"\n{'=' * 60}")
        print(f"  {title}")
        print(f"{'=' * 60}\n")


def print_finding(severity: str, message: str, url: str = None):
    """Print a finding with severity color"""
    colors = {
        "critical": "red",
        "high": "orange3",
        "medium": "yellow",
        "low": "green",
        "info": "blue",
    }
    icons = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
        "info": "ℹ️",
    }

    icon = icons.get(severity.lower(), "•")
    color = colors.get(severity.lower(), "white")

    if RICH_AVAILABLE:
        console.print(f"{icon} [{color}][{severity.upper()}][/] {message}")
        if url:
            console.print(f"   [dim]{url}[/]")
    else:
        print(f"{icon} [{severity.upper()}] {message}")
        if url:
            print(f"   {url}")


@click.group()
@click.version_option(version=__version__, prog_name="GitExpose")
def cli():
    """
    GitExpose Advanced - Next-Gen Security Scanner
    
    Comprehensive scanner for exposed sensitive files, vulnerable frameworks,
    AI/ML infrastructure, and supply chain threats.
    """
    pass


@cli.command("full-audit")
@click.argument('target')
@click.option('-c', '--concurrency', default=50, help='Max concurrent requests')
@click.option('-t', '--timeout', default=10, help='Request timeout in seconds')
@click.option('-o', '--output', type=click.Choice(['console', 'json', 'html']), default='console')
@click.option('--out-file', help='Output file path')
@click.option('--git-dump', is_flag=True, help='Dump exposed git repositories')
@click.option('--react2shell', is_flag=True, help='Check for React2Shell (CVE-2025-55182)')
@click.option('--ml-models', is_flag=True, help='Scan for exposed ML models')
@click.option('--llm-exposure', is_flag=True, help='Scan for LLM/RAG infrastructure')
@click.option('--unicode-detect', is_flag=True, help='Detect invisible Unicode')
@click.option('--source-maps', is_flag=True, help='Scan for source maps')
@click.option('--cicd', is_flag=True, help='Scan for CI/CD exposure')
@click.option('--api-discovery', is_flag=True, help='Discover API endpoints')
@click.option('--full-audit', is_flag=True, help='Enable all scan types')
@click.option('-v', '--verbose', is_flag=True, help='Verbose output')
@click.option('-q', '--quiet', is_flag=True, help='Minimal output')
def full_audit(target, concurrency, timeout, output, out_file, git_dump, react2shell,
               ml_models, llm_exposure, unicode_detect, source_maps, cicd, api_discovery,
               full_audit, verbose, quiet):
    """
    Comprehensive security scan of a target.
    
    Example:
        gitexpose scan example.com --full-audit
        gitexpose scan example.com --react2shell --ml-models
    """
    if not quiet:
        print_banner()

    # Enable all if full audit
    if full_audit:
        react2shell = ml_models = llm_exposure = unicode_detect = True
        source_maps = cicd = api_discovery = git_dump = True

    asyncio.run(_run_scan(
        target=target,
        concurrency=concurrency,
        timeout=timeout,
        output=output,
        out_file=out_file,
        git_dump=git_dump,
        react2shell=react2shell,
        ml_models=ml_models,
        llm_exposure=llm_exposure,
        unicode_detect=unicode_detect,
        source_maps=source_maps,
        cicd=cicd,
        api_discovery=api_discovery,
        verbose=verbose,
        quiet=quiet
    ))


async def _run_scan(**kwargs):
    """Execute the scan with all enabled modules"""
    import time
    start_time = time.time()

    target = kwargs['target']
    results = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "modules": {},
        "total_findings": 0,
        "critical_findings": 0,
    }

    if not kwargs['quiet']:
        print_section(f"Scanning: {target}")

    # Create progress display
    if RICH_AVAILABLE and not kwargs['quiet']:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:

            # Calculate total tasks
            tasks = []
            if kwargs['react2shell']:
                tasks.append(("React2Shell Detection", _scan_react2shell))
            if kwargs['ml_models']:
                tasks.append(("ML Model Scan", _scan_ml_models))
            if kwargs['llm_exposure']:
                tasks.append(("LLM/RAG Exposure", _scan_llm_exposure))
            if kwargs['unicode_detect']:
                tasks.append(("Unicode Detection", _scan_unicode))
            if kwargs['source_maps']:
                tasks.append(("Source Map Analysis", _scan_sourcemaps))
            if kwargs['cicd']:
                tasks.append(("CI/CD Exposure", _scan_cicd))
            if kwargs['api_discovery']:
                tasks.append(("API Discovery", _scan_api))

            if not tasks:
                # Default scan
                tasks.append(("Basic Scan", _scan_basic))

            main_task = progress.add_task("[cyan]Overall Progress", total=len(tasks))

            for task_name, task_func in tasks:
                task_id = progress.add_task(f"[yellow]{task_name}", total=100)

                try:
                    result = await task_func(target, kwargs.get('verbose', False))
                    results["modules"][task_name] = result

                    # Count findings
                    if isinstance(result, dict):
                        findings = result.get('findings_count', result.get('exposures_count', 0))
                        results["total_findings"] += findings
                        results["critical_findings"] += result.get('critical_findings', 0)

                    progress.update(task_id, completed=100)
                except Exception as e:
                    results["modules"][task_name] = {"error": str(e)}
                    progress.update(task_id, completed=100)

                progress.advance(main_task)
    else:
        # Non-rich output
        if kwargs['react2shell']:
            print("  [*] Running React2Shell detection...")
            results["modules"]["React2Shell"] = await _scan_react2shell(target, kwargs.get('verbose', False))

        if kwargs['ml_models']:
            print("  [*] Scanning for ML models...")
            results["modules"]["ML Models"] = await _scan_ml_models(target, kwargs.get('verbose', False))

        if kwargs['llm_exposure']:
            print("  [*] Checking LLM/RAG exposure...")
            results["modules"]["LLM Exposure"] = await _scan_llm_exposure(target, kwargs.get('verbose', False))

        if kwargs['unicode_detect']:
            print("  [*] Detecting invisible Unicode...")
            results["modules"]["Unicode"] = await _scan_unicode(target, kwargs.get('verbose', False))

    # Calculate duration
    results["scan_duration"] = time.time() - start_time

    # Output results
    if kwargs['output'] == 'json':
        output_json(results, kwargs.get('out_file'))
    elif kwargs['output'] == 'html':
        output_html(results, kwargs.get('out_file'))
    else:
        output_console(results, kwargs.get('quiet', False))


async def _scan_react2shell(target: str, verbose: bool) -> dict:
    """Run React2Shell detection"""
    try:
        from .react2shell_detector import React2ShellDetector

        detector = React2ShellDetector(deep_scan=True)
        finding = await detector.scan(target)

        return {
            "status": finding.status.value,
            "framework": finding.framework.value,
            "version": finding.framework_version,
            "risk_score": finding.risk_score,
            "evidence": finding.evidence,
            "endpoints_count": len(finding.endpoints),
            "recommendations": finding.recommendations,
            "critical_findings": 1 if finding.status.value == "vulnerable" else 0,
        }
    except Exception as e:
        return {"error": str(e)}


async def _scan_ml_models(target: str, verbose: bool) -> dict:
    """Run ML model scan"""
    try:
        from .ml_model_scanner import MLModelScanner

        scanner = MLModelScanner(deep_analysis=True)
        result = await scanner.scan(target)

        return {
            "exposed_models_count": len(result.exposed_models),
            "exposed_models": [
                {
                    "path": m.path,
                    "format": m.format.value,
                    "risk": m.risk_level.value,
                }
                for m in result.exposed_models[:10]
            ],
            "total_risk_score": result.total_risk_score,
            "recommendations": result.recommendations,
            "critical_findings": len([m for m in result.exposed_models if m.risk_level.value == "critical"]),
        }
    except Exception as e:
        return {"error": str(e)}


async def _scan_llm_exposure(target: str, verbose: bool) -> dict:
    """Run LLM exposure scan"""
    try:
        from .llm_exposure_scanner import LLMExposureScanner

        scanner = LLMExposureScanner()
        result = await scanner.scan(target)

        return {
            "exposures_count": len(result.exposures),
            "exposures": [
                {
                    "type": e.exposure_type.value,
                    "severity": e.severity.value,
                    "url": e.url,
                }
                for e in result.exposures[:10]
            ],
            "detected_technologies": result.detected_technologies,
            "total_risk_score": result.total_risk_score,
            "recommendations": result.recommendations,
            "critical_findings": len([e for e in result.exposures if e.severity.value == "critical"]),
        }
    except Exception as e:
        return {"error": str(e)}


async def _scan_unicode(target: str, verbose: bool) -> dict:
    """Run Unicode detection"""
    try:
        from .invisible_unicode_detector import InvisibleUnicodeScanner

        scanner = InvisibleUnicodeScanner()
        result = await scanner.scan(target)

        return {
            "files_analyzed": len(result.analyzed_files),
            "total_anomalies": result.total_anomalies,
            "critical_findings": result.critical_findings,
            "malicious_files": [
                a.path for a in result.analyzed_files if a.is_likely_malicious
            ],
            "recommendations": result.recommendations,
        }
    except Exception as e:
        return {"error": str(e)}


async def _scan_sourcemaps(target: str, verbose: bool) -> dict:
    """Run source map scan"""
    try:
        from .sourcemap_analyzer import SourceMapAnalyzer

        analyzer = SourceMapAnalyzer()
        result = await analyzer.scan(target)

        return result
    except Exception as e:
        return {"error": str(e)}


async def _scan_cicd(target: str, verbose: bool) -> dict:
    """Run CI/CD scan"""
    try:
        from .cicd_scanner import CICDScanner

        scanner = CICDScanner()
        result = await scanner.scan(target)

        return result
    except Exception as e:
        return {"error": str(e)}


async def _scan_api(target: str, verbose: bool) -> dict:
    """Run API discovery"""
    try:
        from .api_discovery import APIDiscovery

        discovery = APIDiscovery()
        result = await discovery.discover(target)

        return result
    except Exception as e:
        return {"error": str(e)}


async def _scan_basic(target: str, verbose: bool) -> dict:
    """Run basic scan"""
    import aiohttp

    findings = []
    paths = [
        ("/.git/config", "critical"),
        ("/.git/HEAD", "critical"),
        ("/.env", "critical"),
        ("/.env.local", "critical"),
        ("/config.json", "high"),
        ("/package.json", "medium"),
    ]

    if not target.startswith(('http://', 'https://')):
        target = f"https://{target}"

    async with aiohttp.ClientSession() as session:
        for path, severity in paths:
            try:
                url = f"{target.rstrip('/')}{path}"
                async with session.get(url, timeout=10, ssl=False) as resp:
                    if resp.status == 200:
                        findings.append({
                            "url": url,
                            "path": path,
                            "severity": severity,
                        })
            except Exception:
                continue

    return {
        "findings_count": len(findings),
        "findings": findings,
        "critical_findings": len([f for f in findings if f["severity"] == "critical"]),
    }


def output_console(results: dict, quiet: bool):
    """Output results to console"""
    if not quiet:
        print_section("Scan Results")

    total = results.get("total_findings", 0)
    critical = results.get("critical_findings", 0)
    duration = results.get("scan_duration", 0)

    if RICH_AVAILABLE and not quiet:
        # Summary table
        table = Table(title="Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Target", results["target"])
        table.add_row("Duration", f"{duration:.2f}s")
        table.add_row("Total Findings", str(total))
        table.add_row("Critical", f"[red]{critical}[/]" if critical > 0 else "0")

        console.print(table)
        console.print()

        # Module results
        for module_name, module_result in results.get("modules", {}).items():
            if "error" in module_result:
                console.print(f"[red]✗ {module_name}: {module_result['error']}[/]")
            else:
                count = module_result.get('findings_count', module_result.get('exposures_count', 0))
                console.print(f"[green]✓ {module_name}: {count} findings[/]")

                # Show details for critical findings
                if module_result.get('critical_findings', 0) > 0:
                    for finding in module_result.get('findings', module_result.get('exposures', []))[:5]:
                        if isinstance(finding, dict):
                            sev = finding.get('severity', finding.get('risk', 'info'))
                            url = finding.get('url', finding.get('path', ''))
                            print_finding(sev, finding.get('type', finding.get('format', 'Unknown')), url)
    else:
        print(f"Target: {results['target']}")
        print(f"Duration: {duration:.2f}s")
        print(f"Total Findings: {total}")
        print(f"Critical: {critical}")


def output_json(results: dict, out_file: Optional[str]):
    """Output results as JSON"""
    json_str = json.dumps(results, indent=2, default=str)

    if out_file:
        with open(out_file, 'w') as f:
            f.write(json_str)
        if RICH_AVAILABLE:
            console.print(f"[green]Results saved to {out_file}[/]")
        else:
            print(f"Results saved to {out_file}")
    else:
        print(json_str)


def output_html(results: dict, out_file: Optional[str]):
    """Output results as HTML report"""
    html = generate_html_report(results)

    out_file = out_file or "gitexpose_report.html"
    with open(out_file, 'w') as f:
        f.write(html)

    if RICH_AVAILABLE:
        console.print(f"[green]HTML report saved to {out_file}[/]")
    else:
        print(f"HTML report saved to {out_file}")


def generate_html_report(results: dict) -> str:
    """Generate HTML report"""
    modules_html = ""
    for name, data in results.get("modules", {}).items():
        if "error" in data:
            status = "error"
            details = f"Error: {data['error']}"
        else:
            count = data.get('findings_count', data.get('exposures_count', 0))
            status = "critical" if data.get('critical_findings', 0) > 0 else "ok"
            details = f"{count} findings"

        modules_html += f"""
        <div class="module {status}">
            <h3>{name}</h3>
            <p>{details}</p>
        </div>
        """

    return f"""<!DOCTYPE html>
<html>
<head>
    <title>GitExpose Security Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', sans-serif; background: #0a0a0f; color: #e0e0e0; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
        header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 2rem; border-radius: 1rem; margin-bottom: 2rem; }}
        h1 {{ font-size: 2rem; color: #00d4ff; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 2rem 0; }}
        .stat {{ background: #1a1a2e; padding: 1.5rem; border-radius: 0.75rem; text-align: center; }}
        .stat-value {{ font-size: 2.5rem; font-weight: bold; color: #00d4ff; }}
        .stat-label {{ color: #888; margin-top: 0.5rem; }}
        .modules {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1rem; }}
        .module {{ background: #1a1a2e; padding: 1.5rem; border-radius: 0.75rem; border-left: 4px solid #00d4ff; }}
        .module.critical {{ border-left-color: #ff4444; }}
        .module.error {{ border-left-color: #ff8800; }}
        .module h3 {{ color: #fff; margin-bottom: 0.5rem; }}
        .module p {{ color: #888; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 GitExpose Security Report</h1>
            <p>Target: {results['target']}</p>
            <p>Generated: {results['timestamp']}</p>
        </header>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-value">{results.get('total_findings', 0)}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat">
                <div class="stat-value" style="color: #ff4444">{results.get('critical_findings', 0)}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat">
                <div class="stat-value">{results.get('scan_duration', 0):.1f}s</div>
                <div class="stat-label">Duration</div>
            </div>
        </div>
        
        <h2 style="margin: 2rem 0 1rem; color: #fff;">Scan Modules</h2>
        <div class="modules">
            {modules_html}
        </div>
    </div>
</body>
</html>"""


@cli.command()
@click.argument('target')
@click.option('--deep-scan/--no-deep-scan', default=True, help='Deep scanning mode')
@click.option('-o', '--output', type=click.Choice(['console', 'json']), default='console')
def react2shell(target, deep_scan, output):
    """
    Scan for React2Shell vulnerability (CVE-2025-55182).
    
    Detects exposed React Server Components, Flight protocol endpoints,
    and vulnerable Next.js configurations.
    """
    print_banner()
    print_section("React2Shell Detection")

    asyncio.run(_run_react2shell(target, deep_scan, output))


async def _run_react2shell(target: str, deep_scan: bool, output: str):
    """Execute React2Shell scan"""
    from .react2shell_detector import React2ShellDetector

    detector = React2ShellDetector(deep_scan=deep_scan)
    finding = await detector.scan(target)

    if output == 'json':
        print(json.dumps({
            "target": target,
            "status": finding.status.value,
            "framework": finding.framework.value,
            "version": finding.framework_version,
            "risk_score": finding.risk_score,
            "evidence": finding.evidence,
            "recommendations": finding.recommendations,
        }, indent=2))
    else:
        print(detector.generate_report(finding))


@cli.command()
@click.argument('target')
@click.option('--deep-analysis/--no-deep-analysis', default=True)
@click.option('-o', '--output', type=click.Choice(['console', 'json']), default='console')
def ml_scan(target, deep_analysis, output):
    """
    Scan for exposed ML model files.
    
    Detects pickle, PyTorch, TensorFlow, and other model formats
    that could contain malicious payloads.
    """
    print_banner()
    print_section("ML Model Supply Chain Scan")

    asyncio.run(_run_ml_scan(target, deep_analysis, output))


async def _run_ml_scan(target: str, deep_analysis: bool, output: str):
    """Execute ML model scan"""
    from .ml_model_scanner import MLModelScanner

    scanner = MLModelScanner(deep_analysis=deep_analysis)
    result = await scanner.scan(target)

    if output == 'json':
        print(json.dumps({
            "target": target,
            "exposed_models": [
                {"path": m.path, "format": m.format.value, "risk": m.risk_level.value}
                for m in result.exposed_models
            ],
            "total_risk_score": result.total_risk_score,
            "recommendations": result.recommendations,
        }, indent=2))
    else:
        print(scanner.generate_report(result))


@cli.command()
@click.argument('target')
@click.option('-o', '--output', type=click.Choice(['console', 'json']), default='console')
def llm_scan(target, output):
    """
    Scan for exposed LLM/RAG infrastructure.
    
    Detects vector databases, system prompts, RAG configs, and AI API keys.
    """
    print_banner()
    print_section("LLM/RAG Infrastructure Scan")

    asyncio.run(_run_llm_scan(target, output))


async def _run_llm_scan(target: str, output: str):
    """Execute LLM exposure scan"""
    from .llm_exposure_scanner import LLMExposureScanner

    scanner = LLMExposureScanner()
    result = await scanner.scan(target)

    if output == 'json':
        print(json.dumps({
            "target": target,
            "exposures": [
                {"type": e.exposure_type.value, "severity": e.severity.value, "url": e.url}
                for e in result.exposures
            ],
            "detected_technologies": result.detected_technologies,
            "total_risk_score": result.total_risk_score,
            "recommendations": result.recommendations,
        }, indent=2))
    else:
        print(scanner.generate_report(result))


@cli.command()
@click.argument('target', required=False)
@click.option('--file', '-f', 'file_path', help='Analyze local file instead of URL')
@click.option('-o', '--output', type=click.Choice(['console', 'json']), default='console')
def unicode_scan(target, file_path, output):
    """
    Detect invisible Unicode characters.
    
    Scans for variation selectors, zero-width chars, and other
    invisible characters used in supply chain attacks like GlassWorm.
    """
    print_banner()
    print_section("Invisible Unicode Detection")

    if file_path:
        asyncio.run(_run_unicode_file(file_path, output))
    elif target:
        asyncio.run(_run_unicode_url(target, output))
    else:
        print("Error: Provide either a target URL or --file path")
        sys.exit(1)


async def _run_unicode_url(target: str, output: str):
    """Scan URL for invisible Unicode"""
    from .invisible_unicode_detector import InvisibleUnicodeScanner

    scanner = InvisibleUnicodeScanner()
    result = await scanner.scan(target)

    if output == 'json':
        print(json.dumps({
            "target": target,
            "files_analyzed": len(result.analyzed_files),
            "total_anomalies": result.total_anomalies,
            "critical_findings": result.critical_findings,
            "recommendations": result.recommendations,
        }, indent=2))
    else:
        print(scanner.generate_report(result))


async def _run_unicode_file(file_path: str, output: str):
    """Analyze local file for invisible Unicode"""
    from .invisible_unicode_detector import InvisibleUnicodeAnalyzer

    with open(file_path, 'r', errors='replace') as f:
        content = f.read()

    analyzer = InvisibleUnicodeAnalyzer()
    anomalies = analyzer.analyze(content, file_path)

    if output == 'json':
        print(json.dumps({
            "file": file_path,
            "anomalies_count": len(anomalies),
            "anomalies": [
                {
                    "category": a.category.value,
                    "threat_level": a.threat_level.value,
                    "codepoint": a.codepoint,
                    "line": a.line_number,
                    "description": a.description,
                }
                for a in anomalies
            ],
        }, indent=2))
    else:
        if anomalies:
            print(f"Found {len(anomalies)} anomalies in {file_path}:\n")
            for a in anomalies:
                print_finding(a.threat_level.value, f"{a.description} ({a.codepoint})", f"Line {a.line_number}")
        else:
            print(f"No invisible Unicode anomalies found in {file_path}")


@cli.command()
def mcp():
    """
    Start GitExpose as an MCP server.
    
    Enables AI agents (Claude, GPT) to use GitExpose tools
    via the Model Context Protocol.
    """
    from .mcp_server import main as mcp_main
    mcp_main()


@cli.command()
def list_tools():
    """List all available scanning tools."""
    print_banner()
    print_section("Available Tools")

    tools = [
        ("scan", "Comprehensive security scan", "--full-audit for all modules"),
        ("react2shell", "React2Shell (CVE-2025-55182) detection", "--deep-scan"),
        ("ml-scan", "ML model supply chain scanning", "--deep-analysis"),
        ("llm-scan", "LLM/RAG infrastructure exposure", "Vector DBs, prompts, configs"),
        ("unicode-scan", "Invisible Unicode detection", "GlassWorm patterns"),
        ("mcp", "Start MCP server", "For AI agent integration"),
        ("supply-chain", "Local-filesystem scan for supply-chain risks (TeamPCP-class)", "--output json"),
    ]

    if RICH_AVAILABLE:
        table = Table(title="GitExpose Tools")
        table.add_column("Command", style="cyan")
        table.add_column("Description", style="white")
        table.add_column("Key Options", style="dim")

        for cmd, desc, opts in tools:
            table.add_row(cmd, desc, opts)

        console.print(table)
    else:
        for cmd, desc, opts in tools:
            print(f"  {cmd:15} - {desc} ({opts})")


def add_verify_args(func):
    """Attach the v0.3 --verify* options to a Click command. Shared by
    supply-chain and git-history so the flag set stays identical."""
    options = [
        click.option("--verify", is_flag=True, default=False,
                     help="Send candidate credentials to provider APIs for liveness check (opt-in)."),
        click.option("--verify-concurrency", type=int, default=5, metavar="N",
                     help="Max concurrent verification requests (default: 5)."),
        click.option("--verify-timeout", type=float, default=5.0, metavar="SECONDS",
                     help="Per-request verification timeout (default: 5.0)."),
        click.option("--verify-only-severity",
                     type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
                     default=None, help="Only verify findings whose severity is >= LEVEL."),
        click.option("--no-verify-banner", is_flag=True, default=False,
                     help="Suppress the consent banner printed when --verify is active."),
    ]
    for option in reversed(options):
        func = option(func)
    return func


@cli.command("supply-chain")
@click.argument("path", type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option("-o", "--output", type=click.Choice(["console", "json", "cyclonedx", "aibom"]),
              default="console")
@click.option("--out-file", type=click.Path(), help="Write output to file instead of stdout")
@click.option("--offline", is_flag=True, default=False,
              help="Skip OSV.dev network lookups; use the curated known-bad list only.")
@click.option("--osv-timeout", type=float, default=10.0, metavar="SECS",
              help="Per-request OSV.dev timeout (default 10s).")
@click.option("--osv-max", type=int, default=5000, metavar="N",
              help="Cap dependencies queried against OSV.dev (default 5000).")
@click.option("--track", is_flag=True, default=False,
              help="Record secret hashes in a cross-source registry for orphan signal (opt-in).")
@click.option("--registry", "registry_path", type=click.Path(), default=None,
              help="Registry file path (default ~/.gitexpose/registry.json). Implies --track.")
@add_verify_args
@add_fail_on_arg
def supply_chain(path: str, output: str, out_file: str, offline: bool,
                 osv_timeout: float, osv_max: int, track: bool, registry_path: str,
                 verify: bool, verify_concurrency: int, verify_timeout: float,
                 verify_only_severity: str, no_verify_banner: bool,
                 fail_on: str):
    """Scan a local directory for supply-chain risks (TeamPCP-class) + live SCA."""
    from .advanced.local_fs_scanner import LocalFilesystemScanner

    scanner = LocalFilesystemScanner()
    findings = scanner.scan(Path(path), track=track or bool(registry_path),
                            registry_path=registry_path)

    # --- v0.5: lock-file SCA + OSV.dev live vulnerability intelligence ---
    import asyncio as _asyncio
    from .supply_chain.lockfiles import parse_all
    from .supply_chain.osv import query_osv
    from .supply_chain.correlate import build_vuln_findings, exploitability_sort_key

    _v05_deps = parse_all(Path(path))

    # Credential co-presence: which source files already produced a credential finding?
    cred_sources = {
        f.get("source") for f in findings
        if f.get("value_full") or f.get("secret") or (f.get("type") or "").endswith("_key")
    }
    # Unpinned packages flagged by the existing dependency_pinning scanner.
    unpinned_packages = {
        (f.get("package") or "").lower().replace("_", "-")
        for f in findings if f.get("type") == "unpinned_ai_middleware"
    }

    # Clamp to sane minimums (a negative --osv-max would silently slice the dep
    # list; a non-positive timeout would degenerate the OSV request).
    osv_max = max(0, osv_max)
    osv_timeout = max(0.1, osv_timeout)

    osv_map = {}
    if not offline and _v05_deps and osv_max:
        if not no_verify_banner:
            click.echo(
                f"ℹ  Querying OSV.dev for {min(len(_v05_deps), osv_max)} dependencies "
                "(package names + versions only; use --offline to disable).",
                err=True,
            )
        osv_map = _asyncio.run(query_osv(_v05_deps, timeout=osv_timeout, max_deps=osv_max))

    vuln_findings = build_vuln_findings(
        osv_map, _v05_deps, unpinned_packages=unpinned_packages, cred_sources=cred_sources
    )
    vuln_findings.sort(key=exploitability_sort_key, reverse=True)
    findings = findings + vuln_findings

    # Ensure every finding dict carries verification_status (non-credential scanners
    # such as dependency_pinning do not set this key; treat absent as "skipped").
    for f in findings:
        f.setdefault("verification_status", "skipped")
        f.setdefault("verification_detail", None)

    if verify:
        import asyncio as _asyncio
        from gitexpose.verification import verify_secrets
        from gitexpose.verification.engine import pair_aws_credentials
        from gitexpose.verification.banner import print_verify_banner

        print_verify_banner(suppress=no_verify_banner)

        # Only credential-style findings are verifiable; vulnerable_dependency
        # findings are not credentials, so exclude them (they keep "skipped").
        to_verify = [f for f in findings if f.get("type") != "vulnerable_dependency"]
        if verify_only_severity:
            _floor = SEVERITY_ORDER[verify_only_severity]
            to_verify = [
                f for f in to_verify
                if SEVERITY_ORDER.get((f.get("severity") or "INFO").upper(), 0) >= _floor
            ]
        pair_aws_credentials(to_verify)
        _asyncio.run(verify_secrets(
            to_verify,
            concurrency=verify_concurrency,
            timeout=verify_timeout,
        ))
        # findings dicts are mutated in-place; findings not in to_verify keep
        # verification_status == "skipped" (set by setdefault above).

        # Honest VEX (spec §6): a vulnerable dependency is "exploitable" only when a
        # credential in the SAME source file was confirmed live. Mark that now that
        # verification has run.
        verified_sources = {
            f.get("source") for f in findings
            if f.get("verification_status") == "verified"
        }
        for f in vuln_findings:
            f["cred_verified_co_present"] = f.get("source") in verified_sources

    for f in findings:
        f.pop("_verify_input", None)

    if output in ("cyclonedx", "aibom"):
        from .reporters.cyclonedx_reporter import build_bom
        text = build_bom(_v05_deps, findings)
    elif output == "json":
        import json as _json
        text = _json.dumps(findings, indent=2, default=str)
    else:
        if not findings:
            text = f"✅ No supply-chain findings in {path}"
        else:
            lines = [f"🔍 {len(findings)} supply-chain finding(s) in {path}:"]
            for f in findings:
                sev = f.get("severity") or "UNKNOWN"
                ftype = f.get("type") or "unknown"
                src = f.get("source") or ""
                desc = next(iter((f.get("description") or "").splitlines()), "")
                lines.append(f"  [{sev}] {ftype}  ({src})")
                if desc:
                    lines.append(f"     {desc}")
                if f.get("attack_class") or f.get("atlas_technique"):
                    parts = []
                    if f.get("attack_class"):
                        ac = f["attack_class"]
                        parts.append(ac if ac.startswith("OWASP") else f"OWASP {ac}")
                    if f.get("atlas_technique"):
                        parts.append(f"ATLAS {f['atlas_technique']}")
                    lines.append(f"     📋 {' · '.join(parts)}")
                if ftype == "vulnerable_dependency":
                    vid = f.get("vuln_id", "?")
                    fix = f.get("fixed_version")
                    fixtxt = f"fix: {fix}" if fix else "no fix available"
                    flags = []
                    if f.get("direct"):
                        flags.append("direct")
                    if not f.get("pinned"):
                        flags.append("unpinned")
                    if f.get("cred_co_present"):
                        flags.append("⚠ creds-co-present")
                    if f.get("known_exploited"):
                        flags.append("KEV")
                    cvss = f.get("cvss_score")
                    cvss_txt = f" CVSS {cvss}" if cvss else ""
                    flagtxt = f" [{', '.join(flags)}]" if flags else ""
                    lines.append(
                        f"     🔗 {f.get('package')}@{f.get('version')} — {vid}{cvss_txt} ({fixtxt}){flagtxt}"
                    )
                if verify:
                    vstatus = f.get("verification_status", "skipped")
                    if vstatus == "verified":
                        lines.append("     ✓ VERIFIED (credential is LIVE)")
                    elif vstatus == "dead":
                        lines.append("     ✗ DEAD (credential rejected by provider)")
                    elif vstatus == "error":
                        vdetail = f.get("verification_detail") or "?"
                        lines.append(f"     ? VERIFY ERROR ({vdetail})")
                    elif vstatus == "unverifiable":
                        lines.append("     – unverifiable (no verifier for this type)")
                    # skipped: print nothing
            text = "\n".join(lines)

    if out_file:
        Path(out_file).write_text(text)
    else:
        click.echo(text)

    sys.exit(exit_code_for(findings, fail_on))


@cli.command("agent-audit")
@click.argument("path", type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option("-o", "--output", type=click.Choice(["console", "json", "sarif"]), default="console")
@click.option("--out-file", type=click.Path(), help="Write output to file instead of stdout")
@click.option("--max-bytes", type=int, default=1024 * 1024, metavar="N",
              help="Per-file size cap (default 1 MB).")
@add_fail_on_arg
def agent_audit(path: str, output: str, out_file: str, max_bytes: int, fail_on: str):
    """Audit AI-agent configs for excessive tool permissions + leaked system prompts."""
    from .agent_exposure import scan as agent_scan

    findings = agent_scan(Path(path))

    if output == "json":
        import json as _json
        text = _json.dumps(findings, indent=2, default=str)
    elif output == "sarif":
        from .agent_exposure.sarif import to_sarif
        text = to_sarif(findings, __version__)
    else:
        if not findings:
            text = f"✅ No agent-exposure findings in {path}"
        else:
            lines = [f"🤖 {len(findings)} agent-exposure finding(s) in {path}:"]
            for f in findings:
                sev = f.get("severity") or "UNKNOWN"
                ftype = f.get("type") or "unknown"
                src = f.get("source") or ""
                lines.append(f"  [{sev}] {ftype}  ({src})")
                desc = f.get("description")
                if desc:
                    lines.append(f"     {desc}")
                if f.get("evidence"):
                    lines.append(f"     ↳ {f['evidence']}")
                parts = []
                if f.get("attack_class"):
                    parts.append(f["attack_class"])
                if f.get("atlas_technique"):
                    parts.append(f"ATLAS {f['atlas_technique']}")
                if f.get("mitre_attack"):
                    parts.append(f"ATT&CK {f['mitre_attack']}")
                if parts:
                    lines.append(f"     📋 {' · '.join(parts)}")
            text = "\n".join(lines)

    if out_file:
        Path(out_file).write_text(text)
    else:
        click.echo(text)

    sys.exit(exit_code_for(findings, fail_on))


@cli.command("git-history")
@click.argument("path", type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option("-o", "--output", type=click.Choice(["console", "json"]), default="console")
@click.option("--out-file", type=click.Path(), help="Write output to file instead of stdout")
@click.option("--since", default=None, help="Only commits after DATE (passthrough to git log).")
@click.option("--max-commits", type=int, default=None, metavar="N",
              help="Cap the number of commits scanned.")
@add_verify_args
@add_fail_on_arg
def git_history(path, output, out_file, since, max_commits,
                verify, verify_concurrency, verify_timeout, verify_only_severity, no_verify_banner,
                fail_on: str):
    """Scan all git history for credentials committed and later removed."""
    from pathlib import Path as _Path
    from .git_history import scan_history

    try:
        findings = scan_history(_Path(path), since=since, max_commits=max_commits)
    except ValueError as exc:
        click.echo(str(exc), err=True)
        sys.exit(2)

    for f in findings:
        f.setdefault("verification_status", "skipped")
        f.setdefault("verification_detail", None)

    if verify:
        import asyncio as _asyncio
        from .verification import verify_secrets
        from .verification.engine import pair_aws_credentials
        from .verification.banner import print_verify_banner

        print_verify_banner(suppress=no_verify_banner)

        to_verify = findings
        if verify_only_severity:
            floor = SEVERITY_ORDER[verify_only_severity]
            to_verify = [f for f in findings
                         if SEVERITY_ORDER.get((f.get("severity") or "INFO").upper(), 0) >= floor]
        pair_aws_credentials(to_verify)
        _asyncio.run(verify_secrets(to_verify, concurrency=verify_concurrency, timeout=verify_timeout))

    for f in findings:
        f.pop("_verify_input", None)

    if output == "json":
        import json as _json
        text = _json.dumps(findings, indent=2, default=str)
    else:
        if not findings:
            text = f"✅ No historical secrets found in {path}"
        else:
            lines = [f"🔍 {len(findings)} historical secret(s) in {path} (across all branches):"]
            for f in findings:
                sev = f.get("severity") or "UNKNOWN"
                lines.append(
                    f"  [{sev}] {f.get('type')}   "
                    f"({f.get('source')} @ {f.get('commit_short')}, {f.get('author')}, "
                    f"{(f.get('commit_date') or '')[:10]})"
                )
                if verify:
                    vstatus = f.get("verification_status", "skipped")
                    if vstatus == "verified":
                        lines.append("     ✓ VERIFIED (credential is LIVE)")
                    elif vstatus == "dead":
                        lines.append("     ✗ DEAD (credential rejected by provider)")
                    elif vstatus == "error":
                        lines.append(f"     ? VERIFY ERROR ({f.get('verification_detail') or '?'})")
                    elif vstatus == "unverifiable":
                        lines.append("     – unverifiable (no verifier for this type)")
            text = "\n".join(lines)

    if out_file:
        _Path(out_file).write_text(text)
    else:
        click.echo(text)

    sys.exit(exit_code_for(findings, fail_on))


# Register the mature web scanner (gitexpose/cli.py) as the canonical `scan` subcommand.
# Imported here (not in cli.py at module level) so the import stays one-way / cycle-free.
from .cli import scan as _web_scan  # noqa: E402
cli.add_command(_web_scan)


def main():
    """Main entry point"""
    cli()


if __name__ == "__main__":
    main()
