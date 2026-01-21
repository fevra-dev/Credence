"""
GitExpose CLI interface.

Usage:
    gitexpose example.com
    gitexpose -f targets.txt -o json --out-file results.json
"""

import logging
import sys
from typing import List, Optional

import click

from . import __version__
from .reporters import ConsoleReporter, CSVReporter, JSONReporter
from .scanner import GitExposeScanner


def setup_logging(verbose: bool) -> None:
    """Configure logging based on verbosity."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format="[%(levelname)s] %(name)s: %(message)s")


def load_targets_from_file(filepath: str) -> List[str]:
    """Load targets from a file (one per line)."""
    targets = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith("#"):
                    targets.append(line)
    except IOError as e:
        raise click.ClickException(f"Cannot read targets file: {e}")
    return targets


@click.command()
@click.argument("targets", nargs=-1)
@click.option(
    "-f",
    "--file",
    type=click.Path(exists=True),
    help="File containing targets (one per line)",
)
@click.option(
    "-o",
    "--output",
    type=click.Choice(["console", "json", "csv"]),
    default="console",
    help="Output format [default: console]",
)
@click.option(
    "--out-file",
    type=click.Path(),
    help="Write output to file instead of stdout",
)
@click.option(
    "-c",
    "--concurrency",
    type=int,
    default=50,
    help="Max concurrent requests [default: 50]",
)
@click.option(
    "-t",
    "--timeout",
    type=int,
    default=10,
    help="Request timeout in seconds [default: 10]",
)
@click.option("-q", "--quiet", is_flag=True, help="Only show vulnerable targets")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose logging")
@click.option("--no-color", is_flag=True, help="Disable colored output")
@click.option(
    "--user-agent",
    type=str,
    default="GitExpose/1.0 (Security Scanner)",
    help="Custom User-Agent string",
)
@click.option("--follow-redirects", is_flag=True, help="Follow HTTP redirects")
@click.option("--version", is_flag=True, help="Show version and exit")
def main(
    targets: tuple,
    file: Optional[str],
    output: str,
    out_file: Optional[str],
    concurrency: int,
    timeout: int,
    quiet: bool,
    verbose: bool,
    no_color: bool,
    user_agent: str,
    follow_redirects: bool,
    version: bool,
) -> None:
    """
    Scan web targets for exposed sensitive files (.git, .env, backups, configs).

    \b
    Examples:
        gitexpose example.com
        gitexpose example.com example.org
        gitexpose -f targets.txt -o json --out-file results.json
        gitexpose -f targets.txt -c 100 -t 5 --quiet
    """
    # Handle version flag
    if version:
        click.echo(f"GitExpose v{__version__}")
        sys.exit(0)

    # Setup logging
    setup_logging(verbose)

    # Collect targets
    target_list = list(targets)

    if file:
        target_list.extend(load_targets_from_file(file))

    # Validate we have targets
    if not target_list:
        click.echo(
            click.style("Error: No targets specified. ", fg="red")
            + "Provide targets as arguments or use -f/--file.",
            err=True,
        )
        sys.exit(2)

    # Deduplicate
    target_list = list(dict.fromkeys(target_list))

    if not quiet:
        click.echo(
            f"\n🔍 Scanning {len(target_list)} target(s) with {concurrency} concurrent requests...\n"
        )

    # Create scanner
    scanner = GitExposeScanner(
        timeout=timeout,
        concurrency=concurrency,
        user_agent=user_agent,
        follow_redirects=follow_redirects,
    )

    # Run scan
    try:
        report = scanner.scan_sync(target_list)
    except Exception as e:
        click.echo(click.style(f"Error during scan: {e}", fg="red"), err=True)
        sys.exit(2)

    # Select reporter
    reporters = {
        "console": ConsoleReporter,
        "json": JSONReporter,
        "csv": CSVReporter,
    }
    reporter = reporters[output](quiet=quiet, verbose=verbose, no_color=no_color)

    # Generate output
    output_str = reporter.generate(report)

    # Write output
    if out_file:
        try:
            with open(out_file, "w") as f:
                f.write(output_str)
            if not quiet:
                click.echo(f"\n📄 Results written to: {out_file}")
        except IOError as e:
            click.echo(click.style(f"Error writing output file: {e}", fg="red"), err=True)
            sys.exit(2)
    else:
        click.echo(output_str)

    # Exit code based on findings
    if report.total_findings > 0:
        sys.exit(1)  # Vulnerabilities found
    else:
        sys.exit(0)  # Clean


if __name__ == "__main__":
    main()

