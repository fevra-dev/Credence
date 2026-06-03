"""
Credence CLI interface.

Usage:
    credence example.com
    credence -f targets.txt -o json --out-file results.json
"""

import logging
import os
import sys
from typing import List, Optional

import click

from . import __version__
from .reporters import ConsoleReporter, CSVReporter, JSONReporter, SARIFReporter
from .scanner import CredenceScanner


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


@click.command("scan")
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
    type=click.Choice(["console", "json", "csv", "sarif"]),
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
    default="Credence/1.0 (Security Scanner)",
    help="Custom User-Agent string",
)
@click.option("--follow-redirects", is_flag=True, help="Follow HTTP redirects")
@click.option("--version", is_flag=True, help="Show version and exit")
def scan(
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
        credence example.com
        credence example.com example.org
        credence -f targets.txt -o json --out-file results.json
        credence -f targets.txt -c 100 -t 5 --quiet
    """
    # Handle version flag
    if version:
        click.echo(f"Credence v{__version__}")
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
    scanner = CredenceScanner(
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
        "sarif": SARIFReporter,
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


_PASSTHROUGH = {"--help", "-h", "--version"}


def _route_argv(argv, known):
    """Prepend the default `scan` command unless argv already names a subcommand
    or is a group-level --help/--version. Keeps bare-target `credence <host>` and
    leading-option `credence -f targets.txt` routing to the web scanner."""
    if argv and argv[0] not in known and argv[0] not in _PASSTHROUGH:
        return ["scan", *argv]
    return list(argv)


def main():
    """Console entry point: the unified `credence` group with a default `scan` command."""
    from .cli_advanced import cli as cli_group  # lazy import → no import cycle
    # Deprecation notice when invoked via the legacy `gitexpose` alias (kept one
    # release). prog_name stays `credence` so help/usage shows the new command.
    invoked = os.path.basename(sys.argv[0]) if sys.argv else ""
    if invoked == "gitexpose":
        print(
            "⚠  `gitexpose` is deprecated and will be removed in the next release — "
            "use `credence` instead (same commands).",
            file=sys.stderr,
        )
    known = set(cli_group.commands)
    cli_group.main(args=_route_argv(sys.argv[1:], known), prog_name="credence")


if __name__ == "__main__":
    main()

