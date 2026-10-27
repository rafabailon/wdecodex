"""Command line interface for WDecodex."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .core import generate
from .errors import WDecodexError
from .utils import default_name, read_log, sanitize_name


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser used by the command line entry point."""

    parser = argparse.ArgumentParser(
        prog="wdecodex",
        description=(
            "Generate a baseline Wazuh decoder and rule set from sample application logs."
        ),
    )
    parser.add_argument(
        "log",
        nargs="?",
        default="-",
        help="log file to analyze, or - to read standard input (default: -)",
    )
    parser.add_argument(
        "-n",
        "--name",
        help="decoder and rule group name (default: input file stem or custom)",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default="wdecodex-output",
        help="directory for generated XML files (default: wdecodex-output)",
    )
    parser.add_argument(
        "--format",
        dest="log_format",
        choices=("auto", "json", "text", "access", "kv"),
        default="auto",
        help="force an input format instead of detecting it (default: auto)",
    )
    parser.add_argument(
        "--base-rule-id",
        type=int,
        default=100000,
        help="first custom rule ID, in the Wazuh range 100000-120000 (default: 100000)",
    )
    parser.add_argument(
        "--max-lines",
        type=int,
        default=5000,
        help="maximum number of non-empty sample lines to analyze (default: 5000)",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="print the decoder and rules to standard output instead of writing files",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line interface and return a process exit code."""

    parser = build_parser()
    args = parser.parse_args(argv)
    name = sanitize_name(args.name or default_name(args.log))

    try:
        log_text = read_log(args.log)
        artifacts = generate(
            log_text,
            name=name,
            log_format=args.log_format,
            base_rule_id=args.base_rule_id,
            max_lines=args.max_lines,
        )
    except WDecodexError as exc:
        print(f"wdecodex: error: {exc}", file=sys.stderr)
        return 2

    if args.stdout:
        sys.stdout.write(artifacts.decoder_xml)
        sys.stdout.write("\n")
        sys.stdout.write(artifacts.rules_xml)
        return 0

    output_dir = Path(args.output_dir)
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        decoder_path = output_dir / f"{name}_decoder.xml"
        rules_path = output_dir / f"{name}_rules.xml"
        decoder_path.write_text(artifacts.decoder_xml, encoding="utf-8")
        rules_path.write_text(artifacts.rules_xml, encoding="utf-8")
    except OSError as exc:
        print(f"wdecodex: error: cannot write output files: {exc}", file=sys.stderr)
        return 2

    print(
        f"Analyzed {artifacts.analysis.total_lines} log lines as {artifacts.analysis.log_format}."
    )
    print(f"Decoder: {decoder_path}")
    print(f"Rules:   {rules_path}")
    return 0
