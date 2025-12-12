#!/usr/bin/env python3
"""
WireGuard Config Wizard

A tool to generate WireGuard configuration files from a YAML definition.

Usage:
    python main.py <config.yaml> [--output <dir>]
"""

import argparse
import sys
from pathlib import Path

from generator import ConfigGenerator


def main():
    parser = argparse.ArgumentParser(
        description="Generate WireGuard configurations from YAML",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
    python main.py config.yaml
    python main.py config.yaml --output ./my-configs
        """
    )
    parser.add_argument(
        "config",
        type=str,
        help="Path to YAML configuration file"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default="output",
        help="Output directory (default: ./output)"
    )

    args = parser.parse_args()

    # Validate config file exists
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Error: Configuration file not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    # Check wg command is available
    import shutil
    if not shutil.which("wg"):
        print("Error: 'wg' command not found. Please install WireGuard tools.", file=sys.stderr)
        print("  Ubuntu/Debian: sudo apt install wireguard-tools", file=sys.stderr)
        print("  macOS: brew install wireguard-tools", file=sys.stderr)
        sys.exit(1)

    # Generate configurations
    try:
        generator = ConfigGenerator(str(config_path))
        generator.generate(args.output)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
