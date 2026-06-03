"""Entry point: ``python -m hackberrypios``.

Default launches the Textual UI. A headless ``--cli`` mode runs a full sweep
and prints / exports a report — handy over SSH or for scripting.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __app_name__, __version__


def _cli(args: argparse.Namespace) -> int:
    from .core.state import AppState

    state = AppState()
    print(f"{__app_name__} {__version__} — headless sweep\n")

    ctx = state.refresh_netinfo()
    if not ctx.primary:
        print("No active network connection. Aborting.", file=sys.stderr)
        return 2
    print(f"Interface : {ctx.primary.name} {ctx.primary.ipv4} "
          f"({ctx.subnet})")
    print(f"Gateway   : {ctx.gateway}")
    print(f"Domain    : {state._guess_domain() or '(none)'}\n")

    print("Discovering hosts…")
    hosts = state.run_discovery()
    print(f"  {len(hosts)} host(s) found")

    if args.domain or state.domain:
        dom = args.domain or state.domain
        print(f"Checking DCs for {dom}…")
        for d in state.run_dc_check(domain=dom):
            print(f"  {d.host}: {d.health}")

    print("Surveying Wi-Fi…")
    state.run_wifi()

    print("Discovering printers…")
    state.run_printers()

    print("Scanning SMB shares…")
    state.run_shares()

    print("Testing gateway latency…")
    state.run_gateway_latency()

    assessment = state.assess()
    print(f"\nNetwork health score: {assessment.score}/100\n")
    print("Top recommendations:")
    for r in assessment.top[:15]:
        print(f"  [{r.priority.label:9}] {r.text}")

    if args.json:
        state.export_json(args.json)
        print(f"\nReport written to {args.json}")
    elif args.print_json:
        print("\n" + json.dumps(state.to_report(), indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="hackberrypios",
        description="One-stop network audit toolkit for the HackberryPi CM5.")
    parser.add_argument("--version", action="version",
                        version=f"{__app_name__} {__version__}")
    parser.add_argument("--cli", action="store_true",
                        help="run a headless full sweep instead of the UI")
    parser.add_argument("--domain", help="AD domain to check (CLI mode)")
    parser.add_argument("--json", metavar="PATH",
                        help="write JSON report to PATH (CLI mode)")
    parser.add_argument("--print-json", action="store_true",
                        help="print JSON report to stdout (CLI mode)")
    args = parser.parse_args(argv)

    if args.cli:
        return _cli(args)

    from .app import HackberryApp
    HackberryApp().run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
