from __future__ import annotations

from arenyxa.console_io import console_write

import argparse
import json
import sys
from pathlib import Path

from arenyxa.application.command_runtime import ArenyxaCommandRuntime, CommandRuntimeError
from arenyxa.application.headless_developer_access import HeadlessDeveloperCredential, login_headless
from arenyxa.bootstrap import bootstrap


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="arenyxa-cli", description="Arenyxa Terminal-First Professional Control Plane")
    parser.add_argument("--data-dir", type=Path, default=None)
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument("--developer-bundle", type=Path, default=None, help="signed .aryxdev bundle for headless CI authentication")
    parser.add_argument("--developer-vault", type=Path, default=None, help="encrypted Developer private-key vault")
    parser.add_argument("--developer-passphrase-stdin", action="store_true", help="read the vault passphrase from stdin; never from argv/environment")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    command = " ".join(args.command).strip()
    if not command:
        command = "help"
    if args.json_output and "--json" not in command.split():
        command += " --json"
    context = bootstrap(data_dir=args.data_dir, start_scheduler=False)
    try:
        headless_requested = args.developer_bundle is not None or args.developer_vault is not None
        if headless_requested:
            if args.developer_bundle is None or args.developer_vault is None or not args.developer_passphrase_stdin:
                console_write(
                    "Headless Developer authentication requires --developer-bundle, --developer-vault, and --developer-passphrase-stdin.",
                    error=True,
                )
                return 3
            manager = getattr(context, "developer_access", None)
            if manager is None:
                console_write("Developer Access manager is unavailable.", error=True)
                return 3

            def passphrase_provider() -> str:
                return sys.stdin.readline().rstrip("\r\n")

            login_headless(
                manager,
                HeadlessDeveloperCredential(
                    bundle_path=args.developer_bundle,
                    vault_path=args.developer_vault,
                    passphrase_provider=passphrase_provider,
                ),
            )
        runtime = context.command_runtime or ArenyxaCommandRuntime(context)
        context.command_runtime = runtime
        try:
            result = runtime.execute(command)
        except CommandRuntimeError as exc:
            result = runtime.error_result(command, exc, json_output=args.json_output)
            text = runtime.render_error(result)
            console_write(text, error=not args.json_output)
            return int(result["exit_code"])
        console_write(runtime.render(result, force_json=args.json_output or result.get("format") == "json"))
        return int(result.get("exit_code", 0))
    finally:
        context.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
