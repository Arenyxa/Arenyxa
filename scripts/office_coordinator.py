from __future__ import annotations

import argparse
import getpass
import signal
import sys
import threading
from pathlib import Path

from arenyxa.bootstrap import bootstrap


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Arenyxa Office Enterprise Coordinator")
    value.add_argument("--data-dir", type=Path, help="Arenyxa data directory containing the Enterprise Vault")
    value.add_argument("--host", default="0.0.0.0", help="Coordinator bind address")
    value.add_argument("--port", type=int, default=0, help="Coordinator TCP port; 0 selects an available port")
    value.add_argument("--username", required=True, help="Enterprise administrator username (not a secret)")
    return value


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    context = bootstrap(args.data_dir)
    stop = threading.Event()
    try:
        enterprise = context.enterprise_identity
        coordinator = context.office_coordinator
        if enterprise is None or coordinator is None:
            raise RuntimeError("Enterprise/Coordinator services are unavailable")
        vault_passphrase = getpass.getpass("Identity Vault passphrase: ")
        enterprise.unlock(vault_passphrase)
        vault_passphrase = ""
        password = getpass.getpass("Enterprise administrator password: ")
        enterprise.login(args.username, password)
        enterprise.step_up(password)
        password = ""
        host, port = coordinator.start_tls(args.host, args.port)
                                                                                           
                                                                                           
                                                      
        try:
            enterprise.logout(reason="COORDINATOR_SERVICE_LEASE_ISSUED")
        except Exception as exc:
                                                                                               
                                                             
            print(f"Administrator session retired; logout audit warning: {exc}", file=sys.stderr)
        print(f"Arenyxa Office Coordinator listening on {host}:{port}")
        print("Trust is Enterprise-Root signed; LAN discovery is not a trust boundary.")
        print(f"Migration model: {coordinator.migration_descriptor()}")

        def request_stop(_signum, _frame):
            stop.set()

        signal.signal(signal.SIGINT, request_stop)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, request_stop)
        while not stop.wait(1.0):
            continue
        return 0
    finally:
        try:
            context.shutdown()
        except Exception as exc:
            print(f"Coordinator shutdown error: {exc}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
