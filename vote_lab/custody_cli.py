"""WITNESS-002 file-only witness role; run each store under its own administrator."""
import argparse
import json
from pathlib import Path
import sys

from .__main__ import read_json


def _emit(value):
    print(json.dumps(value, indent=2, allow_nan=False))


def _identity(path):
    from .records import digest
    wrapper = read_json(path)
    if not isinstance(wrapper, dict) or set(wrapper) != {"identity", "fingerprint"}:
        raise ValueError("Expected a public identity wrapper, never a private store")
    if wrapper["fingerprint"] != digest(wrapper["identity"]):
        raise ValueError("Public identity fingerprint does not match its descriptor")
    return wrapper["identity"]


def main(argv=None):
    parser = argparse.ArgumentParser(description="WITNESS-002 experimental witness; no real custody certification")
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Generate this witness's key locally; never transfer its store")
    init.add_argument("--store", type=Path, required=True)
    init.add_argument("--observer-id", choices=("observer-1", "observer-2"), required=True)
    for name in ("identity", "trust", "observe", "export"):
        command = commands.add_parser(name)
        command.add_argument("--store", type=Path, required=True)
        if name == "observe":
            command.add_argument("--record", type=Path, required=True)
            command.add_argument("--refresh", action="store_true", help="Refresh the SAME frozen closed archive only")
        if name == "export":
            command.add_argument("--out", type=Path, required=True)
    pin = commands.add_parser("pin", help="Check fingerprints independently compared over an authentic channel")
    pin.add_argument("--store", type=Path, required=True)
    pin.add_argument("--anchor", type=Path, required=True)
    pin.add_argument("--identity-a", type=Path, required=True)
    pin.add_argument("--identity-b", type=Path, required=True)
    pin.add_argument("--anchor-sha256", required=True)
    pin.add_argument("--identity-a-sha256", required=True)
    pin.add_argument("--identity-b-sha256", required=True)
    pin.add_argument("--single-observer", choices=("observer-1", "observer-2"), help="Explicit weaker negative-control policy")
    verify = commands.add_parser("verify", help="Offline public evidence check; missing inputs are INCONCLUSIVE")
    verify.add_argument("--publication", type=Path)
    verify.add_argument("--trust", type=Path)
    verify.add_argument("--evidence", type=Path, action="append", default=[])
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            from .custody_verify import verify_custody
            if args.publication is None:
                raise ValueError("Publication input is missing")
            result = verify_custody(read_json(args.publication),
                                    read_json(args.trust) if args.trust else None,
                                    [read_json(path) for path in args.evidence])
            _emit(result)
            return {"PASS": 0, "FAIL": 1, "INCONCLUSIVE": 3}[result["status"]]
        from .custody import (export_evidence, export_trust, init_witness,
                              observe, pin_trust, public_identity)
        if args.command == "init":
            _emit(init_witness(args.store, args.observer_id))
        elif args.command == "identity":
            _emit(public_identity(args.store))
        elif args.command == "trust":
            _emit(export_trust(args.store))
        elif args.command == "pin":
            identities = {identity["observer_id"]: identity for identity in
                          (_identity(args.identity_a), _identity(args.identity_b))}
            result = pin_trust(args.store, read_json(args.anchor), identities,
                               args.anchor_sha256,
                               {"observer-1": args.identity_a_sha256, "observer-2": args.identity_b_sha256},
                               [args.single_observer] if args.single_observer else None)
            _emit(result)
        elif args.command == "observe":
            result = observe(args.store, read_json(args.record), refresh=args.refresh)
            result["real_custody_status"] = "INCONCLUSIVE"
            _emit(result)
            return 0 if result["status"] == "PASS" else 1
        elif args.command == "export":
            result = export_evidence(args.store)
            with args.out.open("x", encoding="utf-8") as stream:
                json.dump(result, stream, indent=2, allow_nan=False)
                stream.write("\n")
            _emit({"export": str(args.out), "real_custody_status": "INCONCLUSIVE"})
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        status = "INCONCLUSIVE" if args.command == "verify" else "FAIL"
        _emit({"status": status, "detection": "INCONCLUSIVE", "crypto_valid": None,
               "real_custody_status": "INCONCLUSIVE", "errors": [str(exc)],
               "scope": "Input/setup failure; no authentic observation or real custody conclusion established"})
        return 3 if status == "INCONCLUSIVE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
