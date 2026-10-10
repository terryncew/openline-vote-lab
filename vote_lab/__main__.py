import argparse
import json
from pathlib import Path
import sys


def read_json(path):
    def unique_keys(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("Duplicate JSON field: " + key)
            obj[key] = value
        return obj
    with Path(path).open("rb") as stream:
        raw = stream.read(20 * 1024 * 1024 + 1)
    if len(raw) > 20 * 1024 * 1024:
        raise ValueError("Artifact exceeds the 20 MiB research-demo limit")
    return json.loads(raw, object_pairs_hook=unique_keys, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON value")))


def main(argv=None):
    parser = argparse.ArgumentParser(description="OpenLine Vote Lab: synthetic, fictional, nonbinding research only")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="Run the local experimental browser demo")
    serve.add_argument("--port", type=int, default=8000)
    demo = sub.add_parser("demo", help="Generate 100 synthetic ballots and public verification artifacts")
    demo.add_argument("--out", type=Path, default=Path("artifacts/baseline"))
    demo.add_argument("--mode", choices=["baseline", "receiver"], default="baseline")
    demo.add_argument("--adversarial", action="store_true")
    verify = sub.add_parser("verify", help="Verify public artifacts offline with no simulation secrets")
    verify.add_argument("--record", required=True, type=Path)
    verify.add_argument("--anchor", required=True, type=Path)
    verify.add_argument("--checkpoint", type=Path)
    verify.add_argument("--receipts", type=Path)
    verify.add_argument("--archive-only", action="store_true", help="Check tally validity only; no completeness claim")
    witness = sub.add_parser("witness-demo", help="Run the bounded WITNESS-001 matched custody experiment offline")
    witness.add_argument("--out", required=True, type=Path)
    witness.add_argument("--export-case", default="rewrite-history", help="Export one scenario only; do not publish adjacent subset plaintext tallies")
    witness_verify = sub.add_parser("witness-verify", help="Verify WITNESS-001 exported evidence offline")
    witness_verify.add_argument("--publication", required=True, type=Path)
    witness_verify.add_argument("--trust", type=Path, help="Separately pinned observer keys and election anchor")
    witness_verify.add_argument("--retained", type=Path, help="Externally retained observer histories and latest heads")
    args = parser.parse_args(argv)
    try:
        if args.command == "witness-verify":
            from .witness_verify import verify_witness
            result = verify_witness(read_json(args.publication), read_json(args.trust) if args.trust else None,
                                    read_json(args.retained) if args.retained else None)
            print(json.dumps(result, indent=2))
            return {"NOT DETECTED": 0, "DETECTED": 1, "INCONCLUSIVE": 3}[result["status"]]
        if args.command == "witness-demo":
            from .witness import ATTACKS as WITNESS_ATTACKS, CONTROLS, WitnessExperiment, format_matrix
            if args.export_case not in WITNESS_ATTACKS and args.export_case not in CONTROLS:
                parser.error("Unknown WITNESS-001 --export-case")
            if args.out.exists():
                raise ValueError("Use a new output directory; existing evidence is never overwritten")
            print("WITNESS-001:100 synthetic voters; all role isolation is simulated. No paid services.", file=sys.stderr)
            experiment = WitnessExperiment()
            result = experiment.run()
            experiment.export(args.out, scenario=args.export_case, results=result)
            print(format_matrix(result))
            print(f"Evidence exported to {args.out}; actual verdicts and trust assumptions in results.json")
            return 0
        if args.command == "serve":
            from .server import create_app
            print("EXPERIMENTAL: 100 synthetic voters only. All simulated role keys share one process.")
            create_app().run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False)
            return 0
        if args.command == "verify":
            from .verification import verify_record
            if not args.checkpoint and not args.archive_only:
                parser.error("verify requires an independently retained --checkpoint, or explicit --archive-only")
            result = verify_record(read_json(args.record), read_json(args.anchor),
                                   read_json(args.checkpoint) if args.checkpoint else None,
                                   read_json(args.receipts) if args.receipts else None,
                                   require_checkpoint=not args.archive_only)
            print(json.dumps(result, indent=2))
            return 0 if result["ok"] else 1
        from .model import ATTACKS, Simulation
        for name in ["anchor", "record", "checkpoint", "receipts"] + (["attacks"] if args.adversarial else []):
            if (args.out / (name + ".json")).exists():
                raise ValueError(f"Refusing to overwrite {args.out / (name + '.json')}; choose a new --out directory")
        sim = Simulation(args.mode)
        print("Encrypting 100 fictional ballots with ElectionGuard; no external services used.", file=sys.stderr)
        sim.simulate()
        sim.seal()
        args.out.mkdir(parents=True, exist_ok=True)
        for name, artifact in [("anchor", sim.anchor), ("record", sim.record), ("checkpoint", sim.checkpoint), ("receipts", sim.receipts())]:
            target = args.out / (name + ".json")
            if target.exists():
                raise ValueError(f"Refusing to overwrite {target}; choose a new --out directory")
            target.write_text(json.dumps(artifact, indent=2) + "\n")
        result = sim.verify()
        if args.adversarial:
            attacks = [sim.attack(attack) for attack in ATTACKS]
            (args.out / "attacks.json").write_text(json.dumps(attacks, indent=2) + "\n")
            result["attacks_detected"] = sum(a["detected"] for a in attacks)
            if not all(a["detected"] for a in attacks):
                result["ok"] = False
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 1
    except (ValueError, OSError, TypeError) as exc:
        print(json.dumps({"ok": False, "errors": [str(exc)]}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
