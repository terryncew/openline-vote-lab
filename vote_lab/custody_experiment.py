"""Local WITNESS-002 apparatus test, explicitly NOT an independent custody test.

The harness invokes separately operable role CLIs but owns the same UID and
storage as every role. It never exports or reads honest witness private keys.
The deliberate one-witness compromise runs inside that witness's role. None
of this creates an independently administered environment.
"""
import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import platform
import pwd
import subprocess
import sys

from .custody_operator import OperatorFixture, make_publication
from .custody_verify import verify_custody
from .records import digest, public_key, sign

EXPECTED = {
    "honest": "PASS", "delete-accepted": "FAIL", "alter-ballot": "FAIL",
    "replace-ballot": "FAIL", "rewrite-history": "FAIL", "conflicting-histories": "FAIL",
    "forge-checkpoint": "FAIL", "replay-checkpoint": "FAIL", "rollback-checkpoint": "FAIL",
    "suppression-before-observation": "PASS", "observer-lost": "FAIL",
    "observer-unavailable": "INCONCLUSIVE", "observer-compromised": "FAIL",
    "compromised-survivor-only": "INCONCLUSIVE", "idempotent-replay": "PASS",
    "isolated-equivocation": "PASS", "all-observers-lost": "INCONCLUSIVE",
    "missing-trust": "INCONCLUSIVE", "missing-identity-pin": "INCONCLUSIVE",
    "invalid-signature": "FAIL",
}


def _write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def _role(*arguments, expected=0):
    run = subprocess.run([sys.executable, "-m", "vote_lab.custody_cli", *map(str, arguments)],
                         capture_output=True, text=True, timeout=90)
    if run.returncode != expected:
        raise ValueError("Witness role failed: " + run.stdout + run.stderr)
    return json.loads(run.stdout)


def _join(evidence):
    return {"schema": "witness-001/retained/v1",
            "histories": {o: h for artifact in evidence for o, h in artifact["histories"].items()},
            "heads": {o: h for artifact in evidence for o, h in artifact["heads"].items()}}


class CustodyExperiment:
    def __init__(self, directory, *, fixture=None):
        self.root = Path(directory).resolve()
        if self.root.exists():
            raise ValueError("Use a fresh output directory; existing evidence is never overwritten")
        self.root.mkdir(parents=True, mode=0o700)
        os.chmod(self.root, 0o700)
        self.fixture = fixture if fixture is not None else OperatorFixture()
        self.fixture.export(self.root / "operator")
        self._pairs = {}
        self.normal = self._pair("normal", [self.fixture.original, self.fixture.original], refresh=True)

    def _pair(self, name, records, *, refresh=False):
        if name in self._pairs:
            return self._pairs[name]
        work = self.root / "local-role-stores" / name
        work.mkdir(parents=True)
        stores, identities = {}, {}
        for number in (1, 2):
            observer = f"observer-{number}"
            store = work / observer
            wrapper = _role("init", "--store", store, "--observer-id", observer)
            stores[observer], identities[observer] = store, wrapper
            _write(work / f"{observer}-identity.json", wrapper)
        anchor = self.root / "operator/anchor.json"
        evidence, first = [], []
        trust = None
        for number, record in enumerate(records, 1):
            observer = f"observer-{number}"
            store = stores[observer]
            trust = _role("pin", "--store", store, "--anchor", anchor,
                          "--identity-a", work / "observer-1-identity.json",
                          "--identity-b", work / "observer-2-identity.json",
                          "--anchor-sha256", digest(self.fixture.anchor),
                          "--identity-a-sha256", identities["observer-1"]["fingerprint"],
                          "--identity-b-sha256", identities["observer-2"]["fingerprint"])
            record_path = work / f"{observer}-private-test-input.json"
            _write(record_path, record)
            _role("observe", "--store", store, "--record", record_path)
            first_path = work / f"{observer}-first-evidence.json"
            _role("export", "--store", store, "--out", first_path)
            first.append(json.loads(first_path.read_text()))
            if refresh:
                _role("observe", "--store", store, "--record", record_path, "--refresh")
            latest_path = work / f"{observer}-current-evidence.json"
            _role("export", "--store", store, "--out", latest_path)
            evidence.append(json.loads(latest_path.read_text()))
            # No secure-erasure claim. These were private synthetic role inputs,
            # not a public feed containing adjacent plaintext subset tallies.
            record_path.unlink()
        pair = {"stores": stores, "identities": identities, "trust": trust,
                "evidence": evidence, "first": first,
                "keys": {o: value["identity"]["public_key"] for o, value in identities.items()}}
        self._pairs[name] = pair
        return pair

    def _compromised_export(self):
        path = self.root / "local-role-stores/normal/compromised-A-private-test-input.json"
        _write(path, self.fixture.prefix)
        # Explicitly compromised Witness A authority, never the operator's
        # honest execution path. Only this child opens A's own private seed.
        code = """
import json,sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from vote_lab.records import digest,sign
store=Path(sys.argv[1]); record=json.loads(Path(sys.argv[2]).read_text())
state=json.loads((store/'state.json').read_text()); anchor=state['trust']['election_anchor']
key=Ed25519PrivateKey.from_private_bytes((store/'signing-key.bin').read_bytes())
history=[]
for sequence in (1,2):
    payload={'domain':'witness-001/checkpoint/v1','election_id':anchor['election_id'],
        'anchor_hash':digest(anchor),'observer_id':'observer-1','sequence':sequence,
        'previous_checkpoint_hash':digest(history[-1]) if history else None,
        'phase':'closed','record_hash':digest(record),'ballot_count':len(record['ballots'])}
    history.append(sign(key,payload))
print(json.dumps({'schema':'witness-001/retained/v1','histories':{'observer-1':history},
    'heads':{'observer-1':{'sequence':2,'checkpoint_hash':digest(history[-1])}}}))
"""
        run = subprocess.run([sys.executable, "-c", code,
                              str(self.normal["stores"]["observer-1"]), str(path)],
                             capture_output=True, text=True, timeout=30)
        path.unlink()
        if run.returncode:
            raise ValueError("Deliberately compromised witness fixture failed: " + run.stderr)
        return json.loads(run.stdout)

    def case(self, scenario):
        pair = self.normal
        trust = deepcopy(pair["trust"])
        evidence = deepcopy(pair["evidence"])
        record_case = "observer-compromised" if scenario == "compromised-survivor-only" else scenario
        if scenario in ("observer-unavailable", "missing-trust", "missing-identity-pin"):
            record_case = "honest"
        record = self.fixture.record_for(record_case)
        advertised = {}
        if scenario in ("conflicting-histories", "isolated-equivocation"):
            pair = self._pair("fork", [self.fixture.original, self.fixture.reordered])
            trust, evidence = deepcopy(pair["trust"]), deepcopy(pair["evidence"])
            if scenario == "isolated-equivocation":
                trust["required_observers"] = ["observer-1"]
                evidence = evidence[:1]
        elif scenario == "suppression-before-observation":
            # Alternative history: nobody in this branch observed the missing
            # ballot. The harness's attempted100 is not verifier evidence.
            pair = self._pair("unobserved-suppression", [self.fixture.prefix, self.fixture.prefix])
            trust, evidence = deepcopy(pair["trust"]), deepcopy(pair["evidence"])
        elif scenario in ("observer-lost", "observer-unavailable"):
            evidence = evidence[1:]
        elif scenario in ("observer-compromised", "compromised-survivor-only"):
            compromised = self._compromised_export()
            evidence = [compromised, evidence[1]] if scenario == "observer-compromised" else [compromised]
        elif scenario == "all-observers-lost":
            evidence = []
        elif scenario == "missing-trust":
            trust = None
        elif scenario == "missing-identity-pin":
            trust["pins"]["identity_hashes"].pop("observer-2")
        elif scenario in ("rollback-checkpoint", "replay-checkpoint"):
            advertised = deepcopy(_join(pair["first"])["histories"])
            if scenario == "replay-checkpoint":
                advertised["observer-2"] = deepcopy(pair["evidence"][1]["histories"]["observer-2"])
        elif scenario in ("idempotent-replay", "invalid-signature"):
            advertised = deepcopy(_join(evidence)["histories"])
            if scenario == "invalid-signature":
                advertised["observer-1"][-1]["signature"] = "AAAA"
        publication = make_publication(self.fixture.anchor, record, pair["keys"], advertised)
        if scenario == "forge-checkpoint":
            publication["observer_keys"]["observer-1"] = public_key(self.fixture.sim.receiver_key)
            payload = {"domain": "witness-001/checkpoint/v1", "election_id": self.fixture.anchor["election_id"],
                       "anchor_hash": digest(self.fixture.anchor), "observer_id": "observer-1", "sequence": 1,
                       "previous_checkpoint_hash": None, "phase": "closed", "record_hash": digest(record),
                       "ballot_count": len(record["ballots"])}
            publication["checkpoints"] = {"observer-1": [sign(self.fixture.sim.receiver_key, payload)]}
        return publication, trust, evidence

    def run(self):
        rows = []
        for scenario, expected in EXPECTED.items():
            publication, trust, evidence = self.case(scenario)
            result = verify_custody(publication, trust, evidence)
            absent = verify_custody(publication, trust, [])
            no_pins = verify_custody(publication, None, evidence)
            # Genuine old evidence is consistent with an old advertised head.
            old_only = None
            if scenario in ("rollback-checkpoint", "replay-checkpoint"):
                older = deepcopy(publication)
                older["checkpoints"] = deepcopy(_join(self.normal["first"])["histories"])
                old_only = verify_custody(older, trust, self.normal["first"])["status"]
            rows.append({"scenario": scenario, "expected_artifact_status": expected,
                         "test_result": "PASS" if result["status"] == expected else "FAIL",
                         "record_hash": digest(publication["record"]), **result,
                         "without_retained_evidence": absent["status"],
                         "without_trust": no_pins["status"],
                         "older_reference_only": old_only,
                         "execution_boundary": "LOCAL_SHARED_UID_ONLY"})
        frozen_before = digest(self.normal["evidence"][0])
        refusal = _role("observe", "--store", self.normal["stores"]["observer-1"],
                        "--record", self.root / "operator/selected-attack-record.json", expected=1)
        after_path = self.root / "witness-A-after-refusal.json"
        _role("export", "--store", self.normal["stores"]["observer-1"], "--out", after_path)
        unchanged = frozen_before == digest(json.loads(after_path.read_text()))
        # Actual local boundary negative control: another same-UID process can
        # rewrite state bytes despite 0700/0600. It preserves content, keys and
        # signatures, so this probe does not destroy the research artifacts.
        probe = subprocess.run([sys.executable, "-c",
            "from pathlib import Path; import os,sys; p=Path(sys.argv[1]); "
            "p.write_bytes(p.read_bytes()); print(os.getuid())",
            str(self.normal["stores"]["observer-1"] / "state.json")],
            capture_output=True, text=True, timeout=30)
        boundary_fail = probe.returncode == 0
        environment = {"platform": platform.platform(), "hostname": platform.node(),
                       "uid": os.getuid(), "gid": os.getgid(), "posix_user": pwd.getpwuid(os.getuid()).pw_name,
                       "workspace": str(Path.cwd()), "python": platform.python_version(),
                       "administrative_owner": "Not independently established; one shared execution authority",
                       "separate_administrators_available": False,
                       "third_party_reproduction": "NOT PERFORMED"}
        results = {"schema": "witness-002/local-results/v1", "experiment": "WITNESS-002",
                   "accepted_synthetic_ballots": len(self.fixture.original["ballots"]),
                   "real_custody_status": "INCONCLUSIVE", "external_test": "PENDING",
                   "environment": environment, "results": rows,
                   "witness_refusal": {"artifact_status": refusal["status"], "retained_evidence_unchanged": unchanged,
                                       "test_result": "PASS" if refusal["checkpoint"] is None and unchanged else "FAIL"},
                   "same_uid_boundary_probe": {"operator_can_rewrite_witness_store": boundary_fail,
                                               "separation_requirement": "FAIL" if boundary_fail else "INCONCLUSIVE",
                                               "scope": "Same-UID local control only; actual external boundary not tested"},
                   "key_provenance": [{"role": f"Witness {name}", "observer_id": f"observer-{number}",
                                       "generated_by": "Own init CLI process", "retained_by": "Own local store, shared UID",
                                       "fingerprint": self.normal["identities"][f"observer-{number}"]["fingerprint"],
                                       "independent_administrative_owner": "NOT ESTABLISHED"}
                                      for number, name in ((1, "A"), (2, "B"))],
                   "privacy": "No choice/opening in commitment exports. Adjacent subset tallies can reveal choices; privacy and receipt-freeness not established.",
                   "external_api_spending_usd": 0}
        _write(self.root / "results.json", results)
        publication, trust, evidence = self.case("rewrite-history")
        _write(self.root / "offline/publication.json", publication)
        _write(self.root / "offline/pinned-trust.json", trust)
        for number, artifact in enumerate(evidence, 1):
            _write(self.root / f"offline/witness-{number}-evidence.json", artifact)
        return results


def main(argv=None):
    parser = argparse.ArgumentParser(description="WITNESS-002 LOCAL apparatus test; real independent custody remains INCONCLUSIVE")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        print("LOCAL SHARED ADMINISTRATOR ONLY. No real custody PASS is possible here.", file=sys.stderr)
        results = CustodyExperiment(args.out).run()
        print("scenario                         artifact       detection       local test")
        for row in results["results"]:
            print(f"{row['scenario']:32} {row['status']:14} {row['detection']:15} {row['test_result']}")
        print("Real custody: INCONCLUSIVE; independently administered external test PENDING.")
        return 0 if all(row["test_result"] == "PASS" for row in results["results"]) and results["witness_refusal"]["test_result"] == "PASS" else 1
    except (ValueError, OSError, TypeError, KeyError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"status": "INCONCLUSIVE", "real_custody_status": "INCONCLUSIVE", "errors": [str(exc)]}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
