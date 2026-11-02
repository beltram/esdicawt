#!/usr/bin/env python3
"""Runs the interop test cases of draft-ietf-spice-sd-cwt/interop for every Issuer x Holder x Verifier available.

    interop/run_matrix.py [--impl NAME ...]

Implementations are the directories of draft-ietf-spice-sd-cwt/interop/implementations. `sd_cwt` and `sd_cwt_js` only
take part when SD_CWT_PYTHON / SD_CWT_JS_DIR are set (see `interop/setup.sh --with-others`).
Writes `results.json` and the logs of every program run to target/interop-results/{timestamp}/.
Needs `cbor2`.
"""

import argparse
import glob
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

import cbor2

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRAFT = os.path.join(ROOT, "draft-ietf-spice-sd-cwt")
HARNESS = os.path.join(DRAFT, "interop")
AEAD_CASE = os.path.join(HARNESS, "test_cases", "aead_first_disclosure")
NOW = 1725244200  # iat of the draft's examples
REDACTED_KEYS = cbor2.CBORSimpleValue(59)


def available(names):
    root = os.path.join(HARNESS, "implementations")
    env = {"sd_cwt": "SD_CWT_PYTHON", "sd_cwt_js": "SD_CWT_JS_DIR"}
    found = []
    for name in sorted(names or os.listdir(root)):
        if name in env and not os.environ.get(env[name]):
            print(f"skipping {name}: {env[name]} is not set")
            continue
        roles = {r for r in ("issue", "present", "verify") if os.access(os.path.join(root, name, r), os.X_OK)}
        # INTEROP.md requires a `target` program, placeholders like `dumb` have none
        if not os.access(os.path.join(root, name, "target"), os.X_OK):
            print(f"skipping {name}: no target program")
        elif roles:
            found.append((name, roles))
    return found


class Run:
    def __init__(self, out):
        self.out = out
        self.results = []

    def exe(self, impl, role, args, stdin, label, cwd=AEAD_CASE):
        exe = os.path.join(HARNESS, "implementations", impl, role)
        log = os.path.join(self.out, f"{label}.log")
        with open(log, "w") as f:
            f.write(f"$ {role} {' '.join(args)}\n")
            f.flush()
            p = subprocess.run([exe, *args], input=stdin, stdout=subprocess.PIPE, stderr=f, cwd=cwd, timeout=60)
        if p.stdout:
            open(os.path.join(self.out, f"{label}.out.cbor"), "wb").write(p.stdout)
        return p.returncode, p.stdout, open(log).read()

    def record(self, case, combo, check, ok, detail=""):
        self.results.append({"case": case, "combo": combo, "check": check, "ok": bool(ok), "detail": detail})
        print(f"  {'PASS' if ok else 'FAIL'} {case:<28} {combo:<44} {check} {detail if not ok else ''}")


def claims_of(stdout):
    try:
        return cbor2.loads(stdout)
    except Exception:
        return None


def leftover_tags(value, path="payload"):
    """Pre-issuance tags (58, 62) that must not survive issuance"""
    found = []
    if isinstance(value, cbor2.CBORTag):
        if value.tag in (58, 62):
            found.append(f"{path}: {value.tag}({value.value!r})")
        found += leftover_tags(value.value, path)
    elif isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, cbor2.CBORTag) and k.tag in (58, 62):
                found.append(f"{path}: key {k.tag}({k.value!r})")
            found += leftover_tags(v, f"{path}/{k}")
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            found += leftover_tags(v, f"{path}/{i}")
    return found


def draft_claims():
    """The pre-issuance claims set of the draft's worked example (issuer_cwt.cbor)"""
    holder = cbor2.loads(open(os.path.join(DRAFT, "examples", "issuer_cwt.cbor"), "rb").read()).value
    payload = cbor2.loads(holder[2])
    T = cbor2.CBORTag
    return cbor2.dumps({
        1: "https://issuer.example",
        2: "https://holder.example",
        4: payload[4], 5: payload[5], 6: payload[6],
        8: payload[8],
        500: True,
        T(58, 501): "ABCD-123456",
        502: [T(58, 1549560720), T(58, 1612560720), 1674004740],
        503: {"country": "us", T(58, "region"): "ca", T(58, "postal_code"): "94188"},
    })


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--impl", action="append")
    impls = available(ap.parse_args().impl)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    out = os.path.join(ROOT, "target", "interop-results", stamp)
    os.makedirs(out, exist_ok=True)
    run = Run(out)
    names = [n for n, _ in impls]
    issuers = [n for n, r in impls if "issue" in r]
    holders = [n for n, r in impls if "present" in r]
    verifiers = [n for n, r in impls if "verify" in r]
    print(f"issuers {issuers}, holders {holders}, verifiers {verifiers}")
    examples = os.path.join(DRAFT, "examples")

    # 1. the draft's own presentations, for every Verifier
    for v in verifiers:
        for case, kbt, expect in [
            ("draft_kbt", "kbt.cbor", {501: "ABCD-123456"}),
            ("draft_nested_kbt", "nested_kbt.cbor", {}),
        ]:
            code, stdout, log = run.exe(v, "verify", ["--issuer", "issuer_pub.pem"], open(os.path.join(examples, kbt), "rb").read(), f"{case}-V={v}")
            claims = claims_of(stdout)
            run.record(case, f"I=draft_H=draft_V={v}", "verify succeeds", code == 0, f"exit {code}: {log.strip().splitlines()[-1]}")
            if code == 0:
                ok = claims is not None and all(claims.get(k) == val for k, val in expect.items())
                run.record(case, f"I=draft_H=draft_V={v}", "disclosed claims are output", ok, repr(claims)[:200])
                if case == "draft_kbt":
                    ok = claims is not None and claims.get(503, {}).get("region") == "ca" and "postal_code" not in claims.get(503, {})
                    run.record(case, f"I=draft_H=draft_V={v}", "only presented claims are output", ok, repr(claims)[:200])

        # negative checks
        kbt = open(os.path.join(examples, "kbt.cbor"), "rb").read()
        code, _, log = run.exe(v, "verify", ["--issuer", "issuer_pub.pem", "--audience", "https://other.example"], kbt, f"negative_audience-V={v}")
        run.record("negative", f"I=draft_H=draft_V={v}", "rejects a wrong --audience", code != 0, f"exit {code}")
        code, _, log = run.exe(v, "verify", ["--issuer", "issuer_pub.pem", "--time", str(NOW + 10 * 86400)], kbt, f"negative_expired-V={v}")
        run.record("negative", f"I=draft_H=draft_V={v}", "rejects an expired SD-CWT (--time)", code != 0, f"exit {code}")
        tampered = bytearray(kbt)
        tampered[-1] ^= 1
        code, _, log = run.exe(v, "verify", ["--issuer", "issuer_pub.pem"], bytes(tampered), f"negative_signature-V={v}")
        run.record("negative", f"I=draft_H=draft_V={v}", "rejects a tampered SD-KBT signature", code != 0, f"exit {code}")

    # 2. presenting the draft's issued SD-CWT, for every Holder x Verifier
    issued = open(os.path.join(AEAD_CASE, "issued.cbor"), "rb").read()
    for h in holders:
        args = ["holder_priv.pem", "--issuer", "issuer_pub.pem", "--disclosure_list", "disclosure_list.cbor"]
        code, kbt, log = run.exe(h, "present", args, issued, f"draft_present-H={h}")
        run.record("draft_present", f"I=draft_H={h}", "present succeeds", code == 0, f"exit {code}: {log.strip().splitlines()[-1]}")
        if code != 0:
            continue
        for v in verifiers:
            combo = f"I=draft_H={h}_V={v}"
            code, stdout, log = run.exe(v, "verify", ["--issuer", "issuer_pub.pem"], kbt, f"draft_present-H={h}_V={v}")
            run.record("draft_present", combo, "verify succeeds", code == 0, f"exit {code}: {log.strip().splitlines()[-1]}")
            claims = claims_of(stdout) if code == 0 else None
            if claims is not None:
                ok = claims.get(503, {}).get("region") == "ca" and 501 not in claims and 1549560720 in claims.get(502, [])
                run.record("draft_present", combo, "exactly the presented claims", ok, repr(claims)[:200])

    # 3. issuing the draft's claims set with its salts, then presenting and verifying it
    claims = draft_claims()
    nonces = os.path.join(out, "draft_nonces.csv")
    with open(nonces, "w") as f:
        f.write(open(os.path.join(examples, "salt_list.csv")).read().strip() + "\n")
        f.write(open(os.path.join(examples, "decoy_list.csv")).read())
    for i in issuers:
        args = [os.path.join(DRAFT, "issuer_privkey.pem"), "--nonces", nonces, "--time", str(NOW)]
        code, sd_cwt, log = run.exe(i, "issue", args, claims, f"draft_issue-I={i}", cwd=out)
        run.record("draft_issue", f"I={i}", "issue succeeds", code == 0, f"exit {code}: {log.strip().splitlines()[-1]}")
        if code != 0:
            continue
        run.record("draft_issue", f"I={i}", "with the draft's salts, equals issuer_cwt.cbor", sd_cwt == issued)
        run.record("draft_issue", f"I={i}", "writes nonce_list.out", os.path.exists(os.path.join(out, "nonce_list.out")))
        for h in holders:
            code, kbt, log = run.exe(h, "present", ["holder_priv.pem", "--issuer", "issuer_pub.pem", "--disclose_all"], sd_cwt, f"draft_issue-I={i}_H={h}")
            run.record("draft_issue", f"I={i}_H={h}", "present --disclose_all succeeds", code == 0, f"exit {code}: {log.strip().splitlines()[-1]}")
            if code != 0:
                continue
            for v in verifiers:
                combo = f"I={i}_H={h}_V={v}"
                code, stdout, log = run.exe(v, "verify", ["--issuer", "issuer_pub.pem"], kbt, f"draft_issue-I={i}_H={h}_V={v}")
                run.record("draft_issue", combo, "verify succeeds", code == 0, f"exit {code}: {log.strip().splitlines()[-1]}")
                c = claims_of(stdout) if code == 0 else None
                if c is not None:
                    ok = c.get(501) == "ABCD-123456" and c.get(503, {}).get("postal_code") == "94188" and len(c.get(502, [])) == 3
                    run.record("draft_issue", combo, "all claims disclosed", ok, repr(c)[:200])

    # 4. shipping_manifest4 (runone.py's case): issuance only, the case has no Holder private key
    case_dir = os.path.join(HARNESS, "test_cases", "shipping_manifest4")
    for i in issuers:
        orig = open(os.path.join(case_dir, "origclaims.cbor"), "rb").read()
        code, sd_cwt, log = run.exe(i, "issue", [os.path.join(case_dir, "issuer_priv.pem")], orig, f"shipping_manifest4-I={i}", cwd=out)
        run.record("shipping_manifest4", f"I={i}", "issue succeeds", code == 0, f"exit {code}: {log.strip().splitlines()[-1]}")
        if code != 0:
            continue
        token = cbor2.loads(sd_cwt).value
        disclosures = [cbor2.loads(d) for d in token[1].get(17, [])]
        left = leftover_tags(cbor2.loads(token[2])) + sum((leftover_tags(d, "disclosure") for d in disclosures), [])
        run.record("shipping_manifest4", f"I={i}", "no To Be Redacted / To Be Decoy tag left in the SD-CWT", not left, "; ".join(left))
        cnf = cbor2.loads(token[2]).get(8, {}).get(1, {})
        valid_cnf = (cnf.get(1) == 1 and cnf.get(-1) in (6, 7)) or (cnf.get(1) == 2 and cnf.get(-1) in (1, 2, 3) and -3 in cnf)
        run.record("shipping_manifest4", f"I={i}", "does not issue with an invalid cnf COSE_Key", valid_cnf, f"issued with cnf {cnf}")

    # 5. AEAD encrypted disclosures, the harness's own runner
    if holders and verifiers:
        p = subprocess.run([sys.executable, os.path.join(HARNESS, "run_aead.py"), *sum((["--impl", n] for n in names if n in holders and n in verifiers), [])],
                           capture_output=True, text=True)
        open(os.path.join(out, "run_aead.txt"), "w").write(p.stdout + p.stderr)
        latest = {}
        for d in glob.glob(os.path.join(HARNESS, "tests", "I=draft_H=*_V=*", "*")):
            combo = os.path.basename(os.path.dirname(d))
            latest[combo] = max(latest.get(combo, ""), d)
        for combo, d in sorted(latest.items()):
            if not any(f"H={h}_V={v}" in combo for h in names for v in names):
                continue
            csv = os.path.join(d, "results.csv")
            logs = {os.path.basename(l): open(l).read().strip() for l in glob.glob(os.path.join(d, "*.log"))}
            if os.path.exists(csv):
                for row in open(csv).read().splitlines():
                    # the check names contain commas ("verify without key passes, 501 withheld"), the status does not
                    check, status, detail = re.fullmatch(r"(.*),(pass|fail),(.*)", row).groups()
                    run.record("aead_first_disclosure", combo, check, status == "pass", detail)
            else:
                # run_aead.py stops before writing results.csv when present fails
                log = logs.get("aead_first_disclosure-present.log", "")
                run.record("aead_first_disclosure", combo, "present", False, log.splitlines()[-1] if log else "")

    json.dump(run.results, open(os.path.join(out, "results.json"), "w"), indent=2)
    failed = [r for r in run.results if not r["ok"]]
    print(f"\n{len(run.results) - len(failed)}/{len(run.results)} checks passed, results in {out}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
