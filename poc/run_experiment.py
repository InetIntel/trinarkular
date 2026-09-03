#!/usr/bin/env python3
"""Repeated ICMP and TCP/443 reachability rounds over a fixed set of /24s.

Each round sweeps every address in every target /24 twice: once with ZMap's
icmp_echoscan probe module, once with tcp_synscan on port 443. Both scans are
single-packet and stateless, following ZMap's default probing strategy
(Durumeric et al., USENIX Security 2013), which reaches ~97.9% of live hosts
with one packet per target.

Raw per-round responder lists and a machine-readable round log are written
under poc/results/<run-id>/ for later analysis by analyze.py.
"""

import argparse
import ipaddress
import json
import os
import random
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results"

# ZMap's measured SYN-ACK tail: 99% of responses arrive within ~1s and 99.9%
# within 8.16s, which is why ZMap itself waits a fixed 8s after the last probe.
# Anything tighter manufactures apparent instability.
MIN_COOLDOWN_SECONDS = 10

SCANS = (
    # (label, zmap probe module, extra args)
    ("icmp", "icmp_echoscan", []),
    ("tcp443", "tcp_synscan", ["--target-ports=443"]),
)

# sudo resets PATH to a secure default that omits Homebrew, so the zmap
# location is resolved explicitly rather than left to the environment.
ZMAP_FALLBACKS = ("/opt/homebrew/sbin/zmap", "/usr/local/sbin/zmap",
                  "/opt/homebrew/bin/zmap", "/usr/local/bin/zmap")


def find_zmap(explicit=None):
    if explicit:
        return explicit
    found = shutil.which("zmap")
    if found:
        return found
    for candidate in ZMAP_FALLBACKS:
        if os.access(candidate, os.X_OK):
            return candidate
    return None


def utc_now():
    return datetime.now(timezone.utc)


def stamp(dt):
    return dt.strftime("%Y%m%dT%H%M%SZ")


def load_targets(path):
    with open(path) as handle:
        blob = json.load(handle)
    networks = []
    for entry in blob["networks"]:
        net = ipaddress.ip_network(entry, strict=True)
        if net.version != 4 or net.prefixlen != 24:
            raise SystemExit(f"target {entry} is not an IPv4 /24")
        if not net.is_global:
            raise SystemExit(f"target {entry} is not globally routable")
        networks.append(net)
    if len(set(networks)) != len(networks):
        raise SystemExit("duplicate networks in target file")
    return blob, networks


def run_zmap(zmap, module, extra, allowlist, out_file, rate, cooldown, iface,
             seed, dry_run):
    cmd = [
        zmap,
        f"--probe-module={module}",
        f"--allowlist-file={allowlist}",
        f"--output-file={out_file}",
        "--output-module=csv",
        "--output-fields=saddr",
        "--output-filter=success=1 && repeat=0",
        "--no-header-row",
        f"--rate={rate}",
        f"--cooldown-time={cooldown}",
        f"--seed={seed}",
        "--sender-threads=1",
        "--verbosity=3",
    ]
    if iface:
        cmd.append(f"--interface={iface}")
    cmd.extend(extra)
    if dry_run:
        cmd.append("--dryrun")

    started = utc_now()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    ended = utc_now()

    record = {
        "command": cmd,
        "started": started.isoformat(),
        "ended": ended.isoformat(),
        "duration_s": round((ended - started).total_seconds(), 3),
        "returncode": proc.returncode,
        "stderr_tail": proc.stderr.strip().splitlines()[-15:],
    }
    return record


def read_responders(path):
    if not path.exists():
        return []
    seen = []
    with open(path) as handle:
        for line in handle:
            addr = line.strip()
            if addr:
                seen.append(addr)
    return sorted(set(seen), key=lambda a: int(ipaddress.ip_address(a)))


def restore_ownership(root):
    """If running under sudo, hand the output back to the invoking user."""
    uid = os.environ.get("SUDO_UID")
    gid = os.environ.get("SUDO_GID")
    if not uid or not gid:
        return
    uid, gid = int(uid), int(gid)
    for path in [root, *root.rglob("*")]:
        try:
            os.chown(path, uid, gid)
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--targets", default=str(HERE / "targets.json"))
    parser.add_argument("--rounds", type=int, default=12,
                        help="number of measurement rounds (default: 12)")
    parser.add_argument("--interval", type=int, default=300,
                        help="seconds between round starts (default: 300)")
    parser.add_argument("--rate", type=int, default=500,
                        help="probe packets per second (default: 500)")
    parser.add_argument("--cooldown", type=int, default=MIN_COOLDOWN_SECONDS,
                        help="seconds to wait for late responses "
                             f"(default: {MIN_COOLDOWN_SECONDS})")
    parser.add_argument("--interface", default=None,
                        help="network interface for zmap (default: zmap picks)")
    parser.add_argument("--run-id", default=None,
                        help="output directory name (default: timestamp)")
    parser.add_argument("--dry-run", action="store_true",
                        help="pass --dryrun to zmap; no packets are sent")
    parser.add_argument("--zmap", default=None,
                        help="path to the zmap binary (default: autodetect)")
    args = parser.parse_args()

    if args.cooldown < MIN_COOLDOWN_SECONDS:
        parser.error(f"--cooldown must be at least {MIN_COOLDOWN_SECONDS}s "
                     "to cover ZMap's measured response tail")
    zmap = find_zmap(args.zmap)
    if zmap is None:
        parser.error("could not locate the zmap binary; pass --zmap")

    targets_meta, networks = load_targets(args.targets)
    address_cnt = sum(net.num_addresses for net in networks)

    run_id = args.run_id or ("dryrun-" if args.dry_run else "") + stamp(utc_now())
    out_root = RESULTS / run_id
    out_root.mkdir(parents=True, exist_ok=True)
    rounds_dir = out_root / "rounds"
    rounds_dir.mkdir(exist_ok=True)

    allowlist = out_root / "allowlist.txt"
    allowlist.write_text("".join(f"{net}\n" for net in networks))

    manifest = {
        "run_id": run_id,
        "started": utc_now().isoformat(),
        "targets_file": str(args.targets),
        "targets_meta": {k: v for k, v in targets_meta.items()
                         if k != "networks"},
        "networks": [str(n) for n in networks],
        "network_cnt": len(networks),
        "addresses_per_round": address_cnt * len(SCANS),
        "rounds_planned": args.rounds,
        "interval_s": args.interval,
        "rate_pps": args.rate,
        "cooldown_s": args.cooldown,
        "interface": args.interface,
        "dry_run": args.dry_run,
        "scans": [label for label, _, _ in SCANS],
        "zmap_path": zmap,
        "zmap_version": subprocess.run(
            [zmap, "--version"], capture_output=True, text=True
        ).stdout.strip().splitlines()[-1],
    }
    (out_root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    print(f"run id      : {run_id}")
    print(f"networks    : {len(networks)} /24s ({address_cnt} addresses)")
    print(f"rounds      : {args.rounds} every {args.interval}s "
          f"(~{args.rounds * args.interval / 60:.0f} min)")
    print(f"probe budget: {address_cnt * len(SCANS) * args.rounds} packets total")
    print(f"output      : {out_root}")
    if args.dry_run:
        print("MODE        : dry run, zmap will not send packets")
    print()

    origin = time.time()
    for rnd in range(args.rounds):
        target_time = origin + rnd * args.interval
        delay = target_time - time.time()
        if delay > 0:
            time.sleep(delay)

        round_start = utc_now()
        round_rec = {
            "round": rnd,
            "started": round_start.isoformat(),
            "scans": {},
        }
        print(f"[round {rnd + 1}/{args.rounds}] {stamp(round_start)}", flush=True)

        for label, module, extra in SCANS:
            out_file = rounds_dir / f"round{rnd:02d}_{label}.csv"
            seed = random.getrandbits(48)
            try:
                rec = run_zmap(zmap, module, extra, allowlist, out_file,
                               args.rate, args.cooldown, args.interface, seed,
                               args.dry_run)
            except subprocess.TimeoutExpired:
                rec = {"error": "zmap timed out", "returncode": None}
            responders = read_responders(out_file)
            rec["seed"] = seed
            rec["responder_cnt"] = len(responders)
            rec["output_file"] = out_file.name
            round_rec["scans"][label] = rec
            status = "ok" if rec.get("returncode") == 0 else "FAILED"
            print(f"  {label:7s} {status:6s} responders={len(responders)}",
                  flush=True)

        round_rec["ended"] = utc_now().isoformat()
        with open(out_root / "rounds.jsonl", "a") as handle:
            handle.write(json.dumps(round_rec) + "\n")

    (out_root / "manifest.json").write_text(
        json.dumps({**manifest, "finished": utc_now().isoformat()}, indent=2)
        + "\n"
    )
    restore_ownership(out_root)
    print(f"\ndone. results in {out_root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
