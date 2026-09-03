#!/usr/bin/env python3
"""Compare ICMP-only and ICMP+TCP/443 reachability detection per /24.

Applies the metric definitions from Sethuraman, Bischof and Dainotti,
"Towards Improving Outage Detection with Multiple Probing Protocols":

  E(b)      hosts in block b that ever responded to any probe
  A(E(b))   block availability: response rate over E(b), averaged over rounds
  sparse    fewer than 15 responding hosts in a round
  reliable  non-sparse and A(E(b)) >= 0.3, the threshold at which Trinocular
            always detects an outage lasting longer than one probing round

Reports these under ICMP-only versus the ICMP+TCP union, plus per-host and
per-block stability across rounds.
"""

import argparse
import ipaddress
import json
import statistics
import subprocess
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results"

SPARSE_THRESHOLD = 15
RELIABLE_AVAILABILITY = 0.3

# trinarkular initialises per-/24 belief at 0.99 and treats a block as UP above
# 0.9 and DOWN below 0.1 (lib/trinarkular_prober.c). Its recovery-probe table is
# indexed by A(E(b))*100 and is undefined below 0.10, so blocks under that value
# cannot be recovery-probed at all.
TRINARKULAR_RECOVERY_FLOOR = 0.10


def latest_run():
    runs = sorted(
        (p for p in RESULTS.iterdir()
         if p.is_dir() and (p / "manifest.json").exists()
         and not p.name.startswith("dryrun-")),
        key=lambda p: p.name,
    )
    if not runs:
        raise SystemExit("no completed runs found under poc/results/")
    return runs[-1]


def block_of(addr):
    return str(ipaddress.ip_network(f"{addr}/24", strict=False))


def load_run(run_dir):
    manifest = json.loads((run_dir / "manifest.json").read_text())
    rounds = []
    log = run_dir / "rounds.jsonl"
    if not log.exists():
        raise SystemExit(f"{log} missing; run produced no rounds")
    for line in log.read_text().splitlines():
        if line.strip():
            rounds.append(json.loads(line))

    # per round: {scan_label: set(addresses)}
    observations = []
    for rec in rounds:
        per_scan = {}
        for label, scan in rec["scans"].items():
            path = run_dir / "rounds" / scan["output_file"]
            addrs = set()
            if path.exists():
                addrs = {ln.strip() for ln in path.read_text().splitlines()
                         if ln.strip()}
            per_scan[label] = addrs
        observations.append({
            "round": rec["round"],
            "started": rec["started"],
            "scans": per_scan,
            "ok": all(s.get("returncode") == 0 for s in rec["scans"].values()),
        })
    return manifest, observations


def availability(ever_set, per_round_sets):
    """A(E(b)): mean per-round response rate over the ever-responsive set."""
    if not ever_set:
        return 0.0
    rates = [len(responders & ever_set) / len(ever_set)
             for responders in per_round_sets]
    return statistics.fmean(rates) if rates else 0.0


def jaccard(a, b):
    if not a and not b:
        return 1.0
    if not (a | b):
        return 1.0
    return len(a & b) / len(a | b)


def whois_org(block):
    """Best-effort network operator label; never fatal."""
    try:
        out = subprocess.run(["whois", block.split("/")[0]],
                             capture_output=True, text=True, timeout=25).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    for key in ("OrgName:", "org-name:", "descr:", "Organization:", "netname:"):
        for line in out.splitlines():
            if line.strip().startswith(key):
                value = line.split(":", 1)[1].strip()
                if value:
                    return value
    return None


def analyse(manifest, observations, with_whois):
    blocks = manifest["networks"]
    n_rounds = len(observations)

    icmp_rounds = [o["scans"].get("icmp", set()) for o in observations]
    tcp_rounds = [o["scans"].get("tcp443", set()) for o in observations]
    union_rounds = [i | t for i, t in zip(icmp_rounds, tcp_rounds)]

    ever_icmp = set().union(*icmp_rounds) if icmp_rounds else set()
    ever_tcp = set().union(*tcp_rounds) if tcp_rounds else set()
    ever_union = ever_icmp | ever_tcp

    host_view = {
        "icmp_only": sorted(ever_icmp - ever_tcp, key=lambda a: int(ipaddress.ip_address(a))),
        "tcp_only": sorted(ever_tcp - ever_icmp, key=lambda a: int(ipaddress.ip_address(a))),
        "both": sorted(ever_icmp & ever_tcp, key=lambda a: int(ipaddress.ip_address(a))),
    }

    # per-host response counts, the analogue of the paper's "responded in k of
    # 9 surveys" distribution
    host_counts = {}
    for addr in ever_union:
        host_counts[addr] = {
            "icmp": sum(1 for r in icmp_rounds if addr in r),
            "tcp443": sum(1 for r in tcp_rounds if addr in r),
            "union": sum(1 for r in union_rounds if addr in r),
        }

    per_block = {}
    for block in blocks:
        net = ipaddress.ip_network(block)
        in_block = lambda s: {a for a in s if ipaddress.ip_address(a) in net}

        b_icmp_rounds = [in_block(r) for r in icmp_rounds]
        b_tcp_rounds = [in_block(r) for r in tcp_rounds]
        b_union_rounds = [in_block(r) for r in union_rounds]

        b_ever_icmp = in_block(ever_icmp)
        b_ever_tcp = in_block(ever_tcp)
        b_ever_union = in_block(ever_union)

        a_icmp = availability(b_ever_icmp, b_icmp_rounds)
        a_union = availability(b_ever_union, b_union_rounds)

        icmp_per_round = [len(r) for r in b_icmp_rounds]
        union_per_round = [len(r) for r in b_union_rounds]

        # sparsity is a per-round property; report the median round
        med_icmp = statistics.median(icmp_per_round) if icmp_per_round else 0
        med_union = statistics.median(union_per_round) if union_per_round else 0

        consecutive = [
            jaccard(b_union_rounds[i], b_union_rounds[i + 1])
            for i in range(len(b_union_rounds) - 1)
        ]

        entry = {
            "block": block,
            "ever": {
                "icmp": len(b_ever_icmp),
                "tcp443": len(b_ever_tcp),
                "icmp_only": len(b_ever_icmp - b_ever_tcp),
                "tcp_only": len(b_ever_tcp - b_ever_icmp),
                "both": len(b_ever_icmp & b_ever_tcp),
                "union": len(b_ever_union),
            },
            "availability": {
                "icmp": round(a_icmp, 4),
                "union": round(a_union, 4),
                "delta": round(a_union - a_icmp, 4),
            },
            "responders_per_round": {
                "icmp": icmp_per_round,
                "tcp443": [len(r) for r in b_tcp_rounds],
                "union": union_per_round,
            },
            "median_responders_per_round": {
                "icmp": med_icmp, "union": med_union,
            },
            "sparse": {
                "icmp": med_icmp < SPARSE_THRESHOLD,
                "union": med_union < SPARSE_THRESHOLD,
            },
            "reliable": {
                "icmp": med_icmp >= SPARSE_THRESHOLD and a_icmp >= RELIABLE_AVAILABILITY,
                "union": med_union >= SPARSE_THRESHOLD and a_union >= RELIABLE_AVAILABILITY,
            },
            "above_trinarkular_recovery_floor": {
                "icmp": a_icmp >= TRINARKULAR_RECOVERY_FLOOR,
                "union": a_union >= TRINARKULAR_RECOVERY_FLOOR,
            },
            "stability": {
                "union_jaccard_consecutive": [round(j, 4) for j in consecutive],
                "union_jaccard_mean": round(statistics.fmean(consecutive), 4)
                if consecutive else None,
                "hosts_responding_every_round": sum(
                    1 for a in b_ever_union
                    if all(a in r for r in b_union_rounds)),
                "hosts_responding_once": sum(
                    1 for a in b_ever_union
                    if sum(1 for r in b_union_rounds if a in r) == 1),
            },
        }
        if with_whois:
            entry["operator"] = whois_org(block)
        per_block[block] = entry

    def count(pred, view):
        return sum(1 for b in per_block.values() if pred(b, view))

    summary = {
        "rounds": n_rounds,
        "rounds_all_scans_ok": sum(1 for o in observations if o["ok"]),
        "blocks": len(blocks),
        "hosts": {
            "ever_icmp": len(ever_icmp),
            "ever_tcp443": len(ever_tcp),
            "icmp_only": len(host_view["icmp_only"]),
            "tcp_only": len(host_view["tcp_only"]),
            "both": len(host_view["both"]),
            "union": len(ever_union),
            "union_gain_over_icmp_pct": round(
                (len(ever_union) - len(ever_icmp)) / len(ever_icmp) * 100, 1)
            if ever_icmp else None,
        },
        "blocks_with_any_responder": {
            "icmp": count(lambda b, _: b["ever"]["icmp"] > 0, None),
            "tcp443": count(lambda b, _: b["ever"]["tcp443"] > 0, None),
            "union": count(lambda b, _: b["ever"]["union"] > 0, None),
        },
        "sparse_blocks": {
            "icmp": count(lambda b, v: b["sparse"][v], "icmp"),
            "union": count(lambda b, v: b["sparse"][v], "union"),
        },
        "reliable_blocks": {
            "icmp": count(lambda b, v: b["reliable"][v], "icmp"),
            "union": count(lambda b, v: b["reliable"][v], "union"),
        },
        "mean_availability": {
            "icmp": round(statistics.fmean(
                b["availability"]["icmp"] for b in per_block.values()), 4),
            "union": round(statistics.fmean(
                b["availability"]["union"] for b in per_block.values()), 4),
        },
        "blocks_becoming_reliable": [
            b["block"] for b in per_block.values()
            if b["reliable"]["union"] and not b["reliable"]["icmp"]
        ],
        "blocks_becoming_nonsparse": [
            b["block"] for b in per_block.values()
            if b["sparse"]["icmp"] and not b["sparse"]["union"]
        ],
        "host_response_count_distribution": {
            view: {
                str(k): sum(1 for c in host_counts.values() if c[view] == k)
                for k in range(n_rounds + 1)
            }
            for view in ("icmp", "tcp443", "union")
        },
        "mean_host_response_count": {
            view: round(statistics.fmean(
                [c[view] for c in host_counts.values()]), 3)
            if host_counts else None
            for view in ("icmp", "tcp443", "union")
        },
    }

    return {
        "summary": summary,
        "per_block": per_block,
        "host_sets": host_view,
        "host_response_counts": host_counts,
    }


def print_report(manifest, result):
    s = result["summary"]
    h = s["hosts"]
    print(f"run {manifest['run_id']}  "
          f"{s['rounds']} rounds ({s['rounds_all_scans_ok']} fully clean)  "
          f"{s['blocks']} /24s\n")

    print("HOSTS (union over all rounds)")
    print(f"  ICMP responsive      {h['ever_icmp']:5d}")
    print(f"  TCP/443 responsive   {h['ever_tcp443']:5d}")
    print(f"  ICMP only            {h['icmp_only']:5d}")
    print(f"  TCP/443 only         {h['tcp_only']:5d}")
    print(f"  both                 {h['both']:5d}")
    print(f"  union                {h['union']:5d}", end="")
    if h["union_gain_over_icmp_pct"] is not None:
        print(f"   (+{h['union_gain_over_icmp_pct']}% over ICMP-only)")
    else:
        print()

    print("\nBLOCK CLASSIFICATION            ICMP-only    ICMP+TCP")
    print(f"  blocks with any responder     {s['blocks_with_any_responder']['icmp']:9d}"
          f"{s['blocks_with_any_responder']['union']:12d}")
    print(f"  sparse (<{SPARSE_THRESHOLD} responders)     "
          f"{s['sparse_blocks']['icmp']:9d}{s['sparse_blocks']['union']:12d}")
    print(f"  reliable (A>={RELIABLE_AVAILABILITY}, nonsparse)"
          f"{s['reliable_blocks']['icmp']:9d}{s['reliable_blocks']['union']:12d}")
    print(f"  mean A(E(b))                  {s['mean_availability']['icmp']:9.3f}"
          f"{s['mean_availability']['union']:12.3f}")

    if s["blocks_becoming_reliable"]:
        print(f"\n  became reliable with TCP: "
              f"{', '.join(s['blocks_becoming_reliable'])}")
    if s["blocks_becoming_nonsparse"]:
        print(f"  became nonsparse with TCP: "
              f"{', '.join(s['blocks_becoming_nonsparse'])}")

    print("\nPER-BLOCK")
    hdr = (f"{'block':20s} {'icmp':>5s} {'tcp':>5s} {'ionly':>6s} {'tonly':>6s} "
           f"{'both':>5s} {'union':>6s} {'A_icmp':>7s} {'A_un':>6s} {'stab':>6s}")
    print("  " + hdr)
    for block in manifest["networks"]:
        b = result["per_block"][block]
        e = b["ever"]
        stab = b["stability"]["union_jaccard_mean"]
        print(f"  {block:20s} {e['icmp']:5d} {e['tcp443']:5d} "
              f"{e['icmp_only']:6d} {e['tcp_only']:6d} {e['both']:5d} "
              f"{e['union']:6d} {b['availability']['icmp']:7.3f} "
              f"{b['availability']['union']:6.3f} "
              f"{stab if stab is not None else float('nan'):6.3f}"
              + (f"  {b['operator']}" if b.get("operator") else ""))

    print("\nSTABILITY (hosts by number of rounds responded, union view)")
    dist = s["host_response_count_distribution"]["union"]
    for k in sorted(dist, key=int):
        if dist[k]:
            print(f"  {k:>3s}/{s['rounds']} rounds: {dist[k]:5d}")
    print(f"  mean rounds responded: icmp={s['mean_host_response_count']['icmp']} "
          f"tcp443={s['mean_host_response_count']['tcp443']} "
          f"union={s['mean_host_response_count']['union']}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("run", nargs="?", default=None,
                        help="run directory or run id (default: latest)")
    parser.add_argument("--whois", action="store_true",
                        help="label each block with its network operator")
    parser.add_argument("--json", dest="json_out", default=None,
                        help="also write the full result as JSON to this path")
    args = parser.parse_args()

    if args.run is None:
        run_dir = latest_run()
    else:
        run_dir = Path(args.run)
        if not run_dir.exists():
            run_dir = RESULTS / args.run
    if not run_dir.exists():
        raise SystemExit(f"no such run: {args.run}")

    manifest, observations = load_run(run_dir)
    if not observations:
        raise SystemExit("run contains no rounds")
    result = analyse(manifest, observations, args.whois)
    print_report(manifest, result)

    out = Path(args.json_out) if args.json_out else run_dir / "analysis.json"
    out.write_text(json.dumps({"manifest": manifest, **result}, indent=2) + "\n")
    print(f"\nfull results: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
