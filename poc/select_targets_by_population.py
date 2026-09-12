#!/usr/bin/env python3
"""Select /24 targets from real AS population data instead of a Censys query.

Motivation: poc/targets.json (the Irish sample) was selected by querying Censys
for hosts with TCP/443 open, which biases the sample toward TCP-responsive,
cloud-heavy address space by construction (10 of 15 blocks turned out to be
AWS/Azure). This script builds a target list the other way around: start from
which ASNs actually have real human users behind them (an APNIC-style AS
population report), then find their announced address space, then verify with
an independent geolocation source that the space is actually physically in the
claimed country rather than leased/announced transit space.

That last step matters. During manual investigation for French Polynesia,
AS9471 (ONATI, the incumbent) was found to announce blocks that geolocate to
Palo Alto, California -- almost certainly leased/transit space, not physically
in French Polynesia. Naively taking "an ASN's announced prefixes" as "that
country's address space" would have silently included those. This script does
the same geolocation cross-check for every candidate before it can be selected.

Inputs:
  - An AS population CSV (APNIC Labs "AS population" report format: a title
    comment line, a header line starting with "#Rank", then rows of
    rank,AS,"AS Name",CC,users_est,pct_country,pct_internet,samples).
  - A CAIDA pfx2as file (tab-separated network / pfxlen / asn; see
    https://publicdata.caida.org/datasets/routing/routeviews-prefix2as/).
  - Optionally, a geolocation CSV (start_ip,end_ip,join_key,city,region,
    country,latitude,longitude,postal_code,timezone) to verify candidates
    actually geolocate to the target country. Strongly recommended: without
    it, ASN-announced space is trusted blindly.

Only prefixes announced natively as /24 are considered as candidates (an ASN
announcing a /21 contributes nothing unless it also announces /24s directly);
splitting larger aggregates into constituent /24s is a possible future
extension, not done here.
"""

import argparse
import bisect
import csv
import ipaddress
import json
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent

# ASNs that show up in AS-population reports but are not fixed, physically
# local infrastructure: CDNs, cloud providers and satellite ISPs. A satellite
# ISP (Starlink) serves real users but not through stable per-country address
# space suited to a fixed /24 reachability scan; CDNs/clouds show up in
# population reports because of cached/proxied traffic, not local residents.
DEFAULT_EXCLUDE_ASNS = {
    "13335",   # Cloudflare
    "36183",   # Akamai Technologies
    "20940",   # Akamai (alternate)
    "16625",   # Akamai (alternate)
    "14593",   # SpaceX Starlink
    "212238",  # Datacamp Limited (CDNEXT)
    "15169",   # Google
    "16509",   # Amazon AWS
    "14618",   # Amazon AWS (alternate)
    "8075",    # Microsoft
    "54113",   # Fastly
}


def load_aspop(path, exclude_asns):
    with open(path, newline="") as f:
        lines = f.readlines()
    # first line is a title/date comment, not real CSV
    reader = csv.reader(lines[1:])
    header = next(reader)
    assert header[0].lstrip("#") == "Rank", f"unexpected aspop header: {header}"

    rows = []
    for row in reader:
        if not row:
            continue
        asn = row[1].lstrip("AS")
        name = row[2]
        cc = row[3]
        users_est = int(row[4])
        pct_country = float(row[5])
        if asn in exclude_asns:
            continue
        rows.append({
            "asn": asn, "name": name, "cc": cc,
            "users_est": users_est, "pct_country": pct_country,
        })
    return rows


def load_pfx2as_slash24s(path, wanted_asns):
    by_asn = defaultdict(list)
    with open(path) as f:
        for line in f:
            net, mask, asn = line.rstrip("\n").split("\t")
            if mask != "24" or asn not in wanted_asns:
                continue
            by_asn[asn].append(ipaddress.ip_network(f"{net}/24"))
    for asn in by_asn:
        by_asn[asn].sort(key=lambda n: int(n.network_address))
    return by_asn


def geo_validate(candidates, location_csv, expect_cc):
    """Check each candidate /24 against a geolocation CSV.

    Returns {network: (country, city) or None}. None means no covering row was
    found (no data either way); a mismatched country is dropped by the caller,
    never silently trusted.

    Does not assume the geolocation file is sorted or IPv4-only: uses a sorted
    candidate index + bisect so row order doesn't matter, and skips IPv6 rows
    explicitly (an IPv6 address's integer value dwarfs any IPv4 one and will
    silently corrupt a naive merge that doesn't guard for it).
    """
    ordered = sorted(candidates, key=lambda n: int(n.network_address))
    net_starts = [int(n.network_address) for n in ordered]
    results = {n: None for n in ordered}

    with open(location_csv, newline="") as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            if ":" in row[0]:
                continue  # IPv6 row; see note above
            start = int(ipaddress.ip_address(row[0]))
            end = int(ipaddress.ip_address(row[1]))
            lo = bisect.bisect_left(net_starts, start)
            hi = bisect.bisect_right(net_starts, end)
            for k in range(lo, hi):
                cand = ordered[k]
                if results[cand] is None and int(cand.broadcast_address) <= end:
                    results[cand] = (row[5], row[3])
    return results


def largest_remainder_allocation(weights, total):
    """Apportion `total` integer slots across `weights` (a dict), preserving
    proportionality via the largest-remainder method rather than naive
    rounding (which can under- or over-allocate the total)."""
    raw = {k: w / sum(weights.values()) * total for k, w in weights.items()}
    floors = {k: int(v) for k, v in raw.items()}
    remainder = total - sum(floors.values())
    order = sorted(raw, key=lambda k: raw[k] - floors[k], reverse=True)
    for k in order[:remainder]:
        floors[k] += 1
    return floors


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--aspop", required=True,
                        help="AS population CSV (APNIC Labs format)")
    parser.add_argument("--pfx2as", required=True,
                        help="CAIDA pfx2as file (network<TAB>pfxlen<TAB>asn)")
    parser.add_argument("--location", default=None,
                        help="geolocation CSV to verify candidates against "
                             "(start_ip,end_ip,...,country,city,...). Strongly "
                             "recommended -- without it, ASN-announced space "
                             "is trusted without checking it is actually in "
                             "the claimed country.")
    parser.add_argument("--count", type=int, default=15,
                        help="total /24s to select (default: 15, matching "
                             "the existing Irish sample for comparability). "
                             "Ignored if --all is given.")
    parser.add_argument("--all", action="store_true",
                        help="select every candidate that survives geo-"
                             "validation (or every candidate, if --location "
                             "is not given), instead of a population-"
                             "proportional subset. --count, --min-asn-slots "
                             "and --seed are ignored in this mode.")
    parser.add_argument("--min-asn-slots", type=int, default=1,
                        help="minimum slots guaranteed to each surviving ASN "
                             "(default: 1)")
    parser.add_argument("--exclude-asn", action="append", default=[],
                        help="additional ASN to exclude (repeatable)")
    parser.add_argument("--include-unverified", action="store_true",
                        help="allow candidates with no geolocation match at "
                             "all (no data either way) to be selected, after "
                             "confirmed candidates are exhausted. Candidates "
                             "that resolve to a DIFFERENT country are never "
                             "selected, regardless of this flag.")
    parser.add_argument("--seed", type=int, default=0,
                        help="deterministic seed for candidate ordering "
                             "within an ASN (default: 0)")
    parser.add_argument("--out", default=str(HERE / "targets.json"),
                        help="output path (default: poc/targets.json -- pass "
                             "a different path to avoid overwriting an "
                             "existing sample)")
    args = parser.parse_args()

    exclude = DEFAULT_EXCLUDE_ASNS | set(args.exclude_asn)
    aspop_rows = load_aspop(args.aspop, exclude)
    if not aspop_rows:
        parser.error("no ASNs left after exclusion -- check --aspop and "
                     "--exclude-asn")

    country = aspop_rows[0]["cc"]
    wanted_asns = {r["asn"] for r in aspop_rows}
    by_asn = load_pfx2as_slash24s(args.pfx2as, wanted_asns)

    print(f"country: {country}", file=sys.stderr)
    for r in aspop_rows:
        cnt = len(by_asn.get(r["asn"], []))
        print(f"  AS{r['asn']:<8s} {r['name']:<45s} "
              f"{r['pct_country']:5.2f}% of country  {cnt:4d} /24s announced",
              file=sys.stderr)

    all_candidates = [n for asn in by_asn for n in by_asn[asn]]
    if not all_candidates:
        parser.error("none of the surviving ASNs announce any native /24s")

    geo = None
    if args.location:
        print(f"\ngeo-validating {len(all_candidates)} candidates against "
              f"{args.location} ...", file=sys.stderr)
        geo = geo_validate(all_candidates, args.location, country)
        confirmed = sum(1 for v in geo.values() if v and v[0] == country)
        mismatched = {v[0] for v in geo.values() if v and v[0] != country}
        unverified = sum(1 for v in geo.values() if v is None)
        print(f"  confirmed {country}: {confirmed}/{len(all_candidates)}",
              file=sys.stderr)
        if mismatched:
            print(f"  DROPPED -- resolved to a different country: "
                  f"{mismatched}", file=sys.stderr)
        print(f"  unverified (no location data either way): {unverified}",
              file=sys.stderr)
    else:
        print("\nWARNING: no --location given; candidates are NOT geo-"
              "validated and ASN-announced space is trusted blindly. This is "
              "how a leased/transit block (e.g. an incumbent's foreign-hosted "
              "space) would slip in silently.", file=sys.stderr)

    def usable(net):
        if geo is None:
            return True
        v = geo[net]
        if v is None:
            return args.include_unverified
        return v[0] == country

    pools = {}
    for asn, nets in by_asn.items():
        surviving = [n for n in nets if usable(n)]
        if surviving:
            pools[asn] = surviving

    if not pools:
        parser.error("no candidates survived geo-validation -- try "
                     "--include-unverified, or check --location covers this "
                     "country")

    if args.all:
        # every surviving candidate, from every surviving ASN -- no
        # population-proportional capping. This is "give me everything
        # confirmed", not "give me a representative sample".
        slots = {asn: len(pool) for asn, pool in pools.items()}
    else:
        weights = {asn: next(r["users_est"] for r in aspop_rows if r["asn"] == asn)
                   for asn in pools}
        slots = largest_remainder_allocation(weights, args.count)
        # respect --min-asn-slots without exceeding what's actually available
        for asn in slots:
            slots[asn] = max(slots[asn], min(args.min_asn_slots, len(pools[asn])))
        # if min-slots pushed the total over args.count, trim from the largest
        # allocations first so small operators keep their guaranteed minimum
        overshoot = sum(slots.values()) - args.count
        if overshoot > 0:
            for asn in sorted(slots, key=lambda a: slots[a], reverse=True):
                if overshoot <= 0:
                    break
                reducible = slots[asn] - args.min_asn_slots
                take = min(reducible, overshoot)
                if take > 0:
                    slots[asn] -= take
                    overshoot -= take

    import random
    rng = random.Random(args.seed)
    selected = []
    for asn, n in slots.items():
        pool = pools[asn][:]
        rng.shuffle(pool)
        # prefer confirmed-geo candidates over unverified ones
        if geo is not None:
            pool.sort(key=lambda net: 0 if (geo[net] and geo[net][0] == country) else 1)
        selected.extend(pool[:n])

    selected.sort(key=lambda n: int(n.network_address))

    networks_meta = {}
    for asn in pools:
        row = next(r for r in aspop_rows if r["asn"] == asn)
        for net in selected:
            if net in pools[asn]:
                g = geo[net] if geo else None
                networks_meta[str(net)] = {
                    "asn": asn,
                    "operator": row["name"],
                    "pct_of_country_population": row["pct_country"],
                    "geo_check": (g[0] if g else "unverified"),
                    "geo_city": (g[1] if g else None),
                }

    out = {
        "source": "aspop+pfx2as",
        "country": country,
        "protocol": None,
        "networks": [str(n) for n in selected],
        "network_meta": networks_meta,
    }
    Path(args.out).write_text(json.dumps(out, indent=2) + "\n")

    print(f"\nselected {len(selected)} /24s -> {args.out}", file=sys.stderr)
    for asn, n in slots.items():
        row = next(r for r in aspop_rows if r["asn"] == asn)
        print(f"  AS{asn} ({row['name']}): {n} blocks", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
