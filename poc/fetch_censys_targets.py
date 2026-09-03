#!/usr/bin/env python3
"""Fetch a small Censys sample and derive candidate IPv4 /24 networks."""

import argparse
import ipaddress
import json
import os
import sys
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path


HERE = Path(__file__).resolve().parent
API_URL = "https://api.platform.censys.io/v3/global/search/query"


def load_secret(path: Path, wanted_key: str) -> str:
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() == wanted_key:
            return value.strip().strip('"').strip("'")
    return ""


def find_ips(value):
    """Yield IPv4 addresses from host.ip fields across API schema variants."""
    if isinstance(value, dict):
        host = value.get("host")
        candidates = [value.get("ip")]
        if isinstance(host, dict):
            candidates.append(host.get("ip"))
        for candidate in candidates:
            if isinstance(candidate, str):
                try:
                    ip = ipaddress.ip_address(candidate)
                    if ip.version == 4 and ip.is_global:
                        yield str(ip)
                except ValueError:
                    pass
        for child in value.values():
            yield from find_ips(child)
    elif isinstance(value, list):
        for child in value:
            yield from find_ips(child)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hosts", type=int, default=100,
                        help="maximum Censys hosts to request (default: 100)")
    parser.add_argument("--networks", type=int, default=5,
                        help="maximum /24 networks to save (default: 5)")
    args = parser.parse_args()

    if not 1 <= args.hosts <= 100:
        parser.error("--hosts must be between 1 and 100")
    if args.networks < 1:
        parser.error("--networks must be positive")

    env_file = HERE / "censys.env"
    token = os.environ.get("CENSYS_API_TOKEN") or load_secret(
        env_file, "CENSYS_API_TOKEN"
    )
    if not token:
        print("CENSYS_API_TOKEN is missing from poc/censys.env", file=sys.stderr)
        return 2
    organization_id = os.environ.get("CENSYS_ORG_ID") or load_secret(
        env_file, "CENSYS_ORG_ID"
    )

    query = (
        'host.location.country="Ireland" and '
        "host.services.port=443 and "
        "host.services.transport_protocol=TCP"
    )
    body = json.dumps({
        "query": query,
        "page_size": args.hosts,
        "fields": ["host.ip", "host.location.country",
                   "host.services.port", "host.services.transport_protocol"],
    }).encode()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "trinarkular-poc/0.1 (academic measurement prototype)",
    }
    if organization_id:
        headers["X-Organization-ID"] = organization_id
    request = urllib.request.Request(
        API_URL,
        data=body,
        method="POST",
        headers=headers,
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as error:
        message = error.read().decode(errors="replace")[:1000]
        print(f"Censys API returned HTTP {error.code}: {message}", file=sys.stderr)
        return 1
    except (urllib.error.URLError, TimeoutError) as error:
        print(f"Could not reach Censys API: {error}", file=sys.stderr)
        return 1

    ips = sorted(set(find_ips(payload)), key=ipaddress.ip_address)
    counts = Counter(
        str(ipaddress.ip_network(f"{ip}/24", strict=False)) for ip in ips
    )
    selected = [network for network, _ in counts.most_common(args.networks)]

    results_dir = HERE / "results"
    results_dir.mkdir(exist_ok=True)
    (results_dir / "censys_ireland_tcp443_ips.json").write_text(
        json.dumps({"query": query, "ips": ips}, indent=2) + "\n"
    )
    targets = {
        "source": "censys",
        "country": "Ireland",
        "protocol": "tcp",
        "port": 443,
        "networks": selected,
        "known_responsive_ips_per_network": {
            network: counts[network] for network in selected
        },
    }
    (HERE / "targets.json").write_text(json.dumps(targets, indent=2) + "\n")

    print(f"Received {len(ips)} unique public IPv4 hosts.")
    print(f"Saved {len(selected)} candidate /24 networks to poc/targets.json.")
    for network in selected:
        print(f"  {network}: {counts[network]} known TCP/443 host(s) in sample")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
