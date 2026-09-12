# POC: Suriname, selected by population instead of protocol

A second run of the ICMP-vs-TCP/443 reachability comparison described in
`poc/README.md`, over a different country and a different way of picking
targets. Same scanner, same analysis code, same metric definitions — the only
thing that changed is how the 263 target /24s were chosen, and that change is
the point of this run.

The Irish sample (`targets.json`, see `poc/README.md`) was pulled from Censys
by querying for hosts with TCP/443 already open. That guarantees every block
in the sample answers TCP before a single packet is sent, which biases the
whole comparison in TCP's favour by construction. This run instead selects
targets by who actually owns and uses the address space — real AS population
data, real BGP-announced prefixes, geolocation-verified — with no protocol
precondition anywhere in the selection. The two runs are not a bigger-vs-
smaller comparison; they ask different questions, and the answers differ
because of that, not because of sample size. See `poc/README.md` for the
papers and repository background this POC is built on; this file only covers
what's specific to the Suriname run.

## Why Suriname

The reference paper (Sethuraman, Bischof, Dainotti) flags several small
address-space countries with the largest reliability gains from adding
transport-layer probing: Ethiopia, Suriname, French Polynesia, Andorra
(plus Yemen, in a separate passage). Ethiopia had already been covered by
someone else. Suriname was chosen from the remainder because it has the
*highest* percentage gain in the paper's own Table 3 (89.1%, versus Ethiopia's
87.5%), and because its telecom landscape splits cleanly into a fixed
incumbent (TeleSur) and a mobile challenger (Digicel) — real operators, no
cloud contamination, directly comparable in spirit to how the Irish sample
mixed ISP and cloud blocks.

French Polynesia was checked and rejected as a second candidate: its
incumbent (ONATI, AS9471) announces prefixes that include blocks which
geolocate to Palo Alto, California — almost certainly leased transit space,
not local infrastructure. That's exactly the kind of thing "an ASN's
announced prefixes" can silently smuggle in if you don't independently verify
where the address space actually is, which is why every candidate below went
through a geolocation check before being trusted.

## Selecting targets by population, not protocol

`select_targets_by_population.py` (new in this run) builds a target list from
three independent data sources rather than a single Censys query:

1. **An AS population report** (APNIC Labs' "AS population" format) ranks a
   country's ASNs by estimated real users. `DEFAULT_EXCLUDE_ASNS` in the
   script drops CDNs, clouds and satellite ISPs that show up in such reports
   without representing fixed local infrastructure — Starlink, Cloudflare,
   Akamai, Datacamp/CDNEXT all appeared in Suriname's report and were
   excluded. What's left for Suriname: TeleSur (93.35% of estimated
   population) and Digicel Suriname (17.42%).
2. **CAIDA's RouteViews prefix-to-AS table**
   (`https://publicdata.caida.org/datasets/routing/routeviews-prefix2as/`,
   tab-separated `network / pfxlen / asn`) gives every /24 each surviving ASN
   natively announces: 265 for TeleSur, 8 for Digicel. Only prefixes
   announced natively as /24 are used; a /21 or /22 an ASN announces isn't
   split into constituent /24s.
3. **An independent IP geolocation database** (`start_ip,end_ip,...,country,
   city,...`) checks every candidate /24 actually resolves to the claimed
   country, using interval containment (does any row in the geolocation file
   fully contain this /24's address range), not a substring match. This step
   is what caught the ONATI/French Polynesia problem above, and confirmed
   263 of 273 TeleSur+Digicel candidates as physically Suriname (the other 10
   simply had no geolocation data either way — never a country mismatch).

```sh
python3 poc/select_targets_by_population.py \
  --aspop aspop-suriname.csv \
  --pfx2as routeviews-rv2-latest.pfx2as \
  --location standard_location.csv \
  --all \
  --out poc/targets_suriname.json
```

`--all` selects every geo-confirmed candidate rather than a population-
proportional subset — this run scanned all 263 confirmed blocks, not a
sample of them. Without `--all`, `--count N` (default 15, for direct
comparability with the Irish sample) apportions N slots across surviving
ASNs by the largest-remainder method, so a minority operator still gets
representation instead of being rounded to zero. `--location` is optional but
strongly recommended: without it, candidates are trusted blindly, which is
exactly the failure mode that produced the Palo-Alto-labelled French
Polynesian blocks.

Both large intermediate files (the pfx2as table, ~14 MB; RIR delegated stats,
used to find a country's ASNs in the first place) are reproducible public
data and are not committed here, the same treatment as the Censys pull for
the Irish sample. `poc/targets_suriname.json` itself — the output, 263
networks plus per-block ASN/operator/population-share/geo-check metadata — is
committed, same as `targets.json`.

## Running

Identical driver and launcher to the Irish run, pointed at the new target
file and different scan parameters:

```sh
sudo bash poc/launch.sh \
  --targets poc/targets_suriname.json \
  --rate 2000 \
  --rounds 24 \
  --interval 300
```

`--rate 2000` (versus the Irish default of 500) keeps per-round send time
sane at 263 blocks: 67,328 addresses per protocol per round takes ~34s to
send at 2000 pps, versus ~135s at 500 pps, which would leave almost no slack
inside a 300s round interval. The per-block treatment is unchanged either
way — every /24 still gets exactly 256 addresses probed once per round, so
the long-run average rate to any single block stays ~0.85 pps regardless of
how many blocks are in the target list or how fast each round's send phase
runs. Scanning more blocks means doing the same gentle thing to more targets
in parallel, not doing anything more aggressive to each one.

24 rounds instead of 12: with the spatial-coverage problem solved by scanning
263 blocks instead of 15, round count was aimed at the temporal weakness
instead — more rounds means a real per-host "responded in k of N" and churn
picture, rather than the near-ceiling artifact a short window produces (see
Results below).

Analyse with the same tool, no changes needed:

```sh
python3 poc/analyze.py 20260911T042041Z            # this run
python3 poc/analyze.py 20260911T042041Z --whois    # per-block operator labels
```

`--whois` on 263 blocks means 263 sequential lookups and can take a long
time or hang on an unresponsive server; the operator labels used below came
from `network_meta` in `targets_suriname.json` instead, which already has
them from the AS-population step with no extra network calls.

## Results from run `20260911T042041Z`

24 of 24 rounds clean, 263 /24s (256 TeleSur, 7 Digicel), 67,328 addresses,
3,231,744 packets, ~116 minutes, single vantage point. A published writeup
with charts covers this run in the same style as the Irish one; the summary
below is the same material as plain text.

| | ICMP only | ICMP + TCP/443 |
|---|---|---|
| Hosts discovered | 484 | **834** (+72.3%) |
| Blocks with any responder | 29 | **59** / 263 |
| Sparse blocks (<15 responders) | 254 | 244 |
| Reliable blocks (A(E(b)) &ge; 0.3) | 9 | 19 |
| Mean A(E(b)), all 263 blocks | 0.110 | 0.219 |
| Mean A(E(b)), the 59 live blocks only | 0.490 | 0.976 |

Findings, with the caveats that matter:

- **204 of 263 blocks (77.6%) are completely dark** — zero responders,
  either protocol, all 24 rounds. The Irish sample could not have shown this
  even in principle: every one of its 15 blocks was pre-selected for having
  TCP/443 open. Here, selecting by ownership alone, most of TeleSur's
  announced space turns out to be reserved or unassigned pools rather than
  live hosts. This is what real address-space utilisation looks like away
  from a sample curated to be responsive.
- **51% of the 59 live blocks are entirely invisible to ICMP**, rescued only
  by adding TCP/443 — and this effect is not spread evenly. All 30 of the
  ICMP-invisible live blocks belong to TeleSur; Digicel has zero. Every one
  of Digicel's 6 live blocks has ICMP presence. TeleSur's fixed broadband and
  Digicel's mobile network are doing genuinely different things, not the
  same thing at different volumes. This is the sharpest form of the
  reference paper's core claim found anywhere in this project, and it
  required removing the TCP-selection bias to see it.
- **Live-block fraction differs sharply by operator**: Digicel 6/7 (85.7%)
  versus TeleSur 53/256 (20.7%). Consistent with a small, densely-used mobile
  allocation against a large, mostly-dormant incumbent pool held for growth.
- **The literature-consistent number in this project came from here, not
  Ireland.** Mean A(E(b)) restricted to the 59 live blocks is 0.490 under
  ICMP alone — close to the reference paper's own reported 0.45, and the
  first number in either run that isn't distorted by a short observation
  window or a curated sample. Averaged over all 263 blocks instead (0.110),
  the same metric mostly reflects how much of the address space is dark, not
  how available the live part is; both readings are reported because neither
  alone tells the whole story.
- **A number I initially misread**: the analysis script's default stability
  figure — mean rounds answered, blended across the whole 834-host union
  population — comes out to 13.8/24 for ICMP and 12.9/24 for TCP, which looks
  far worse than Ireland's ~99%. That comparison is invalid on its face: it's
  diluted by hosts that never used a given protocol at all (a TCP-only host
  contributes a 0 to the ICMP average), and Ireland's figure wasn't computed
  that way. Restricted the same way for both — mean rounds answered *among
  hosts that ever used that protocol* — Suriname is 99.0% (ICMP) / 99.5%
  (TCP), statistically identical to Ireland's 98.7%/99.2%. Once a real host
  is observed at all, it is exactly as consistent here as in Ireland; the
  bigger, unbiased sample changed which hosts were found, not how reliably
  any found host answers.
- **Aggregate counts held steady across the full two hours**: ICMP ranged
  474–484, TCP/443 stayed in a similarly narrow band, no drift over 24
  rounds — consistent with Ireland and with ZMap's measured ~2% single-packet
  loss.

## Why the two runs disagree

Not because Suriname has more blocks. Because Ireland's selection criterion
(Censys query for open TCP/443) makes "ICMP-invisible block" and "dark
block" structurally impossible outcomes — every block was pre-filtered to
have a visible protocol before scanning began. Suriname's selection criterion
(AS ownership + population, geo-validated, no protocol precondition) allows
both outcomes to actually occur, and they did, at scale. Ireland answers
*given blocks already known to serve TCP/443, how much does ICMP miss?*
Suriname answers the question the reference paper actually asks: *across a
real operator's real address space, with no protocol precondition, how much
does a second protocol change what's visible?* That's the harder version of
the question, and the one that produced both the most literature-consistent
availability number and the strongest evidence yet for the paper's central
claim.

## Scanning conduct

Same low-volume treatment as Ireland, at larger absolute scale: ~0.85
packets/second average to any single /24, unchanged by scanning 263 blocks
instead of 15, since each block still receives exactly 256 addresses once
per round regardless of how many other blocks are in the target list. The
aggregate footprint is materially larger in a different sense worth being
explicit about: 263 blocks is not an illustrative sample of Suriname, it is
essentially the entirety of TeleSur's and Digicel's geo-confirmed announced
/24 space — closer to a full sweep of the country's fixed-broadband and
mobile customer address space than a representative slice of it. Same
intent-signalling gap as the Irish run applies here too, at this larger
scope: no scan-explanation page, no reverse DNS, no advertised opt-out
contact on the source address. See `poc/README.md`'s Scanning Conduct section
and Table 5 of the ZMap paper.

## Limitations

263 blocks, two operators, one country, one vantage point, one TCP port, no
outage observed. Geo-validation caught one real false-positive problem
(French Polynesia's ONATI) but is not a guarantee against every possible one
— it depends entirely on the geolocation source's own accuracy and coverage.
Whether Suriname's ISP-heavy, ownership-selected pattern (mostly-dark address
space, operator-specific ICMP-invisibility) or Ireland's cloud-heavy,
TCP-preselected pattern is more typical of outage-detection targets generally
is a question this project can gesture at, not answer — that would need many
countries and many operators, all sampled the protocol-blind way this run
demonstrates.
