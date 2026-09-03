# POC: comparing /24 reachability detection methods

A small live experiment asking whether adding one transport-layer probe to ICMP
changes what a Trinocular-style outage detector can see at /24 granularity.

Trinocular (and `trinarkular`, this repository's implementation of it) infers
whether a /24 is up by probing hosts inside it with ICMP echo. Its known weakness
is blocks with too few ICMP-responsive hosts to sample reliably. This POC measures,
over a fixed set of 15 IPv4 /24s, how much coverage a single TCP SYN probe on
port 443 adds on top of an ICMP-only baseline.

The experiment is deliberately small and exploratory. It is not a validation of
outage detection: no outage occurred while it ran, so it measures *coverage* and
short-term *response stability* only.

## Background

Two papers motivate the design:

- **Sethuraman, Bischof, Dainotti**, *Towards Improving Outage Detection with
  Multiple Probing Protocols* (Georgia Tech). Joins ISI/ANT ICMP censuses with
  Censys ZMap TCP/UDP snapshots across nine surveys and finds that transport
  probing discovers additional responsive hosts, reduces the number of sparse
  /24s by 17-21%, and raises reliable blocks from 56.5% to 70-72%. This POC
  reuses its metric definitions verbatim (see below) and tests its coverage
  claim at small scale. Section 8 of that paper proposes conducting TCP/UDP
  scans with ZMap and building hit lists from them — which is what this POC does.
- **Durumeric, Wustrow, Halderman**, *ZMap: Fast Internet-Wide Scanning and its
  Security Applications* (USENIX Security 2013). Source of the scanner and of the
  probing parameters used here: single-packet probes reach ~97.9% of live hosts,
  99.9% of SYN-ACKs arrive within 8.16 s, and scan rate has no measurable effect
  on hit rate. Its Section 5 recommended practices inform the scanning conduct
  described below.

The relevant `trinarkular` internals, for reference: `lib/trinarkular_prober.c`
holds the Bayesian model (belief initialised at 0.99, UP above 0.9, DOWN below
0.1, adaptive budget of 14 probes per /24 per round) and a recovery-probe table
indexed by `A(E(b)) * 100` that is undefined below `A(E(b)) = 0.10`.
`lib/trinarkular_probelist.c` parses the probelist format that a future converter
could emit from these results.

## Contents

| Path | Purpose |
|---|---|
| `targets.json` | The 15 target /24s. Hand-selected via the Censys web UI. |
| `run_experiment.py` | Measurement driver: repeated ICMP + TCP/443 rounds via ZMap. |
| `analyze.py` | Computes the comparison metrics and prints a report. |
| `launch.sh` | Starts a detached privileged run (see *Running* below). |
| `fetch_censys_targets.py` | Censys API target fetcher. Unused — see *Targets*. |
| `censys.env.example` | Template for Censys credentials. |
| `results/` | Run output. Git-ignored. |

`censys.env` and `results/` are both git-ignored. The two source papers are not
committed to this repository.

## Requirements

- ZMap 4.x (`brew install zmap`), which needs root for raw sockets
- Python 3.8+ (standard library only)
- `whois` on `PATH` for the optional `--whois` operator labels

## Running

ZMap needs raw sockets, so the run must be privileged. Run the launcher under
`sudo` **in a real terminal**, in the foreground, so `sudo` can prompt:

```sh
sudo bash poc/launch.sh
```

It prints a PID and returns immediately; the measurement continues detached and
survives the terminal closing. Output goes to `poc/results/run.log`.

Backgrounding `sudo` itself does not work: it tries to read the password prompt
from the terminal, receives `SIGTTIN`, and is suspended before ever gaining
privilege. The launcher exists to keep `sudo` in the foreground while the
measurement process is the thing that detaches. For the same reason this cannot
be launched from a non-interactive shell with no tty.

Arguments are passed through to `run_experiment.py`:

```sh
sudo bash poc/launch.sh --rounds 4 --interval 60   # short run
```

Defaults: 12 rounds, 300 s apart, 500 pps, 10 s cooldown. A dry run sends no
packets and needs no privilege:

```sh
python3 poc/run_experiment.py --dry-run --interface en0
```

Then analyse:

```sh
python3 poc/analyze.py            # latest run
python3 poc/analyze.py --whois    # add per-block operator labels
python3 poc/analyze.py <run-id>   # a specific run
```

`analyze.py` reads however many rounds exist, so a partial or in-progress run
analyses cleanly.

## What a round does

Each round sweeps all 256 addresses of every target /24 twice:

1. `zmap --probe-module=icmp_echoscan`
2. `zmap --probe-module=tcp_synscan --target-ports=443`

One packet per address per probe, no retransmission — ZMap's default. Each scan
draws a fresh random 48-bit address permutation seed, which is recorded so any
round can be reproduced. Each scan then listens for a 10 s cooldown, above the
8.16 s within which ZMap measured 99.9% of SYN-ACKs arriving; the script refuses
a shorter cooldown, since a tighter one manufactures apparent instability.

## Output layout

```
results/<run-id>/
  manifest.json                    parameters, zmap version and path, packet budget
  allowlist.txt                    the CIDRs — the scanner's only reachable targets
  rounds.jsonl                     one record per round: argv, timings, seed,
                                   return code, responder count, zmap stderr tail
  rounds/roundNN_icmp.csv          raw responder addresses
  rounds/roundNN_tcp443.csv
  analysis.json                    everything analyze.py computed
```

## Metrics

Taken from the Sethuraman et al. paper so results are comparable to it:

- **E(b)** — hosts in block *b* that ever responded to any probe.
- **A(E(b))** — block availability: the per-round response rate over E(b),
  averaged across rounds.
- **sparse** — fewer than 15 responding hosts in a round.
- **reliable** — non-sparse and `A(E(b)) >= 0.3`, the threshold above which
  Trinocular always detects an outage lasting longer than one probing round.

Reported per /24 and in aggregate: ICMP-only, TCP-only, both, and union host
sets; A(E(b)) under ICMP-only versus union; sparse and reliable classification
under each; which blocks cross those thresholds; and three stability views — the
per-host distribution of "responded in k of N rounds", mean Jaccard similarity
between consecutive rounds, and counts of hosts answering every round versus
exactly once. Blocks below `A(E(b)) = 0.10` are flagged, since that is where
`trinarkular`'s own recovery-probe table goes undefined.

## Results from run `20260903T044734Z`

12 of 12 rounds clean, 15 /24s, 3,840 addresses, 92,160 packets, 56 minutes,
single vantage point.

| | ICMP only | ICMP + TCP/443 |
|---|---|---|
| Hosts discovered | 379 | **839** (+121%) |
| Sparse blocks | 12 | **1** |
| Reliable blocks | 3 | **14** |
| Mean A(E(b)) | 0.974 | 0.980 |

Findings, with the caveats that matter:

- **Only 35 hosts (4.2% of the union) answered both probes.** The two responder
  populations are almost disjoint — 344 ICMP-only, 460 TCP-only. TCP is not
  thickening a known host population; it is discovering a different one. This
  differs from the reference study, where dual-responsive hosts were a
  substantial and highly available group.
- **The pooled +121% understates the typical block.** `79.143.204.0/24` holds 194
  hosts — 51% of all ICMP-responsive hosts here — and gains nothing from TCP,
  dragging the pooled ratio down. The *median* block gains a factor of 4.0
  against a pooled 2.2. Outage detection operates per /24, so the median is the
  operationally relevant figure.
- **The reliability gain is entirely a sparsity gain.** Mean A(E(b)) is 0.974
  under ICMP alone, against 0.45 in the reference study, because availability
  over "hosts that ever responded" is near-tautological in a 56-minute window.
  The availability criterion therefore never binds, and the 3 -> 14 transition is
  decided purely by the 15-responder sparsity line. This experiment cannot test
  the study's availability claim.
- **`86.41.165.0/24` (Eircom ADSL pools) stays sparse under both protocols**, at
  11 responders. Residential access space is the case Trinocular handles worst
  and the case transport probing was meant to fix.
- **Stability is near-ceiling but churn is visible.** 823 of 839 hosts answered
  all 12 rounds; aggregate counts varied under 1% round to round, inside ZMap's
  ~2% single-packet loss. The 16 hosts that did churn cluster in two AWS blocks
  and mostly answered once and never again — the signature of short-lived
  instances.

## Targets

`targets.json` was assembled by hand from the Censys web interface, querying
Irish hosts with TCP/443 open. `fetch_censys_targets.py` implements the same
query against the Censys API but is unused: the Censys Free tier does not permit
API search, so the script returns HTTP 403. It is kept for anyone with a paid
tier.

Consequences for interpretation: the sample is **selected for having TCP/443
open**, which biases the comparison in TCP's favour by construction, and it is
cloud-heavy — by WHOIS, 10 blocks are Amazon, 1 Microsoft and 1 enterprise
(Vesta Payment Solutions), leaving 3 Irish ISP blocks (Js Whizzy, Eircom,
Magnet). Whether a block is cloud or ISP does not cleanly predict which protocol
sees it: two of the cloud blocks are ICMP-dominant.

## Scanning conduct

Volume was kept far below any plausible nuisance threshold: each /24 receives 256
packets over ~8 s, then nothing for 5 minutes — about 0.85 packets/second to any
one block, roughly an eighth of the per-/24 rate a full-speed ZMap Internet scan
delivers. A ZMap allowlist generated from `targets.json` is the scanner's only
reachable destination set, so the run cannot stray outside the listed blocks.

The intent-signalling half of ZMap's recommended practices was **not** in place
for this run: no scan-explanation page on the source address, no reverse DNS
identifying it as research, and no advertised opt-out contact. Anyone repeating
this against third-party networks should consider putting those in place, and
should note that probes otherwise arrive with nothing marking them as research
traffic. See Table 5 of the ZMap paper.

## Limitations

15 blocks; Censys-sourced and selected for open TCP/443; one vantage point; one
hour; one TCP port; no outage observed. A single outlier block moves the headline
figure by nearly a factor of two. Results are exploratory and do not generalise
past this sample.

## Possible next step

The measured responder sets map onto the probelist format
`lib/trinarkular_probelist.c` already parses: per-/24 `host_cnt`, an
`avg_resp_rate` that becomes the prober's `s24->aeb` seed, and a `hosts[]` array
of `host_ip`. A converter would let the real Bayesian prober run against measured
rather than historical hit lists — the integration step the reference study
leaves for future work.
