# I3 — Zigbee ZCL Attribute Fuzzer

Offline, stdlib-only Zigbee ZigBee Cluster Library (ZCL) attribute fuzzer: builds
malformed ZCL read/write/discover frames, mutates attribute payloads across 60+
clusters, and detects anomaly/crash signatures in simulated device responses.

## What it does

- **ZCL frame building** — constructs read-attributes, write-attributes, and
  discover-attributes frames for any cluster ID (0x0000 Basic … 0xFC00–0xFFFF
  manufacturer-specific ranges).
- **10 mutation strategies** — bit-flip, boundary values, truncation, overflow,
  format-string, buffer-overflow values, type-confusion, extra-data, repeated-data,
  and random payloads for attribute values.
- **Crash/anomaly detection** — baselines a cluster, then flags unexpected
  responses, oversized responses, and timeout runs that cross a threshold.
- **Deterministic sweeps** — seedable RNG (`--seed`) so fuzz campaigns are
  reproducible for tests and reruns.
- **JSON reports** — writes `i3_demo_report.json` / `i3_report.json` into
  `reports/` (gitignored).

The engine is purposely *offline-first*: everything runs against local structures
and a simulated response model. Pointing it at a live radio requires a Zigbee
gateway/dongle and is out of scope for this fixture set.

## Quick start

```bash
python3 zigbee_fuzzer.py --demo            # seeded offline demo sweep, exit 0
python3 zigbee_fuzzer.py --json            # custom sweep + JSON report
python3 zigbee_fuzzer.py --short-addr 0x1234 --ext-addr 0x0011223344556677 --iterations 50
```

## CLI

```
zigbee_fuzzer.py [--short-addr HEX] [--ext-addr HEX] [--iterations N]
                 [--seed N] [--json] [--report-dir DIR] [--demo]
```

- `--demo` — run the seeded offline demo (3 iterations/cluster) and write
  `reports/i3_demo_report.json`. Exit 0.
- `--json` — write a JSON report of a full sweep to `reports/`.
- `--report-dir` — where reports land (default `reports`).
- `--seed` — RNG seed for reproducibility (default 42).

## Tests

```bash
python3 -m unittest discover -s tests -v
```

19 deterministic offline tests: frame-shape and command encoding, response
parsing, all 10 mutation strategies, crash-detector thresholds, seeded-sweep
reproducibility, and the demo/report path.

## Metrics

- 60+ ZCL clusters enumerated (Basic, Power Config, On/Off, Level Control,
  IAS Zone, Metering, Scenes, Groups, …).
- 10 mutation strategies applied per attribute write.
- 3 attack surfaces fuzzed: read, write, discover.
- Crash detector: unexpected/oversized responses + timeout thresholding.

## IMPORTANT: Read before use.

This is a security-testing reference implementation. It performs no actions
against any network or device without explicit invocation and ships only offline
fixtures. Side-effecting use against a Zigbee network (real radios, real devices)
requires explicit written authorization from the network owner for every node
reached. See the LICENSE for the full Authorization / CFAA / Responsible
Disclosure notice.

## License

MIT + the "AUTHORIZATION REQUIRED — READ BEFORE USE" shield. See `LICENSE`.