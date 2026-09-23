> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# I3 — Zigbee ZCL Attribute Fuzzer

Offline, stdlib-only Zigbee fuzzer for IoT device robustness testing — builds malformed Zigbee
Cluster Library (ZCL) read/write/discover frames, mutates attribute payloads across 60+ clusters,
and detects anomaly and crash signatures in simulated device responses.

![MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/i3-zigbee-fuzz)
![GitHub last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/i3-zigbee-fuzz)
![GitHub issues](https://img.shields.io/github/issues/5h4d0wn1k/i3-zigbee-fuzz)

## Why

Zigbee devices live on radios with weak integrity guarantees, so the Zigbee Cluster Library — the
application layer that carries attribute reads and writes — is a prime fuzzing surface for IoT
security research. I3 builds real ZCL frame structures, runs ten mutation strategies against
attribute values, and flags unexpected, oversized, or timed-out responses through a crash detector.
It is an educational IoT-security and wireless-robustness tool that is deliberately offline-first:
everything runs against local structures and a simulated response model, so no radio is touched.
Any real use against a Zigbee network requires explicit written authorization for every node
reached.

## Features

- **ZCL frame building** — read-attributes, write-attributes, and discover-attributes frames for
  any cluster ID (`0x0000` Basic through manufacturer-specific `0xFC00+`).
- **10 mutation strategies** — bit-flip, boundary, truncation, overflow, format-string,
  buffer-overflow values, type-confusion, extra-data, repeated-data, and random payloads.
- **Crash / anomaly detection** — baselines a cluster, then flags unexpected or oversized responses
  and timeout runs past a threshold.
- **Reproducible sweeps** — seedable RNG (`--seed`) for deterministic campaigns.
- **JSON reports** — writes `i3_demo_report.json` / `i3_report.json` into `reports/` (gitignored).

## Quickstart

Prerequisite: Python 3 (standard library only).

```bash
python3 zigbee_fuzzer.py --demo                 # seeded offline sweep, exit 0
python3 zigbee_fuzzer.py --json                 # full sweep + JSON report in reports/
python3 zigbee_fuzzer.py --short-addr 0x1234 --ext-addr 0x0011223344556677 \
    --iterations 50 --seed 42
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Project structure

- `zigbee_fuzzer.py` — ZCL fuzzer engine and CLI (report dir default: `reports`).
- `tests/` — deterministic offline tests for frame encoding, mutation strategies, and crash
  detection.

## Documentation

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [ETHICS.md](ETHICS.md) · [SCOPE.md](SCOPE.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Keep the engine offline-first and seedable.

## License

MIT — see [LICENSE](LICENSE).