# I3 — Zigbee ZCL Attribute Fuzzer

ZCL cluster fuzzing, attribute mutation, response parsing, and crash detection for Zigbee devices.

## Overview

This project implements a Zigbee ZCL (Zigbee Cluster Library) attribute fuzzer that:
- Builds ZCL read, write, discover, and configure reporting frames
- Mutates payloads using 10 different mutation strategies
- Parses ZCL responses and detects anomalies
- Identifies potential device crashes from response patterns
- Covers 40+ ZCL clusters with 100+ attribute definitions

## Features

- **ZCL Frame Builder**: Construct read/write/discover/reporting ZCL frames from scratch
- **10 Mutation Strategies**: bit flip, byte replace, boundary values, overflow, truncation, repeat, random, format string, null inject, type confusion
- **Crash Detection**: Timeout monitoring, empty response detection, oversized response detection, baseline comparison
- **40+ ZCL Clusters**: Basic, On/Off, Level Control, Temperature, IAS Zone, Metering, etc.
- **ZCL Response Parser**: Decode frame control, sequence numbers, command IDs, and payloads
- **Comprehensive Logging**: Track all sent/received packets with full hex dumps

## Dependencies

Standard library only (no pip install needed):
- `struct`, `random`, `os`, `hashlib`, `collections`

## Usage

```bash
# Fuzz a Zigbee device (simulated)
python3 zigbee_fuzzer.py <short_addr_hex> [ext_addr_hex] [iterations]

# Examples
python3 zigbee_fuzzer.py 0x1234
python3 zigbee_fuzzer.py 0x1234 0x0011223344556677 50
```

## Example Output

```
============================================================
  I3 - Zigbee ZCL Attribute Fuzzer
  Target: short=0x1234, ext=0x0
============================================================

  [Cluster] Basic (0x0)
  Fuzzing cluster Basic (0x0) - 20 iterations
    [!] ANOMALY: SUSPECTED_CRASH - Multiple consecutive timeouts

  [Cluster] On/Off (0x6)
  Fuzzing cluster On/Off (0x6) - 20 iterations

============================================================
  Phase 2: Write Attribute Mutation
============================================================

  [Write Fuzz] Basic
  Fuzzing write on Basic - 40 iterations
    [!] ANOMALY: OVERSIZED_RESPONSE - Response size 256 exceeds 200 bytes

============================================================
  Crash Detection Summary
============================================================
  Total crashes:    1
  Total errors:     0
  Unique responses: 142
  Packets sent:     480
============================================================
```

## ZCL Frame Structure

```
+------------------+------------------+------------------+------------------+
| Frame Control    | Transaction Seq  | Command ID       | Cluster ID       |
| (1 byte)         | (1 byte)         | (1 byte)         | (2 bytes)        |
+------------------+------------------+------------------+------------------+
| Payload (variable)                                                           |
+------------------------------------------------------------------------------+
```

## Mutation Strategies

| Strategy | Description |
|----------|-------------|
| bit_flip | Random bit flips in payload bytes |
| byte_replace | Replace bytes with 0x00, 0xFF, random, or neighbor values |
| boundary | Insert boundary values (0x00, 0x01, 0x7F, 0x80, 0xFF) |
| overflow | Append extra bytes (0 to 1024 bytes) |
| truncation | Truncate payload to 0, 1, half, or length-1 |
| repeat | Repeat payload 2-20 times |
| random_payload | Replace with fully random bytes |
| format_string | Insert format string patterns (%n, %s, %x) |
| null_inject | Insert null bytes at random positions |
| type_confusion | Generate payload for wrong data type |

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the device owner before fuzzing Zigbee devices
- Fuzzing IoT devices may cause unexpected behavior or data loss
- This tool should ONLY be used on devices you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **FCC Regulations**: Transmitting on Zigbee frequencies without authorization may violate FCC rules
- **State Laws**: Many states have additional computer crime statutes
- **Manufacturer Terms**: Fuzzing may void device warranties

### Acceptable Use
- Testing security of your own Zigbee devices
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training
- Contributing to Zigbee security research

### Prohibited Use
- Fuzzing devices you do not own
- Disrupting Zigbee networks without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
