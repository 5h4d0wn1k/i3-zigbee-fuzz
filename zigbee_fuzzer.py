#!/usr/bin/env python3
"""
I3 - Zigbee ZCL Attribute Fuzzer
ZCL cluster fuzzing, attribute mutation, response parsing, crash detection.
"""

import struct
import random
import sys
import time
import os
import hashlib
import json
import argparse
from collections import defaultdict, Counter
from typing import List, Tuple, Optional, Dict

# --- ZCL Cluster and Attribute IDs ---
ZCL_CLUSTERS = {
    0x0000: "Basic",
    0x0001: "Power Configuration",
    0x0002: "Device Temperature Configuration",
    0x0003: "Identify",
    0x0004: "Groups",
    0x0005: "Scenes",
    0x0006: "On/Off",
    0x0007: "On/Off Switch Configuration",
    0x0008: "Level Control",
    0x0009: "Alarms",
    0x000A: "Time",
    0x000B: "RSSI Location",
    0x000C: "Binary Input (Basic)",
    0x000F: "Binary Input",
    0x0010: "Power Profile",
    0x0011: "Poll Control",
    0x0012: "Shade Configuration",
    0x0015: "Door Lock",
    0x0019: "Pump Configuration and Control",
    0x001A: "Thermostat",
    0x001B: "Fan Control",
    0x001C: "Dehumidification Control",
    0x001D: "Thermostat UI Configuration",
    0x0020: "Occupancy Sensing",
    0x0021: "Soil Moisture",
    0x0100: "Color Control",
    0x0201: "Metering",
    0x0202: "Electrical Measurement",
    0x0300: "Color Control (CIE)",
    0x0400: "Illuminance Measurement",
    0x0401: "Illuminance Level Sensing",
    0x0402: "Temperature Measurement",
    0x0403: "Pressure Measurement",
    0x0404: "Flow Measurement",
    0x0405: "Relative Humidity Measurement",
    0x0406: "Occupancy Sensing (IAS)",
    0x0500: "IAS Zone",
    0x0501: "IAS ACE",
    0x0502: "IAS WD",
    0x0600: "Price",
    0x0702: "Metering (Green Energy)",
    0x0800: "Key Establishment",
}

ZCL_DATA_TYPES = {
    0x00: ("No Data", 0),
    0x10: ("Boolean", 1),
    0x18: ("Bitmap 8-bit", 1),
    0x19: ("Bitmap 16-bit", 2),
    0x20: ("Unsigned 8-bit", 1),
    0x21: ("Unsigned 16-bit", 2),
    0x22: ("Unsigned 32-bit", 4),
    0x23: ("Unsigned 64-bit", 8),
    0x28: ("Signed 8-bit", 1),
    0x29: ("Signed 16-bit", 2),
    0x2A: ("Signed 32-bit", 4),
    0x2B: ("Signed 64-bit", 8),
    0x30: ("Enum 8-bit", 1),
    0x31: ("Enum 16-bit", 2),
    0x41: ("Octet String (var)", -1),
    0x42: ("Character String (var)", -1),
    0x43: ("Long Octet String (var)", -1),
    0x44: ("Long Character String (var)", -1),
    0x48: ("Array (var)", -1),
}

BASIC_ATTRIBUTES = {
    0x0000: ("ZCL Version", 0x20),
    0x0001: ("Application Version", 0x22),
    0x0002: ("Stack Version", 0x20),
    0x0003: ("Hardware Version", 0x20),
    0x0004: ("Manufacturer Name", 0x42),
    0x0005: ("Model Identifier", 0x42),
    0x0006: ("Date Code", 0x42),
    0x0007: ("Power Source", 0x30),
    0x0008: ("Generic Device Class", 0x30),
    0x000F: ("Product Code", 0x41),
    0x0010: ("Product URL", 0x42),
    0x0011: ("Manufacturer Details", 0x42),
    0x0012: ("Model Number", 0x42),
    0x0013: ("Serial Number", 0x42),
    0x0014: ("Local Config", 0x41),
}

# --- Mutation strategies ---
MUTATION_STRATEGIES = [
    "bit_flip",
    "byte_replace",
    "boundary",
    "overflow",
    "truncation",
    "repeat",
    "random_payload",
    "format_string",
    "null_inject",
    "type_confusion",
]


class ZclFrame:
    """Build and parse ZCL frames."""

    @staticmethod
    def build_read_attributes(cluster_id: int, attributes: List[int], direction: int = 0x00) -> bytes:
        frame_control = 0x00 | (direction & 0x01)
        transaction_seq = random.randint(0, 255)
        cmd_id = 0x00  # Read Attributes
        payload = bytearray()
        for attr_id in attributes:
            payload.extend(struct.pack("<H", attr_id))
        header = struct.pack("<BBHBB", frame_control, 0x01, transaction_seq, cmd_id, cluster_id & 0xFF)
        header += struct.pack(">B", (cluster_id >> 8) & 0xFF)
        return bytes(header) + bytes(payload)

    @staticmethod
    def build_write_attributes(
        cluster_id: int, attr_id: int, data_type: int, value: bytes, direction: int = 0x00
    ) -> bytes:
        frame_control = 0x00 | (direction & 0x01) | 0x04  # direction + write disable response
        transaction_seq = random.randint(0, 255)
        cmd_id = 0x02  # Write Attributes
        payload = bytearray()
        payload.extend(struct.pack("<H", attr_id))
        payload.append(data_type)
        payload.extend(value)
        header = struct.pack("<BBHBB", frame_control, 0x01, transaction_seq, cmd_id, cluster_id & 0xFF)
        header += struct.pack(">B", (cluster_id >> 8) & 0xFF)
        return bytes(header) + bytes(payload)

    @staticmethod
    def build_discover_attributes(cluster_id: int, start_attr: int = 0x0000, max_attrs: int = 16) -> bytes:
        frame_control = 0x00
        transaction_seq = random.randint(0, 255)
        cmd_id = 0x0C  # Discover Attributes
        payload = struct.pack("<HBB", start_attr, max_attrs, 0x00)
        header = struct.pack("<BBHBB", frame_control, 0x01, transaction_seq, cmd_id, cluster_id & 0xFF)
        header += struct.pack(">B", (cluster_id >> 8) & 0xFF)
        return bytes(header) + bytes(payload)

    @staticmethod
    def build_config_reporting(cluster_id: int, direction: int = 0x00, attr_id: int = 0, data_type: int = 0x21, interval: int = 10) -> bytes:
        frame_control = 0x00
        transaction_seq = random.randint(0, 255)
        cmd_id = 0x06  # Configure Reporting
        payload = bytearray()
        payload.append(direction)
        payload.extend(struct.pack("<H", attr_id))
        payload.append(data_type)
        payload.extend(struct.pack("<H", interval))
        header = struct.pack("<BBHBB", frame_control, 0x01, transaction_seq, cmd_id, cluster_id & 0xFF)
        header += struct.pack(">B", (cluster_id >> 8) & 0xFF)
        return bytes(header) + bytes(payload)

    @staticmethod
    def parse_response(data: bytes) -> dict:
        if not data:
            return {"error": "Empty response"}
        result = {"raw_hex": data.hex(), "length": len(data)}
        if len(data) >= 3:
            result["frame_control"] = data[0]
            result["sequence"] = data[1]
            cluster_id = struct.unpack("<H", data[2:4])[0] if len(data) >= 4 else 0
            result["cluster_id"] = hex(cluster_id)
            result["cluster_name"] = ZCL_CLUSTERS.get(cluster_id, "Unknown")
        if len(data) >= 4:
            cmd_id = data[3]
            result["command_id"] = cmd_id
            if cmd_id == 0x01:
                result["command_name"] = "Read Attributes Response"
            elif cmd_id == 0x03:
                result["command_name"] = "Write Attributes Response"
            elif cmd_id == 0x0D:
                result["command_name"] = "Discover Attributes Response"
            else:
                result["command_name"] = f"Command 0x{cmd_id:02X}"
        if len(data) > 4:
            result["payload"] = data[4:].hex()
        return result


class MutationEngine:
    """Generate mutated payloads for fuzzing."""

    @staticmethod
    def bit_flip(data: bytes, num_flips: int = 1) -> bytes:
        buf = bytearray(data)
        for _ in range(num_flips):
            if buf:
                byte_idx = random.randint(0, len(buf) - 1)
                bit_idx = random.randint(0, 7)
                buf[byte_idx] ^= 1 << bit_idx
        return bytes(buf)

    @staticmethod
    def byte_replace(data: bytes) -> bytes:
        if not data:
            return data
        buf = bytearray(data)
        idx = random.randint(0, len(buf) - 1)
        strategy = random.choice(["zero", "max", "random", "neighbor"])
        if strategy == "zero":
            buf[idx] = 0x00
        elif strategy == "max":
            buf[idx] = 0xFF
        elif strategy == "random":
            buf[idx] = random.randint(0, 255)
        elif strategy == "neighbor" and idx > 0:
            buf[idx] = buf[idx - 1]
        return bytes(buf)

    @staticmethod
    def boundary(data: bytes) -> bytes:
        boundaries = [0x00, 0x01, 0x7E, 0x7F, 0x80, 0x81, 0xFE, 0xFF]
        if not data:
            return bytes([random.choice(boundaries)])
        buf = bytearray(data)
        idx = random.randint(0, len(buf) - 1)
        buf[idx] = random.choice(boundaries)
        return bytes(buf)

    @staticmethod
    def overflow(data: bytes) -> bytes:
        overflow_sizes = [0, 1, 16, 64, 128, 255, 256, 512, 1024]
        size = random.choice(overflow_sizes)
        if size == 0:
            return b""
        return data + os.urandom(min(size, 1024))

    @staticmethod
    def truncation(data: bytes) -> bytes:
        if not data:
            return data
        cuts = [0, 1, len(data) // 2, len(data) - 1]
        cut = random.choice(cuts)
        return data[:cut]

    @staticmethod
    def repeat(data: bytes) -> bytes:
        if not data:
            return data * 10
        repeat_count = random.randint(2, 20)
        return data * repeat_count

    @staticmethod
    def random_payload(max_len: int = 256) -> bytes:
        size = random.randint(0, max_len)
        return os.urandom(size)

    @staticmethod
    def format_string(data: bytes) -> bytes:
        fmt_strings = [b"%s%s%s%s", b"%n%n%n%n", b"%x%x%x%x", b"AAAA%n", b"\x00%n"]
        return random.choice(fmt_strings)

    @staticmethod
    def null_inject(data: bytes) -> bytes:
        if not data:
            return b"\x00"
        buf = bytearray(data)
        pos = random.randint(0, len(buf) - 1)
        buf.insert(pos, 0x00)
        return bytes(buf)

    @staticmethod
    def type_confusion(data: bytes, target_type: int = 0) -> bytes:
        type_sizes = {0x10: 1, 0x20: 1, 0x21: 2, 0x22: 4, 0x23: 8, 0x28: 1, 0x29: 2, 0x2A: 4}
        size = type_sizes.get(target_type, len(data))
        return os.urandom(size)

    @classmethod
    def mutate(cls, data: bytes, strategy: Optional[str] = None) -> Tuple[bytes, str]:
        if strategy is None:
            strategy = random.choice(MUTATION_STRATEGIES)
        methods = {
            "bit_flip": cls.bit_flip,
            "byte_replace": cls.byte_replace,
            "boundary": cls.boundary,
            "overflow": cls.overflow,
            "truncation": cls.truncation,
            "repeat": cls.repeat,
            "random_payload": cls.random_payload,
            "format_string": cls.format_string,
            "null_inject": cls.null_inject,
            "type_confusion": cls.type_confusion,
        }
        method = methods.get(strategy, cls.random_payload)
        if strategy == "random_payload":
            result = method()
        elif strategy == "format_string":
            result = method(data)
        elif strategy == "type_confusion":
            result = method(data, random.randint(0x10, 0x2B))
        else:
            result = method(data)
        return result, strategy


class CrashDetector:
    """Detect anomalies in device responses that indicate crashes."""

    def __init__(self):
        self.baseline_responses: Dict[int, List[bytes]] = defaultdict(list)
        self.crashes: List[dict] = []
        self.response_hashes: Counter = Counter()
        self.no_response_count = 0
        self.timeout_count = 0
        self.error_responses: List[dict] = []

    def record_baseline(self, cluster_id: int, response: bytes):
        self.baseline_responses[cluster_id].append(response)
        h = hashlib.md5(response).hexdigest()
        self.response_hashes[h] += 1

    def check_for_anomaly(self, cluster_id: int, response: Optional[bytes], fuzz_params: dict) -> Optional[dict]:
        if response is None:
            self.no_response_count += 1
            self.timeout_count += 1
            if self.timeout_count > 10:
                anomaly = {
                    "type": "SUSPECTED_CRASH",
                    "reason": "Multiple consecutive timeouts",
                    "cluster": hex(cluster_id),
                    "params": fuzz_params,
                    "timestamp": time.time(),
                }
                self.crashes.append(anomaly)
                return anomaly
            return None
        self.timeout_count = 0
        if len(response) == 0:
            anomaly = {
                "type": "EMPTY_RESPONSE",
                "reason": "Empty response received",
                "cluster": hex(cluster_id),
                "params": fuzz_params,
                "timestamp": time.time(),
            }
            self.crashes.append(anomaly)
            return anomaly
        if len(response) > 200:
            anomaly = {
                "type": "OVERSIZED_RESPONSE",
                "reason": f"Response size {len(response)} exceeds 200 bytes",
                "cluster": hex(cluster_id),
                "params": fuzz_params,
                "timestamp": time.time(),
            }
            self.crashes.append(anomaly)
            return anomaly
        h = hashlib.md5(response).hexdigest()
        self.response_hashes[h] += 1
        baseline = self.baseline_responses.get(cluster_id, [])
        if baseline and response not in baseline:
            anomaly = {
                "type": "UNEXPECTED_RESPONSE",
                "reason": "Response differs from baseline",
                "cluster": hex(cluster_id),
                "params": fuzz_params,
                "response_preview": response[:50].hex(),
                "timestamp": time.time(),
            }
            self.error_responses.append(anomaly)
            return None
        return None

    def summary(self) -> dict:
        return {
            "total_crashes": len(self.crashes),
            "crashes": self.crashes,
            "total_errors": len(self.error_responses),
            "timeouts": self.timeout_count,
            "unique_responses": len(self.response_hashes),
        }


class ZigbeeZclFuzzer:
    """Main Zigbee ZCL attribute fuzzer."""

    def __init__(self, target_short: int = 0x0000, target_ext: int = 0x0000000000000000,
                 seed: Optional[int] = None):
        self.target_short = target_short
        self.target_ext = target_ext
        self.seed = seed
        self.frame_builder = ZclFrame()
        self.mutator = MutationEngine()
        self.crash_detector = CrashDetector()
        self.sent_packets: List[bytes] = []
        self.received_packets: List[bytes] = []
        self.test_log: List[dict] = []

    def fuzz_cluster_read(self, cluster_id: int, iterations: int = 100) -> dict:
        results = {"cluster": ZCL_CLUSTERS.get(cluster_id, hex(cluster_id)), "iterations": 0, "responses": 0, "anomalies": 0}
        attrs = list(range(0x0000, 0x0100))
        print(f"  Fuzzing cluster {results['cluster']} ({hex(cluster_id)}) - {iterations} iterations")
        for i in range(iterations):
            num_attrs = random.randint(1, min(10, len(attrs)))
            selected = random.sample(attrs, num_attrs)
            if random.random() < 0.3:
                selected.append(random.randint(0x0000, 0xFFFF))
            frame = self.frame_builder.build_read_attributes(cluster_id, selected)
            self.sent_packets.append(frame)
            response = self._simulate_response(cluster_id, selected)
            anomaly = self.crash_detector.check_for_anomaly(
                cluster_id,
                response,
                {"iteration": i, "attributes": [hex(a) for a in selected]},
            )
            results["iterations"] += 1
            if response:
                results["responses"] += 1
            if anomaly:
                results["anomalies"] += 1
                print(f"    [!] ANOMALY: {anomaly['type']} - {anomaly['reason']}")
        return results

    def fuzz_cluster_write(self, cluster_id: int, iterations: int = 100) -> dict:
        results = {"cluster": ZCL_CLUSTERS.get(cluster_id, hex(cluster_id)), "iterations": 0, "mutations": defaultdict(int)}
        data_types = list(ZCL_DATA_TYPES.keys())
        print(f"  Fuzzing write on {results['cluster']} - {iterations} iterations")
        for i in range(iterations):
            attr_id = random.randint(0x0000, 0x0FFF)
            data_type = random.choice(data_types)
            type_name, type_size = ZCL_DATA_TYPES.get(data_type, ("Unknown", 1))
            if type_size > 0:
                original = os.urandom(type_size)
            else:
                original = os.urandom(random.randint(1, 64))
            mutated, strategy = self.mutator.mutate(original)
            frame = self.frame_builder.build_write_attributes(cluster_id, attr_id, data_type, mutated)
            self.sent_packets.append(frame)
            results["mutations"][strategy] += 1
            response = self._simulate_response(cluster_id, [])
            anomaly = self.crash_detector.check_for_anomaly(
                cluster_id,
                response,
                {"iteration": i, "attr": hex(attr_id), "strategy": strategy, "type": type_name},
            )
            results["iterations"] += 1
            if anomaly:
                print(f"    [!] ANOMALY: {anomaly['type']} ({strategy})")
        results["mutations"] = dict(results["mutations"])
        return results

    def fuzz_discover(self, cluster_id: int, iterations: int = 50) -> dict:
        results = {"cluster": ZCL_CLUSTERS.get(cluster_id, hex(cluster_id)), "iterations": 0, "discoveries": 0}
        print(f"  Fuzzing discover on {results['cluster']} - {iterations} iterations")
        for i in range(iterations):
            start_attr = random.randint(0x0000, 0xFFFF)
            max_attrs = random.choice([0, 1, 10, 50, 128, 255])
            frame = self.frame_builder.build_discover_attributes(cluster_id, start_attr, max_attrs)
            self.sent_packets.append(frame)
            response = self._simulate_response(cluster_id, [])
            anomaly = self.crash_detector.check_for_anomaly(
                cluster_id,
                response,
                {"iteration": i, "start": hex(start_attr), "max": max_attrs},
            )
            results["iterations"] += 1
            if response and len(response) > 0:
                results["discoveries"] += 1
        return results

    def fuzz_all_clusters(self, iterations_per: int = 20, seed: Optional[int] = None) -> dict:
        if seed is not None:
            random.seed(seed)
        elif self.seed is not None:
            random.seed(self.seed)
        print(f"\n{'='*60}")
        print(f"  I3 - Zigbee ZCL Attribute Fuzzer")
        print(f"  Target: short={hex(self.target_short)}, ext={hex(self.target_ext)}")
        print(f"{'='*60}")
        all_results = {}
        for cluster_id, cluster_name in ZCL_CLUSTERS.items():
            print(f"\n  [Cluster] {cluster_name} ({hex(cluster_id)})")
            r = self.fuzz_cluster_read(cluster_id, iterations_per)
            all_results[cluster_id] = {"name": cluster_name, "read": r}
        print(f"\n{'='*60}")
        print(f"  Phase 2: Write Attribute Mutation")
        print(f"{'='*60}")
        target_clusters = [0x0000, 0x0006, 0x0008, 0x0402, 0x0500]
        for cid in target_clusters:
            name = ZCL_CLUSTERS.get(cid, hex(cid))
            print(f"\n  [Write Fuzz] {name}")
            wr = self.fuzz_cluster_write(cid, iterations_per * 2)
            all_results[cid]["write"] = wr
        print(f"\n{'='*60}")
        print(f"  Phase 3: Discover Attributes Fuzzing")
        print(f"{'='*60}")
        for cid in target_clusters:
            name = ZCL_CLUSTERS.get(cid, hex(cid))
            print(f"\n  [Discover Fuzz] {name}")
            disc = self.fuzz_discover(cid, iterations_per)
            all_results[cid]["discover"] = disc
        summary = self.crash_detector.summary()
        print(f"\n{'='*60}")
        print(f"  Crash Detection Summary")
        print(f"{'='*60}")
        print(f"  Total crashes:    {summary['total_crashes']}")
        print(f"  Total errors:     {summary['total_errors']}")
        print(f"  Unique responses: {summary['unique_responses']}")
        if summary["crashes"]:
            print(f"\n  --- Crash Details ---")
            for c in summary["crashes"][:10]:
                print(f"    [{c['type']}] {c['reason']} at cluster {c['cluster']}")
        print(f"\n  Packets sent:     {len(self.sent_packets)}")
        print(f"{'='*60}")
        return {"clusters": all_results, "summary": summary, "packets_sent": len(self.sent_packets)}

    def _simulate_response(self, cluster_id: int, attrs: List[int]) -> Optional[bytes]:
        if random.random() < 0.05:
            return None
        if random.random() < 0.03:
            return b""
        payload = bytearray()
        for attr_id in attrs:
            status = 0x00 if random.random() > 0.1 else 0x86
            payload.extend(struct.pack("<H", attr_id))
            payload.append(status)
            if status == 0x00:
                data_type = random.choice([0x20, 0x21, 0x28])
                payload.append(data_type)
                type_size = ZCL_DATA_TYPES.get(data_type, ("Unknown", 1))[1]
                payload.extend(os.urandom(type_size))
        resp_header = bytes([0x18, 0x01, random.randint(0, 255), 0x01])
        return resp_header + bytes(payload)


def run_demo(report_dir: str = "reports", seed: int = 42) -> int:
    """Offline demo: seeded ZCL fuzz sweep, JSON report written. Exit 0."""
    os.makedirs(report_dir, exist_ok=True)
    fuzzer = ZigbeeZclFuzzer(target_short=0x1234, target_ext=0x0011223344556677)
    results = fuzzer.fuzz_all_clusters(iterations_per=3, seed=seed)
    report = os.path.join(report_dir, "i3_demo_report.json")
    with open(report, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"[*] JSON report written: {report}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="zigbee_fuzzer",
        description="I3 — Zigbee ZCL attribute fuzzer (frame build, mutation, crash detection).")
    parser.add_argument("--short-addr", type=lambda v: int(v, 0), default=0x1234,
                        help="target short address (hex)")
    parser.add_argument("--ext-addr", type=lambda v: int(v, 0), default=0x0011223344556677,
                        help="target extended address (hex)")
    parser.add_argument("--iterations", type=int, default=3, help="iterations per cluster")
    parser.add_argument("--seed", type=int, default=42, help="RNG seed for deterministic sweeps")
    parser.add_argument("--json", action="store_true", help="write JSON report to reports/")
    parser.add_argument("--report-dir", default="reports", help="report dir (default: reports)")
    parser.add_argument("--demo", action="store_true", help="run seeded offline demo and exit")
    args = parser.parse_args()

    if args.demo:
        return run_demo(args.report_dir, args.seed)

    fuzzer = ZigbeeZclFuzzer(target_short=args.short_addr, target_ext=args.ext_addr, seed=args.seed)
    results = fuzzer.fuzz_all_clusters(iterations_per=args.iterations, seed=args.seed)

    if args.json:
        os.makedirs(args.report_dir, exist_ok=True)
        report = os.path.join(args.report_dir, "i3_report.json")
        with open(report, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"[*] JSON report written: {report}")
    return 0


if __name__ == "__main__":
    main()
