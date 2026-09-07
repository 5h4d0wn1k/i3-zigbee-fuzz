#!/usr/bin/env python3
"""Deterministic offline tests for I3 — Zigbee ZCL fuzzer."""

import json
import os
import random
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import zigbee_fuzzer as i3
from zigbee_fuzzer import (
    MutationEngine, ZclFrame, CrashDetector, ZigbeeZclFuzzer, run_demo)


class TestZclFrames(unittest.TestCase):
    # Builder layout: [fc][man][seq_lo][seq_hi][cmd][clu_lo][clu_hi] then payload
    def test_read_attributes_frame_shape(self):
        frame = ZclFrame.build_read_attributes(0x0006, [0x0000, 0x0101])
        self.assertEqual(frame[0], 0x00)
        self.assertEqual(frame[4], 0x00)  # command = read attributes
        self.assertEqual(frame[5], 0x06)  # cluster low
        self.assertEqual(frame[6], 0x00)  # cluster high
        payload = frame[7:]
        self.assertEqual(struct.unpack("<H", payload[0:2])[0], 0x0000)
        self.assertEqual(struct.unpack("<H", payload[2:4])[0], 0x0101)

    def test_write_attributes_contains_datatype_and_value(self):
        frame = ZclFrame.build_write_attributes(0x0006, 0x0000, 0x20, b"\x01")
        self.assertEqual(frame[0], 0x04)  # frame control + write-disable-response
        self.assertEqual(frame[4], 0x02)  # write command
        self.assertEqual(frame[7:9], b"\x00\x00")  # attr id
        self.assertEqual(frame[9], 0x20)  # unsigned 8-bit
        self.assertEqual(frame[10], 0x01)  # value

    def test_discover_attributes_command(self):
        frame = ZclFrame.build_discover_attributes(0x0000, 0x0000)
        self.assertEqual(frame[4], 0x0C)
        self.assertEqual(frame[7:9], b"\x00\x00")

    def test_parse_response_command_detection(self):
        resp = bytes([0x18, 0x01, 0x7F, 0x01]) + b"\x00\x00\x00"
        parsed = ZclFrame.parse_response(resp)
        self.assertEqual(parsed["command_name"], "Read Attributes Response")
        self.assertEqual(parsed["length"], 7)
        self.assertEqual(parsed["command_id"], 0x01)

    def test_parse_response_write(self):
        resp = bytes([0x18, 0x01, 0x7F, 0x03]) + b"\x00"
        parsed = ZclFrame.parse_response(resp)
        self.assertEqual(parsed["command_name"], "Write Attributes Response")
        self.assertEqual(parsed["cluster_id"], hex(0x037f))


class TestMutationEngine(unittest.TestCase):
    def test_all_strategies_run(self):
        for strategy in i3.MUTATION_STRATEGIES:
            random.seed(7)
            data = b"\x00\x01\x02\x03"
            out, name = MutationEngine.mutate(data, strategy)
            self.assertEqual(name, strategy)
            self.assertIsInstance(out, bytes)

    def test_deterministic_with_seed(self):
        random.seed(1234)
        a, _ = MutationEngine.mutate(b"abcdef", "bit_flip")
        random.seed(1234)
        b, _ = MutationEngine.mutate(b"abcdef", "bit_flip")
        self.assertEqual(a, b)

    def test_bit_flip_one_byte_change(self):
        random.seed(7)
        original = b"\x00\x01\x02\x03\x04"
        mutated = MutationEngine.bit_flip(original, 1)
        diff = sum(1 for x, y in zip(original, mutated) if x != y)
        self.assertEqual(diff, 1)

    def test_boundary_values(self):
        random.seed(3)
        out = MutationEngine.boundary(b"\x10")
        self.assertIn(out[0], [0x00, 0x01, 0x7E, 0x7F, 0x80, 0x81, 0xFE, 0xFF])

    def test_truncation_never_grows(self):
        data = b"\x00\x01\x02\x03\x04\x05"
        for seed in range(20):
            random.seed(seed)
            self.assertTrue(len(MutationEngine.truncation(data)) <= len(data))

    def test_overflow_appends_data(self):
        random.seed(1)
        out = MutationEngine.overflow(b"\x01\x02")
        self.assertGreaterEqual(len(out), 2)


class TestCrashDetector(unittest.TestCase):
    def test_baseline_then_unexpected(self):
        cd = CrashDetector()
        cd.record_baseline(0x0006, b"good-response")
        anomaly = cd.check_for_anomaly(0x0006, b"different", {"n": 1})
        self.assertIsNone(anomaly)
        self.assertEqual(len(cd.error_responses), 1)

    def test_oversized_response_tracked(self):
        cd = CrashDetector()
        cd.record_baseline(0x0000, b"ok")
        anomaly = cd.check_for_anomaly(0x0000, b"\x00" * 300, {"n": 1})
        self.assertEqual(anomaly["type"], "OVERSIZED_RESPONSE")

    def test_timeouts_accumulate_crash(self):
        cd = CrashDetector()
        anomaly = None
        for i in range(12):
            anomaly = cd.check_for_anomaly(0x0000, None, {"n": i})
            if anomaly:
                break
        self.assertIsNotNone(anomaly)
        self.assertEqual(anomaly["type"], "SUSPECTED_CRASH")
        self.assertGreaterEqual(cd.summary()["total_crashes"], 1)

    def test_no_response_does_not_crash_immediately(self):
        cd = CrashDetector()
        self.assertIsNone(cd.check_for_anomaly(0x0000, None, {"n": 1}))


class TestFuzzerDeterministic(unittest.TestCase):
    def test_seeded_sweep_reproducible(self):
        fuzzer_a = ZigbeeZclFuzzer()
        r_a = fuzzer_a.fuzz_all_clusters(iterations_per=2, seed=99)
        fuzzer_b = ZigbeeZclFuzzer()
        r_b = fuzzer_b.fuzz_all_clusters(iterations_per=2, seed=99)
        self.assertEqual(len(r_a["clusters"]), len(r_b["clusters"]))
        self.assertEqual(r_a["packets_sent"], r_b["packets_sent"])
        self.assertEqual(r_a["summary"]["unique_responses"],
                         r_b["summary"]["unique_responses"])

    def test_write_mutations_counted(self):
        fuzzer = ZigbeeZclFuzzer()
        res = fuzzer.fuzz_cluster_write(0x0006, iterations=10)
        self.assertEqual(res["iterations"], 10)
        self.assertGreater(sum(res["mutations"].values()), 0)

    def test_write_covers_multiple_strategies(self):
        fuzzer = ZigbeeZclFuzzer()
        res = fuzzer.fuzz_cluster_write(0x0006, iterations=40)
        self.assertGreaterEqual(len(res["mutations"]), 3)


class TestDemo(unittest.TestCase):
    def test_demo_exits_zero_with_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = run_demo(os.path.join(tmp, "reports"), seed=42)
            self.assertEqual(rc, 0)
            report = os.path.join(tmp, "reports", "i3_demo_report.json")
            self.assertTrue(os.path.exists(report))
            with open(report) as f:
                data = json.load(f)
            self.assertIn("summary", data)
            self.assertIn("packets_sent", data)
            self.assertGreater(data["packets_sent"], 0)
            self.assertTrue(any(cid in data["clusters"] for cid in ("0", "6", "520")))


if __name__ == "__main__":
    unittest.main()