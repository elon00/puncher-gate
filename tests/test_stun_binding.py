"""Implementation-coupled offline positive and adversarial STUN parser tests."""

import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "stun_binding.py"
spec = importlib.util.spec_from_file_location("stun_binding", MODULE_PATH)
stun = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stun)
TX = bytes(range(12))
COOKIE = struct.pack("!I", stun.MAGIC_COOKIE)


def packet(*, address=(203, 0, 113, 8), port=3478, tx=TX, cookie=COOKIE,
           attr_type=stun.XOR_MAPPED_ADDRESS, attr_value=None, msg_type=stun.BINDING_SUCCESS):
    if attr_value is None:
        value = b"\x00\x01" + struct.pack("!H", port ^ (stun.MAGIC_COOKIE >> 16))
        value += bytes(x ^ y for x, y in zip(address, cookie))
    else:
        value = attr_value
    attr = struct.pack("!HH", attr_type, len(value)) + value
    attr += b"\x00" * (-len(value) % 4)
    return struct.pack("!HH", msg_type, len(attr)) + cookie + tx + attr


class BindingSuccessTests(unittest.TestCase):
    def assert_invalid(self, data, expected_tx=TX):
        with self.assertRaises(stun.StunParseError):
            stun.parse_binding_success(data, expected_tx)

    def test_valid_ipv4_response(self):
        self.assertEqual(stun.parse_binding_success(packet(), TX), {"address": "203.0.113.8", "port": 3478})

    def test_second_endpoint(self):
        self.assertEqual(stun.parse_binding_success(packet(address=(198, 51, 100, 9), port=65000), TX),
                         {"address": "198.51.100.9", "port": 65000})

    def test_reject_short_header(self):
        self.assert_invalid(packet()[:19])

    def test_reject_extra_trailing_bytes(self):
        self.assert_invalid(packet() + b"\x00")

    def test_reject_wrong_cookie(self):
        self.assert_invalid(packet()[:4] + b"\x00\x00\x00\x00" + packet()[8:])

    def test_reject_wrong_transaction_id(self):
        self.assert_invalid(packet(), b"x" * 12)

    def test_reject_short_expected_transaction_id(self):
        self.assert_invalid(packet(), b"x")

    def test_reject_non_success_message(self):
        self.assert_invalid(packet(msg_type=0x0001))

    def test_reject_bad_message_length(self):
        p = bytearray(packet())
        p[2:4] = b"\x00\x09"
        self.assert_invalid(bytes(p))

    def test_reject_truncated_attribute(self):
        p = bytearray(packet())
        p[22:24] = b"\x00\x20"
        self.assert_invalid(bytes(p))

    def test_reject_duplicate_mapped_attribute(self):
        p = packet()
        attrs = p[20:]
        self.assert_invalid(p[:2] + struct.pack("!H", len(attrs) * 2) + p[4:20] + attrs + attrs)

    def test_reject_missing_mapped_attribute(self):
        self.assert_invalid(packet(attr_type=0x8022))

    def test_reject_unknown_required_attribute(self):
        self.assert_invalid(packet(attr_type=0x0015))

    def test_reject_ipv6_family(self):
        self.assert_invalid(packet(attr_value=b"\x00\x02" + b"\x00" * 6))

    def test_reject_zero_port(self):
        self.assert_invalid(packet(port=0))

    def test_reject_multicast(self):
        self.assert_invalid(packet(address=(224, 0, 0, 1)))

    def test_cli_positive(self):
        p = subprocess.run([sys.executable, str(MODULE_PATH), "--packet-hex", packet().hex(),
                            "--transaction-id-hex", TX.hex()], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout), {"address": "203.0.113.8", "port": 3478})

    def test_cli_rejects_tampering(self):
        p = subprocess.run([sys.executable, str(MODULE_PATH), "--packet-hex", packet().hex(),
                            "--transaction-id-hex", (b"x" * 12).hex()], capture_output=True, text=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("STUN_PARSE_ERROR", p.stderr)


if __name__ == "__main__":
    unittest.main()
