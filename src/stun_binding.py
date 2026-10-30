"""Strict offline STUN Binding Success response parser (IPv4 only).

No socket, NAT traversal, authentication, or cryptographic validation is performed.
RFC 8489 framing and XOR-MAPPED-ADDRESS are parsed for test-fixture verification.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import struct

MAGIC_COOKIE = 0x2112A442
BINDING_SUCCESS = 0x0101
XOR_MAPPED_ADDRESS = 0x0020


class StunParseError(ValueError):
    """Malformed or unsupported STUN response."""


def parse_binding_success(packet: bytes, expected_transaction_id: bytes) -> dict[str, str | int]:
    """Return IPv4 address/port for a matching Binding Success response.

    This is a *format parser*, not an authenticated response validator. Callers
    must separately establish a trusted response source and transaction context.
    """
    if len(expected_transaction_id) != 12:
        raise StunParseError("expected transaction ID must be 12 bytes")
    if len(packet) < 20:
        raise StunParseError("truncated STUN header")
    message_type, message_length, cookie = struct.unpack_from("!HHI", packet)
    if message_type != BINDING_SUCCESS:
        raise StunParseError("not a STUN Binding Success response")
    if cookie != MAGIC_COOKIE:
        raise StunParseError("invalid STUN magic cookie")
    if message_length % 4 or len(packet) != 20 + message_length:
        raise StunParseError("invalid STUN message length")
    if packet[8:20] != expected_transaction_id:
        raise StunParseError("transaction ID mismatch")

    offset = 20
    mapped = None
    while offset < len(packet):
        if offset + 4 > len(packet):
            raise StunParseError("truncated attribute header")
        attribute_type, attribute_length = struct.unpack_from("!HH", packet, offset)
        offset += 4
        padded_length = (attribute_length + 3) & ~3
        if offset + padded_length > len(packet):
            raise StunParseError("truncated attribute value")
        value = packet[offset:offset + attribute_length]
        offset += padded_length
        if attribute_type == XOR_MAPPED_ADDRESS:
            if mapped is not None:
                raise StunParseError("duplicate XOR-MAPPED-ADDRESS")
            if len(value) != 8 or value[0] != 0 or value[1] != 1:
                raise StunParseError("invalid or unsupported XOR-MAPPED-ADDRESS")
            port = struct.unpack_from("!H", value, 2)[0] ^ (MAGIC_COOKIE >> 16)
            address_bytes = bytes(a ^ b for a, b in zip(value[4:8], struct.pack("!I", MAGIC_COOKIE)))
            address = ipaddress.IPv4Address(address_bytes)
            if port == 0 or address.is_unspecified or address.is_multicast:
                raise StunParseError("invalid mapped endpoint")
            mapped = {"address": str(address), "port": port}
        elif attribute_type < 0x8000:
            # Unrecognized comprehension-required attribute: fail closed.
            raise StunParseError("unknown comprehension-required attribute")
    if mapped is None:
        raise StunParseError("missing XOR-MAPPED-ADDRESS")
    return mapped


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline STUN Binding Success fixture validator")
    parser.add_argument("--packet-hex", required=True)
    parser.add_argument("--transaction-id-hex", required=True)
    args = parser.parse_args()
    try:
        packet = bytes.fromhex(args.packet_hex)
        transaction_id = bytes.fromhex(args.transaction_id_hex)
        result = parse_binding_success(packet, transaction_id)
    except (ValueError, StunParseError) as exc:
        parser.exit(2, f"STUN_PARSE_ERROR: {exc}\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
