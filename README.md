# Puncher Gate — offline STUN fixture validation

This QMOOSA-1000 **Batch 183 / tests** component provides a bounded, genuine offline parser for STUN Binding Success responses carrying an IPv4 XOR-MAPPED-ADDRESS attribute. It does **not** establish a live NAT traversal implementation, authenticated peer identity, packet-source authenticity, an RFC 8489-complete STUN stack, PQC/FIPS validation, or production readiness.

## Verify locally (no keys, network calls, paid services or deployment)

```bash
python -m compileall -q src tests
python -m unittest discover -s tests -p 'test_*.py' -v
python tests/reality_check_harness.py
cargo fmt --all -- --check
cargo test --all-targets
```

The Python tests construct valid and adversarial STUN fixtures, invoke the real parser, check transaction-ID matching and bounds handling, and exercise the command-line interface. `src/main.rs` is a diagnostic message only; it does not provide a NAT implementation.

## Scope and limitations

- Strict offline STUN Binding Success (`0x0101`) framing and magic-cookie checks.
- IPv4 XOR-MAPPED-ADDRESS decoding, length and duplicate checks, expected transaction ID checks, malformed and unsupported attribute rejection.
- Unknown comprehension-required attributes are rejected. Unknown comprehension-optional attributes may be skipped. IPv6 is not supported.
- A matched transaction ID is **not** message authentication. The parser does not validate MESSAGE-INTEGRITY, FINGERPRINT, remote endpoints, source addresses or timing. Never treat its output as trusted network identity or connectivity proof.
- No external network, live RPC, real cryptography, x402 settlement, or mainnet/testnet action is performed.
- The pre-existing `ARCHITECTURE.md` is an aspirational blueprint, not implemented evidence. Any `100/100`, FIPS or production claim in historical documents is not substantiated.

## Acceptance gates

CI must run the implementation-coupled regression suite and Python CodeQL. Green CI is necessary but insufficient for security approval. A production STUN/NAT traversal product additionally needs real network integration tests, authentication and spoofing threat analysis, RFC conformance, resource limits, independent review and deployment-specific acceptance. Keep deployment blocked.
