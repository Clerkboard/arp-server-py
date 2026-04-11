#!/usr/bin/env python3
"""JCS canonicalization test vectors from ACP spec Appendix D."""

import json
import sys

from acp_crypto import canonicalize

# ---------------------------------------------------------------------------
# Vectors
# ---------------------------------------------------------------------------

VECTORS = [
    {
        "name": "Vector 1 -- Key ordering",
        "input": {
            "type": "request",
            "acp": "1.0",
            "to": "did:web:b.com:agent",
            "id": "msg_001",
            "from": "did:web:a.com:agent",
            "createdAt": "2026-04-12T00:00:00Z",
            "body": {"text": "hello"},
        },
        "expected": '{"acp":"1.0","body":{"text":"hello"},"createdAt":"2026-04-12T00:00:00Z","from":"did:web:a.com:agent","id":"msg_001","to":"did:web:b.com:agent","type":"request"}',
    },
    {
        "name": "Vector 2 -- Numerics and nesting",
        "input": {
            "count": 1,
            "rate": 0.5,
            "nested": {"z": True, "a": False},
            "list": [3, 1, 2],
        },
        "expected": '{"count":1,"list":[3,1,2],"nested":{"a":false,"z":true},"rate":0.5}',
    },
    {
        "name": "Vector 3 -- Unicode",
        "input": {
            "emoji": "\u2615",
            "path": "/donn\u00e9es/caf\u00e9",
            "null_val": None,
            "empty": "",
        },
        "expected": '{"emoji":"\u2615","empty":"","null_val":null,"path":"/donn\u00e9es/caf\u00e9"}',
    },
]

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

passed = 0
failed = 0

for v in VECTORS:
    result = canonicalize(v["input"])
    if result == v["expected"]:
        passed += 1
        print(f"  PASS  {v['name']}")
    else:
        failed += 1
        print(f"  FAIL  {v['name']}")
        print(f"         got:      {result}")
        print(f"         expected: {v['expected']}")

total = passed + failed
print(f"\n{passed}/{total} vectors passed")

sys.exit(1 if failed else 0)
