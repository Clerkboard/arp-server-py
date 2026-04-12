#!/usr/bin/env python3
"""ARP test client -- sends signed messages to a local ARP server and verifies responses."""

from __future__ import annotations

import json
import sys
import urllib.request
import urllib.error
import uuid
from datetime import datetime, timezone, timedelta
from typing import Tuple

# We reuse crypto helpers from the project -- run from the project root.
from arp_crypto import (
    generate_keypair,
    public_key_to_multibase,
    sign_message,
    verify_signature,
    public_key_from_multibase,
    canonicalize,
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SERVER = "http://localhost:3142"
AGENT_NAME = "echo"
SENDER_NAME = "test-sender"
SENDER_DID = f"did:web:localhost:{SENDER_NAME}"
AGENT_DID = f"did:web:localhost:{AGENT_NAME}"
INBOX_URL = f"{SERVER}/{AGENT_NAME}/inbox"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

passed = 0
failed = 0


def msg_id() -> str:
    return f"msg_{uuid.uuid4().hex}"


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def expires_iso() -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


def send(envelope: dict) -> Tuple[int, dict]:
    """Send a signed ARP envelope to the server and return (status_code, response_body)."""
    data = json.dumps(envelope).encode("utf-8")
    req = urllib.request.Request(
        INBOX_URL,
        data=data,
        headers={
            "Content-Type": "application/arp+json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            body = json.loads(resp.read())
            return resp.status, body
    except urllib.error.HTTPError as e:
        body = json.loads(e.read())
        return e.code, body


def check(label: str, condition: bool, detail: str = "") -> None:
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS  {label}")
    else:
        failed += 1
        msg = f"  FAIL  {label}"
        if detail:
            msg += f"  -- {detail}"
        print(msg)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_discovery() -> None:
    """Test DID document and agent card endpoints."""
    print("\n--- Discovery ---")

    # DID document
    req = urllib.request.Request(f"{SERVER}/{AGENT_NAME}/did.json")
    with urllib.request.urlopen(req) as resp:
        doc = json.loads(resp.read())
    check("DID document returns id", doc.get("id") == AGENT_DID, f"got {doc.get('id')}")
    check(
        "DID document has verificationMethod",
        len(doc.get("verificationMethod", [])) > 0,
    )

    # Agent card
    req = urllib.request.Request(f"{SERVER}/.well-known/arp/{AGENT_NAME}.json")
    with urllib.request.urlopen(req) as resp:
        card = json.loads(resp.read())
    check("Agent card name", card.get("name") == AGENT_NAME)
    check("Agent card has publicKey", card.get("publicKey", "").startswith("z"))

    # Index
    req = urllib.request.Request(f"{SERVER}/.well-known/arp/index.json")
    with urllib.request.urlopen(req) as resp:
        index = json.loads(resp.read())
    check("Agent index lists agent", len(index.get("agents", [])) == 1)


def test_first_contact(private_key, pub_multibase: str, server_pub_multibase: str) -> None:
    """Send a first-contact negotiate message."""
    print("\n--- First Contact (negotiate) ---")

    envelope = {
        "arp": "1.0",
        "id": msg_id(),
        "type": "negotiate",
        "from": SENDER_DID,
        "to": AGENT_DID,
        "createdAt": now_iso(),
        "expiresAt": expires_iso(),
        "body": {
            "firstContact": True,
            "publicKey": pub_multibase,
        },
    }
    signed = sign_message(envelope, private_key)

    status, resp = send(signed)
    check("Status 200", status == 200, f"got {status}")
    check("Type is acknowledge", resp.get("type") == "acknowledge", f"got {resp.get('type')}")
    check("Body accepted", resp.get("body", {}).get("accepted") is True)

    # Verify server's signature on the response
    server_pub = public_key_from_multibase(server_pub_multibase)
    sig_valid = verify_signature(resp, server_pub)
    check("Server signature valid", sig_valid)


def test_echo(private_key, server_pub_multibase: str) -> None:
    """Send an echo request after first contact."""
    print("\n--- Echo Request ---")

    echo_body = {
        "greeting": "Hello, ARP!",
        "numbers": [1, 2, 3],
        "nested": {"key": "value"},
    }

    envelope = {
        "arp": "1.0",
        "id": msg_id(),
        "type": "request",
        "from": SENDER_DID,
        "to": AGENT_DID,
        "capability": "echo",
        "createdAt": now_iso(),
        "expiresAt": expires_iso(),
        "body": echo_body,
    }
    signed = sign_message(envelope, private_key)

    status, resp = send(signed)
    check("Status 200", status == 200, f"got {status}")
    check("Type is response", resp.get("type") == "response", f"got {resp.get('type')}")
    check("Body echoed back", resp.get("body", {}).get("echo") == echo_body, f"got {resp.get('body')}")

    # Verify server signature
    server_pub = public_key_from_multibase(server_pub_multibase)
    sig_valid = verify_signature(resp, server_pub)
    check("Server signature valid", sig_valid)


def test_unknown_capability(private_key) -> None:
    """Send a request for an unknown capability."""
    print("\n--- Unknown Capability ---")

    envelope = {
        "arp": "1.0",
        "id": msg_id(),
        "type": "request",
        "from": SENDER_DID,
        "to": AGENT_DID,
        "capability": "nonexistent",
        "createdAt": now_iso(),
        "expiresAt": expires_iso(),
        "body": {},
    }
    signed = sign_message(envelope, private_key)

    status, resp = send(signed)
    check("Status 200", status == 200, f"got {status}")
    check("Type is error", resp.get("type") == "error", f"got {resp.get('type')}")
    check(
        "Error code CAPABILITY_UNKNOWN",
        resp.get("body", {}).get("code") == "CAPABILITY_UNKNOWN",
        f"got {resp.get('body', {}).get('code')}",
    )


def test_duplicate_rejection(private_key) -> None:
    """Send the same message ID twice to test idempotency."""
    print("\n--- Duplicate Rejection ---")

    fixed_id = msg_id()
    envelope = {
        "arp": "1.0",
        "id": fixed_id,
        "type": "request",
        "from": SENDER_DID,
        "to": AGENT_DID,
        "capability": "echo",
        "createdAt": now_iso(),
        "expiresAt": expires_iso(),
        "body": {"test": "duplicate"},
    }
    signed = sign_message(envelope, private_key)

    # First send should succeed
    status1, _ = send(signed)
    check("First send succeeds", status1 == 200, f"got {status1}")

    # Second send with same ID should be rejected
    status2, resp2 = send(signed)
    check("Duplicate rejected with 409", status2 == 409, f"got {status2}")


def test_first_contact_required() -> None:
    """Send a request from an unknown DID without negotiating first."""
    print("\n--- First Contact Required ---")

    stranger_key, stranger_pub = generate_keypair()
    stranger_did = "did:web:localhost:stranger"
    pub_mb = public_key_to_multibase(stranger_pub)

    envelope = {
        "arp": "1.0",
        "id": msg_id(),
        "type": "request",
        "from": stranger_did,
        "to": AGENT_DID,
        "capability": "echo",
        "createdAt": now_iso(),
        "expiresAt": expires_iso(),
        "body": {"publicKey": pub_mb, "test": "should fail"},
    }
    signed = sign_message(envelope, stranger_key)

    status, resp = send(signed)
    check("Status 403", status == 403, f"got {status}")
    check(
        "Error code FIRST_CONTACT_REQUIRED",
        resp.get("body", {}).get("code") == "FIRST_CONTACT_REQUIRED",
        f"got {resp.get('body', {}).get('code')}",
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    global passed, failed

    print("ARP Test Client")
    print(f"Target: {INBOX_URL}")
    print()

    # Generate test sender key pair
    private_key, public_key = generate_keypair()
    pub_multibase = public_key_to_multibase(public_key)
    print(f"Sender DID   : {SENDER_DID}")
    print(f"Sender PubKey: {pub_multibase}")

    # Fetch server's public key from agent card
    req = urllib.request.Request(f"{SERVER}/.well-known/arp/{AGENT_NAME}.json")
    with urllib.request.urlopen(req) as resp:
        card = json.loads(resp.read())
    server_pub_multibase = card["publicKey"]
    print(f"Server PubKey: {server_pub_multibase}")

    # Run tests
    test_discovery()
    test_first_contact(private_key, pub_multibase, server_pub_multibase)
    test_echo(private_key, server_pub_multibase)
    test_unknown_capability(private_key)
    test_duplicate_rejection(private_key)
    test_first_contact_required()

    # Summary
    total = passed + failed
    print(f"\n{'=' * 40}")
    print(f"Results: {passed}/{total} passed", end="")
    if failed:
        print(f", {failed} FAILED")
    else:
        print(" -- ALL PASSED")
    print(f"{'=' * 40}")

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
