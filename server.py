"""ARP Reference Server -- FastAPI implementation of the Agent Relations Protocol (v0.4.0).

Routes:

  GET  /{name}/did.json              -- DID document
  GET  /.well-known/arp/{name}.json  -- Agent Card
  GET  /.well-known/arp/index.json   -- Agent directory
  GET  /agents.txt                   -- Discovery hint file
  POST /{name}/inbox                 -- Message inbox
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from typing import Any, Optional
from urllib.parse import urlparse

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from arp_crypto import (
    KeyManager,
    canonicalize,
    multibase_decode,
    public_key_from_multibase,
    sign_message,
    verify_signature,
)
from arp_store import IdempotencyStore, RelationStore

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

load_dotenv()

AGENT_NAME = os.getenv("ARP_AGENT_NAME", "echo")
DOMAIN = os.getenv("ARP_DOMAIN", "localhost")
PORT = int(os.getenv("ARP_PORT", "3142"))
DATA_DIR = os.getenv("ARP_DATA_DIR", "./data")

MAX_BODY_SIZE = 1_048_576  # 1 MB

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger("arp.server")

# Open capabilities -- accept requests without a first-contact handshake
OPEN_CAPABILITIES: set[str] = {"echo"}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _scheme() -> str:
    """Return http for localhost, https otherwise."""
    return "http" if DOMAIN == "localhost" else "https"


def _base_url() -> str:
    """Build the base URL including port when running on localhost."""
    scheme = _scheme()
    if DOMAIN == "localhost":
        return f"{scheme}://{DOMAIN}:{PORT}"
    return f"{scheme}://{DOMAIN}"


def _did() -> str:
    """Return this agent's DID."""
    return f"did:web:{DOMAIN}:{AGENT_NAME}"


def _msg_id() -> str:
    """Generate a unique message ID."""
    return f"msg_{uuid.uuid4().hex}"


def _now_iso() -> str:
    """Current UTC time in ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_response(
    msg_type: str,
    to_did: str,
    body: dict,
    correlation_id: str | None = None,
) -> dict:
    """Build and sign a response envelope."""
    msg: dict[str, Any] = {
        "arp": "1.0",
        "id": _msg_id(),
        "type": msg_type,
        "from": _did(),
        "to": to_did,
        "createdAt": _now_iso(),
        "body": body,
    }
    if correlation_id:
        msg["correlationId"] = correlation_id
    return sign_message(msg, keys.private_key)


def _error_response(
    to_did: str,
    code: str,
    message: str,
    retryable: bool,
    correlation_id: str | None = None,
    status_code: int = 400,
) -> Response:
    """Build a signed ARP error response and wrap it in a FastAPI Response."""
    envelope = _build_response(
        msg_type="error",
        to_did=to_did,
        body={"code": code, "message": message, "retryable": retryable},
        correlation_id=correlation_id,
    )
    return Response(
        content=json.dumps(envelope),
        status_code=status_code,
        media_type="application/arp+json",
    )


# ---------------------------------------------------------------------------
# contentRef validation (ARP v0.3)
# ---------------------------------------------------------------------------

# Regex for private/reserved hostnames
_PRIVATE_HOST_RE = re.compile(
    r"^("
    r"localhost"
    r"|127\.0\.0\.1"
    r"|0\.0\.0\.0"
    r"|::1"
    r"|\[?::1\]?"
    r"|::ffff:127\.0\.0\.1"
    r"|::ffff:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|::ffff:192\.168\.\d{1,3}\.\d{1,3}"
    r"|::ffff:172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|fe80:.*"
    r"|f[cd].*"
    r"|169\.254\.\d{1,3}\.\d{1,3}"
    r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r")$",
    re.IGNORECASE,
)

_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def validate_content_refs(body: Any) -> Optional[str]:
    """Recursively walk *body* and validate every ``contentRef`` object.

    Returns an error message string if validation fails, or ``None`` if
    everything is valid.  Only structural checks are performed -- the URL
    is NOT fetched and the hash is NOT verified.
    """

    def _walk(node: Any) -> Optional[str]:
        if isinstance(node, dict):
            if "contentRef" in node:
                ref = node["contentRef"]
                if not isinstance(ref, dict):
                    return "contentRef must be an object"

                # --- url ---
                url = ref.get("url")
                if url is None:
                    return "contentRef.url is required"
                if not isinstance(url, str) or not url.startswith("https://"):
                    return "contentRef.url must start with https://"

                # Check for private/reserved hostnames
                try:
                    parsed = urlparse(url)
                    hostname = parsed.hostname or ""
                    if _PRIVATE_HOST_RE.match(hostname):
                        return f"contentRef.url must not reference private host: {hostname}"
                except Exception:
                    return "contentRef.url is not a valid URL"

                # --- sha256 ---
                sha = ref.get("sha256")
                if sha is None:
                    return "contentRef.sha256 is required"
                if not isinstance(sha, str) or not _HEX64_RE.match(sha):
                    return "contentRef.sha256 must be a 64-character hex string"

                # --- size ---
                size = ref.get("size")
                if size is None:
                    return "contentRef.size is required"
                if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
                    return "contentRef.size must be a positive integer"

            # Recurse into all values
            for v in node.values():
                err = _walk(v)
                if err:
                    return err

        elif isinstance(node, list):
            for item in node:
                err = _walk(item)
                if err:
                    return err

        return None

    return _walk(body)


# ---------------------------------------------------------------------------
# Globals (initialized in lifespan)
# ---------------------------------------------------------------------------

keys: KeyManager
relation_store: RelationStore
idempotency: IdempotencyStore


async def _idempotency_cleanup_loop() -> None:
    """Periodically clean up expired idempotency entries."""
    while True:
        await asyncio.sleep(300)  # every 5 minutes
        idempotency.cleanup()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global keys, relation_store, idempotency

    os.makedirs(DATA_DIR, exist_ok=True)
    keys = KeyManager(DATA_DIR)
    relation_store = RelationStore(DATA_DIR)
    idempotency = IdempotencyStore()

    logger.info("=== ARP Server Started (v0.4.0) ===")
    logger.info("  Agent : %s", AGENT_NAME)
    logger.info("  DID   : %s", _did())
    logger.info("  Inbox : %s/%s/inbox", _base_url(), AGENT_NAME)
    logger.info("  PubKey: %s", keys.public_key_multibase)
    logger.info("====================================")

    cleanup_task = asyncio.create_task(_idempotency_cleanup_loop())
    yield
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="ARP Server", lifespan=lifespan)

# ---------------------------------------------------------------------------
# Routes: Discovery (static paths BEFORE parameterized paths)
# ---------------------------------------------------------------------------


@app.get("/agents.txt")
async def agents_txt() -> Response:
    """Serve agents.txt discovery hint file (Section 5.3).

    v0.4.0: renamed arp-index -> arp-directory, added open-capabilities
    and crawl-delay.
    """
    open_caps = ", ".join(sorted(OPEN_CAPABILITIES))
    content = (
        "# ARP agents for this domain\n"
        f"arp-directory: {_base_url()}/.well-known/arp/index.json\n"
        "arp-version: 1.0\n"
        f"open-capabilities: {open_caps}\n"
        "crawl-delay: 10\n"
    )
    return Response(content=content, media_type="text/plain")


@app.get("/.well-known/arp/index.json")
async def agent_index() -> Response:
    """Serve the agent directory for this domain.

    v0.4.0: added @context and @type: CollectionPage.
    """
    index = {
        "@context": {
            "@vocab": "https://schema.org/",
            "arp": "https://agentrelationsprotocol.com/ns/",
        },
        "@type": "CollectionPage",
        "domain": DOMAIN,
        "protocol": "arp/1.0",
        "agents": [
            {
                "name": AGENT_NAME,
                "url": f"/.well-known/arp/{AGENT_NAME}.json",
                "summary": "Echo agent for testing",
                "tags": ["echo", "testing"],
            }
        ],
        "pagination": {"hasMore": False, "total": 1},
    }
    return Response(
        content=json.dumps(index, indent=2),
        media_type="application/json",
    )


@app.get("/.well-known/arp/{name}.json")
async def agent_card(name: str) -> Response:
    """Serve the Agent Card for an agent.

    v0.4.0: added @context, @type: SoftwareApplication, open flag on
    echo capability, and private-echo capability.
    """
    if name != AGENT_NAME:
        return Response(status_code=404, content="Agent not found")

    card = {
        "@context": {
            "@vocab": "https://schema.org/",
            "arp": "https://agentrelationsprotocol.com/ns/",
        },
        "@type": "SoftwareApplication",
        "arp": "1.0",
        "name": AGENT_NAME,
        "did": _did(),
        "inbox": f"{_base_url()}/{AGENT_NAME}/inbox",
        "publicKey": keys.public_key_multibase,
        "description": "Echo agent -- returns whatever you send it. For testing ARP message flow.",
        "capabilities": [
            {
                "name": "echo",
                "description": "Echoes back the message body. Useful for testing signing, verification, and message flow.",
                "schema": {"type": "object"},
                "responseSchema": {"type": "object"},
                "open": True,
            },
            {
                "name": "private-echo",
                "description": "Same as echo but requires a relation. For testing first-contact enforcement.",
                "schema": {"type": "object"},
                "responseSchema": {"type": "object"},
            },
        ],
        "auth": {
            "required": True,
            "methods": ["did-signature"],
            "openAccess": True,
            "allowlist": [],
            "denylist": [],
        },
        "rateLimit": {"requests": 100, "window": "60s"},
        "contact": f"admin@{DOMAIN}",
        # v0.7 -- Notifications (Section 21.6)
        "notifications": {
            "supported": True,
            "events": {
                "order.shipped": 'Fires when a demo order is "shipped"',
                "order.delivered": 'Fires when a demo order is "delivered"',
            },
            "defaultLease": 604800,  # 7 days
            "maxLease": 7776000,  # 90 days
        },
        # v0.7 -- Settlements (Section 22.3)
        "settlements": {
            "supported": True,
            "rails": [
                {
                    "name": "x402-base-usdc",
                    "spec": "https://x402.org/spec/1.0",
                    "currencies": ["USDC"],
                },
            ],
            "primitives": ["prepay", "postpay"],
            "settlementWindow": "PT24H",
            "quoteCapability": "arp:settlement.quote",
        },
    }
    return Response(
        content=json.dumps(card, indent=2),
        media_type="application/json",
    )


@app.get("/{name}/did.json")
async def did_document(name: str) -> Response:
    """Serve the DID document for an agent."""
    if name != AGENT_NAME:
        return Response(status_code=404, content="Agent not found")

    did = _did()
    doc = {
        "@context": "https://www.w3.org/ns/did/v1",
        "id": did,
        "verificationMethod": [
            {
                "id": f"{did}#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": keys.public_key_multibase,
            }
        ],
        "authentication": [f"{did}#key-1"],
        "assertionMethod": [f"{did}#key-1"],
        "service": [
            {
                "id": "#arp",
                "type": "AgentRelationsProtocol",
                "serviceEndpoint": f"{_base_url()}/{AGENT_NAME}/inbox",
            }
        ],
    }
    return Response(
        content=json.dumps(doc, indent=2),
        media_type="application/json",
    )


# ---------------------------------------------------------------------------
# Route: Inbox
# ---------------------------------------------------------------------------


@app.post("/{name}/inbox")
async def inbox(name: str, request: Request) -> Response:
    """Receive and process ARP messages (v0.4.0)."""
    if name != AGENT_NAME:
        return Response(status_code=404, content="Agent not found")

    # --- Content-Type check ---
    content_type = request.headers.get("content-type", "")
    if "application/arp+json" not in content_type and "application/json" not in content_type:
        return Response(
            status_code=415,
            content=json.dumps({"error": "Content-Type must be application/arp+json or application/json"}),
            media_type="application/json",
        )

    # --- Size check ---
    raw_body = await request.body()
    if len(raw_body) > MAX_BODY_SIZE:
        return _error_response(
            to_did="unknown",
            code="MESSAGE_TOO_LARGE",
            message=f"Message exceeds maximum size of {MAX_BODY_SIZE} bytes",
            retryable=False,
            status_code=413,
        )

    # --- Parse JSON ---
    try:
        msg = json.loads(raw_body)
    except json.JSONDecodeError:
        return Response(
            status_code=400,
            content=json.dumps({"error": "Invalid JSON"}),
            media_type="application/json",
        )

    # --- Validate required envelope fields ---
    required_fields = ["arp", "id", "type", "from", "to", "createdAt", "body", "signature"]
    missing = [f for f in required_fields if f not in msg]
    if missing:
        sender_did = msg.get("from", "unknown")
        return _error_response(
            to_did=sender_did,
            code="SCHEMA_INVALID",
            message=f"Missing required fields: {', '.join(missing)}",
            retryable=False,
            correlation_id=msg.get("id"),
        )

    sender_did = msg["from"]
    msg_id = msg["id"]
    msg_type = msg["type"]
    correlation_id = msg.get("correlationId", msg_id)

    # --- Check expiration ---
    now = datetime.now(timezone.utc)
    if "expiresAt" in msg and msg["expiresAt"]:
        try:
            expires = datetime.fromisoformat(msg["expiresAt"].replace("Z", "+00:00"))
            if now > expires:
                return _error_response(
                    to_did=sender_did,
                    code="MESSAGE_EXPIRED",
                    message="Message has expired",
                    retryable=False,
                    correlation_id=correlation_id,
                )
        except (ValueError, TypeError):
            pass  # If expiresAt is malformed, skip expiration check
    else:
        # No expiresAt -- reject if createdAt > 24 hours old
        try:
            created = datetime.fromisoformat(msg["createdAt"].replace("Z", "+00:00"))
            if now - created > timedelta(hours=24):
                return _error_response(
                    to_did=sender_did,
                    code="MESSAGE_EXPIRED",
                    message="Message older than 24 hours with no expiresAt",
                    retryable=False,
                    correlation_id=correlation_id,
                )
        except (ValueError, TypeError):
            pass

    # --- Idempotency check ---
    if idempotency.has_message(msg_id):
        return _error_response(
            to_did=sender_did,
            code="SCHEMA_INVALID",
            message=f"Duplicate message ID: {msg_id}",
            retryable=False,
            correlation_id=correlation_id,
            status_code=409,
        )

    # --- Resolve sender's public key & check relation state (v0.4.0) ---
    sender_pub_key = None
    existing_relation = relation_store.get_relation(sender_did)
    has_active_relation = relation_store.has_active_relation(sender_did)
    is_open_capability = msg_type == "request" and msg.get("capability", "") in OPEN_CAPABILITIES

    if existing_relation and existing_relation["status"] != "terminated":
        # Known sender -- use pinned key from relation
        pinned_multibase = existing_relation["pinnedKey"]

        # If sender provides a publicKey in body, check it matches pin
        body_key = msg.get("body", {}).get("publicKey")
        if body_key and body_key != pinned_multibase:
            return _error_response(
                to_did=sender_did,
                code="KEY_MISMATCH",
                message="Sender's public key does not match pinned key",
                retryable=False,
                correlation_id=correlation_id,
            )

        try:
            sender_pub_key = public_key_from_multibase(pinned_multibase)
        except Exception:
            return _error_response(
                to_did=sender_did,
                code="AUTH_FAILED",
                message="Failed to load pinned public key",
                retryable=False,
                correlation_id=correlation_id,
            )

    elif msg_type == "negotiate" and isinstance(msg.get("body", {}).get("publicKey"), str):
        # First contact -- accept key from negotiate body
        body_key = msg["body"]["publicKey"]
        try:
            sender_pub_key = public_key_from_multibase(body_key)
        except Exception:
            return _error_response(
                to_did=sender_did,
                code="AUTH_FAILED",
                message="Invalid publicKey format",
                retryable=False,
                correlation_id=correlation_id,
            )

    elif is_open_capability and not has_active_relation:
        # Open capability from unknown sender -- require publicKey in body
        body_key = msg.get("body", {}).get("publicKey")
        if isinstance(body_key, str):
            try:
                sender_pub_key = public_key_from_multibase(body_key)
            except Exception:
                return _error_response(
                    to_did=sender_did,
                    code="AUTH_FAILED",
                    message="Invalid publicKey format",
                    retryable=False,
                    correlation_id=correlation_id,
                )
        else:
            return _error_response(
                to_did=sender_did,
                code="AUTH_FAILED",
                message="Open capability requests from unknown senders must include publicKey in body",
                retryable=False,
                correlation_id=correlation_id,
            )

    elif existing_relation and existing_relation["status"] == "terminated":
        # Terminated relation -- reject all messages
        return _error_response(
            to_did=sender_did,
            code="AUTH_DENIED",
            message="Relation has been terminated",
            retryable=False,
            correlation_id=correlation_id,
            status_code=403,
        )

    elif msg_type == "request" and not is_open_capability:
        # Non-open capability, no relation -- require first contact
        return _error_response(
            to_did=sender_did,
            code="FIRST_CONTACT_REQUIRED",
            message="Send a negotiate message with firstContact: true before making requests",
            retryable=True,
            correlation_id=correlation_id,
            status_code=403,
        )

    elif msg_type != "negotiate":
        return _error_response(
            to_did=sender_did,
            code="FIRST_CONTACT_REQUIRED",
            message="Send a negotiate message with firstContact: true before making requests",
            retryable=True,
            correlation_id=correlation_id,
            status_code=403,
        )

    if sender_pub_key is None:
        return _error_response(
            to_did=sender_did,
            code="AUTH_FAILED",
            message="Unable to resolve sender public key",
            retryable=False,
            correlation_id=correlation_id,
        )

    # --- Verify signature ---
    if not verify_signature(msg, sender_pub_key):
        return _error_response(
            to_did=sender_did,
            code="AUTH_FAILED",
            message="Signature verification failed",
            retryable=False,
            correlation_id=correlation_id,
            status_code=401,
        )

    # --- Relation management: TOFU + lifecycle (v0.4.0) ---
    if existing_relation and existing_relation["status"] != "terminated":
        sender_multibase = existing_relation["pinnedKey"]
        # Touch the relation (reactivates dormant)
        relation_store.touch_relation(sender_did)
    elif msg_type == "negotiate":
        # First contact -- create relation
        body_key = msg.get("body", {}).get("publicKey", "")
        relation_store.create_relation(sender_did, body_key)
    # Open capability from unknown sender: no relation created (spec: step 4)

    # --- Record message ID (only after signature verified) ---
    idempotency.add_message(msg_id)

    # --- Validate contentRef objects in body (ARP v0.3) ---
    content_ref_err = validate_content_refs(msg.get("body", {}))
    if content_ref_err:
        return _error_response(
            to_did=sender_did,
            code="SCHEMA_INVALID",
            message=content_ref_err,
            retryable=False,
            correlation_id=correlation_id,
        )

    # --- Process by message type ---
    logger.info("Processing message: id=%s type=%s from=%s", msg_id, msg_type, sender_did)

    # v0.7 -- Notifications (Section 21): fire-and-forget, 202 Accepted, no body
    if msg_type == "notify":
        event = msg.get("event") or ""
        notification_id = msg.get("notificationId") or ""
        if not event or not notification_id:
            return _error_response(
                to_did=sender_did,
                code="SCHEMA_INVALID",
                message="notify messages MUST include event and notificationId",
                retryable=False,
                correlation_id=correlation_id,
            )
        logger.info(
            "Notification received: from=%s event=%s notificationId=%s",
            sender_did, event, notification_id,
        )
        # Reference server logs and acks; real applications dispatch to handlers.
        return Response(status_code=202)

    if msg_type == "negotiate":
        # Check for termination request (v0.4.0 Section 11.3)
        if msg.get("body", {}).get("terminate") is True:
            relation_store.terminate_relation(sender_did)
            response_envelope = _build_response(
                msg_type="acknowledge",
                to_did=sender_did,
                body={
                    "terminated": True,
                    "message": "Relation terminated.",
                },
                correlation_id=correlation_id,
            )
        else:
            trust_level = relation_store.get_trust_level(sender_did)
            approved_until = (
                datetime.now(timezone.utc) + timedelta(days=30)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            response_envelope = _build_response(
                msg_type="acknowledge",
                to_did=sender_did,
                body={
                    "firstContact": True,
                    "approvedCapabilities": ["echo", "private-echo"],
                    "approvedUntil": approved_until,
                    "trustLevel": trust_level,
                    "message": "First contact acknowledged. Relation created.",
                },
                correlation_id=correlation_id,
            )
        logger.info("Processed negotiate from %s", sender_did)

    elif msg_type == "request":
        capability = msg.get("capability")
        trust_level = relation_store.get_trust_level(sender_did)

        if capability == "echo":
            response_envelope = _build_response(
                msg_type="response",
                to_did=sender_did,
                body={
                    "echo": msg["body"],
                    "receivedAt": _now_iso(),
                    "trustLevel": trust_level,
                    "openRequest": is_open_capability and not has_active_relation,
                },
                correlation_id=correlation_id,
            )
            logger.info("Echoed request from %s", sender_did)

        elif capability == "private-echo":
            # private-echo is NOT open -- if we got here the relation check passed
            response_envelope = _build_response(
                msg_type="response",
                to_did=sender_did,
                body={
                    "echo": msg["body"],
                    "receivedAt": _now_iso(),
                    "trustLevel": trust_level,
                    "openRequest": False,
                },
                correlation_id=correlation_id,
            )
            logger.info("Private-echoed request from %s", sender_did)

        else:
            response_envelope = _build_response(
                msg_type="error",
                to_did=sender_did,
                body={
                    "code": "CAPABILITY_UNKNOWN",
                    "message": f"Unknown capability: {capability}",
                    "retryable": False,
                },
                correlation_id=correlation_id,
            )
            logger.warning("Unknown capability '%s' from %s", capability, sender_did)

    elif msg_type == "cancel":
        response_envelope = _build_response(
            msg_type="acknowledge",
            to_did=sender_did,
            body={"cancelled": True},
            correlation_id=correlation_id,
        )
        logger.info("Acknowledged cancel from %s", sender_did)

    else:
        response_envelope = _build_response(
            msg_type="acknowledge",
            to_did=sender_did,
            body={"acknowledged": True},
            correlation_id=correlation_id,
        )
        logger.info("Acknowledged %s from %s", msg_type, sender_did)

    return Response(
        content=json.dumps(response_envelope, indent=2),
        status_code=200,
        media_type="application/arp+json",
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=PORT,
        log_level="info",
    )
