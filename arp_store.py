"""ARP storage: relation store (v0.4.0) and message idempotency store.

The Relation Store replaces the old PinStore. It maps a DID to its full
relation record -- pinned key, status (active/dormant/terminated), first
contact timestamp, last activity timestamp, and completion count.

Backed by ``data/relations.json``.  Migrates transparently from the old
``data/pins.json`` if present.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Literal, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

RelationStatus = Literal["pending", "active", "dormant", "terminated"]
TrustLevel = Literal["trusted", "known", "new", "unknown"]

NINETY_DAYS_S = 90 * 24 * 60 * 60


# ---------------------------------------------------------------------------
# Relation Store (v0.4.0 -- replaces PinStore)
# ---------------------------------------------------------------------------


class RelationStore:
    """Tracks relations with peer agents.

    Each relation stores the pinned public key, lifecycle status, and
    interaction history used to compute trust levels.
    """

    def __init__(self, data_dir: str) -> None:
        self.data_dir = Path(data_dir)
        self.relations_path = self.data_dir / "relations.json"
        self._relations: dict[str, dict] = {}
        self._load()

    # -- persistence --------------------------------------------------------

    def _load(self) -> None:
        """Load relations from disk, migrating from pins.json if needed."""
        pins_path = self.data_dir / "pins.json"

        # Migrate from old pins.json if relations.json doesn't exist
        if not self.relations_path.exists() and pins_path.exists():
            try:
                with open(pins_path) as f:
                    raw = json.load(f)
                for did, pin in raw.items():
                    self._relations[did] = {
                        "peerDid": did,
                        "pinnedKey": pin.get("public_key_multibase", pin.get("pinnedKey", "")),
                        "status": "active",
                        "firstContact": pin.get("first_contact", pin.get("firstContact", datetime.now(timezone.utc).isoformat())),
                        "lastActivity": pin.get("first_contact", pin.get("firstContact", datetime.now(timezone.utc).isoformat())),
                        "completions": 0,
                    }
                self._save()
                logger.info("Migrated %d pins to relations", len(self._relations))
                return
            except Exception:
                pass  # Fall through to fresh start

        if self.relations_path.exists():
            try:
                with open(self.relations_path) as f:
                    self._relations = json.load(f)
                logger.info("Loaded %d relations from %s", len(self._relations), self.relations_path)
            except Exception:
                self._relations = {}
        else:
            self._relations = {}

    def _save(self) -> None:
        """Persist relations to disk."""
        os.makedirs(self.data_dir, exist_ok=True)
        with open(self.relations_path, "w") as f:
            json.dump(self._relations, f, indent=2)

    # -- query methods ------------------------------------------------------

    def has_relation(self, did: str) -> bool:
        """Check whether we have any record for this DID."""
        return did in self._relations

    def get_relation(self, did: str) -> Optional[dict]:
        """Return the full relation record for a DID, or None."""
        return self._relations.get(did)

    def has_active_relation(self, did: str) -> bool:
        """Check if a DID has an active or dormant (reactivatable) relation."""
        rel = self._relations.get(did)
        if rel is None:
            return False
        return rel["status"] in ("active", "dormant")

    def get_pinned_key(self, did: str) -> Optional[str]:
        """Get the pinned key for a DID (if relation exists and is not terminated)."""
        rel = self._relations.get(did)
        if rel is None or rel["status"] == "terminated":
            return None
        return rel["pinnedKey"]

    # -- mutation methods ---------------------------------------------------

    def create_relation(self, did: str, public_key_multibase: str) -> None:
        """Create a new relation on first contact."""
        now = datetime.now(timezone.utc).isoformat()
        self._relations[did] = {
            "peerDid": did,
            "pinnedKey": public_key_multibase,
            "status": "active",
            "firstContact": now,
            "lastActivity": now,
            "completions": 0,
        }
        self._save()
        logger.info("Created relation: did=%s status=active", did)

    def touch_relation(self, did: str) -> None:
        """Record activity on an existing relation (reactivates dormant)."""
        rel = self._relations.get(did)
        if rel is None:
            return
        rel["lastActivity"] = datetime.now(timezone.utc).isoformat()
        if rel["status"] == "dormant":
            rel["status"] = "active"
            logger.info("Reactivated dormant relation: did=%s", did)
        self._save()

    def terminate_relation(self, did: str) -> None:
        """Terminate a relation (all future messages rejected)."""
        rel = self._relations.get(did)
        if rel is None:
            return
        rel["status"] = "terminated"
        self._save()
        logger.info("Terminated relation: did=%s", did)

    def add_completion(self, did: str) -> None:
        """Increment the completion count for a relation."""
        rel = self._relations.get(did)
        if rel is None:
            return
        rel["completions"] = rel.get("completions", 0) + 1
        rel["lastActivity"] = datetime.now(timezone.utc).isoformat()
        self._save()

    # -- trust computation (Section 10.7) -----------------------------------

    def get_trust_level(self, did: str) -> TrustLevel:
        """Compute the trust level for a peer based on relation history."""
        rel = self._relations.get(did)
        if rel is None or rel["status"] == "terminated":
            return "unknown"

        # Check dormancy (90-day threshold)
        if rel["status"] == "active":
            try:
                last = datetime.fromisoformat(rel["lastActivity"].replace("Z", "+00:00"))
                inactive_s = (datetime.now(timezone.utc) - last).total_seconds()
                if inactive_s > NINETY_DAYS_S:
                    rel["status"] = "dormant"
                    self._save()
            except Exception:
                pass

        completions = rel.get("completions", 0)

        if rel["status"] == "dormant":
            # Dormancy downgrades by one tier
            if completions >= 5:
                return "known"      # would be trusted -> known
            if completions >= 1:
                return "new"        # would be known -> new
            return "unknown"        # would be new -> unknown

        # Active relation
        if completions >= 5:
            return "trusted"
        if completions >= 1:
            return "known"
        return "new"


# ---------------------------------------------------------------------------
# Idempotency Store
# ---------------------------------------------------------------------------


class IdempotencyStore:
    """In-memory store of seen message IDs for duplicate detection.

    Entries older than 24 hours are pruned on cleanup.
    """

    EXPIRY_SECONDS = 86400  # 24 hours

    def __init__(self) -> None:
        self._seen: dict[str, float] = {}  # message_id -> unix timestamp

    def has_message(self, message_id: str) -> bool:
        """Return True if this message ID has already been processed."""
        return message_id in self._seen

    def add_message(self, message_id: str) -> None:
        """Record a message ID as processed."""
        self._seen[message_id] = time.time()

    def cleanup(self) -> int:
        """Remove entries older than 24 hours. Returns number of entries removed."""
        cutoff = time.time() - self.EXPIRY_SECONDS
        expired = [mid for mid, ts in self._seen.items() if ts < cutoff]
        for mid in expired:
            del self._seen[mid]
        if expired:
            logger.debug("Idempotency cleanup: removed %d expired entries", len(expired))
        return len(expired)

    @property
    def size(self) -> int:
        """Return the number of tracked message IDs."""
        return len(self._seen)
