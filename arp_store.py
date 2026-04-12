"""ARP storage: key pin store (TOFU) and message idempotency store."""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class PinStore:
    """Trust-On-First-Use key pin store, backed by a JSON file on disk.

    Stores the public key for each DID we have interacted with. On subsequent
    contacts, the stored key must match; a mismatch signals a potential attack.
    """

    def __init__(self, data_dir: str) -> None:
        self.data_dir = Path(data_dir)
        self.pins_path = self.data_dir / "pins.json"
        self._pins: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        """Load pins from disk."""
        if self.pins_path.exists():
            with open(self.pins_path) as f:
                self._pins = json.load(f)
            logger.info("Loaded %d key pins from %s", len(self._pins), self.pins_path)
        else:
            self._pins = {}

    def _save(self) -> None:
        """Persist pins to disk."""
        os.makedirs(self.data_dir, exist_ok=True)
        with open(self.pins_path, "w") as f:
            json.dump(self._pins, f, indent=2)

    def has_pin(self, did: str) -> bool:
        """Check whether we have a pinned key for this DID."""
        return did in self._pins

    def get_pin(self, did: str) -> Optional[dict]:
        """Return the pin record for a DID, or None."""
        return self._pins.get(did)

    def set_pin(self, did: str, public_key_multibase: str) -> None:
        """Pin a public key for a DID. Saves to disk immediately."""
        self._pins[did] = {
            "public_key_multibase": public_key_multibase,
            "first_contact": datetime.now(timezone.utc).isoformat(),
        }
        self._save()
        logger.info("Pinned key for %s", did)


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
