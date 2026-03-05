"""
ZAK Edition — runtime edition detection for open-source vs enterprise gating.

Usage:
    from zak.core.edition import get_edition, is_enterprise, Edition, EditionError

Control via environment variable:
    ZAK_EDITION=open-source   (default)
    ZAK_EDITION=enterprise
"""

from __future__ import annotations

import os
from enum import Enum


class Edition(str, Enum):
    OPEN_SOURCE = "open-source"
    ENTERPRISE = "enterprise"


def get_edition() -> Edition:
    """Return the current edition based on the ZAK_EDITION environment variable."""
    val = os.getenv("ZAK_EDITION", "open-source").lower().strip()
    if val in ("enterprise", "ent"):
        return Edition.ENTERPRISE
    return Edition.OPEN_SOURCE


def is_enterprise() -> bool:
    """Return True if running under the enterprise edition."""
    return get_edition() == Edition.ENTERPRISE


class EditionError(Exception):
    """Raised when an enterprise-only feature is accessed on the open-source edition."""
    pass
