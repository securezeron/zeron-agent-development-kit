"""
ZAK Graph Adapter Factory — auto-selects graph backend based on configuration.

Backend selection (via ``ZAK_GRAPH_BACKEND`` env var):
    memory    — In-memory dict store, zero dependencies (default)
    memgraph  — Memgraph via Bolt protocol (requires neo4j package + running Memgraph)
    kuzu      — Alias for memgraph (backward compat)

Usage:
    from zak.sif.graph.factory import create_adapter
    adapter = create_adapter()  # reads ZAK_GRAPH_BACKEND env var
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


def create_adapter(**kwargs: Any) -> Any:
    """
    Create and return a graph adapter instance based on ``ZAK_GRAPH_BACKEND``.

    Returns:
        InMemoryGraphAdapter or KuzuAdapter, both sharing the same public interface.
    """
    backend = os.getenv("ZAK_GRAPH_BACKEND", "memory").lower().strip()

    if backend == "memory":
        from zak.sif.graph.memory_adapter import InMemoryGraphAdapter
        return InMemoryGraphAdapter(**kwargs)

    if backend in ("memgraph", "kuzu"):
        try:
            from zak.sif.graph.adapter import KuzuAdapter
            return KuzuAdapter(**kwargs)
        except ImportError:
            logger.warning(
                "ZAK_GRAPH_BACKEND=%s but neo4j package not installed. "
                "Falling back to in-memory graph. "
                "Install with: pip install 'zin-adk[graph]'",
                backend,
            )
            from zak.sif.graph.memory_adapter import InMemoryGraphAdapter
            return InMemoryGraphAdapter(**kwargs)
        except Exception as exc:
            logger.warning(
                "ZAK_GRAPH_BACKEND=%s but connection failed: %s. "
                "Falling back to in-memory graph.",
                backend, exc,
            )
            from zak.sif.graph.memory_adapter import InMemoryGraphAdapter
            return InMemoryGraphAdapter(**kwargs)

    logger.warning(
        "Unknown ZAK_GRAPH_BACKEND='%s'. Valid: memory, memgraph. "
        "Falling back to memory.",
        backend,
    )
    from zak.sif.graph.memory_adapter import InMemoryGraphAdapter
    return InMemoryGraphAdapter(**kwargs)
