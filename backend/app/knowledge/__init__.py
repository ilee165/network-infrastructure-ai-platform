"""Graph + RAG infrastructure (ADR-0005, REPO-STRUCTURE D5).

``app.knowledge`` is the only package that talks to Neo4j. The graph is a pure
projection of the Postgres ``normalized_*`` tables — writes flow one way and a
full rebuild (drop + re-project) must always work.
"""

from app.knowledge.neo4j_client import (
    Neo4jClient,
    create_client,
    dispose_client,
    get_client,
)
from app.knowledge.topology_read import GraphData, fetch_graph

__all__ = [
    "GraphData",
    "Neo4jClient",
    "create_client",
    "dispose_client",
    "fetch_graph",
    "get_client",
]
