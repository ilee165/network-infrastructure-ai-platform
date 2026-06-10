"""LangGraph supervisor + specialist agents (ADR-0003, brief section 5).

Layout (REPO-STRUCTURE section 2): ``framework/`` holds the shared layers
(tool wrappers, approval gate, reasoning traces, registry, supervisor) used by
all ten core agents. Specialist packages (``master_architect/``,
``troubleshooting/``, ...) land with M3 and may import *only*
``agents.framework`` plus ``core``/``schemas``/``llm`` (REPO-STRUCTURE
section 3.2, row 11).
"""
