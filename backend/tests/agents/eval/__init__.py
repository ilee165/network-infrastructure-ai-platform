"""M3 agent eval suite (task M3-17).

Encodes the seven MVP.md §5 exit criteria as automated, deterministic tests.
Everything here is offline: a scripted fake chat model stands in for the LLM,
an in-memory SQLite engine carries the persistence (sessions, traces, audit),
and fixture payloads ground every agent answer. No network, no real provider.
"""
