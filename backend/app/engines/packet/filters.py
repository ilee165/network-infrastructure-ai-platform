"""Capture-filter validation/whitelist (M5; ADR-0023 §1 — sandbox control).

Every capture filter and tshark display filter is **untrusted input**. A filter
string is never interpolated into a shell command line (the engine always passes
argv lists — :mod:`app.engines.packet.sandbox` / :mod:`app.engines.packet.capture`),
but it *is* handed to ``tcpdump`` / ``tshark`` as one argv element, so it must
still be constrained to a safe grammar before it ever reaches a child process:

- A BPF capture filter (``tcpdump -f``/``tshark -f``) may contain only the
  characters BPF itself uses — protocol/qualifier words, numbers, dotted IPs,
  the ``and``/``or``/``not`` keywords, parentheses, and a small set of
  comparison/arithmetic operators. Shell metacharacters (``; | & $ ` > < \\``
  newlines, quotes, command/argv-splitting characters) are rejected outright, so
  even a hypothetical future shell sink cannot be reached, and a malformed BPF
  cannot smuggle extra tshark/tcpdump arguments.
- An empty/``None`` filter is allowed (capture everything on the interface).

This module is the single chokepoint: capture orchestration and the analysis
sandbox both validate here before building any argv, so a rejected filter never
produces a subprocess at all (:class:`FilterValidationError` is raised first).
"""

from __future__ import annotations

import re

from app.core.errors import PluginError

__all__ = [
    "FilterValidationError",
    "MAX_FILTER_LENGTH",
    "validate_capture_filter",
]

#: Hard cap on a filter string — a BPF expression is short; anything longer is
#: an abuse attempt, not a real capture filter.
MAX_FILTER_LENGTH = 1024

#: The complete set of characters a legitimate BPF capture filter uses. Note the
#: deliberate *absence* of every shell metacharacter (``; | & $ ` \\ ' " > <``),
#: newlines, and ``-`` at a token boundary — so a filter can never be parsed as
#: an extra option/flag or a second command. Whitelist (allow-known-good), never
#: blacklist.
_BPF_ALLOWED = re.compile(r"^[A-Za-z0-9_.:/ ()\[\]=!<>+*-]*$")

#: Tokens BPF permits. Anything alphabetic in the filter must be one of these
#: keywords/qualifiers (case-insensitive) — an unknown bareword is rejected so a
#: filter cannot reference arbitrary identifiers. Mirrors the tcpdump/pcap-filter
#: primitive + qualifier vocabulary (bounded subset sufficient for diagnostics).
_BPF_KEYWORDS = frozenset(
    {
        "and",
        "or",
        "not",
        "host",
        "net",
        "mask",
        "port",
        "portrange",
        "src",
        "dst",
        "gateway",
        "broadcast",
        "multicast",
        "less",
        "greater",
        "proto",
        "protochain",
        "ip",
        "ip6",
        "arp",
        "rarp",
        "tcp",
        "udp",
        "icmp",
        "icmp6",
        "ether",
        "vlan",
        "mpls",
        "len",
    }
)


class FilterValidationError(PluginError):
    """A capture/display filter failed validation (untrusted input rejected).

    The message names *why* the filter was rejected but never re-emits the full
    offending string into a shell — the filter is data, not a command. Raising
    this aborts the capture/analysis before any argv is built or any child
    process is spawned (ADR-0023 §1).
    """

    title = "Capture Filter Rejected"
    slug = "capture-filter-rejected"


def validate_capture_filter(capture_filter: str | None) -> str | None:
    """Validate an untrusted BPF capture filter; return it unchanged or raise.

    Returns ``None`` for an empty/``None`` filter (capture everything). For a
    non-empty filter every character must be in the BPF whitelist and every
    alphabetic token must be a known BPF keyword/qualifier — so the string cannot
    contain a shell metacharacter, cannot begin a new argument/flag, and cannot
    reference an arbitrary identifier. Validation happens *before* any argv is
    constructed, so a rejected filter never reaches ``tcpdump``/``tshark``.

    :raises FilterValidationError: the filter is too long, contains a character
        outside the BPF whitelist (e.g. a shell metacharacter), or contains a
        bareword that is not a recognized BPF keyword.
    """
    if capture_filter is None:
        return None
    stripped = capture_filter.strip()
    if not stripped:
        return None
    if len(stripped) > MAX_FILTER_LENGTH:
        raise FilterValidationError(
            f"capture filter exceeds {MAX_FILTER_LENGTH} characters (rejected as untrusted input)"
        )
    if not _BPF_ALLOWED.match(stripped):
        raise FilterValidationError(
            "capture filter contains characters outside the BPF whitelist "
            "(shell metacharacters and control characters are rejected)"
        )
    for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", stripped):
        if token.lower() not in _BPF_KEYWORDS:
            raise FilterValidationError(
                f"capture filter contains an unrecognized token {token!r}; "
                "only BPF protocol/qualifier keywords are allowed"
            )
    return stripped
