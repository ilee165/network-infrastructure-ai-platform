"""Prompt-redaction layer (A9 — secure by default).

Network device configuration routinely carries plaintext or trivially
reversible secrets (SNMP communities, Cisco type-7 passwords, routing-protocol
auth keys, RADIUS/TACACS shared keys, IPsec pre-shared keys, ...). Those secrets
must never leave the process inside an LLM prompt — not even to a *local*
provider, and certainly never to an external one.

This module strips known vendor secret patterns from any text or message list
*before* it reaches a provider. The redaction runs centrally, inside the
:func:`~app.llm.providers.get_chat_model` factory, by wrapping every model in a
:class:`RedactingChatModel`; callers therefore cannot bypass it by forgetting to
redact manually (defence in depth — A9).

Design properties:

* **Profile-independent.** The same redaction runs for ``local``, ``anthropic``,
  ``openai`` and ``azure``; there is no "trusted" provider.
* **Stable tokens.** Each secret class is replaced by a fixed sentinel such as
  ``<<REDACTED:snmp_community>>`` so prompts stay diff-stable and the model still
  sees *that* a secret existed and of which kind.
* **Idempotent.** Re-redacting already-redacted text is a no-op: the sentinels do
  not themselves match any secret pattern, and the directive prefixes that remain
  no longer have a secret value to capture.
* **Conservative.** Only the secret *value* is replaced; the surrounding
  directive (``snmp-server community``, ``enable secret``) is preserved so the
  model keeps useful structural context. Benign configuration is untouched.

Vault-stored credentials never reach a prompt under any profile: even if a
device credential were interpolated into context by mistake, its on-the-wire
representation matches one of these patterns and is stripped here.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from typing import Any, Final

from langchain_core.callbacks import (
    AsyncCallbackManagerForLLMRun,
    CallbackManagerForLLMRun,
    Callbacks,
)
from langchain_core.language_models import BaseChatModel, LanguageModelInput
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatResult, LLMResult
from langchain_core.prompt_values import ChatPromptValue, PromptValue, StringPromptValue
from langchain_core.runnables import Runnable
from langchain_core.tools import BaseTool
from pydantic import ConfigDict

#: Stable replacement token per secret class. Keys are referenced by tests and
#: by callers that want to assert on a specific redaction kind.
REDACTION_TOKENS: Final[dict[str, str]] = {
    "snmp_community": "<<REDACTED:snmp_community>>",
    "snmpv3_auth": "<<REDACTED:snmpv3_auth>>",
    "cisco_type7": "<<REDACTED:cisco_type7>>",
    "cisco_type89": "<<REDACTED:cisco_type89>>",
    "enable_secret": "<<REDACTED:enable_secret>>",
    "routing_auth_key": "<<REDACTED:routing_auth_key>>",
    "interface_auth_key": "<<REDACTED:interface_auth_key>>",
    "aaa_shared_key": "<<REDACTED:aaa_shared_key>>",
    "ipsec_psk": "<<REDACTED:ipsec_psk>>",
    "plaintext_password": "<<REDACTED:plaintext_password>>",
}

# A redacted value sentinel; used in patterns to avoid re-matching an
# already-substituted token (belt-and-braces on top of value-shape guards).
_TOKEN = r"<<REDACTED:[a-z0-9_]+>>"

# Ordered list of (kind, compiled-pattern). Order matters: the more specific
# encodings (SNMPv3 strings, type 8/9, "key 7 <hex>") are tried before broader
# ones so each secret is classified once. Every pattern captures the directive
# context in group 1 and the secret value in the trailing portion; the
# replacement keeps group 1 and substitutes the value with the kind's token.
#
# All patterns are anchored on a word boundary and require an actual value that
# is *not* already a redaction token, which is what makes redaction idempotent.

_VALUE = rf"(?!{_TOKEN})\S+"  # a non-empty token that is not an existing sentinel

_PATTERNS: Final[list[tuple[str, re.Pattern[str]]]] = [
    # SNMPv3 user auth/priv secrets: `... auth <algo> <secret> [priv <algo> <secret>]`.
    # Handled first because the line also contains the word "snmp-server".
    (
        "snmpv3_auth",
        re.compile(
            rf"\b(auth\s+(?:md5|sha|sha256|sha512))\s+{_VALUE}"
            rf"(?:(\s+priv\s+(?:des|3des|aes(?:\s+(?:128|192|256))?))\s+{_VALUE})?",
            re.IGNORECASE,
        ),
    ),
    # SNMP community string: `snmp-server community <secret> [RO|RW|<acl>]`.
    (
        "snmp_community",
        re.compile(
            rf"\b(snmp-server\s+community)\s+{_VALUE}",
            re.IGNORECASE,
        ),
    ),
    # Cisco type 8 / type 9 hashes, optionally introduced by a directive +
    # encoding number: `enable secret 9 $9$...`, `username u secret 8 $8$...`,
    # or a bare `$8$...`/`$9$...`. The whole encoded blob (including the `$N$`
    # prefix and any leading "secret 8"/"secret 9" directive) is consumed so no
    # `$8$` fragment is left behind.
    (
        "cisco_type89",
        re.compile(
            r"\b((?:enable\s+)?(?:password|secret))\s+(?:8|9)\s+\$(?:8|9)\$\S+",
            re.IGNORECASE,
        ),
    ),
    (
        "cisco_type89",
        re.compile(
            r"\$(?:8|9)\$\S+",
        ),
    ),
    # Cisco type 7 reversible password: `password 7 <hex>` / `secret 7 <hex>`,
    # optionally with a leading `enable`. The AAA `key 7` form is classified as
    # an aaa_shared_key below.
    (
        "cisco_type7",
        re.compile(
            r"\b((?:enable\s+)?(?:password|secret))\s+7\s+[0-9A-Fa-f]+",
            re.IGNORECASE,
        ),
    ),
    # RADIUS / TACACS shared keys: `radius-server key [7] <secret>`,
    # `tacacs-server key [7] <secret>`. The optional `7` encoding number is
    # consumed as part of the value prefix (never matched as the value itself),
    # which keeps redaction idempotent.
    (
        "aaa_shared_key",
        re.compile(
            rf"\b((?:radius-server|tacacs-server)\s+key)\s+(?:7\s+)?{_VALUE}",
            re.IGNORECASE,
        ),
    ),
    # IPsec / ISAKMP pre-shared key: `crypto isakmp key [<enc>] <secret> address ...`
    # or `pre-shared-key [<enc>] <secret>`. Real configs prefix the PSK with an
    # encoding indicator (`0` plaintext, `6` type-6 reversible blob) that must be
    # consumed *before* the value so the digit is not mistaken for the secret and
    # the actual key left behind. The value stops before a trailing
    # `address`/`hostname` clause so peer context is preserved.
    (
        "ipsec_psk",
        re.compile(
            rf"\b(crypto\s+isakmp\s+key)\s+(?:\d+\s+)?(?!{_TOKEN})\S+"
            rf"(?=\s+(?:address|hostname)\b|\s*$)",
            re.IGNORECASE,
        ),
    ),
    (
        "ipsec_psk",
        re.compile(
            rf"\b(crypto\s+isakmp\s+key)\s+(?:\d+\s+)?{_VALUE}",
            re.IGNORECASE,
        ),
    ),
    # Juniper / multi-vendor pre-shared-key with an optional encoding keyword or
    # digit (`ascii-text`, `hexadecimal`, `0`) between the directive and value.
    (
        "ipsec_psk",
        re.compile(
            rf"\b(pre-shared-key(?:\s+(?:local|remote))?)"
            rf"\s+(?:(?:ascii-text|hexadecimal|\d+)\s+)?"
            rf"(?!(?:local|remote|ascii-text|hexadecimal|\d+)\b)(?!{_TOKEN})\S+",
            re.IGNORECASE,
        ),
    ),
    # Routing-protocol authentication keys/passwords:
    #   `ip ospf message-digest-key <id> md5 <secret>`
    #   `neighbor <ip> password <secret>`   (BGP)
    #   `... authentication-key <secret>`    (OSPF/ISIS/interface)
    #   `... message-digest-key <id> md5 <secret>`
    (
        "routing_auth_key",
        re.compile(
            rf"\b(message-digest-key\s+\d+\s+md5)\s+{_VALUE}",
            re.IGNORECASE,
        ),
    ),
    (
        "routing_auth_key",
        re.compile(
            rf"\b(neighbor\s+\S+\s+password)\s+{_VALUE}",
            re.IGNORECASE,
        ),
    ),
    # `... authentication-key [<key-id>] [<md5|encoding>] <secret>`. Several
    # vendors prefix the secret with a numeric key-id and/or an encoding keyword
    # (`md5`, a type number such as `7`). Those indicators are part of the
    # directive context (captured in group 1 and preserved) — only the trailing
    # secret value is tokenized. Without consuming them the redactor would strip
    # the key-id and leave `md5 <secret>` / the type-7 hex in cleartext.
    (
        "routing_auth_key",
        re.compile(
            rf"\b(authentication-key(?:\s+\d+)?(?:\s+md5)?)\s+(?!(?:md5|\d+)\b)(?!{_TOKEN})\S+",
            re.IGNORECASE,
        ),
    ),
    # Interface link-auth secrets: PPP CHAP/PAP passwords.
    (
        "interface_auth_key",
        re.compile(
            rf"\b(ppp\s+(?:chap|pap)\s+password)\s+{_VALUE}",
            re.IGNORECASE,
        ),
    ),
    # Enable secret (plaintext or already-typed forms not matched above):
    # `enable secret <secret>` / `enable password <secret>`. Placed late so the
    # type 8/9 and type 7 encodings are classified first.
    (
        "enable_secret",
        re.compile(
            rf"\b(enable\s+(?:secret|password))\s+{_VALUE}",
            re.IGNORECASE,
        ),
    ),
    # Plaintext local credentials and line/vty passwords:
    #   `username <u> password <plaintext>` / `username <u> secret <plaintext>`
    #   `password <plaintext>` (line con/vty) / explicit type-0 `password 0 <pw>`
    # These are the most common cleartext credentials in discovery / config-backup
    # output. Placed last so every typed/encoded form (type 7/8/9, enable secret,
    # routing/aaa/ipsec keys) is classified first; the optional `0` encoding digit
    # is consumed before the value, and the `(?!_TOKEN)` guard keeps it from
    # re-matching an already-redacted value (idempotent).
    (
        "plaintext_password",
        re.compile(
            rf"\b((?:username\s+\S+\s+)?(?:password|secret))\s+(?:0\s+)?(?!{_TOKEN})\S+",
            re.IGNORECASE,
        ),
    ),
]


def _replace(kind: str, match: re.Match[str]) -> str:
    """Build the replacement: keep the directive (group 1, if any), drop value.

    Patterns that capture a directive prefix in group 1 keep it for context;
    bare-value patterns (e.g. a standalone ``$9$...`` hash) have no group 1 and
    are replaced wholesale by the token.
    """
    directive = match.group(1) if match.lastindex else None
    if directive:
        return f"{directive} {REDACTION_TOKENS[kind]}"
    return REDACTION_TOKENS[kind]


def redact_prompt(text: str) -> str:
    """Return *text* with every known vendor secret pattern redacted.

    Each secret value is replaced by a stable ``<<REDACTED:...>>`` token while
    its directive prefix is preserved. The function is idempotent: applying it
    to already-redacted text returns that text unchanged.
    """
    redacted = text
    for kind, pattern in _PATTERNS:

        def _sub(match: re.Match[str], _kind: str = kind) -> str:
            return _replace(_kind, match)

        redacted = pattern.sub(_sub, redacted)
    return redacted


def _redact_content(content: object) -> object:
    """Redact a message ``content`` value (str or list of content blocks)."""
    if isinstance(content, str):
        return redact_prompt(content)
    if isinstance(content, list):
        blocks: list[object] = []
        for block in content:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                new_block = dict(block)
                new_block["text"] = redact_prompt(block["text"])
                blocks.append(new_block)
            elif isinstance(block, str):
                blocks.append(redact_prompt(block))
            else:
                blocks.append(block)
        return blocks
    return content


def redact_messages(messages: Sequence[BaseMessage]) -> list[BaseMessage]:
    """Return a new message list with secrets redacted in every message body.

    The input messages are never mutated; each message is shallow-copied with
    its redacted content via Pydantic's ``model_copy``.
    """
    redacted: list[BaseMessage] = []
    for message in messages:
        new_content = _redact_content(message.content)
        if new_content == message.content:
            redacted.append(message)
        else:
            redacted.append(message.model_copy(update={"content": new_content}))
    return redacted


def _redact_prompt_value(value: PromptValue) -> PromptValue:
    """Redact the messages carried by a converted :class:`PromptValue`."""
    if isinstance(value, StringPromptValue):
        return StringPromptValue(text=redact_prompt(value.text))
    return ChatPromptValue(messages=redact_messages(value.to_messages()))


class RedactingChatModel(BaseChatModel):
    """A ``BaseChatModel`` wrapper that redacts secrets on every call path.

    Constructed centrally by :func:`~app.llm.providers.get_chat_model` so no
    caller can bypass redaction. It intercepts the two convergence points used
    by LangChain/LangGraph:

    * :meth:`generate_prompt` / :meth:`agenerate_prompt` — used by
      ``invoke``/``ainvoke``/``generate``/``batch``; and
    * :meth:`_convert_input` — used by ``stream``/``astream``.

    Generation itself, tool binding, and metadata are delegated unchanged to the
    wrapped ``inner`` model.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    inner: BaseChatModel

    @property
    def _llm_type(self) -> str:
        return f"redacting:{self.inner._llm_type}"

    # -- convergence point 1: invoke / ainvoke / generate / batch -----------
    def generate_prompt(
        self,
        prompts: list[PromptValue],
        stop: list[str] | None = None,
        callbacks: Callbacks = None,
        **kwargs: Any,
    ) -> LLMResult:
        redacted = [_redact_prompt_value(p) for p in prompts]
        return self.inner.generate_prompt(redacted, stop=stop, callbacks=callbacks, **kwargs)

    async def agenerate_prompt(
        self,
        prompts: list[PromptValue],
        stop: list[str] | None = None,
        callbacks: Callbacks = None,
        **kwargs: Any,
    ) -> LLMResult:
        redacted = [_redact_prompt_value(p) for p in prompts]
        return await self.inner.agenerate_prompt(redacted, stop=stop, callbacks=callbacks, **kwargs)

    # -- convergence point 2: stream / astream ------------------------------
    def _convert_input(self, model_input: LanguageModelInput) -> PromptValue:
        return _redact_prompt_value(super()._convert_input(model_input))

    # -- delegation ---------------------------------------------------------
    def bind_tools(
        self,
        tools: Sequence[dict[str, Any] | type | Callable[..., Any] | BaseTool],
        **kwargs: Any,
    ) -> Runnable[LanguageModelInput, AIMessage]:
        return self.inner.bind_tools(tools, **kwargs)

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        # Reached only if some path bypasses generate_prompt; redact here too so
        # the wrapper is safe even then.
        return self.inner._generate(
            redact_messages(messages), stop=stop, run_manager=run_manager, **kwargs
        )

    async def _agenerate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: AsyncCallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        return await self.inner._agenerate(
            redact_messages(messages), stop=stop, run_manager=run_manager, **kwargs
        )


def wrap_with_redaction(model: BaseChatModel) -> RedactingChatModel:
    """Wrap *model* so every prompt is redacted before it reaches the provider."""
    if isinstance(model, RedactingChatModel):
        return model
    return RedactingChatModel(inner=model)


__all__ = [
    "REDACTION_TOKENS",
    "RedactingChatModel",
    "redact_messages",
    "redact_prompt",
    "wrap_with_redaction",
]
