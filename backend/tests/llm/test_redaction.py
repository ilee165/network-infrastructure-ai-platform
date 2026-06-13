"""Tests for the prompt-redaction layer (app/llm/redaction.py, A9).

Every model invocation must strip vendor secrets *before* the prompt leaves
the process, on every profile (including ``local``). These tests assert that:

* each seeded secret pattern is replaced by a stable token,
* redaction is idempotent (re-redacting redacted text is a no-op),
* benign configuration passes through unchanged, and
* the central wiring in ``get_chat_model`` redacts even when a caller forgets
  to redact manually — and does so for every profile.

No network access: the wiring test wraps a scripted fake chat model and
inspects the messages it actually received.
"""

from __future__ import annotations

import pytest
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from app.core.config import Settings
from app.llm.providers import KNOWN_PROFILES, get_chat_model
from app.llm.redaction import (
    REDACTION_TOKENS,
    RedactingChatModel,
    redact_messages,
    redact_prompt,
)

# Each entry: (label, secret-bearing config line, the redaction-kind token that
# must appear afterwards, and a non-secret substring that must survive).
SECRET_CASES: list[tuple[str, str, str, str]] = [
    (
        "snmp_community",
        "snmp-server community S3cr3tRO RO",
        "snmp_community",
        "snmp-server community",
    ),
    (
        "snmpv3_auth",
        "snmp-server user admin GRP v3 auth sha AuthPass123 priv aes 128 PrivPass456",
        "snmpv3_auth",
        "snmp-server user admin",
    ),
    (
        "cisco_type7",
        "username bob password 7 070C285F4D06",
        "cisco_type7",
        "username bob password",
    ),
    (
        "cisco_type8",
        "username carol secret 8 $8$dsYGNam3K1SIJO$7nv/35M/qr6t051dHa7CYzns3HmiWqxxQELqMrtoBuM",
        "cisco_type89",
        "username carol secret",
    ),
    (
        "cisco_type9",
        "enable secret 9 $9$nhEmQVczB7dqsO$X.NN.5KTHc.PmGwiL.S6/mQ.GW21Ek1dNXLm6F",
        "cisco_type89",
        "enable secret",
    ),
    (
        "enable_secret_plain",
        "enable secret MyEnablePass",
        "enable_secret",
        "enable secret",
    ),
    (
        "ospf_md5_key",
        "ip ospf message-digest-key 1 md5 OspfMd5Secret",
        "routing_auth_key",
        "ip ospf message-digest-key 1 md5",
    ),
    (
        "bgp_neighbor_password",
        "neighbor 10.0.0.1 password BgpPeerSecret",
        "routing_auth_key",
        "neighbor 10.0.0.1 password",
    ),
    (
        "interface_auth_key",
        "ppp chap password InterfaceChapSecret",
        "interface_auth_key",
        "ppp chap password",
    ),
    (
        "radius_key7",
        "radius-server key 7 060506324F41",
        "aaa_shared_key",
        "radius-server key",
    ),
    (
        "tacacs_shared_key",
        "tacacs-server key MyTacacsSharedSecret",
        "aaa_shared_key",
        "tacacs-server key",
    ),
    (
        "ipsec_psk",
        "crypto isakmp key MyPreSharedKey address 10.0.0.2",
        "ipsec_psk",
        "crypto isakmp key",
    ),
]


class _CapturingChatModel(BaseChatModel):
    """A fake chat model that records the messages it is asked to generate.

    It performs no real inference: ``_generate`` records what reached it (after
    redaction) on the class and returns a fixed reply, so the wiring tests can
    assert on the captured input.
    """

    captured: list[BaseMessage] = []

    @property
    def _llm_type(self) -> str:
        return "capturing-fake"

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: object = None,
        **kwargs: object,
    ) -> ChatResult:
        type(self).captured = list(messages)
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content="ok"))])


class TestRedactPromptPatterns:
    @pytest.mark.parametrize(
        ("label", "line", "kind", "survives"),
        SECRET_CASES,
        ids=[c[0] for c in SECRET_CASES],
    )
    def test_each_secret_pattern_is_redacted(
        self, label: str, line: str, kind: str, survives: str
    ) -> None:
        redacted = redact_prompt(line)
        token = REDACTION_TOKENS[kind]
        assert token in redacted, f"{label}: expected {token} in {redacted!r}"
        # The secret material itself must be gone: the original line must change.
        assert redacted != line
        # The non-secret directive prefix is preserved for model context.
        assert survives in redacted

    def test_actual_secret_value_does_not_survive(self) -> None:
        redacted = redact_prompt("snmp-server community SuperSecretRO RO")
        assert "SuperSecretRO" not in redacted

    def test_multiple_secrets_in_one_block_all_redacted(self) -> None:
        block = "\n".join(line for _, line, _, _ in SECRET_CASES)
        redacted = redact_prompt(block)
        for _, _, kind, _ in SECRET_CASES:
            assert REDACTION_TOKENS[kind] in redacted


class TestIdempotency:
    @pytest.mark.parametrize("line", [c[1] for c in SECRET_CASES], ids=[c[0] for c in SECRET_CASES])
    def test_redacting_twice_is_a_noop(self, line: str) -> None:
        once = redact_prompt(line)
        twice = redact_prompt(once)
        assert twice == once

    def test_pre_redacted_token_is_untouched(self) -> None:
        text = f"interface auth uses {REDACTION_TOKENS['snmp_community']} now"
        assert redact_prompt(text) == text


class TestBenignTextUntouched:
    @pytest.mark.parametrize(
        "benign",
        [
            "interface GigabitEthernet0/0\n description uplink to core",
            "router bgp 65001\n neighbor 10.0.0.1 remote-as 65002",
            "ip route 0.0.0.0 0.0.0.0 192.0.2.1",
            "hostname edge-router-01",
            "Please summarize the OSPF adjacency state for area 0.",
            "snmp-server location DC1 rack 42",
        ],
    )
    def test_non_secret_config_passes_through_unchanged(self, benign: str) -> None:
        assert redact_prompt(benign) == benign


class TestRedactMessages:
    def test_string_content_messages_are_redacted(self) -> None:
        messages: list[BaseMessage] = [
            SystemMessage(content="You are a network assistant."),
            HumanMessage(content="snmp-server community LeakRO RO"),
        ]
        out = redact_messages(messages)
        assert "LeakRO" not in str(out[1].content)
        assert REDACTION_TOKENS["snmp_community"] in str(out[1].content)
        # Benign system message survives verbatim.
        assert out[0].content == "You are a network assistant."

    def test_list_block_content_is_redacted(self) -> None:
        msg = HumanMessage(
            content=[
                {"type": "text", "text": "enable secret PlainTextEnable"},
                {"type": "text", "text": "hostname r1"},
            ]
        )
        out = redact_messages([msg])
        blocks = out[0].content
        assert isinstance(blocks, list)
        assert "PlainTextEnable" not in str(blocks)
        assert REDACTION_TOKENS["enable_secret"] in str(blocks)
        assert any("hostname r1" in str(b) for b in blocks)

    def test_original_messages_are_not_mutated(self) -> None:
        original = HumanMessage(content="enable secret LeakMe")
        redact_messages([original])
        assert original.content == "enable secret LeakMe"


@pytest.fixture(autouse=True)
def _clean_provider_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate from real provider credentials on the host."""
    for var in (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "AZURE_OPENAI_API_KEY",
        "AZURE_OPENAI_ENDPOINT",
        "OPENAI_API_VERSION",
    ):
        monkeypatch.delenv(var, raising=False)


class TestCentralWiring:
    def test_get_chat_model_returns_redacting_wrapper(self, settings: Settings) -> None:
        model = get_chat_model("local", settings)
        assert isinstance(model, RedactingChatModel)

    def test_wrapper_is_a_base_chat_model_and_binds_tools(self, settings: Settings) -> None:
        model = get_chat_model("local", settings)
        assert isinstance(model, BaseChatModel)
        # bind_tools must not explode (delegated to the inner model).
        assert model.bind_tools([]) is not None

    def test_invoke_redacts_even_when_caller_forgets(self) -> None:
        inner = _CapturingChatModel()
        wrapped = RedactingChatModel(inner=inner)
        wrapped.invoke([HumanMessage(content="snmp-server community BypassRO RO")])
        captured = _CapturingChatModel.captured
        assert captured, "inner model received no messages"
        joined = " ".join(str(m.content) for m in captured)
        assert "BypassRO" not in joined
        assert REDACTION_TOKENS["snmp_community"] in joined

    async def test_ainvoke_redacts(self) -> None:
        inner = _CapturingChatModel()
        wrapped = RedactingChatModel(inner=inner)
        await wrapped.ainvoke([HumanMessage(content="enable secret AsyncLeak")])
        joined = " ".join(str(m.content) for m in _CapturingChatModel.captured)
        assert "AsyncLeak" not in joined
        assert REDACTION_TOKENS["enable_secret"] in joined

    def test_redaction_applies_on_every_profile(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://unit-test.openai.azure.example")
        monkeypatch.setenv("OPENAI_API_VERSION", "2024-06-01")
        for profile in KNOWN_PROFILES:
            model = get_chat_model(profile, settings)
            assert isinstance(model, RedactingChatModel), profile
