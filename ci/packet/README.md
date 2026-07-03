# Packet-analysis executor bite-proof helpers (ADR-0049 §Acceptance)

These files back the Linux CI job `packet-analysis-bite-proof` in
`.github/workflows/ci.yml`. That job is the **re-enable gate** for the
packet-analysis service: ADR-0049 requires the executor-split sandbox to be
test-pinned by a three-leg Linux bite-proof (real seccomp + tshark) that is green
at HEAD before the service goes back on by default. The job builds the
`packet-analysis` image (`--target packet-analysis`, which ships tshark +
libseccomp) and runs the **real** `python -m app.engines.packet.executor` under
the real deployment posture (`--cap-drop ALL`, `--user 10001`, `--read-only`, the
committed dispatcher seccomp profile). None of this can run on the Windows dev
host — the seccomp filter load is Linux-kernel-only — so locally these are only
authored + syntax-checked; the live run is verified on CI.

| File | Leg | What it proves |
|---|---|---|
| `gen_fixture_pcap.py` | GREEN | Writes a 1-packet Ethernet/IPv4/UDP libpcap (stdlib only) that the confined executor dissects into a schema-valid `PacketFindings` (`packet_count == 1`). |
| `assert_findings.py` | GREEN | Validates the executor's stdout is a schema-shaped `PacketFindings` with `packet_count >= 1`. |
| `wedge_tshark.sh` | TIMEOUT | Stand-in "tshark" that records its PID and sleeps 600s — the grandchild the dispatcher's process-group kill must reap. |
| `timeout_reap_driver.py` | TIMEOUT | Drives the real `sandbox._spawn_and_reap` with a small outer timeout + large inner timeout, then asserts the wedge grandchild is gone (killpg worked, no orphan). |

The RED leg uses the executor's own `--self-test={socket,ptrace}` flag (no helper
file): under confinement the probe is denied (`SELFTEST_DENIED`, exit 80); the
negative control runs the same probe **unconfined** (enforcement off) and must
SUCCEED (`SELFTEST_NOT_CONFINED`, exit 81) — if the negative control does not
flip, the gate is not biting and the job fails.
