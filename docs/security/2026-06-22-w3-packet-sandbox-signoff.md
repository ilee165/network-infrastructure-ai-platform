# W3 Security Review Sign-Off — Packet-Sandbox OS-Isolation (M5 §2 successor)

**Date:** 2026-06-22
**Milestone:** P1 W3 (packet-sandbox OS-isolation + K8s hardening round 1)
**Authority:** CLAUDE.md "Development Standards" step 5 (security review);
`docs/roadmap/P1-PLAN.md` §3 row W3; ADR-0031 (packet-sandbox OS-isolation),
ADR-0029 (K8s/Helm GA + hardening R1), ADR-0023 §1 (the OS-isolation half it
deferred), ADR-0013 §4 (chart `PodSecurityContext`/NetworkPolicy promise).
**Purpose:** the successor sign-off named in ADR-0031 §7. It re-evaluates the M5
sign-off's **control #2** (`docs/security/2026-06-19-m5-security-review-signoff.md`
§2), which was **PARTIAL** because the OS-level isolation half had no implemented
or declared evidence. That work landed in P1 W3 (PR #58); this note signs control
#2 **PASS** against the rendered manifests + the runtime posture hook + the green
CI policy-as-test job.

Legend: **PASS** = control implemented, evidenced (`file:line` / rendered-manifest
field / pinning test), and gate-verified. All backend/frontend/infra/docker CI
jobs are green on the sign-off commit.

---

## M5 control #2 — Packet sandbox per D14: OS-level isolation

**Status: PASS** (was PARTIAL at M5; the deferred OS-level half is now implemented,
rendered, and policy-as-test verified.)

The M5 sign-off signed the **process-launch** controls (argv-not-shell, filter
whitelist, `-n`, hard timeout, capture/analysis credential split) PASS and
explicitly deferred the **OS-level** half — resource limits, no-network container,
dropped capabilities, non-root, read-only mount — because `deploy/kubernetes/` was
README-only and the Compose stack ran one shared unhardened worker. W3 closes that
gap on both deployment targets (Helm + Compose) and adds a fail-closed runtime
backstop in code.

### 2a. Analysis Pod containment profile (ADR-0031 §2) — PASS

The `packet-analysis` parser (highest-risk workload: untrusted pcap → tshark C
dissectors) runs under the full hardened `securityContext`, rendered from
hardened-by-default values:

- **non-root:** `runAsNonRoot: true`, `runAsUser >= 10000`
  (`deploy/kubernetes/netops/templates/packet-analysis-deployment.yaml:42,60-61`).
- **no privilege escalation:** `allowPrivilegeEscalation: false` (`:63`).
- **zero capabilities:** `capabilities.drop: ["ALL"]`, **no `add`** — `NET_RAW`
  must not appear here (`:68`; asserted absent by the admission rule, 2d).
- **read-only rootfs:** `readOnlyRootFilesystem: true` (`:64`); one sized
  `emptyDir` scratch at the tshark temp path is the only writable mount.
- **seccomp:** `seccompProfile.type: Localhost` referencing the §3 profile
  (`:46-48,70-72`).
- **pcap volume `readOnly: true`** and CPU/memory `requests`+`limits` (the parser
  cannot alter evidence and an adversarial capture is OOM/CPU-bounded, not a node
  exhaustion).

### 2b. Localhost seccomp profile (ADR-0031 §3) — PASS

`deploy/kubernetes/netops/seccomp/packet-analysis-seccomp.json` is **deny-by-default**:
`"defaultAction": "SCMP_ACT_ERRNO"` with an allow-list of only the file-read /
memory / process-lifecycle syscalls tshark+pyshark need. **Explicitly denied** (not
in the allow-list, so caught by the default action): `socket(AF_PACKET)`, `bpf`,
`ptrace`, `mount`, `unshare`, `setns`, `keyctl`/`add_key`/`request_key`,
`process_vm_readv/writev`, `kexec`, `init_module`, `personality` — the known
sandbox-escape / network-path primitives. Mirrored **byte-for-byte** to
`deploy/docker/seccomp/packet-analysis-seccomp.json` and wired via Compose
`security_opt: ["seccomp=…"]` so both deployment targets stay in lockstep
(ADR-0013 two-artifact discipline). `RuntimeDefault` is the floor; this is the
target because the runtime default still permits `socket`/`bpf`/`unshare`.

### 2c. Default-deny egress NetworkPolicy (ADR-0031 §4) — PASS

`deploy/kubernetes/netops/templates/packet-analysis-networkpolicy.yaml` selects the
analysis pod, `policyTypes: [Ingress, Egress]`, **no ingress rules** (deny all
inbound), and egress allow-listed to **cluster DNS (53), Postgres, and the
Redis/broker** only — nothing else leaves the parser. (The Redis/broker egress was
the W3 review's critical fix: without it the Celery worker silently drops all
work.) The credential-bearing `packet-capture` workload has its **own** policy
(`packet-capture-networkpolicy.yaml`) confining egress to the management subnet —
it is not granted unrestricted egress.

### 2d. NET_RAW scoped to capture only, on a tainted pool, admission-enforced (ADR-0031 §2/§5) — PASS

- `packet-capture` is the **sole** workload that adds `NET_RAW`/`NET_ADMIN`
  (worker-side tcpdump), drop-ALL otherwise
  (`packet-capture-deployment.yaml:76-80`), pinned to the tainted packet node pool
  so a raw-socket-capable Pod never co-schedules with a general Pod.
- The Kyverno `ClusterPolicy` rule `restrict-net-raw-to-packet-sandbox`
  (`templates/policy/kyverno-clusterpolicy.yaml:89-102`) makes the parser **subject
  to** the rule via a narrow capture-only deviation label, so a `NET_RAW`
  regression on the analysis pod **fails admission** — the deviation cannot
  silently spread. A `ValidatingAdmissionPolicy` fallback ships for webhook-averse
  clusters. Namespace carries PSS `enforce: restricted`.

### 2e. Fail-closed runtime backstop (ADR-0031 §2 final ¶) — PASS

A Python hook asserts the OS posture **before** tshark is ever spawned, so a
misconfigured deployment fails closed instead of running unconfined:

- `app/engines/packet/posture.py::assert_sandbox_posture(*, enforced)` checks
  effective UID ≠ 0, `CAP_NET_RAW` absent from the permitted set, and `/` mounted
  read-only; raises `PostureError` on the first failure (naming the control, no
  secret material). Missing `/proc` reads **fail closed**.
- Invoked on **both** tshark spawn paths: the worker task
  (`app/workers/tasks/packet.py:157`) and the synchronous
  `GET /captures/{id}/analysis` API path (`app/api/v1/agents.py:200`) — the latter
  was the W3 review's must-fix (the web pod was a second, unguarded spawn path).
- Gated by `settings.packet_sandbox_posture_enforced` (**default `True`**;
  `app/core/config.py:112`). Off only for the eager unit/CI runner where OS
  controls are not applied.

**Evidence (tests):**
- `tests/engines/packet/test_posture.py::test_posture_passes_when_hardened`
- `::test_posture_refuses_when_running_as_root`
- `::test_posture_refuses_when_cap_net_raw_permitted`
- `::test_posture_refuses_when_rootfs_writable`
- `::test_posture_failclosed_on_missing_proc`
- `::test_posture_error_carries_no_secret_material`
- `::test_posture_disabled_is_a_noop`

**Evidence (policy-as-test gate):** CI job **`infra (helm lint, kubeconform,
kube-linter, conftest)`** (`.github/workflows/ci.yml:189`) renders the chart and
asserts each control above via conftest/OPA on the rendered manifests
(`deploy/kubernetes/policy/rego/hardening.rego`) plus helm lint + kubeconform +
kube-linter. **Green on PR #58** — this is the ADR-0031 §7 exit evidence.

---

## Sign-off

| # | Control | M5 status | W3 status |
|---|---------|-----------|-----------|
| 2 | Packet sandbox per D14 — OS-level limits / no-network / dropped caps / non-root / RO mount | PARTIAL (process-launch only) | **PASS** |

**M5 §2 is hereby signed PASS.** The OS-level isolation half ADR-0023 §1 deferred
is implemented on both deployment targets (Helm chart + Compose seccomp lockstep),
backstopped by a fail-closed runtime posture hook, and verified by the green
`infra` policy-as-test CI job on the rendered chart (ADR-0031 §7 exit criterion).

**Deferred (non-blocking, tracked → W4), do not block this PASS:**
- seccomp-installer DaemonSet / node-provisioning to place the Localhost profile at
  the kubelet seccomp root (chart references the path; node-copy not yet shipped —
  pods needing the profile will not start until provisioned).
- Trivy **config** (IaC misconfig) scan currently `exit-code: 0` (non-blocking);
  conftest/OPA is the enforcing policy gate. Consider `exit-code: 1` + `.trivyignore`.
- conftest rego asserts admission rule **names**, not full rule **bodies**;
  `--namespace`/`--all-namespaces` invocation contradiction; Compose `security_opt`
  relative-path resolves to client CWD.
- gVisor/Kata runtimeClass — recorded PROPOSED future hardening (ADR-0031
  alternatives §5), layered on top of, not instead of, the §2–§5 controls.
