# ADR-0031: Packet Capture Sandbox OS-Level Isolation

**Status:** Proposed | **Date:** 2026-06-20 | **Milestone:** P1 W0

## Context

ADR-0023 (D14 realization) split packet-analysis containment into two halves: **process-launch controls** (argv-not-shell, filter whitelist, `-n` no-resolution, hard subprocess timeout, capture/analysis credential split) and **OS-level isolation** (resource limits, no egress, dropped capabilities, non-root, read-only mount). M5 shipped and test-pinned the process-launch half; the OS-level half was explicitly deferred. The M5 security sign-off (`docs/security/2026-06-19-m5-security-review-signoff.md` §2) records control #2 as **PARTIAL** for exactly this reason: "resource (CPU/mem) limits, no-network container, dropped capabilities (`cap_drop: [ALL]`), non-root, read-only pcap mount … have no implemented or declared evidence today" because `deploy/kubernetes/` is README-only (chart planned, "no manifests ship") and `deploy/docker/docker-compose.yml` runs a single shared Celery `worker` over all queues (`discovery,config,packet,docs,system`) with no `cap_drop`, `security_opt`, `read_only`, network isolation, or `mem_limit`/`cpus`.

P1 W0 is the design gate that closes this gap. Per `docs/roadmap/P1-PLAN.md` §1/§3 (W3) this ADR is the "M5 carry-in — Packet-sandbox OS-isolation" item that "clears the PARTIAL M5 security sign-off (ADR-0013 §4 / ADR-0023 §1)". The scope source is `PRODUCTION.md` §5 (security-hardening checklist — "Collector network segmentation: workers reaching device management networks run in a dedicated namespace/node pool with egress restricted … via NetworkPolicy") and §3.1 (the production topology, which already places `WP[packet workers - sandboxed node pool]` as a distinct worker tier).

The driving threat is unchanged and restated from ADR-0023: **pcaps are untrusted, remote-attacker-controlled input** and **tshark's C dissectors carry parsing CVEs**. The process-launch controls keep a hostile filename or filter from executing; they do **not** contain a memory-corruption exploit *inside* the tshark process. OS-level isolation is the boundary that ensures that if a dissector is popped, the attacker lands in a process that is non-root, holds no Linux capabilities, has no writable filesystem, has no network route out, and shares a node with nothing worth stealing. This ADR is **Proposed** — it is the design contract; the pod profile, seccomp profile, NetworkPolicy, and node-pool taint land in P1 W3 (`wf-infra` for the declarative YAML, `wf-implementer` for the Python runtime hooks).

This ADR **extends** ADR-0023 §1 (the OS-isolation half it deferred) and ADR-0013 §4 (the Helm chart's `PodSecurityContext`/NetworkPolicy promise). It contradicts neither. Where it adds precision beyond `PRODUCTION.md` §9 (which proposed packet workers be "`NET_RAW`-capable but still non-root"), it **narrows** that statement: §2 below decides that the *parser* is **not** `NET_RAW`-capable — only a separate privileged capture sidecar/node-pool is — and explains why.

## Decision

**The `packet` queue runs as two distinct, separately-hardened workloads on a dedicated tainted node pool. The capture path (privileged: `NET_RAW`, credential-bearing, read-write pcap mount) and the analysis/parse path (unprivileged: zero capabilities, no credentials, read-only pcap mount, no egress, seccomp-confined, read-only root filesystem, resource-bounded) never share a Pod, a ServiceAccount, or a Linux capability set. `NET_RAW` is granted only to the capture workload and only on the tainted node pool, so a raw-socket-capable workload can never co-schedule with a general platform Pod.**

### 1. Two workloads, not one — the privilege split made physical

ADR-0023 §2 already separated capture (credentials, rw) from analysis (no credentials, ro) at the *role* level. M5 implemented both roles inside the single shared worker container. P1 makes the split a **deployment boundary**: two Kubernetes Deployments, each with its own SecurityContext, ServiceAccount, and NetworkPolicy.

| Property | `packet-capture` workload | `packet-analysis` workload |
|---|---|---|
| Job | run `tcpdump` worker-side; drive device-side capture (`eos` monitor-session) | run tshark/pyshark over the stored pcap |
| Input trust | trusted (we issue the BPF/vendor filter) | **untrusted** (the pcap bytes) |
| Linux caps | `drop: [ALL]`, `add: [NET_RAW, NET_ADMIN]` (worker-side `tcpdump` only) | `drop: [ALL]`, **add: none** |
| Device credentials | yes — vault-reachable via `credential_ref` (ADR-0011 §2) for the SSH capture session | **no** — not granted the credentials-service role; vault unreachable (ADR-0023 §1) |
| pcap volume mount | read-write (writes the capture file) | **read-only** |
| Egress | management-subnet only (device SSH/capture) via NetworkPolicy | **default-deny** (Postgres results + read-only pcap volume only) |
| Node pool | `packet` tainted pool | `packet` tainted pool (same taint; analysis Pods need no `NET_RAW`) |
| ServiceAccount | `packet-capture-sa`, `automountServiceAccountToken: false` | `packet-analysis-sa`, `automountServiceAccountToken: false` |

The point of separation (ADR-0023 §1): the credential-bearing path and the untrusted-parser exposure never live in the same process. M5's shared-worker arrangement violated this physically even though the code kept the roles distinct; P1 fixes it.

A worker-side `tcpdump` capture genuinely needs `NET_RAW` (open a raw/packet socket on the host interface). The **parser does not** — tshark reads a file, not a socket. This is why `PRODUCTION.md` §9's "`NET_RAW`-capable but still non-root" is narrowed here to apply **only to the capture workload**: granting `NET_RAW` to the parser would hand a dissector-CVE exploit a raw socket for free. The analysis workload's capability set is empty.

### 2. Analysis-Pod hardening — the containment profile

The `packet-analysis` Pod is the highest-risk workload on the platform. Its `securityContext` (Pod + container) is:

| Control | Value | Why |
|---|---|---|
| `runAsNonRoot` | `true` | a dissector exploit lands as an unprivileged UID, not root |
| `runAsUser` / `runAsGroup` | non-zero (e.g. `10001`) | explicit, not image-default |
| `allowPrivilegeEscalation` | `false` | no setuid/`no-new-privileges` path to regain privilege |
| `capabilities.drop` | `["ALL"]` | tshark file-parsing needs **zero** capabilities |
| `capabilities.add` | `[]` | explicitly none — narrows `PRODUCTION.md` §9 for the parser |
| `readOnlyRootFilesystem` | `true` | no writable code/lib paths; matches `PRODUCTION.md` §9 "`readOnlyRootFilesystem: true` everywhere" |
| `seccompProfile.type` | `Localhost`, ref the profile in §3 | syscall-level confinement of the C parser |
| pcap volume mount | `readOnly: true` | parser cannot alter/delete evidence (only capture + retention write/delete, ADR-0023 §2/§4) |
| writable scratch | a single `emptyDir` at the pyshark/tshark temp path, `sizeLimit` set | `readOnlyRootFilesystem` still needs a bounded tmp; `PRODUCTION.md` §9 names "pcap scratch" as the allowed writable `emptyDir` |
| `resources.requests`/`limits` | CPU + memory bounded (e.g. `limits: cpu, memory`) | an oversized/adversarial capture is OOM-killed/CPU-throttled, not allowed to exhaust the node (`PRODUCTION.md` §9 "Resource requests/limits on every container") |

This **adds to** — does not replace — the M5 process-launch controls (argv-not-shell, filter whitelist, `-n`, hard subprocess timeout): defense in depth. The subprocess timeout (ADR-0023 §1) and the memory `limit` are complementary — the timeout bounds wall-clock, the cgroup memory limit bounds RSS; a pcap that is slow *and* memory-hungry hits whichever fires first.

A Python runtime hook in the analysis worker asserts the expected posture at task start (effective UID ≠ 0, no `CAP_NET_RAW` in the permitted set, root filesystem read-only) and refuses to spawn tshark otherwise — so a misconfigured deployment fails closed rather than silently running unconfined. This is the `wf-implementer` half of W3 (sandbox runtime hooks) named in `P1-PLAN.md` §3.

### 3. seccomp profile

A `Localhost`-type seccomp profile (shipped with the Helm chart, applied via `securityContext.seccompProfile`) confines the analysis container to the syscalls tshark/pyshark actually need. Posture:

- **Default action `SCMP_ACT_ERRNO`** (deny-by-default), with an allow-list covering the file-read, memory, and process-lifecycle syscalls the tshark child and the Python parent require.
- **Explicitly absent / denied:** raw-socket and network-namespace syscalls (`socket(AF_PACKET, …)`), `mount`, `ptrace`, `bpf`, keyring, and `unshare`/`setns` — none are needed to parse a file, and each is a known sandbox-escape primitive.
- The profile is **versioned in-repo** alongside the Helm chart (one source of truth, ADR-0013) and is validated in CI (the `wf-infra` policy-as-test discipline, `P1-PLAN.md` §2). A Compose-equivalent JSON profile is wired via `security_opt: ["seccomp=<file>"]` so the two deployment targets stay in lockstep (ADR-0013 negative).

`RuntimeDefault` is the floor we will not ship below; the custom `Localhost` profile is the target because the platform's default (e.g. Docker/containerd) seccomp still permits `socket`/`bpf`, which the parser must never call.

### 4. Default-deny egress NetworkPolicy

The analysis workload gets a **default-deny ingress+egress** NetworkPolicy (matching `PRODUCTION.md` §9 "default-deny ingress+egress in all platform namespaces") with only the minimum allows:

- **Egress allowed:** Postgres (write normalized findings + `pcap_metadata`) and DNS to the cluster resolver *only if required by the Postgres connection*; **no** route to device-management subnets, **no** internet egress, **no** Redis-write beyond result backend if the architecture routes results through Postgres directly.
- **Ingress allowed:** none from outside the namespace (the worker pulls jobs from Redis; the broker connection is egress from the worker's perspective and is allow-listed to the Redis Service only).
- tshark is still invoked with **`-n`** (ADR-0023 §1) so even the DNS allow is never exercised by dissection — the NetworkPolicy is the backstop, `-n` is the primary control. Two independent layers, neither relied on alone.

The **capture** workload's NetworkPolicy is separate and **does** allow management-subnet egress (it must reach devices), confined to those subnets — this is the `PRODUCTION.md` §5 "collector network segmentation" item. The capture workload, however, never parses untrusted bytes, so its broader egress is paired with no dissector exposure. The two NetworkPolicies make the trade explicit: egress lives with capture (trusted input), parsing lives with analysis (no egress).

### 5. Dedicated node pool — taint + toleration so `NET_RAW` never co-schedules

`PRODUCTION.md` §3.1 already shows `WP[packet workers - sandboxed node pool]` and §9 requires the packet workers to be "isolated on a dedicated node pool". This ADR fixes the mechanism:

- **Node taint:** the packet node pool carries `node-role.netops/packet=true:NoSchedule`.
- **Toleration:** only the `packet-capture` and `packet-analysis` Deployments declare the matching toleration. No general platform workload (`api`, `config`/`docs`/`discovery` workers, data stores) tolerates the taint, so the scheduler will never place a general Pod on a node where a `NET_RAW`-capable capture Pod runs.
- **`nodeSelector`/affinity:** both packet Deployments select the packet pool; analysis Pods may additionally use anti-affinity from credential-bearing capture Pods if operators want capture and parse on separate nodes within the pool (PROPOSED hardening, not required for the gate).
- **PSS exception, scoped:** the cluster enforces Pod Security Standards `restricted` namespace-wide (`PRODUCTION.md` §9). The packet workloads need a **documented, minimal deviation** because the capture Pod adds `NET_RAW`. The deviation is granted **only** to the packet namespace/node pool and **only** for `NET_RAW`+`NET_ADMIN` on the capture workload; the analysis workload stays fully `restricted`-compliant (it adds no capability). This is the exact "documented, minimal deviation … isolated on a dedicated node pool with its own seccomp profile and a default-deny NetworkPolicy" carve-out `PRODUCTION.md` §9 anticipated. **No privileged containers anywhere** — `NET_RAW` is a single capability, not `privileged: true`.

This taint/toleration model is the decision that satisfies the task's "so `NET_RAW` workloads never co-schedule with general workloads": isolation is enforced by the scheduler (taint), not by convention.

### 6. Secret posture (unchanged, restated)

No credential material appears in any manifest, env value, log line, audit detail, or exception. The capture workload reaches the vault by `credential_ref` (ADR-0011 §2, ADR-0024 §2 posture) and the device-credential plaintext lives only inside the SSH/capture session (M5 sign-off §5; `backend/app/workers/tasks/packet.py` "Secret discipline (D11)"). The analysis workload holds **no** credentials at all. Helm injects platform secrets (DB password, KEK reference) via `existingSecret` references (ADR-0013 §4); **no Kubernetes Secret holds device credentials** — they stay AES-256-GCM-encrypted in Postgres (`PRODUCTION.md` §9). pcap files themselves may contain cleartext payload credentials; their at-rest exposure is bounded by retention/tombstone (ADR-0023 §4) and access by the audited `engineer`+ download (ADR-0023 §5) — out of scope for this OS-isolation ADR but noted so the boundary is complete.

### 7. Clearing the M5 PARTIAL sign-off — residual risk and exit criterion

This ADR is the **design** that clears `m5-security-signoff §2`. It does not by itself flip the control to PASS — implementation lands in P1 W3.

- **Residual risk while PARTIAL (today → W3 lands):** the M5 process-launch controls are real and test-pinned, but a tshark dissector memory-corruption CVE exploited in the M5/Compose arrangement runs in a worker that is **root-capable, on the shared worker, with egress and (for the shared container) reachability to other queues' resources**. Until the two-workload split + this profile ship, a successful dissector exploit is a node-level and lateral-movement risk, not a contained one. This is the precise residual the M5 sign-off flagged.
- **Exit criterion (flips §2 to PASS):** the `packet-analysis` Deployment runs `runAsNonRoot`, `capabilities.drop:[ALL]` with no `add`, `readOnlyRootFilesystem:true`, the §3 seccomp profile, the §4 default-deny egress NetworkPolicy, and §2 resource limits; the `packet-capture` Deployment is separated with `NET_RAW` scoped to it; both are pinned to the §5 tainted node pool with a documented PSS deviation; and CI policy-as-test (helm lint / kubeconform / kube-linter / conftest-OPA, `P1-PLAN.md` §2) asserts each control on the rendered chart. A successor sign-off note re-evaluates §2 against the rendered manifests + passing policy tests and signs **PASS** only then. Until that evidence exists, §2 stays PARTIAL (M5 sign-off's own instruction: "It must not be signed PASS until that work lands").

## Consequences

**Positive**
- A tshark dissector CVE exploited on untrusted pcap bytes lands in a process that is non-root, capability-less, read-only-rootfs, seccomp-confined, egress-denied, resource-bounded, and on a node sharing nothing worth stealing — the real containment boundary ADR-0023 promised, now physical.
- `NET_RAW` is confined to the capture workload on a tainted pool, so the scheduler — not convention — guarantees a raw-socket-capable Pod never sits beside a general platform Pod; the parser holds zero capabilities.
- The capture/analysis split is enforced at the Pod/ServiceAccount/NetworkPolicy level, so neither half ever holds both credentials and untrusted-parser exposure; this also tightens M5, which kept the roles distinct only in code.
- Two independent layers back each high-value control (egress: `-n` + default-deny NetworkPolicy; resource bound: subprocess timeout + cgroup limits; privilege: process-launch controls + dropped caps/seccomp) — defense in depth, no single point of failure.
- Closes the named M5 PARTIAL item with an explicit, testable exit criterion and a successor sign-off, ending the silent-drift risk.

**Negative**
- A dedicated, tainted packet node pool plus two separate Deployments is more operational surface than one shared worker (extra node pool to size, two SecurityContexts/NetworkPolicies/ServiceAccounts to maintain, Compose↔Helm lockstep for the seccomp profile per ADR-0013's two-artifact tax).
- A custom `Localhost` seccomp profile is a maintenance item: a tshark/pyshark upgrade that needs a new syscall fails closed and requires a profile bump (intentional — fail-closed is the safer default — but it is a real upgrade-time gate).
- The documented PSS `restricted` deviation for `NET_RAW` on the capture workload is a (minimal, scoped) widening of the namespace-wide policy; it must be re-justified at each K8s hardening review so it does not quietly broaden.
- The packet node pool may be under-utilized at low capture volume (dedicated capacity for a bursty workload); bin-packing it with other batch work is rejected (§5) because that would re-admit general workloads onto `NET_RAW` nodes.

## Alternatives considered

1. **Keep the single shared worker; rely only on the M5 process-launch controls.** Rejected, security-critical: that worker is credential-bearing, root-capable, and has reachability to other queues' data stores. Process-launch controls stop a hostile filename from executing but do nothing to contain a memory-corruption exploit *inside* tshark — exactly the threat ADR-0023's OS-isolation half exists to contain. This is the status quo the M5 sign-off marked PARTIAL; leaving it is declining to fix the flagged residual.
2. **Grant the parser `NET_RAW` too (literal reading of `PRODUCTION.md` §9 "`NET_RAW`-capable but still non-root").** Rejected: tshark parses a *file*, never opens a socket, so `NET_RAW` is unnecessary for the parser and would hand a dissector-CVE exploit a raw socket for free. §1/§2 narrow §9 so `NET_RAW` lives only on the capture workload; the parser's capability set is empty. (This is a deliberate, documented narrowing of a PROPOSED line in PRODUCTION.md, not a contradiction of a binding D-decision.)
3. **One Pod with a privileged capture sidecar + analysis container sharing the pcap `emptyDir`.** Rejected: co-locating a `NET_RAW`-capable, credential-bearing container in the same Pod as the untrusted-parser container re-creates the very adjacency the split exists to remove — a parser escape shares the Pod network namespace and node with the credentialed capture process. Separate Deployments on the shared read-write pcap *volume* (capture writes, analysis reads read-only) give the same data hand-off without the privilege adjacency.
4. **`RuntimeDefault` seccomp instead of a custom `Localhost` profile.** Rejected as insufficient: the container-runtime default still permits `socket`, `bpf`, and `unshare`, which a dissector exploit could use to open a network path or escape. A deny-by-default allow-list profile (§3) is the calibrated control; `RuntimeDefault` is kept only as the floor we will not ship below.
5. **gVisor / Kata (kernel-level sandbox runtime) for the analysis Pod instead of seccomp+caps+NetworkPolicy.** Rejected for P1 as a hard requirement: a userspace-kernel or microVM runtime is the strongest containment but adds a runtimeClass dependency and per-node operational burden not all on-prem clusters can meet, conflicting with "Local first / Self hosted" (CLAUDE.md). It is recorded as a **PROPOSED future hardening** (an opt-in `runtimeClassName` value in the chart) layered on top of — not instead of — the §2–§5 controls, which are sufficient to clear the M5 PARTIAL item.
6. **Affinity/`nodeSelector` only (no taint) to keep packet workloads on their pool.** Rejected: a selector attracts packet Pods to the pool but does **not** repel general Pods from it, so a general workload could still land on a `NET_RAW` node. The taint+toleration (§5) is what makes co-scheduling impossible; the selector/affinity is complementary, not a substitute.
