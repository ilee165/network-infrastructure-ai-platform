# Policy-as-test for the netops chart (P1 W3, ADR-0031 + ADR-0029 §3/§5).
#
# These OPA/conftest rules run against the RENDERED chart manifests
# (`helm template`). They are the evidence that flips the M5 PARTIAL
# packet-sandbox sign-off (ADR-0031 §7 exit criterion): each `deny` rule
# expresses one required control and fails the gate if a rendered manifest
# violates it. NEVER weaken a rule to make it green — fix the manifest.
#
# Run: helm template netops deploy/kubernetes/netops | conftest test - \
#        --policy deploy/kubernetes/policy/rego --namespace netops.hardening

package netops.hardening

import rego.v1

# ---------------------------------------------------------------------------
# conftest feeds each rendered YAML document as a separate `input` object; the
# rules below match on `input.kind` + `input.metadata.name` directly.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# ADR-0031 §2 — packet-analysis containment profile
# ---------------------------------------------------------------------------

# NET_RAW must NOT appear anywhere on packet-analysis.
deny contains msg if {
	input.kind == "Deployment"
	input.metadata.name == "packet-analysis"
	some c in input.spec.template.spec.containers
	some cap in c.securityContext.capabilities.add
	msg := sprintf("packet-analysis container %q must add no capabilities (found %q); NET_RAW is forbidden on the parser (ADR-0031 §2)", [c.name, cap])
}

# capabilities.drop must be exactly [ALL].
deny contains msg if {
	input.kind == "Deployment"
	input.metadata.name == "packet-analysis"
	some c in input.spec.template.spec.containers
	not drops_all(c)
	msg := sprintf("packet-analysis container %q must drop ALL capabilities (ADR-0031 §2)", [c.name])
}

drops_all(c) if {
	some d in c.securityContext.capabilities.drop
	d == "ALL"
}

deny contains msg if {
	input.kind == "Deployment"
	input.metadata.name == "packet-analysis"
	some c in input.spec.template.spec.containers
	c.securityContext.runAsNonRoot != true
	msg := sprintf("packet-analysis container %q must set runAsNonRoot=true (ADR-0031 §2)", [c.name])
}

deny contains msg if {
	input.kind == "Deployment"
	input.metadata.name == "packet-analysis"
	some c in input.spec.template.spec.containers
	c.securityContext.runAsUser < 10000
	msg := sprintf("packet-analysis container %q must set runAsUser>=10000 (ADR-0031 §2)", [c.name])
}

deny contains msg if {
	input.kind == "Deployment"
	input.metadata.name == "packet-analysis"
	some c in input.spec.template.spec.containers
	c.securityContext.allowPrivilegeEscalation != false
	msg := sprintf("packet-analysis container %q must set allowPrivilegeEscalation=false (ADR-0031 §2)", [c.name])
}

deny contains msg if {
	input.kind == "Deployment"
	input.metadata.name == "packet-analysis"
	some c in input.spec.template.spec.containers
	c.securityContext.readOnlyRootFilesystem != true
	msg := sprintf("packet-analysis container %q must set readOnlyRootFilesystem=true (ADR-0031 §2)", [c.name])
}

# seccompProfile type Localhost referencing the §3 profile.
deny contains msg if {
	input.kind == "Deployment"
	input.metadata.name == "packet-analysis"
	some c in input.spec.template.spec.containers
	c.securityContext.seccompProfile.type != "Localhost"
	msg := sprintf("packet-analysis container %q must use a Localhost seccomp profile (ADR-0031 §3)", [c.name])
}

deny contains msg if {
	input.kind == "Deployment"
	input.metadata.name == "packet-analysis"
	some c in input.spec.template.spec.containers
	not c.securityContext.seccompProfile.localhostProfile
	msg := sprintf("packet-analysis container %q must reference the Localhost seccomp profile file (ADR-0031 §3)", [c.name])
}

# resources.requests AND limits present.
deny contains msg if {
	input.kind == "Deployment"
	input.metadata.name == "packet-analysis"
	some c in input.spec.template.spec.containers
	not c.resources.requests
	msg := sprintf("packet-analysis container %q must declare resource requests (ADR-0031 §2)", [c.name])
}

deny contains msg if {
	input.kind == "Deployment"
	input.metadata.name == "packet-analysis"
	some c in input.spec.template.spec.containers
	not c.resources.limits
	msg := sprintf("packet-analysis container %q must declare resource limits (ADR-0031 §2)", [c.name])
}

# pcap volume mounted readOnly:true on the analysis pod.
deny contains msg if {
	input.kind == "Deployment"
	input.metadata.name == "packet-analysis"
	some c in input.spec.template.spec.containers
	some m in c.volumeMounts
	m.name == "pcaps"
	m.readOnly != true
	msg := "packet-analysis must mount the pcap volume readOnly:true (ADR-0031 §2)"
}

# ---------------------------------------------------------------------------
# ADR-0031 §1 — capture/analysis split: NET_RAW only on capture
# ---------------------------------------------------------------------------

deny contains msg if {
	input.kind == "Deployment"
	input.metadata.name == "packet-capture"
	not capture_has_net_raw
	msg := "packet-capture must add NET_RAW (the capture half needs the raw socket; ADR-0031 §1)"
}

capture_has_net_raw if {
	some c in input.spec.template.spec.containers
	some cap in c.securityContext.capabilities.add
	cap == "NET_RAW"
}

# ---------------------------------------------------------------------------
# ADR-0031 §5 — dedicated packet node pool: taint toleration + selector
# ---------------------------------------------------------------------------

packet_deployment_names := {"packet-capture", "packet-analysis"}

deny contains msg if {
	input.kind == "Deployment"
	packet_deployment_names[input.metadata.name]
	not has_packet_toleration
	msg := sprintf("%s must tolerate the packet node-pool taint node-role.netops/packet (ADR-0031 §5)", [input.metadata.name])
}

has_packet_toleration if {
	some t in input.spec.template.spec.tolerations
	t.key == "node-role.netops/packet"
}

deny contains msg if {
	input.kind == "Deployment"
	packet_deployment_names[input.metadata.name]
	not input.spec.template.spec.nodeSelector["node-role.netops/packet"]
	msg := sprintf("%s must select the packet node pool via nodeSelector (complement to the taint, ADR-0031 §5)", [input.metadata.name])
}

# ---------------------------------------------------------------------------
# ADR-0029 §5 / ADR-0031 §1 — least-privilege RBAC
# ---------------------------------------------------------------------------

deny contains msg if {
	input.kind == "ServiceAccount"
	input.automountServiceAccountToken != false
	msg := sprintf("ServiceAccount %q must set automountServiceAccountToken=false (ADR-0029 §5)", [input.metadata.name])
}

# No ClusterRoleBinding may be shipped by the chart.
deny contains msg if {
	input.kind == "ClusterRoleBinding"
	msg := sprintf("chart must ship ZERO ClusterRoleBinding (found %q, ADR-0029 §5)", [input.metadata.name])
}

deny contains msg if {
	input.kind == "Deployment"
	packet_deployment_names[input.metadata.name]
	input.spec.template.spec.automountServiceAccountToken != false
	msg := sprintf("%s pod spec must set automountServiceAccountToken=false (ADR-0029 §5)", [input.metadata.name])
}

# Each packet workload has its own ServiceAccount (not shared).
deny contains msg if {
	input.kind == "Deployment"
	input.metadata.name == "packet-analysis"
	input.spec.template.spec.serviceAccountName != "packet-analysis-sa"
	msg := "packet-analysis must use its own ServiceAccount packet-analysis-sa (ADR-0031 §1)"
}

deny contains msg if {
	input.kind == "Deployment"
	input.metadata.name == "packet-capture"
	input.spec.template.spec.serviceAccountName != "packet-capture-sa"
	msg := "packet-capture must use its own ServiceAccount packet-capture-sa (ADR-0031 §1)"
}

# ---------------------------------------------------------------------------
# ADR-0031 §4 — default-deny egress NetworkPolicy for analysis
# ---------------------------------------------------------------------------

deny contains msg if {
	input.kind == "NetworkPolicy"
	input.spec.podSelector.matchLabels["app.kubernetes.io/component"] == "packet-analysis"
	not policy_has_egress(input)
	msg := "packet-analysis NetworkPolicy must declare policyTypes Egress (default-deny egress, ADR-0031 §4)"
}

policy_has_egress(np) if {
	some t in np.spec.policyTypes
	t == "Egress"
}

deny contains msg if {
	input.kind == "NetworkPolicy"
	input.spec.podSelector.matchLabels["app.kubernetes.io/component"] == "packet-analysis"
	not policy_has_ingress(input)
	msg := "packet-analysis NetworkPolicy must declare policyTypes Ingress (default-deny ingress, ADR-0031 §4)"
}

policy_has_ingress(np) if {
	some t in np.spec.policyTypes
	t == "Ingress"
}

# Egress must NOT be a wide-open allow (no empty `to`+`ports` rule).
deny contains msg if {
	input.kind == "NetworkPolicy"
	input.spec.podSelector.matchLabels["app.kubernetes.io/component"] == "packet-analysis"
	some rule in input.spec.egress
	not rule.to
	msg := "packet-analysis egress must not contain an unrestricted (no `to`) rule (ADR-0031 §4)"
}

# The analysis worker is a Celery worker — it MUST be allow-listed egress to the
# Redis broker (port 6379) or it pulls zero tasks and silently drops all work
# (ADR-0031 §4 "the broker connection is egress … allow-listed to the Redis
# Service only"). This is the finding-1/finding-4 regression guard.
deny contains msg if {
	input.kind == "NetworkPolicy"
	input.spec.podSelector.matchLabels["app.kubernetes.io/component"] == "packet-analysis"
	not policy_allows_redis_egress(input)
	msg := "packet-analysis NetworkPolicy must allow egress to the Redis broker on 6379 (the Celery worker pulls tasks from the broker; ADR-0031 §4)"
}

policy_allows_redis_egress(np) if {
	some rule in np.spec.egress
	some p in rule.ports
	p.port == 6379
}

# ---------------------------------------------------------------------------
# ADR-0031 §4 — packet-CAPTURE NetworkPolicy: management-subnet egress, not
# unrestricted. The capture pod is credential-bearing and holds NET_RAW, so its
# egress must be confined (PRODUCTION.md §5). A MISSING capture NetworkPolicy
# means unrestricted egress — the finding-3 gap.
# ---------------------------------------------------------------------------

deny contains msg if {
	input.kind == "NetworkPolicy"
	input.spec.podSelector.matchLabels["app.kubernetes.io/component"] == "packet-capture"
	not policy_has_egress(input)
	msg := "packet-capture NetworkPolicy must declare policyTypes Egress (confined egress, ADR-0031 §4)"
}

# Capture egress must reach a management-subnet CIDR (ipBlock) — that is the
# whole point of the capture policy (PRODUCTION.md §5 collector segmentation).
deny contains msg if {
	input.kind == "NetworkPolicy"
	input.spec.podSelector.matchLabels["app.kubernetes.io/component"] == "packet-capture"
	not capture_allows_management_cidr(input)
	msg := "packet-capture NetworkPolicy must allow egress to a management-subnet CIDR (ipBlock) (ADR-0031 §4 / PRODUCTION.md §5)"
}

capture_allows_management_cidr(np) if {
	some rule in np.spec.egress
	some target in rule.to
	target.ipBlock.cidr
}

# Capture egress must NOT contain a wide-open (no `to`) rule.
deny contains msg if {
	input.kind == "NetworkPolicy"
	input.spec.podSelector.matchLabels["app.kubernetes.io/component"] == "packet-capture"
	some rule in input.spec.egress
	not rule.to
	msg := "packet-capture egress must not contain an unrestricted (no `to`) rule (ADR-0031 §4)"
}

# ---------------------------------------------------------------------------
# ADR-0029 §3 — namespace PSS restricted labels (install namespace)
#
# The packet-CAPTURE namespace is intentionally relaxed (enforce=privileged) so
# built-in PSA admits the documented NET_RAW deviation a pod label cannot exempt
# (ADR-0031 §5). It is identified by the packet-capture component label; the
# restricted assertions below apply to the GENERAL install namespace only.
# ---------------------------------------------------------------------------

is_capture_namespace(ns) if {
	ns.metadata.labels["app.kubernetes.io/component"] == "packet-capture"
}

deny contains msg if {
	input.kind == "Namespace"
	not is_capture_namespace(input)
	input.metadata.labels["pod-security.kubernetes.io/enforce"] != "restricted"
	msg := "install namespace must enforce Pod Security Standard `restricted` (ADR-0029 §3)"
}

deny contains msg if {
	input.kind == "Namespace"
	not is_capture_namespace(input)
	input.metadata.labels["pod-security.kubernetes.io/audit"] != "restricted"
	msg := "install namespace must set PSA audit=restricted (ADR-0029 §3)"
}

deny contains msg if {
	input.kind == "Namespace"
	not is_capture_namespace(input)
	input.metadata.labels["pod-security.kubernetes.io/warn"] != "restricted"
	msg := "install namespace must set PSA warn=restricted (ADR-0029 §3)"
}

# ---------------------------------------------------------------------------
# ADR-0031 §5 — packet-CAPTURE namespace reconciles NET_RAW against PSA level.
# Capture adds NET_RAW, which PSS `restricted`/`baseline` forbid; the only PSA
# level that admits it is `privileged`. This rule catches the render-time
# conflict the finding flagged: a capture namespace at a level that would reject
# its own NET_RAW pod.
# ---------------------------------------------------------------------------

deny contains msg if {
	input.kind == "Namespace"
	is_capture_namespace(input)
	enforce := input.metadata.labels["pod-security.kubernetes.io/enforce"]
	enforce != "privileged"
	msg := sprintf("packet-capture namespace must enforce PSA `privileged` to admit its NET_RAW pod (found %q; restricted/baseline reject added NET_RAW, ADR-0031 §5)", [enforce])
}

# The capture Deployment (NET_RAW) must NOT land in a `restricted`-enforced
# namespace — assert it carries the capture-only net-raw deviation label so the
# admission allow-list scopes the deviation to it alone (ADR-0031 §2/§5).
deny contains msg if {
	input.kind == "Deployment"
	input.metadata.name == "packet-capture"
	not input.spec.template.metadata.labels["netops.io/net-raw"]
	msg := "packet-capture pod must carry the capture-only `netops.io/net-raw` deviation label so admission scopes NET_RAW to it (ADR-0031 §2/§5)"
}

# The analysis parser must NOT carry the net-raw deviation label — it must stay
# subject to the restrict-net-raw admission rule (ADR-0031 §2: NET_RAW must never
# reach the parser). This is the finding-6 regression guard.
deny contains msg if {
	input.kind == "Deployment"
	input.metadata.name == "packet-analysis"
	input.spec.template.metadata.labels["netops.io/net-raw"]
	msg := "packet-analysis must NOT carry the `netops.io/net-raw` label — the parser must stay subject to the NET_RAW admission rule (ADR-0031 §2)"
}

# ---------------------------------------------------------------------------
# ADR-0029 §5 — admission policy: no `latest`, PSS-deviation allow-list present
# ---------------------------------------------------------------------------

deny contains msg if {
	input.kind == "ClusterPolicy"
	input.metadata.name == "netops-hardening-baseline"
	not has_rule(input, "disallow-latest-tag")
	msg := "admission ClusterPolicy must include a disallow-latest-tag rule (ADR-0029 §5)"
}

deny contains msg if {
	input.kind == "ClusterPolicy"
	input.metadata.name == "netops-hardening-baseline"
	not has_rule(input, "restrict-net-raw-to-packet-sandbox")
	msg := "admission ClusterPolicy must include the packet-sandbox NET_RAW deviation allow-list (ADR-0029 §5 / ADR-0031 §5)"
}

# The signed-image (cosign) verify rule must ALWAYS render (ADR-0029 §5 rule 2 —
# rule present, enforcement gated by admission.signedImages.enabled, default off
# per W3). Its absence means the supply-chain enforcement rule was dropped.
deny contains msg if {
	input.kind == "ClusterPolicy"
	input.metadata.name == "netops-hardening-baseline"
	not policy_has_verify_images(input)
	msg := "admission ClusterPolicy must include the cosign signed-image verify rule (verify-image-signatures); it renders always, enforcement gated by admission.signedImages.enabled (ADR-0029 §5)"
}

policy_has_verify_images(policy) if {
	some r in policy.spec.rules
	r.name == "verify-image-signatures"
	r.verifyImages
}

has_rule(policy, name) if {
	some r in policy.spec.rules
	r.name == name
}

# No image in any Deployment may use the `latest` tag (chart-side parity with
# the admission rule, asserted directly on the rendered manifests).
deny contains msg if {
	input.kind == "Deployment"
	some c in input.spec.template.spec.containers
	endswith(c.image, ":latest")
	msg := sprintf("image %q must not use the `latest` tag (ADR-0029 §5)", [c.image])
}

deny contains msg if {
	input.kind == "Deployment"
	some c in input.spec.template.spec.containers
	not contains(c.image, ":")
	msg := sprintf("image %q must carry an explicit tag or digest (ADR-0029 §5)", [c.image])
}

# ===========================================================================
# ADR-0029 §2 / PRODUCTION.md §3.1 — W4 platform NetworkPolicies (the firewall
# spec). The §3.1 topology diagram IS the firewall: a default-deny floor plus
# one additive allow per §2 arrow, every egress confined to a known
# component/port, and NO external-LLM egress unless the opt-in is set. These
# rules run per rendered document (conftest --all-namespaces, no --combine), so
# they assert the SHAPE of each W4 policy directly on the rendered manifests.
# The packet-capture / packet-analysis policies are W3-owned and asserted above.
# ===========================================================================

# The §2 allow edge table, as a known set of {dest-component, port}. An egress
# allow that targets any port outside this set is not a §2 arrow and is denied.
# (DNS :53 is the universal default-deny backstop, also permitted.) Port 9000 is
# the W5-T1 MinIO/S3 object-store edge (the backup CronJob → object store,
# ADR-0030 §4); :443 already covers an HTTPS S3 endpoint. Port 8432 is the W5-T1
# pgBackRest TLS-server edge: the backup CronJob → the in-postgres `pgbackrest
# server` sidecar (mTLS), since the CronJob pod has no PGDATA volume of its own
# and cannot read pg1-path directly (ADR-0030 §4).
netpol_known_egress_ports := {5432, 7687, 6379, 11434, 9000, 8432, 443, 53}

# Names of the W3-owned packet NetworkPolicies — excluded from the W4 platform
# assertions below (they carry their own ADR-0031 rules earlier in this file).
is_packet_netpol(np) if {
	np.spec.podSelector.matchLabels["app.kubernetes.io/component"] == "packet-analysis"
}

is_packet_netpol(np) if {
	np.spec.podSelector.matchLabels["app.kubernetes.io/component"] == "packet-capture"
}

# --- default-deny floor: when the default-deny-all policy is rendered it MUST
# select all pods ({}) and declare BOTH Ingress and Egress, or it is not a floor.
deny contains msg if {
	input.kind == "NetworkPolicy"
	endswith(input.metadata.name, "-default-deny-all")
	count(object.keys(input.spec.podSelector)) != 0
	msg := "default-deny-all NetworkPolicy must select ALL pods (podSelector {}) (ADR-0029 §2)"
}

deny contains msg if {
	input.kind == "NetworkPolicy"
	endswith(input.metadata.name, "-default-deny-all")
	not policy_has_ingress(input)
	msg := "default-deny-all NetworkPolicy must declare policyTypes Ingress (ADR-0029 §2)"
}

deny contains msg if {
	input.kind == "NetworkPolicy"
	endswith(input.metadata.name, "-default-deny-all")
	not policy_has_egress(input)
	msg := "default-deny-all NetworkPolicy must declare policyTypes Egress (ADR-0029 §2)"
}

# The default-deny-all policy must carry NO allow rules — any ingress/egress rule
# on it would punch a hole in the floor (allows belong in additive policies).
deny contains msg if {
	input.kind == "NetworkPolicy"
	endswith(input.metadata.name, "-default-deny-all")
	count(object.get(input.spec, "egress", [])) != 0
	msg := "default-deny-all NetworkPolicy must contain NO egress allow rules (the floor stays empty; ADR-0029 §2)"
}

deny contains msg if {
	input.kind == "NetworkPolicy"
	endswith(input.metadata.name, "-default-deny-all")
	count(object.get(input.spec, "ingress", [])) != 0
	msg := "default-deny-all NetworkPolicy must contain NO ingress allow rules (the floor stays empty; ADR-0029 §2)"
}

# --- no blanket egress: NO platform NetworkPolicy egress rule may omit `to`
# (a missing `to` = allow-to-anywhere, exactly what default-deny forbids). The
# DNS-egress policy and every §2 allow target an explicit `to`. (packet policies
# already carry this guard above; exclude them to avoid duplicate messages.)
deny contains msg if {
	input.kind == "NetworkPolicy"
	not is_packet_netpol(input)
	some rule in object.get(input.spec, "egress", [])
	not rule.to
	msg := sprintf("NetworkPolicy %q has an egress rule with no `to` — blanket egress is forbidden (ADR-0029 §2)", [input.metadata.name])
}

# --- every egress allow port must map to a known §2 edge. An egress port outside
# netpol_known_egress_ports is not a §3.1 arrow and is denied.
deny contains msg if {
	input.kind == "NetworkPolicy"
	not is_packet_netpol(input)
	some rule in object.get(input.spec, "egress", [])
	some p in object.get(rule, "ports", [])
	not netpol_known_egress_ports[p.port]
	msg := sprintf("NetworkPolicy %q egress targets port %v, not a known §2 edge port (5432/7687/6379/11434/443/53) (ADR-0029 §2)", [input.metadata.name, p.port])
}

# --- external-LLM egress is OPT-IN, default OFF: the allow-external-llm-egress
# policy MUST NOT render unless networkPolicy.externalLlmEgress.enabled. It is
# identified by its component label `external-llm-egress` (label-based, matching
# the rest of this file). On the default render (opt-in off) this policy is
# absent; its presence means the secure default was inverted. When an operator
# opts in, this is the documented, reviewed exception — they regenerate the
# G-SEC evidence with the flag and accept this single failure consciously.
deny contains msg if {
	input.kind == "NetworkPolicy"
	input.metadata.labels["app.kubernetes.io/component"] == "external-llm-egress"
	msg := "external-LLM egress NetworkPolicy must NOT render unless networkPolicy.externalLlmEgress.enabled — it is opt-in, default-off (ADR-0029 §2)"
}

# ===========================================================================
# W4-T5 — RBAC + admission allow-list singularity (ADR-0029 §5, exit §7.4/§7.5)
#
# The admission PSS-deviation allow-list must name EXACTLY ONE workload — the
# ADR-0031 packet sandbox — and nothing else. The allow-list is expressed as the
# `netops.io/net-raw: allowed` Pod label that the restrict-net-raw admission rule
# excludes (kyverno-clusterpolicy.yaml / validatingadmissionpolicy.yaml). These
# rules prove cardinality = 1 and that every W4 service stays SUBJECT to the
# rule, asserted per rendered document (conftest --all-namespaces, no --combine).
# ===========================================================================

# The SINGLE workload permitted the NET_RAW / PSS deviation. Cardinality = 1:
# this is the ONLY Deployment whose name may carry the net-raw deviation label.
net_raw_allowed_workload := "packet-capture"

# W4 platform Deployments — these MUST stay subject to restrict-net-raw (they may
# never be exempted via the deviation label). Matched by component label so a
# rename of the fullname prefix does not slip a workload past this guard.
is_w4_platform_deployment(dep) if {
	dep.kind == "Deployment"
	dep.metadata.labels["app.kubernetes.io/component"] in {"api", "worker", "frontend"}
}

# --- Cardinality = 1: any workload OTHER than the packet sandbox that carries
# the net-raw deviation label widens the allow-list beyond one. The pod-template
# label is what admission matches, so assert on it. packet-capture is permitted
# (asserted-present elsewhere); ANY other named Deployment with the label fails.
deny contains msg if {
	input.kind == "Deployment"
	input.spec.template.metadata.labels["netops.io/net-raw"]
	input.metadata.name != net_raw_allowed_workload
	msg := sprintf("admission NET_RAW deviation allow-list must name EXACTLY ONE workload (%q); Deployment %q also carries the `netops.io/net-raw` label — cardinality must be 1 (ADR-0029 §5 / ADR-0031 §5)", [net_raw_allowed_workload, input.metadata.name])
}

# The same cardinality guard at the object-metadata level (some manifests label
# the Deployment object as well as the pod template).
deny contains msg if {
	input.kind == "Deployment"
	input.metadata.labels["netops.io/net-raw"]
	input.metadata.name != net_raw_allowed_workload
	msg := sprintf("admission NET_RAW deviation allow-list must name EXACTLY ONE workload (%q); Deployment %q also carries the `netops.io/net-raw` object label — cardinality must be 1 (ADR-0029 §5 / ADR-0031 §5)", [net_raw_allowed_workload, input.metadata.name])
}

# --- Every W4 Deployment (api/worker/frontend) must stay SUBJECT to the
# restrict-net-raw admission rule — i.e. it must NOT carry the deviation label on
# its pod template, or admission would exempt it and a NET_RAW regression on a
# platform service would pass silently (ADR-0029 §5 / ADR-0031 §2).
deny contains msg if {
	is_w4_platform_deployment(input)
	input.spec.template.metadata.labels["netops.io/net-raw"]
	msg := sprintf("W4 Deployment %q must stay SUBJECT to restrict-net-raw — it must NOT carry the `netops.io/net-raw` deviation label (ADR-0029 §5 / ADR-0031 §2)", [input.metadata.name])
}

# --- and must not carry the broad packet-sandbox (custom-seccomp) deviation
# label either: only the packet sandbox may deviate from RuntimeDefault.
deny contains msg if {
	is_w4_platform_deployment(input)
	input.spec.template.metadata.labels["netops.io/packet-sandbox"]
	msg := sprintf("W4 Deployment %q must NOT carry the `netops.io/packet-sandbox` deviation label — only the packet sandbox may deviate from restricted (ADR-0029 §3/§5)", [input.metadata.name])
}

# --- A W4 platform Deployment must NEVER add NET_RAW/NET_ADMIN directly (the
# admission rule denies it; this is the chart-side parity guard on the rendered
# pod spec, so a regression is caught at policy-test time, not only at admission).
deny contains msg if {
	is_w4_platform_deployment(input)
	some c in input.spec.template.spec.containers
	some cap in object.get(object.get(object.get(c, "securityContext", {}), "capabilities", {}), "add", [])
	cap in {"NET_RAW", "NET_ADMIN"}
	msg := sprintf("W4 Deployment %q container %q must add no NET_RAW/NET_ADMIN (found %q) — only the packet sandbox may (ADR-0029 §5 / ADR-0031 §2)", [input.metadata.name, c.name, cap])
}

# --- W4 ServiceAccounts must set automountServiceAccountToken=false. The generic
# ServiceAccount rule above already covers ALL SAs; this is the explicit W4
# coverage for the api/worker/frontend (+data store) identities (ADR-0029 §5).
w4_sa_components := {"api", "worker", "frontend", "postgres", "neo4j", "redis", "ollama"}

deny contains msg if {
	input.kind == "ServiceAccount"
	w4_sa_components[input.metadata.labels["app.kubernetes.io/component"]]
	input.automountServiceAccountToken != false
	msg := sprintf("W4 ServiceAccount %q (component %q) must set automountServiceAccountToken=false (ADR-0029 §5)", [input.metadata.name, input.metadata.labels["app.kubernetes.io/component"]])
}

# --- The migration-Job RBAC, when rendered, must be NAMESPACED only: a Role +
# RoleBinding, never a ClusterRole/ClusterRoleBinding. The ClusterRoleBinding
# guard already exists above; assert the migration RoleBinding binds a Role (not
# a ClusterRole) so an opt-in migration grant can never escalate cluster-wide.
deny contains msg if {
	input.kind == "RoleBinding"
	input.metadata.labels["app.kubernetes.io/component"] == "migration-job"
	input.roleRef.kind != "Role"
	msg := sprintf("migration-job RoleBinding must bind a namespaced Role, not %q (ADR-0029 §5 — no cluster-scope grants)", [input.roleRef.kind])
}

# No ClusterRole may be shipped by the chart (parity with the ClusterRoleBinding
# guard — least-privilege RBAC grants are namespaced Roles only, ADR-0029 §5).
deny contains msg if {
	input.kind == "ClusterRole"
	msg := sprintf("chart must ship ZERO ClusterRole (found %q, ADR-0029 §5)", [input.metadata.name])
}

# --- The migration-job Role's configmaps rule MUST carry a non-empty
# resourceNames list. An empty/absent resourceNames grants get/list/watch on
# EVERY ConfigMap in the namespace, contradicting the in-template least-privilege
# claim ("GET on EXACTLY the migration Job's own ConfigMap by name") and ADR-0029
# §5. The template now `required`s configMapName, so this is the policy-test guard
# that the broadening can never reappear (e.g. via a future un-guarded edit).
deny contains msg if {
	input.kind == "Role"
	input.metadata.labels["app.kubernetes.io/component"] == "migration-job"
	some rule in input.rules
	"configmaps" in rule.resources
	count(object.get(rule, "resourceNames", [])) == 0
	msg := "migration-job Role configmaps rule must carry a non-empty resourceNames list — an empty list grants get/list/watch on ALL ConfigMaps in the namespace, not the Job's own (ADR-0029 §5 least-privilege)"
}

# ===========================================================================
# W4-T6 — GENERIC per-workload hardening (ADR-0029 §3, exit §7.1)
#
# The earlier rules assert hardening on the packet-* workloads by NAME. These
# generic rules assert the SAME ADR-0029 §3 container controls on EVERY platform
# workload (api/worker/frontend + the postgres/neo4j/redis/ollama data stores),
# across both Deployment and StatefulSet — so a hardening regression on ANY
# service (not just packet-*) fails the gate. The packet-capture / packet-analysis
# workloads are deliberately EXCLUDED here (they carry the documented ADR-0031
# deviation and are governed by the named rules above). Matched by the component
# label so a fullname-prefix rename cannot slip a workload past this guard.
# ===========================================================================

# The platform workload components every generic §3 control applies to. packet-*
# is intentionally absent (governed by the named ADR-0031 rules above).
platform_workload_components := {"api", "worker", "frontend", "postgres", "neo4j", "redis", "ollama"}

# True for a rendered Deployment/StatefulSet that is one of the platform services.
is_platform_workload(obj) if {
	obj.kind in {"Deployment", "StatefulSet"}
	platform_workload_components[obj.metadata.labels["app.kubernetes.io/component"]]
}

# Component label of the workload (for message clarity).
workload_component(obj) := obj.metadata.labels["app.kubernetes.io/component"]

# --- drop ALL capabilities (no exception for platform services) ---
deny contains msg if {
	is_platform_workload(input)
	some c in input.spec.template.spec.containers
	not drops_all(c)
	msg := sprintf("%s workload %q container %q must drop ALL capabilities (ADR-0029 §3)", [workload_component(input), input.metadata.name, c.name])
}

# --- platform services may add NO capability at all (only packet-capture may) ---
deny contains msg if {
	is_platform_workload(input)
	some c in input.spec.template.spec.containers
	some cap in object.get(object.get(object.get(c, "securityContext", {}), "capabilities", {}), "add", [])
	msg := sprintf("%s workload %q container %q must add NO capabilities (found %q); only packet-capture may add one (ADR-0029 §3)", [workload_component(input), input.metadata.name, c.name, cap])
}

# --- runAsNonRoot: true on every platform container ---
deny contains msg if {
	is_platform_workload(input)
	some c in input.spec.template.spec.containers
	c.securityContext.runAsNonRoot != true
	msg := sprintf("%s workload %q container %q must set runAsNonRoot=true (ADR-0029 §3)", [workload_component(input), input.metadata.name, c.name])
}

# --- readOnlyRootFilesystem: true on every platform container ---
deny contains msg if {
	is_platform_workload(input)
	some c in input.spec.template.spec.containers
	c.securityContext.readOnlyRootFilesystem != true
	msg := sprintf("%s workload %q container %q must set readOnlyRootFilesystem=true (ADR-0029 §3 — writable scratch is an enumerated emptyDir only)", [workload_component(input), input.metadata.name, c.name])
}

# --- allowPrivilegeEscalation: false on every platform container ---
deny contains msg if {
	is_platform_workload(input)
	some c in input.spec.template.spec.containers
	c.securityContext.allowPrivilegeEscalation != false
	msg := sprintf("%s workload %q container %q must set allowPrivilegeEscalation=false (ADR-0029 §3)", [workload_component(input), input.metadata.name, c.name])
}

# --- seccompProfile set (pod-level or container-level) on every platform
# container, and it must be RuntimeDefault (only the packet sandbox may run a
# Localhost profile — ADR-0029 §3). ---
deny contains msg if {
	is_platform_workload(input)
	some c in input.spec.template.spec.containers
	not container_seccomp_set(input, c)
	msg := sprintf("%s workload %q container %q must set a seccompProfile (pod- or container-level) (ADR-0029 §3)", [workload_component(input), input.metadata.name, c.name])
}

container_seccomp_set(obj, c) if {
	c.securityContext.seccompProfile.type
}

container_seccomp_set(obj, _) if {
	obj.spec.template.spec.securityContext.seccompProfile.type
}

deny contains msg if {
	is_platform_workload(input)
	some c in input.spec.template.spec.containers
	t := c.securityContext.seccompProfile.type
	t != "RuntimeDefault"
	msg := sprintf("%s workload %q container %q seccompProfile must be RuntimeDefault (found %q); only the packet sandbox may run a Localhost profile (ADR-0029 §3)", [workload_component(input), input.metadata.name, c.name, t])
}

# --- resource requests AND limits present on every platform container ---
deny contains msg if {
	is_platform_workload(input)
	some c in input.spec.template.spec.containers
	not c.resources.requests
	msg := sprintf("%s workload %q container %q must declare resource requests (ADR-0029 §3 — never absent)", [workload_component(input), input.metadata.name, c.name])
}

deny contains msg if {
	is_platform_workload(input)
	some c in input.spec.template.spec.containers
	not c.resources.limits
	msg := sprintf("%s workload %q container %q must declare resource limits (ADR-0029 §3 — never absent)", [workload_component(input), input.metadata.name, c.name])
}

# --- no `latest` / tagless image on any platform container (parity with the
# named Deployment rules above, extended to StatefulSets). ---
deny contains msg if {
	is_platform_workload(input)
	some c in input.spec.template.spec.containers
	endswith(c.image, ":latest")
	msg := sprintf("%s workload %q image %q must not use the `latest` tag (ADR-0029 §5)", [workload_component(input), input.metadata.name, c.image])
}

deny contains msg if {
	is_platform_workload(input)
	some c in input.spec.template.spec.containers
	not contains(c.image, ":")
	not contains(c.image, "@sha256:")
	msg := sprintf("%s workload %q image %q must carry an explicit tag or digest (ADR-0029 §5)", [workload_component(input), input.metadata.name, c.image])
}

# ===========================================================================
# W4-T6 — admission rule BODY assertions (ADR-0029 §5, exit §7.4)
#
# The W3 rules above assert the admission ClusterPolicy includes rules by NAME
# (has_rule). These assert the rule BODIES do what their names claim, so a future
# edit that keeps the rule name but guts the pattern is caught:
#   - disallow-latest-tag actually matches an image pattern that bans `:latest`.
#   - restrict-net-raw excludes EXACTLY the net-raw deviation selector and nothing
#     wider (the allow-list selector matches the packet-sandbox label only).
# ===========================================================================

# The disallow-latest-tag rule must carry a validate.pattern banning `:latest`
# on container images (a name-only rule with an empty body would pass has_rule
# but enforce nothing).
deny contains msg if {
	input.kind == "ClusterPolicy"
	input.metadata.name == "netops-hardening-baseline"
	some r in input.spec.rules
	r.name == "disallow-latest-tag"
	not latest_rule_bans_latest(r)
	msg := "disallow-latest-tag admission rule must carry a validate.pattern that bans `:latest` on container images — a name-only rule enforces nothing (ADR-0029 §5)"
}

latest_rule_bans_latest(r) if {
	some c in r.validate.pattern.spec.containers
	contains(c.image, "!*:latest")
}

# The restrict-net-raw-to-packet-sandbox rule's exclude selector must match
# EXACTLY the netRawDeviationSelector label set (the chart's `netops.io/net-raw`
# allow-list) — not a broader/empty selector that would exempt more than the one
# permitted workload. Asserts the allow-list selector is precisely the deviation
# label and nothing else (cardinality of the selector keys = 1, the net-raw key).
deny contains msg if {
	input.kind == "ClusterPolicy"
	input.metadata.name == "netops-hardening-baseline"
	some r in input.spec.rules
	r.name == "restrict-net-raw-to-packet-sandbox"
	not net_raw_exclude_is_exactly_net_raw(r)
	msg := "restrict-net-raw-to-packet-sandbox exclude selector must match EXACTLY the `netops.io/net-raw` deviation label (one key) — a broader/empty selector would exempt more than the single permitted workload (ADR-0029 §5 / ADR-0031 §5)"
}

# True only when the rule excludes via a resource selector whose matchLabels is
# exactly { "netops.io/net-raw": <value> } — one key, the net-raw label.
net_raw_exclude_is_exactly_net_raw(r) if {
	some e in r.exclude.any
	labels := e.resources.selector.matchLabels
	count(labels) == 1
	labels["netops.io/net-raw"]
}

# ===========================================================================
# W4-T6 — no inlined secret literal (ADR-0029 §6, exit §7.5)
#
# Secrets are by-reference: when an existingSecret is supplied the chart must
# render NO Secret object at all (the dev-convenience secret.yaml is guarded
# `{{- if not .Values.secrets.existingSecret }}`). And NO Secret the chart ships
# may inline an obvious credential key in stringData/data. These assert directly
# on the rendered manifests so a regression (templating a real credential, or
# emitting secret.yaml under existingSecret) fails the gate.
# ===========================================================================

# Obvious credential key names that must NEVER be inlined in a chart-shipped
# Secret as a real value. The dev-convenience Secret is explicitly marked with
# `netops.io/dev-secret: "true"` and holds only render-time random placeholders
# (randAlphaNum) — it is exempt from the literal check but still subject to the
# existingSecret-absence guard below.
credential_key_substrings := {"password", "secret", "token", "key", "auth"}

is_dev_convenience_secret(s) if {
	s.metadata.annotations["netops.io/dev-secret"] == "true"
}

# --- Any chart-shipped Secret OTHER than the marked dev-convenience one must not
# exist (the chart ships exactly one Secret, and only when no existingSecret is
# set). A second/unmarked Secret means a real credential was templated in. ---
deny contains msg if {
	input.kind == "Secret"
	not is_dev_convenience_secret(input)
	msg := sprintf("chart must ship NO Secret holding credential material — only the marked dev-convenience Secret (netops.io/dev-secret=true) may render, and only when secrets.existingSecret is empty (Secret %q found; ADR-0029 §6)", [input.metadata.name])
}

# --- The dev-convenience Secret's credential-looking keys must hold render-time
# generated placeholders, NEVER an authored literal. The template uses
# `randAlphaNum`, which produces alphanumeric-only values; a value containing a
# non-alphanumeric character (':', '/', '=', whitespace, …) other than the
# documented neo4j `user/<rand>` and `dev-local:<rand>` shapes signals an inlined
# literal. This is a defensive guard on the rendered manifest (ADR-0029 §6).
deny contains msg if {
	input.kind == "Secret"
	is_dev_convenience_secret(input)
	some k, v in object.get(input, "stringData", {})
	key_is_credential(k)
	not value_is_generated_placeholder(v)
	msg := sprintf("dev-convenience Secret key %q must hold a render-time generated placeholder (randAlphaNum), not an inlined literal (ADR-0029 §6)", [k])
}

key_is_credential(k) if {
	some sub in credential_key_substrings
	contains(lower(k), sub)
}

# Accept the alphanumeric randAlphaNum output and its two documented composite
# shapes: neo4j `<user>/<rand>` and the dev KMS `dev-local:<rand>` reference.
value_is_generated_placeholder(v) if {
	regex.match(`^[A-Za-z0-9]+$`, v)
}

value_is_generated_placeholder(v) if {
	regex.match(`^[A-Za-z0-9._-]+/[A-Za-z0-9]+$`, v)
}

value_is_generated_placeholder(v) if {
	regex.match(`^dev-local:[A-Za-z0-9]+$`, v)
}

# ===========================================================================
# W5-T1 — pgBackRest Postgres backup tier (ADR-0030 §1/§4, ADR-0011 §1/§4)
#
# The backup CronJobs are the load-bearing DR tier: a mis-configured off-host
# repo (no encryption, a reachable/inlined credential, an unverified backup) is a
# new exfiltration surface for audit/PII/credential-bearing rows (ADR-0030
# Negative). These rules assert, on the RENDERED backup manifests:
#   - the repo cipher passphrase + object-store credential are external-secret
#     REFS (valueFrom.secretKeyRef), NEVER a literal `value:` (secret-surface gate);
#   - `pgbackrest verify` GATES every backup job (a backup that cannot be verified
#     is a failed backup — ADR-0030 §1 req 2);
#   - the schedule matches weekly-full / daily-incr cadence;
#   - repo encryption is aes-256-cbc (independent of object-store SSE);
#   - the backup ConfigMap inlines NO cipher/credential literal.
# The generic per-workload hardening rules above ALSO cover the backup CronJob
# pods by component label (`backup`), so drop-ALL/non-root/RO-rootfs/limits are
# already gated there — these rules add the backup-SPECIFIC controls.
# ===========================================================================

# A rendered pgBackRest BACKUP CronJob is identified by the `backup` component
# label AND a backup-type of exactly `full` or `incr`. Other `backup`-component
# CronJobs carry a DIFFERENT backup-type and have their OWN dedicated rules, so
# they are EXCLUDED here so the pgBackRest cadence/verify/naming rules (weekly-full
# / daily-incr, `-pgbackrest-full/-incr` suffix, `pgbackrest verify`) do not
# mis-fire on them:
#   - the W5-T2 PITR restore-DRILL (backup-type `drill`);
#   - the W5-T4 pcap volume SNAPSHOT (backup-type `pcap-snapshot`) — an rsync/
#     sha256 snapshot of the pcap volume, NOT a pgBackRest backup (no `verify`,
#     no full/incr cadence);
#   - the W5-T4 pcap SPOT-RESTORE drill (backup-type `pcap-drill`).
# Scoping by a POSITIVE backup-type allow-set (full|incr) means any future
# backup-type is excluded by default (fail-safe), not silently swept in.
pgbackrest_backup_type(t) if t == "full"

pgbackrest_backup_type(t) if t == "incr"

is_backup_cronjob(obj) if {
	obj.kind == "CronJob"
	obj.metadata.labels["app.kubernetes.io/component"] == "backup"
	pgbackrest_backup_type(obj.metadata.labels["netops.io/backup-type"])
}

# The container spec list inside a CronJob's Job template.
backup_containers(cj) := cj.spec.jobTemplate.spec.template.spec.containers

# --- secret-surface: the cipher pass + S3 credential env vars must come from a
# secretKeyRef, never an inline `value:` literal. Any env var whose NAME signals a
# credential (PGBACKREST_REPO*_CIPHER_PASS / *_KEY / *_KEY_SECRET) MUST use
# valueFrom.secretKeyRef. A literal `value:` on such an env is a denied inline
# secret (ADR-0030 §1 / ADR-0029 §6). ---
backup_credential_env(name) if {
	endswith(name, "CIPHER_PASS")
}

backup_credential_env(name) if {
	endswith(name, "S3_KEY")
}

backup_credential_env(name) if {
	endswith(name, "S3_KEY_SECRET")
}

deny contains msg if {
	is_backup_cronjob(input)
	some c in backup_containers(input)
	some e in object.get(c, "env", [])
	backup_credential_env(e.name)
	object.get(e, "value", null) != null
	msg := sprintf("backup CronJob %q env %q must NOT carry an inline `value:` literal — the repo cipher pass / object-store credential are external-secret refs only (ADR-0030 §1 / ADR-0029 §6)", [input.metadata.name, e.name])
}

deny contains msg if {
	is_backup_cronjob(input)
	some c in backup_containers(input)
	some e in object.get(c, "env", [])
	backup_credential_env(e.name)
	not e.valueFrom.secretKeyRef
	msg := sprintf("backup CronJob %q env %q must be sourced from valueFrom.secretKeyRef (the repo cipher pass / object-store credential are by-reference only; ADR-0030 §1)", [input.metadata.name, e.name])
}

# --- verify GATES every backup: the backup container's command/args must invoke
# `pgbackrest verify`. A backup job that never verifies its repo is a failed
# control (ADR-0030 §1 req 2). Asserted on the rendered argv text. ---
deny contains msg if {
	is_backup_cronjob(input)
	some c in backup_containers(input)
	not container_runs_verify(c)
	msg := sprintf("backup CronJob %q container %q must run `pgbackrest verify` (the verify GATES every backup — an unverifiable backup is a failed backup; ADR-0030 §1)", [input.metadata.name, c.name])
}

# True when any element of the container's command or args mentions `pgbackrest`
# AND `verify` (the shell-wrapped script runs `pgbackrest ... verify`).
container_runs_verify(c) if {
	some arg in array.concat(object.get(c, "command", []), object.get(c, "args", []))
	contains(arg, "pgbackrest")
	contains(arg, "verify")
}

# --- cadence: exactly one weekly-full + one daily-incr. The full CronJob runs
# weekly (cron day-of-week field is a single day, not `*`); the incr CronJob runs
# on the other days. Assert each rendered backup CronJob carries a non-empty
# schedule and that the full/incr names are distinguishable by a `-full`/`-incr`
# suffix so the cadence pair is explicit (ADR-0030 §1 req 2). ---
deny contains msg if {
	is_backup_cronjob(input)
	not input.spec.schedule
	msg := sprintf("backup CronJob %q must declare a schedule (weekly-full / daily-incr cadence; ADR-0030 §1)", [input.metadata.name])
}

deny contains msg if {
	is_backup_cronjob(input)
	not backup_name_is_full_or_incr(input.metadata.name)
	msg := sprintf("backup CronJob %q must be named with a `-pgbackrest-full` or `-pgbackrest-incr` suffix so the weekly-full / daily-incr cadence pair is explicit (ADR-0030 §1)", [input.metadata.name])
}

backup_name_is_full_or_incr(name) if {
	endswith(name, "-pgbackrest-full")
}

backup_name_is_full_or_incr(name) if {
	endswith(name, "-pgbackrest-incr")
}

# The weekly-full CronJob's schedule must NOT run every day-of-week (`* * * * *`
# style with a `*` DOW would make it daily, not weekly). A weekly full pins the
# day-of-week field to a specific day (ADR-0030 §1). Asserted on the `-full` job.
deny contains msg if {
	is_backup_cronjob(input)
	endswith(input.metadata.name, "-pgbackrest-full")
	parts := split(input.spec.schedule, " ")
	count(parts) == 5
	parts[4] == "*"
	msg := sprintf("weekly-full backup CronJob %q must pin the day-of-week field (a `*` DOW makes it daily, not weekly; ADR-0030 §1)", [input.metadata.name])
}

# --- concurrency: a backup must never overlap the next tick (a second pgbackrest
# against the same stanza races the repo). concurrencyPolicy must be Forbid or
# Replace, never Allow (ADR-0030 §4 independence/safety). ---
deny contains msg if {
	is_backup_cronjob(input)
	object.get(input.spec, "concurrencyPolicy", "Allow") == "Allow"
	msg := sprintf("backup CronJob %q must set concurrencyPolicy Forbid/Replace — overlapping pgbackrest runs race the repo (ADR-0030 §4)", [input.metadata.name])
}

# --- repo encryption: the stanza ConfigMap must declare aes-256-cbc repo
# encryption (independent of object-store SSE — ADR-0030 §1 / Alt #3). The
# pgBackRest config lives in a ConfigMap whose component label is `backup`; assert
# it carries `repo1-cipher-type=aes-256-cbc`. A repo with cipher-type=none (or a
# missing cipher-type) is an unencrypted off-host repo — denied. ---
is_backup_configmap(obj) if {
	obj.kind == "ConfigMap"
	obj.metadata.labels["app.kubernetes.io/component"] == "backup"
}

deny contains msg if {
	is_backup_configmap(input)
	some k, v in object.get(input, "data", {})
	endswith(k, ".conf")
	not contains(v, "repo1-cipher-type=aes-256-cbc")
	msg := sprintf("backup ConfigMap %q key %q must set `repo1-cipher-type=aes-256-cbc` — repo encryption is ON and independent of object-store SSE (ADR-0030 §1 / Alt #3)", [input.metadata.name, k])
}

# --- no inlined secret in the backup ConfigMap: the pgBackRest config is
# NON-secret coordinates only. The cipher pass + S3 credential are supplied as env
# from the Secret at runtime (pgBackRest reads PGBACKREST_* env), NEVER baked into
# the .conf. Assert the config does not inline a cipher-pass or S3 key literal —
# a `repo1-cipher-pass=` / `repo1-s3-key=` with a value is a denied inline secret
# (ADR-0030 §1 / ADR-0011 §4 — the repo and its key never co-located). ---
backup_config_secret_directive(line) if {
	regex.match(`repo1-cipher-pass=\S`, line)
}

backup_config_secret_directive(line) if {
	regex.match(`repo1-s3-key=\S`, line)
}

backup_config_secret_directive(line) if {
	regex.match(`repo1-s3-key-secret=\S`, line)
}

deny contains msg if {
	is_backup_configmap(input)
	some _, v in object.get(input, "data", {})
	some line in split(v, "\n")
	backup_config_secret_directive(line)
	msg := sprintf("backup ConfigMap %q must NOT inline a repo cipher-pass / S3 key in the pgBackRest config — they are supplied as PGBACKREST_* env from the Secret at runtime (ADR-0030 §1 / ADR-0011 §4)", [input.metadata.name])
}

# --- the backup CronJob must mount the credential env from the SAME existingSecret
# the rest of the chart uses (no second Secret object) — covered by the chart-ships-
# one-Secret rule above. Here we assert the backup job's pod is hardened the same
# way (automountServiceAccountToken=false) so a backup pod cannot reach the K8s API
# with its mounted token (ADR-0029 §5). ---
deny contains msg if {
	is_backup_cronjob(input)
	input.spec.jobTemplate.spec.template.spec.automountServiceAccountToken != false
	msg := sprintf("backup CronJob %q pod must set automountServiceAccountToken=false — the backup job talks to Postgres + the object store, not the K8s API (ADR-0029 §5)", [input.metadata.name])
}

# --- the backup NetworkPolicy must be confined egress (no blanket `to`). The
# generic no-empty-`to` rule above already covers every non-packet NetworkPolicy;
# this asserts the backup policy declares Egress (so the default-deny floor is
# additively opened for it, not left implicitly open). ---
deny contains msg if {
	input.kind == "NetworkPolicy"
	input.spec.podSelector.matchLabels["app.kubernetes.io/component"] == "backup"
	not policy_has_egress(input)
	msg := "backup NetworkPolicy must declare policyTypes Egress (confined egress to postgres + the object store; ADR-0030 §4 / ADR-0029 §2)"
}

# --- per-container hardening on the backup CronJob (the generic is_platform_workload
# rules above only match Deployment/StatefulSet by container path; a CronJob nests
# its containers under jobTemplate.spec.template.spec, so the same ADR-0029 §3
# controls are asserted here for the backup pod). Every backup container must drop
# ALL caps, add none, run non-root + RO-rootfs + no-privesc + RuntimeDefault
# seccomp, and carry resource requests AND limits. ---
deny contains msg if {
	is_backup_cronjob(input)
	some c in backup_containers(input)
	not drops_all(c)
	msg := sprintf("backup CronJob %q container %q must drop ALL capabilities (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_backup_cronjob(input)
	some c in backup_containers(input)
	some cap in object.get(object.get(object.get(c, "securityContext", {}), "capabilities", {}), "add", [])
	msg := sprintf("backup CronJob %q container %q must add NO capabilities (found %q; ADR-0029 §3)", [input.metadata.name, c.name, cap])
}

deny contains msg if {
	is_backup_cronjob(input)
	some c in backup_containers(input)
	c.securityContext.runAsNonRoot != true
	msg := sprintf("backup CronJob %q container %q must set runAsNonRoot=true (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_backup_cronjob(input)
	some c in backup_containers(input)
	c.securityContext.readOnlyRootFilesystem != true
	msg := sprintf("backup CronJob %q container %q must set readOnlyRootFilesystem=true (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_backup_cronjob(input)
	some c in backup_containers(input)
	c.securityContext.allowPrivilegeEscalation != false
	msg := sprintf("backup CronJob %q container %q must set allowPrivilegeEscalation=false (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_backup_cronjob(input)
	some c in backup_containers(input)
	not backup_container_seccomp_set(input, c)
	msg := sprintf("backup CronJob %q container %q must set a RuntimeDefault seccompProfile (ADR-0029 §3)", [input.metadata.name, c.name])
}

backup_container_seccomp_set(cj, c) if {
	c.securityContext.seccompProfile.type == "RuntimeDefault"
}

backup_container_seccomp_set(cj, _) if {
	cj.spec.jobTemplate.spec.template.spec.securityContext.seccompProfile.type == "RuntimeDefault"
}

deny contains msg if {
	is_backup_cronjob(input)
	some c in backup_containers(input)
	not c.resources.requests
	msg := sprintf("backup CronJob %q container %q must declare resource requests (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_backup_cronjob(input)
	some c in backup_containers(input)
	not c.resources.limits
	msg := sprintf("backup CronJob %q container %q must declare resource limits (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_backup_cronjob(input)
	some c in backup_containers(input)
	endswith(c.image, ":latest")
	msg := sprintf("backup CronJob %q image %q must not use the `latest` tag (ADR-0029 §5)", [input.metadata.name, c.image])
}

# ===========================================================================
# W5-T2 — Postgres PITR restore-DRILL (ADR-0030 §5/§5.1, ADR-0011 §1/§2)
#
# The drill restores from the object-store repo ALONE to a THROWAWAY target and
# asserts RPO-in-window + audit immutability + credential fail-closed + verify.
# These rules assert, on the RENDERED drill manifests, the policy-surface
# invariants the spec's `helm lint / kubeconform / conftest` gate requires:
#   - the drill credential is an EXTERNAL-SECRET ref (no inline `value:` secret);
#   - the suspended quarterly CronJob renders `suspend: true` (built P1, run P2 —
#     a drill that auto-fires in P1 is a regression, ADR-0030 §5 / P1-PLAN.md §6);
#   - the drill is P2-execution flagged (the `netops.io/execution-phase: P2` ann);
#   - the drill restores to a THROWAWAY scratch path (--pg1-path + emptyDir),
#     never the live PGDATA PVC — isolation is the path override + scratch volume
#     (the drill renders into the release namespace; there is no separate one);
#   - the drill pod is hardened the same as every backup pod (the CronJob path is
#     already covered by the backup rules above; the drill JOB — a separate kind —
#     is covered here so its container controls are asserted too).
# The drill objects carry BOTH the `backup` component label AND a
# `netops.io/backup-type: drill` label; match on the latter to scope these rules.
# ===========================================================================

# A rendered drill object (Job OR CronJob) carries the drill backup-type label.
is_pitr_drill(obj) if {
	obj.metadata.labels["netops.io/backup-type"] == "drill"
}

# The drill pod-template spec, normalized across Job (spec.template.spec) and
# CronJob (spec.jobTemplate.spec.template.spec).
drill_pod_spec(obj) := obj.spec.template.spec if {
	obj.kind == "Job"
}

drill_pod_spec(obj) := obj.spec.jobTemplate.spec.template.spec if {
	obj.kind == "CronJob"
}

# --- secret-surface: any drill env whose NAME signals a credential (the repo
# cipher pass, S3 key/secret, DB password, or the KEK reference) MUST come from a
# secretKeyRef and carry NO inline `value:` literal (ADR-0030 §1 / ADR-0029 §6). ---
drill_credential_env(name) if {
	endswith(name, "CIPHER_PASS")
}

drill_credential_env(name) if {
	endswith(name, "S3_KEY")
}

drill_credential_env(name) if {
	endswith(name, "S3_KEY_SECRET")
}

drill_credential_env(name) if {
	name == "PGPASSWORD"
}

drill_credential_env(name) if {
	endswith(name, "KEK_REF")
}

deny contains msg if {
	is_pitr_drill(input)
	some c in drill_pod_spec(input).containers
	some e in object.get(c, "env", [])
	drill_credential_env(e.name)
	object.get(e, "value", null) != null
	msg := sprintf("PITR drill %q env %q must NOT carry an inline `value:` literal — the repo cipher pass / S3 credential / DB password / KEK reference are external-secret refs only (ADR-0030 §1 / ADR-0029 §6)", [input.metadata.name, e.name])
}

deny contains msg if {
	is_pitr_drill(input)
	some c in drill_pod_spec(input).containers
	some e in object.get(c, "env", [])
	drill_credential_env(e.name)
	not e.valueFrom.secretKeyRef
	msg := sprintf("PITR drill %q env %q must be sourced from valueFrom.secretKeyRef (credentials are by-reference only; ADR-0030 §1 / ADR-0011 §4)", [input.metadata.name, e.name])
}

# --- built P1, run P2: the quarterly drill CronJob MUST render suspended so K8s
# never auto-fires it in P1 (ADR-0030 §5 / P1-PLAN.md §6). A non-suspended drill
# CronJob is the regression this catches. ---
deny contains msg if {
	is_pitr_drill(input)
	input.kind == "CronJob"
	input.spec.suspend != true
	msg := sprintf("PITR drill CronJob %q must render `suspend: true` — the drill is BUILT in P1 and EXECUTED in P2; it must not auto-fire (ADR-0030 §5 / P1-PLAN.md §6)", [input.metadata.name])
}

# --- the drill must be P2-execution flagged so the evidence/aggregation layer
# (W5-T5) knows execution is deferred (ADR-0030 §5 — built P1, run P2). ---
deny contains msg if {
	is_pitr_drill(input)
	object.get(input.metadata.annotations, "netops.io/execution-phase", "") != "P2"
	msg := sprintf("PITR drill %q must carry the `netops.io/execution-phase: P2` annotation (built P1, executed quarterly in P2; ADR-0030 §5)", [input.metadata.name])
}

# --- THROWAWAY target: the drill restore data dir must NOT be the live PGDATA PVC
# path, and the restore volume must be an emptyDir scratch (never a
# persistentVolumeClaim). A drill that writes to the live PVC is a footgun
# (ADR-0030 §5.1 — restore to a clean/throwaway instance). The live PGDATA path is
# `/var/lib/postgresql/data/pgdata` (postgres-statefulset / pgbackrest config). ---
deny contains msg if {
	is_pitr_drill(input)
	some c in drill_pod_spec(input).containers
	some e in object.get(c, "env", [])
	e.name == "DRILL_RESTORE_PATH"
	startswith(e.value, "/var/lib/postgresql/data")
	msg := sprintf("PITR drill %q restore path %q must be a THROWAWAY scratch dir, NOT the live PGDATA path — a drill must never restore over production data (ADR-0030 §5.1)", [input.metadata.name, e.value])
}

deny contains msg if {
	is_pitr_drill(input)
	some v in object.get(drill_pod_spec(input), "volumes", [])
	v.name == "drill-restore"
	not v.emptyDir
	msg := sprintf("PITR drill %q `drill-restore` volume must be an emptyDir scratch (throwaway), never a PVC (ADR-0030 §5.1)", [input.metadata.name])
}

# --- the drill pod must not mount the live PGDATA PVC at all (no persistentVolumeClaim
# referencing the postgres data volume) — the restore is repo-sourced + scratch-only. ---
deny contains msg if {
	is_pitr_drill(input)
	some v in object.get(drill_pod_spec(input), "volumes", [])
	v.persistentVolumeClaim
	msg := sprintf("PITR drill %q must mount NO persistentVolumeClaim — the restore is object-store-sourced to throwaway scratch only (ADR-0030 §5.1)", [input.metadata.name])
}

# --- the drill pod must talk to Postgres + the object store, not the K8s API:
# automountServiceAccountToken=false (parity with the backup CronJob, ADR-0029 §5). ---
deny contains msg if {
	is_pitr_drill(input)
	drill_pod_spec(input).automountServiceAccountToken != false
	msg := sprintf("PITR drill %q pod must set automountServiceAccountToken=false — it talks to Postgres + the object store, not the K8s API (ADR-0029 §5)", [input.metadata.name])
}

# --- per-container hardening on the drill (the generic platform rules match
# Deployment/StatefulSet, and the backup-CronJob rules match `backup_containers`
# of a CronJob; the drill JOB is a separate kind, so assert the SAME ADR-0029 §3
# controls on its containers here so a hardening regression on the drill pod fails
# the gate too). drop ALL caps, add none, non-root, RO-rootfs, no-privesc,
# RuntimeDefault seccomp, resource requests AND limits. ---
deny contains msg if {
	is_pitr_drill(input)
	some c in drill_pod_spec(input).containers
	not drops_all(c)
	msg := sprintf("PITR drill %q container %q must drop ALL capabilities (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_pitr_drill(input)
	some c in drill_pod_spec(input).containers
	some cap in object.get(object.get(object.get(c, "securityContext", {}), "capabilities", {}), "add", [])
	msg := sprintf("PITR drill %q container %q must add NO capabilities (found %q; ADR-0029 §3)", [input.metadata.name, c.name, cap])
}

deny contains msg if {
	is_pitr_drill(input)
	some c in drill_pod_spec(input).containers
	c.securityContext.runAsNonRoot != true
	msg := sprintf("PITR drill %q container %q must set runAsNonRoot=true (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_pitr_drill(input)
	some c in drill_pod_spec(input).containers
	c.securityContext.readOnlyRootFilesystem != true
	msg := sprintf("PITR drill %q container %q must set readOnlyRootFilesystem=true (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_pitr_drill(input)
	some c in drill_pod_spec(input).containers
	c.securityContext.allowPrivilegeEscalation != false
	msg := sprintf("PITR drill %q container %q must set allowPrivilegeEscalation=false (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_pitr_drill(input)
	some c in drill_pod_spec(input).containers
	not drill_container_seccomp_set(input, c)
	msg := sprintf("PITR drill %q container %q must set a RuntimeDefault seccompProfile (ADR-0029 §3)", [input.metadata.name, c.name])
}

drill_container_seccomp_set(obj, c) if {
	c.securityContext.seccompProfile.type == "RuntimeDefault"
}

drill_container_seccomp_set(obj, _) if {
	drill_pod_spec(obj).securityContext.seccompProfile.type == "RuntimeDefault"
}

deny contains msg if {
	is_pitr_drill(input)
	some c in drill_pod_spec(input).containers
	not c.resources.requests
	msg := sprintf("PITR drill %q container %q must declare resource requests (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_pitr_drill(input)
	some c in drill_pod_spec(input).containers
	not c.resources.limits
	msg := sprintf("PITR drill %q container %q must declare resource limits (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_pitr_drill(input)
	some c in drill_pod_spec(input).containers
	endswith(c.image, ":latest")
	msg := sprintf("PITR drill %q image %q must not use the `latest` tag (ADR-0029 §5)", [input.metadata.name, c.image])
}

# --- the drill must actually RUN `pgbackrest verify` (assertion d) — a drill that
# never verifies the restored stanza is missing one of the four ADR-0030 §5.1
# checks. Asserted on the rendered argv text (the sh -c script). ---
deny contains msg if {
	is_pitr_drill(input)
	some c in drill_pod_spec(input).containers
	not container_runs_verify(c)
	msg := sprintf("PITR drill %q container %q must run `pgbackrest verify` on the restored stanza (ADR-0030 §5.1 assertion d)", [input.metadata.name, c.name])
}

# --- the drill must invoke the assertion harness (`run_drill`) — the four
# pass/fail checks are the whole point; a restore with no assertions is not a
# drill (ADR-0030 §5.1). Asserted on the rendered argv text. ---
deny contains msg if {
	is_pitr_drill(input)
	some c in drill_pod_spec(input).containers
	not container_runs_drill_harness(c)
	msg := sprintf("PITR drill %q container %q must invoke the assertion harness (`run_drill`) — a restore with no pass/fail assertions is not a drill (ADR-0030 §5.1)", [input.metadata.name, c.name])
}

container_runs_drill_harness(c) if {
	some arg in array.concat(object.get(c, "command", []), object.get(c, "args", []))
	contains(arg, "run_drill")
}

# ===========================================================================
# W5-T4 — pcap volume snapshot + spot-restore drill (ADR-0030 §3/§5.4;
# ADR-0023 §3/§4/§5)
#
# pcaps hold cleartext credentials/PII — the WHOLE risk is DR resurrecting a
# purged payload (ADR-0030 §3, the load-bearing constraint). These rules assert,
# on the RENDERED pcap manifests, that DR HONORS — never subverts — the ADR-0023
# retention contract:
#   - the SNAPSHOT CronJob (backup-type `pcap-snapshot`): its object-store
#     credential is an external-secret REF (least-privilege, write-to-`pcaps/`-
#     prefix only — never inlined); it reads the pcap volume READ-ONLY; and it
#     invokes the model-reusing planner (`pcap.snapshot`) that skips tombstoned
#     files (no duplicated retention logic);
#   - the SPOT-RESTORE drill (backup-type `pcap-drill`): suspended ANNUAL CronJob
#     (built P1, run P2 — §5.4); P2-execution flagged; credentials are external-
#     secret REFs; it restores to a THROWAWAY emptyDir (never the live pcap PVC);
#     and it invokes the assertion harness (`pcap.run_drill`) that sha256-verifies
#     and PROVES no tombstoned resurrection.
# The generic per-container hardening is asserted here too (the CronJob/Job kinds
# nest containers under their own paths). Both objects carry the `backup` component
# label; match on the W5-T4 backup-type labels to scope these rules. The W5-T1
# pgBackRest cadence rules EXCLUDE these backup-types (is_backup_cronjob scopes to
# full|incr only), so they do not mis-fire here.
# ===========================================================================

# A rendered pcap SNAPSHOT CronJob (the daily live-only snapshot).
is_pcap_snapshot(obj) if {
	obj.kind == "CronJob"
	obj.metadata.labels["netops.io/backup-type"] == "pcap-snapshot"
}

# A rendered pcap SPOT-RESTORE drill object (Job OR suspended annual CronJob).
is_pcap_drill(obj) if {
	obj.metadata.labels["netops.io/backup-type"] == "pcap-drill"
}

# The container list of a pcap-snapshot CronJob.
pcap_snapshot_containers(cj) := cj.spec.jobTemplate.spec.template.spec.containers

# The pcap-drill pod spec, normalized across Job and CronJob.
pcap_drill_pod_spec(obj) := obj.spec.template.spec if {
	obj.kind == "Job"
}

pcap_drill_pod_spec(obj) := obj.spec.jobTemplate.spec.template.spec if {
	obj.kind == "CronJob"
}

# --- secret-surface: any pcap env whose NAME signals a credential (the pcap
# object-store key/secret or the DB password) MUST come from a secretKeyRef and
# carry NO inline `value:` literal (ADR-0030 §3 / ADR-0029 §6). ---
pcap_credential_env(name) if {
	endswith(name, "S3_KEY")
}

pcap_credential_env(name) if {
	endswith(name, "S3_KEY_SECRET")
}

pcap_credential_env(name) if {
	name == "PGPASSWORD"
}

# Snapshot CronJob credential checks.
deny contains msg if {
	is_pcap_snapshot(input)
	some c in pcap_snapshot_containers(input)
	some e in object.get(c, "env", [])
	pcap_credential_env(e.name)
	object.get(e, "value", null) != null
	msg := sprintf("pcap snapshot %q env %q must NOT carry an inline `value:` literal — the object-store credential / DB password are external-secret refs only (ADR-0030 §3 / ADR-0029 §6)", [input.metadata.name, e.name])
}

deny contains msg if {
	is_pcap_snapshot(input)
	some c in pcap_snapshot_containers(input)
	some e in object.get(c, "env", [])
	pcap_credential_env(e.name)
	not e.valueFrom.secretKeyRef
	msg := sprintf("pcap snapshot %q env %q must be sourced from valueFrom.secretKeyRef (the object-store credential / DB password are by-reference only; ADR-0030 §3 / ADR-0023 §5)", [input.metadata.name, e.name])
}

# Spot-restore drill credential checks (same secret-surface guard).
deny contains msg if {
	is_pcap_drill(input)
	some c in pcap_drill_pod_spec(input).containers
	some e in object.get(c, "env", [])
	pcap_credential_env(e.name)
	object.get(e, "value", null) != null
	msg := sprintf("pcap restore drill %q env %q must NOT carry an inline `value:` literal — credentials are external-secret refs only (ADR-0030 §3 / ADR-0029 §6)", [input.metadata.name, e.name])
}

deny contains msg if {
	is_pcap_drill(input)
	some c in pcap_drill_pod_spec(input).containers
	some e in object.get(c, "env", [])
	pcap_credential_env(e.name)
	not e.valueFrom.secretKeyRef
	msg := sprintf("pcap restore drill %q env %q must be sourced from valueFrom.secretKeyRef (credentials are by-reference only; ADR-0030 §3)", [input.metadata.name, e.name])
}

# --- least-privilege credential SEPARATION: the pcap snapshot must use the pcap-
# prefix-scoped credential (secrets.keys.pcapSnapshotS3*), NEVER the pgbackrest/
# repo S3 credential (secrets.keys.backupRepoS3*). Reusing the pgbackrest key here
# would grant the snapshot the pgbackrest/ prefix (broad grant) and vice-versa —
# a leak of one would expose the other's prefix (ADR-0030 §3 / least-privilege §7).
# Asserted by the secretKeyRef KEY NAME the snapshot env points at. ---
deny contains msg if {
	is_pcap_snapshot(input)
	some c in pcap_snapshot_containers(input)
	some e in object.get(c, "env", [])
	endswith(e.name, "S3_KEY")
	key := e.valueFrom.secretKeyRef.key
	contains(key, "backup-repo-s3")
	msg := sprintf("pcap snapshot %q env %q must reference the pcap-prefix-scoped credential (pcap-snapshot-s3-*), NOT the pgbackrest repo credential %q — a snapshot that reuses the pgbackrest credential gets a broad cross-prefix grant (ADR-0030 §3 / least-privilege §7)", [input.metadata.name, e.name, key])
}

# --- the snapshot must mount the pcap volume READ-ONLY (it reads captures, writes
# only the object store; a writable mount risks integrity — ADR-0023 §3). ---
deny contains msg if {
	is_pcap_snapshot(input)
	some c in pcap_snapshot_containers(input)
	some m in c.volumeMounts
	m.name == "pcaps"
	m.readOnly != true
	msg := sprintf("pcap snapshot %q must mount the pcap volume readOnly:true — it reads captures and writes only the object store (ADR-0023 §3)", [input.metadata.name])
}

# --- the snapshot must invoke the model-reusing planner (`pcap.snapshot`), which
# SKIPS tombstoned files + prunes tombstoned object copies by calling the
# pcap_metadata model — a snapshot that does not is not retention-honoring
# (requirement 1, the no-resurrection-at-snapshot guard). Asserted on argv text. ---
deny contains msg if {
	is_pcap_snapshot(input)
	some c in pcap_snapshot_containers(input)
	not container_runs_pcap_snapshot(c)
	msg := sprintf("pcap snapshot %q container %q must invoke the model-reusing planner (`pcap.snapshot`) — it must skip tombstoned files + prune tombstoned copies by calling pcap_metadata, not re-implement retention (ADR-0023 §4 / ADR-0030 §3)", [input.metadata.name, c.name])
}

container_runs_pcap_snapshot(c) if {
	some arg in array.concat(object.get(c, "command", []), object.get(c, "args", []))
	contains(arg, "pcap.snapshot")
}

# --- built P1, run P2: the ANNUAL pcap drill CronJob MUST render suspended so K8s
# never auto-fires it in P1 (ADR-0030 §5.4 / P1-PLAN.md §6). ---
deny contains msg if {
	is_pcap_drill(input)
	input.kind == "CronJob"
	input.spec.suspend != true
	msg := sprintf("pcap restore drill CronJob %q must render `suspend: true` — built P1, executed annually in P2; it must not auto-fire (ADR-0030 §5.4)", [input.metadata.name])
}

# --- the drill must be P2-execution flagged (the W5-T5 evidence layer knows
# execution is deferred — ADR-0030 §5.4). ---
deny contains msg if {
	is_pcap_drill(input)
	object.get(input.metadata.annotations, "netops.io/execution-phase", "") != "P2"
	msg := sprintf("pcap restore drill %q must carry the `netops.io/execution-phase: P2` annotation (built P1, executed annually in P2; ADR-0030 §5.4)", [input.metadata.name])
}

# --- THROWAWAY restore: the drill restore volume must be an emptyDir scratch
# (never a PVC), and the drill must mount NO persistentVolumeClaim — so a restore
# can NEVER write onto the live pcap volume (no resurrection path onto the live
# disk; ADR-0030 §3 / §5.1). ---
deny contains msg if {
	is_pcap_drill(input)
	some v in object.get(pcap_drill_pod_spec(input), "volumes", [])
	v.name == "drill-restore"
	not v.emptyDir
	msg := sprintf("pcap restore drill %q `drill-restore` volume must be an emptyDir scratch (throwaway), never a PVC (ADR-0030 §5.1)", [input.metadata.name])
}

deny contains msg if {
	is_pcap_drill(input)
	some v in object.get(pcap_drill_pod_spec(input), "volumes", [])
	v.persistentVolumeClaim
	msg := sprintf("pcap restore drill %q must mount NO persistentVolumeClaim — the restore is object-store-sourced to throwaway scratch only; it must never touch the live pcap volume (ADR-0030 §3/§5.1)", [input.metadata.name])
}

# --- the drill must invoke the assertion harness (`pcap.run_drill`) — the sha256-
# verify + no-resurrection + engineer+ gate assertions are the whole point; a
# restore with no assertions is not a drill (ADR-0023 §5 / ADR-0030 §3). ---
deny contains msg if {
	is_pcap_drill(input)
	some c in pcap_drill_pod_spec(input).containers
	not container_runs_pcap_drill(c)
	msg := sprintf("pcap restore drill %q container %q must invoke the assertion harness (`pcap.run_drill`) — a restore with no sha256/no-resurrection/gated assertions is not a drill (ADR-0023 §5 / ADR-0030 §3)", [input.metadata.name, c.name])
}

container_runs_pcap_drill(c) if {
	some arg in array.concat(object.get(c, "command", []), object.get(c, "args", []))
	contains(arg, "pcap.run_drill")
}

# --- the drill restore is engineer+ GATED (ADR-0023 §5): the rendered pod must
# carry the DRILL_MIN_ROLE env so the harness enforces the gate. A drill with no
# min-role would restore for any actor — the ungated read path the spec forbids. ---
deny contains msg if {
	is_pcap_drill(input)
	some c in pcap_drill_pod_spec(input).containers
	not pcap_drill_has_min_role(c)
	msg := sprintf("pcap restore drill %q container %q must set DRILL_MIN_ROLE so the restore stays engineer+ gated (ADR-0023 §5 — no new ungated read path)", [input.metadata.name, c.name])
}

pcap_drill_has_min_role(c) if {
	some e in object.get(c, "env", [])
	e.name == "DRILL_MIN_ROLE"
}

# --- pod hardening parity for both pcap objects (the CronJob/Job kinds nest
# containers under their own paths; assert the ADR-0029 §3 controls here so a
# hardening regression on the pcap pods fails the gate too). The snapshot is a
# CronJob; the drill is a Job AND a CronJob. Cover both via a unified container
# iterator. ---
pcap_workload_containers(obj) := pcap_snapshot_containers(obj) if {
	is_pcap_snapshot(obj)
}

pcap_workload_containers(obj) := pcap_drill_pod_spec(obj).containers if {
	is_pcap_drill(obj)
}

is_pcap_workload(obj) if is_pcap_snapshot(obj)

is_pcap_workload(obj) if is_pcap_drill(obj)

deny contains msg if {
	is_pcap_workload(input)
	some c in pcap_workload_containers(input)
	not drops_all(c)
	msg := sprintf("pcap workload %q container %q must drop ALL capabilities (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_pcap_workload(input)
	some c in pcap_workload_containers(input)
	some cap in object.get(object.get(object.get(c, "securityContext", {}), "capabilities", {}), "add", [])
	msg := sprintf("pcap workload %q container %q must add NO capabilities (found %q; ADR-0029 §3)", [input.metadata.name, c.name, cap])
}

deny contains msg if {
	is_pcap_workload(input)
	some c in pcap_workload_containers(input)
	c.securityContext.runAsNonRoot != true
	msg := sprintf("pcap workload %q container %q must set runAsNonRoot=true (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_pcap_workload(input)
	some c in pcap_workload_containers(input)
	c.securityContext.readOnlyRootFilesystem != true
	msg := sprintf("pcap workload %q container %q must set readOnlyRootFilesystem=true (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_pcap_workload(input)
	some c in pcap_workload_containers(input)
	c.securityContext.allowPrivilegeEscalation != false
	msg := sprintf("pcap workload %q container %q must set allowPrivilegeEscalation=false (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_pcap_workload(input)
	some c in pcap_workload_containers(input)
	not c.resources.requests
	msg := sprintf("pcap workload %q container %q must declare resource requests (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_pcap_workload(input)
	some c in pcap_workload_containers(input)
	not c.resources.limits
	msg := sprintf("pcap workload %q container %q must declare resource limits (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_pcap_workload(input)
	some c in pcap_workload_containers(input)
	endswith(c.image, ":latest")
	msg := sprintf("pcap workload %q image %q must not use the `latest` tag (ADR-0029 §5)", [input.metadata.name, c.image])
}

# --- the pcap pods talk to Postgres + the object store, not the K8s API:
# automountServiceAccountToken=false (parity with the backup CronJob, ADR-0029 §5). ---
deny contains msg if {
	is_pcap_snapshot(input)
	input.spec.jobTemplate.spec.template.spec.automountServiceAccountToken != false
	msg := sprintf("pcap snapshot %q pod must set automountServiceAccountToken=false (ADR-0029 §5)", [input.metadata.name])
}

deny contains msg if {
	is_pcap_drill(input)
	pcap_drill_pod_spec(input).automountServiceAccountToken != false
	msg := sprintf("pcap restore drill %q pod must set automountServiceAccountToken=false (ADR-0029 §5)", [input.metadata.name])
}
