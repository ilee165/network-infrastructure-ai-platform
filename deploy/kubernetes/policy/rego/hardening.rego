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
# (DNS :53 is the universal default-deny backstop, also permitted.)
netpol_known_egress_ports := {5432, 7687, 6379, 11434, 443, 53}

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
