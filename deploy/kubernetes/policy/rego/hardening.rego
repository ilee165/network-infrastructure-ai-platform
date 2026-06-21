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

# ---------------------------------------------------------------------------
# ADR-0029 §3 — namespace PSS restricted labels
# ---------------------------------------------------------------------------

deny contains msg if {
	input.kind == "Namespace"
	input.metadata.labels["pod-security.kubernetes.io/enforce"] != "restricted"
	msg := "namespace must enforce Pod Security Standard `restricted` (ADR-0029 §3)"
}

deny contains msg if {
	input.kind == "Namespace"
	input.metadata.labels["pod-security.kubernetes.io/audit"] != "restricted"
	msg := "namespace must set PSA audit=restricted (ADR-0029 §3)"
}

deny contains msg if {
	input.kind == "Namespace"
	input.metadata.labels["pod-security.kubernetes.io/warn"] != "restricted"
	msg := "namespace must set PSA warn=restricted (ADR-0029 §3)"
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
