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
# rule present, enforcement driven by security.imageVerification.enabled, default
# ON per W6-T5). Its absence means the supply-chain enforcement rule was dropped.
deny contains msg if {
	input.kind == "ClusterPolicy"
	input.metadata.name == "netops-hardening-baseline"
	not policy_has_verify_images(input)
	msg := "admission ClusterPolicy must include the cosign signed-image verify rule (verify-image-signatures); it renders always, enforcement driven by security.imageVerification.enabled (ADR-0029 §5 / P1 W6-T5)"
}

# P1 W6-T5 SECURE-BY-DEFAULT: the verify-images rule must ENFORCE (not Audit) and
# be required, so an unsigned/forged image is REJECTED at admission. Asserted on
# the default-rendered chart: failureAction Enforce + required true + verifyDigest
# (a tag-swap to an unsigned digest is also rejected). This is the "signed admits /
# unsigned rejects" guard — it fails the build if verification is silently flipped
# to Audit-only or made non-blocking by default.
deny contains msg if {
	input.kind == "ClusterPolicy"
	input.metadata.name == "netops-hardening-baseline"
	some r in input.spec.rules
	r.name == "verify-image-signatures"
	some vi in r.verifyImages
	vi.failureAction != "Enforce"
	msg := sprintf("verify-image-signatures must Enforce by default (secure-by-default), got failureAction=%q (P1 W6-T5 / ADR-0029 §5)", [vi.failureAction])
}

deny contains msg if {
	input.kind == "ClusterPolicy"
	input.metadata.name == "netops-hardening-baseline"
	some r in input.spec.rules
	r.name == "verify-image-signatures"
	some vi in r.verifyImages
	vi.required != true
	msg := "verify-image-signatures must be required:true by default — a verification it cannot perform must REJECT, not skip (P1 W6-T5)"
}

deny contains msg if {
	input.kind == "ClusterPolicy"
	input.metadata.name == "netops-hardening-baseline"
	some r in input.spec.rules
	r.name == "verify-image-signatures"
	some vi in r.verifyImages
	vi.verifyDigest != true
	msg := "verify-image-signatures must verifyDigest:true so a tag-swap to an unsigned digest is rejected (P1 W6-T5)"
}

# The verifier must be REAL, not the W3 empty-string placeholder that admitted
# everything: either a keyless issuer+subject pair or a publicKeys key-ref. An
# empty issuer with empty subject is a no-op attestor and would admit unsigned
# images even under Enforce — this guard rejects that misconfiguration.
deny contains msg if {
	input.kind == "ClusterPolicy"
	input.metadata.name == "netops-hardening-baseline"
	some r in input.spec.rules
	r.name == "verify-image-signatures"
	some vi in r.verifyImages
	not verify_images_has_real_attestor(vi)
	msg := "verify-image-signatures must carry a real attestor (keyless issuer+subject OR a publicKeys key-ref), not an empty placeholder (P1 W6-T5)"
}

# Both CI-built images (backend + frontend) must be covered by the signature
# policy — signing only one leaves the other an unsigned-image admission hole.
deny contains msg if {
	input.kind == "ClusterPolicy"
	input.metadata.name == "netops-hardening-baseline"
	some r in input.spec.rules
	r.name == "verify-image-signatures"
	some required_image in {"netops-backend", "netops-frontend"}
	not verify_images_covers(r, required_image)
	msg := sprintf("verify-image-signatures must cover the %q image reference (P1 W6-T5)", [required_image])
}

policy_has_verify_images(policy) if {
	some r in policy.spec.rules
	r.name == "verify-image-signatures"
	r.verifyImages
}

# A real keyless attestor: non-empty issuer AND a non-empty subject matcher.
verify_images_has_real_attestor(vi) if {
	some attestor in vi.attestors
	some entry in attestor.entries
	entry.keyless.issuer != ""
	keyless_has_subject(entry.keyless)
}

# A real key-ref attestor: a non-empty publicKeys reference.
verify_images_has_real_attestor(vi) if {
	some attestor in vi.attestors
	some entry in attestor.entries
	entry.keys.publicKeys != ""
}

keyless_has_subject(kl) if kl.subjectRegExp != ""

keyless_has_subject(kl) if kl.subject != ""

verify_images_covers(rule, image) if {
	some vi in rule.verifyImages
	some ref in vi.imageReferences
	startswith(ref, image)
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
# Port 26379 is the W1-T4 Redis Sentinel control port (ADR-0044 §1): the
# api/worker → sentinel discovery edge and the sentinel↔sentinel quorum-gossip
# edge ride it under the default-deny floor. It renders ONLY on the opt-in
# redisSentinel HA tier; on the default single-instance render no egress targets
# it, so adding it to the known set does not loosen the GA default.
netpol_known_egress_ports := {5432, 7687, 6379, 11434, 9000, 8432, 443, 53, 26379}

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
# netpol_known_egress_ports is not a §3.1 arrow and is denied. The W4-T5 collector
# mgmt-subnet egress policy (ADR-0041) is EXCLUDED here — it reaches device
# MANAGEMENT ports (SSH/SNMP/NETCONF…), not §2 in-cluster edges, and is governed by
# its own device-mgmt port allow-set in the W4-T5 region below (same exclusion shape
# as the packet policies).
deny contains msg if {
	input.kind == "NetworkPolicy"
	not is_packet_netpol(input)
	not is_collector_egress_netpol(input)
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
# W4-T5 — collector/worker default-deny egress to the device MANAGEMENT subnet
# (ADR-0041 §1, PRODUCTION.md §9 collector network segmentation, gate G-SEC).
#
# The collector/worker pods are the components that reach out to managed devices.
# A default-deny egress floor (networkpolicies.yaml `-default-deny-all`) already
# denies ALL egress; the §2 allows re-permit the in-cluster data stores + DNS, and
# this ADR-0041 policy re-permits the ONE external destination collectors
# legitimately reach — the device MANAGEMENT subnet(s) — as `ipBlock` CIDR(s) on a
# confined device-mgmt port set. The external allow-list is `ipBlock` ONLY
# (selectors cannot express an external CIDR) and is the mgmt subnet + named
# in-cluster services ONLY: NO 0.0.0.0/0, NO blanket RFC1918 (the over-broad
# allow-list ADR-0041 §Consequences/Alt #2 rejects). These rules assert that shape
# on the RENDERED manifest, per document (conftest --all-namespaces, no --combine).
#
# Identified by its component label `collector-egress` (label-based, matching the
# rest of this file), so a fullname-prefix rename cannot slip a policy past the
# guard. The packet-capture policy carries its OWN ADR-0031 mgmt-egress rules
# above; this is the ADR-0041 collector/worker control, distinct from it.
# ===========================================================================

# The device-MANAGEMENT {port, protocol} edges a collector legitimately reaches
# (ADR-0041 §1): SSH (22/TCP), SNMP (161/UDP), NETCONF (830/TCP), HTTPS device APIs
# (443/TCP). The PROTOCOL is part of the edge: SNMP is UDP, so a TCP/161 render does
# NOT permit SNMP polling under the default-deny floor — modelling protocol here is
# the guard against that false promise. An egress {port, protocol} on the collector
# mgmt policy outside this set is not a device-mgmt edge and is denied. This is a
# SCOPED allow-set for this policy ONLY — it is NOT folded into the §2 in-cluster
# `netpol_known_egress_ports` (those are cluster edges; these are device ports). A
# new device-mgmt edge is added here consciously, never silently.
collector_mgmt_ports := {
	{"port": 22, "protocol": "TCP"},
	{"port": 161, "protocol": "UDP"},
	{"port": 443, "protocol": "TCP"},
	{"port": 830, "protocol": "TCP"},
}

# True for the W4-T5 collector mgmt-subnet egress NetworkPolicy. Identified by the
# policy's OWN metadata component label `collector-egress` (its identity), NOT its
# podSelector (which targets the `worker` pods it binds) — same identification shape
# as the `external-llm-egress` policy above.
is_collector_egress_netpol(np) if {
	np.metadata.labels["app.kubernetes.io/component"] == "collector-egress"
}

# --- the collector mgmt-egress policy must be EGRESS-typed (it is an egress
# control; an ingress-only render would be inert). ---
deny contains msg if {
	is_collector_egress_netpol(input)
	not policy_has_egress(input)
	msg := "collector mgmt-egress NetworkPolicy must declare policyTypes Egress (default-deny egress re-permitting the mgmt subnet only; ADR-0041 §1)"
}

# --- the collector mgmt-egress policy must re-permit a device MANAGEMENT subnet
# via an `ipBlock` CIDR — that is the whole point (ADR-0041 §1; selectors cannot
# express an external CIDR). A policy with no ipBlock allow reaches no device. ---
deny contains msg if {
	is_collector_egress_netpol(input)
	not collector_allows_management_cidr(input)
	msg := "collector mgmt-egress NetworkPolicy must allow egress to a device management subnet (ipBlock CIDR) — the ONLY external destination collectors legitimately reach (ADR-0041 §1 / PRODUCTION.md §9)"
}

collector_allows_management_cidr(np) if {
	some rule in np.spec.egress
	some target in rule.to
	target.ipBlock.cidr
}

# --- ALLOW-LIST MINIMALITY (the load-bearing W4-T5 guard, ADR-0041 §Consequences
# / Alt #2): an over-broad allow-list silently reopens the exfiltration/pivot path
# the control exists to close. NO collector mgmt-egress ipBlock CIDR may be the
# whole internet (`0.0.0.0/0`) or an IPv6 default route (`::/0`). ---
deny contains msg if {
	is_collector_egress_netpol(input)
	some rule in object.get(input.spec, "egress", [])
	some target in object.get(rule, "to", [])
	cidr := target.ipBlock.cidr
	cidr in {"0.0.0.0/0", "::/0"}
	msg := sprintf("collector mgmt-egress NetworkPolicy must NOT allow the whole internet (found ipBlock %q) — the allow-list is the device mgmt subnet only, never 0.0.0.0/0 (ADR-0041 §Alt #2 / minimality)", [cidr])
}

# --- ALLOW-LIST MINIMALITY (cont.): the allow-list must not be BLANKET RFC1918 —
# permitting all three private supernets (10/8, 172.16/12, 192.168/16) at once
# re-permits the entire private address space (every other namespace, every other
# subnet), which is the over-broad allow-list ADR-0041 rejects. The mgmt subnet is
# a NARROW range an operator configures, not "all of RFC1918". An exact-match on
# all three /8-/12-/16 supernets in the same policy is the blanket-RFC1918 tell. ---
rfc1918_supernets := {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

collector_cidrs := {cidr |
	some rule in object.get(input.spec, "egress", [])
	some target in object.get(rule, "to", [])
	cidr := target.ipBlock.cidr
}

deny contains msg if {
	is_collector_egress_netpol(input)
	# every one of the three RFC1918 supernets is present verbatim in the allow-list
	count(rfc1918_supernets - collector_cidrs) == 0
	msg := "collector mgmt-egress NetworkPolicy must NOT allow BLANKET RFC1918 (10/8 + 172.16/12 + 192.168/16 together re-permit the whole private space) — narrow it to the operator-configured device mgmt subnet(s) (ADR-0041 §Alt #2 / minimality)"
}

# --- the collector mgmt-egress policy must NOT contain a wide-open (no `to`) rule:
# a missing `to` = allow-to-anywhere, exactly what default-deny forbids (ADR-0041
# §1). (The generic no-blanket-egress rule above also covers this; this is the
# W4-T5-named guard so a regression names the control it broke.) ---
deny contains msg if {
	is_collector_egress_netpol(input)
	some rule in object.get(input.spec, "egress", [])
	not rule.to
	msg := "collector mgmt-egress NetworkPolicy must not contain an unrestricted (no `to`) egress rule — the allow-list is the mgmt subnet only (ADR-0041 §1)"
}

# --- every mgmt-egress {port, protocol} must be a known device-MGMT edge
# (SSH 22/TCP, SNMP 161/UDP, NETCONF 830/TCP, HTTPS-API 443/TCP). A {port, protocol}
# outside collector_mgmt_ports is not a device-mgmt edge and is denied — keeps the
# control confined to the device-reaching protocols, not "any port to the mgmt
# subnet", and rejects a TCP/161 render that would silently fail to permit UDP SNMP.
# K8s defaults an omitted `protocol` to TCP, so normalize before the set lookup. ---
deny contains msg if {
	is_collector_egress_netpol(input)
	some rule in object.get(input.spec, "egress", [])
	some p in object.get(rule, "ports", [])
	proto := object.get(p, "protocol", "TCP")
	not collector_mgmt_ports[{"port": p.port, "protocol": proto}]
	msg := sprintf("collector mgmt-egress NetworkPolicy targets %v/%v, not a known device-management edge (22/TCP, 161/UDP, 443/TCP, 830/TCP) (ADR-0041 §1)", [proto, p.port])
}

# --- the collector mgmt-egress policy must SELECT the collector/worker pods (by
# their existing `worker` app label, ADR-0041 §1) — a policy that selects the wrong
# pods confines nothing. Asserted via podSelector matchLabels component=worker. ---
deny contains msg if {
	is_collector_egress_netpol(input)
	not input.spec.podSelector.matchLabels["app.kubernetes.io/component"] == "worker"
	msg := "collector mgmt-egress NetworkPolicy must select the worker/collector pods (podSelector app.kubernetes.io/component=worker; ADR-0041 §1)"
}

# --- ALLOW-LIST MINIMALITY (cont., P1net/PR#76): every external `to` target MUST be
# `ipBlock`-ONLY. The earlier `collector_allows_management_cidr` only checks that AN
# ipBlock is PRESENT — a MIXED `to` target (ipBlock + a podSelector/namespaceSelector
# in the SAME target, or a non-ipBlock target alongside the ipBlock) would silently
# re-permit in-cluster/other-namespace destinations the ADR-0041 §1 minimality control
# forbids. Assert ipBlock-ONLY: any `to` target that carries a selector key (pod/
# namespace/ipBlock-missing) on this policy is denied. ---
collector_to_target_is_ipblock_only(target) if {
	target.ipBlock
	not target.podSelector
	not target.namespaceSelector
}

deny contains msg if {
	is_collector_egress_netpol(input)
	some rule in object.get(input.spec, "egress", [])
	some target in object.get(rule, "to", [])
	not collector_to_target_is_ipblock_only(target)
	msg := "collector mgmt-egress NetworkPolicy `to` targets must be ipBlock-ONLY — a mixed ipBlock+selector (or a non-ipBlock) target re-permits in-cluster/other-namespace destinations the minimality control forbids (ADR-0041 §1 / §Alt #2, P1net/PR#76)"
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
# is intentionally absent (governed by the named ADR-0031 rules above). The W1-T4
# Redis Sentinel pods (`redis-sentinel`) are INCLUDED so every ADR-0029 §3 control
# (drop-ALL, non-root, RO-rootfs, no-privesc, RuntimeDefault seccomp, limits) is
# asserted on them too — they render only on the opt-in redisSentinel HA tier.
platform_workload_components := {"api", "worker", "frontend", "postgres", "neo4j", "redis", "ollama", "redis-sentinel"}

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

# --- REQUIRED credential envs: the prior rules only validate a credential env when
# it is PRESENT, so DELETING or RENAMING the pgBackRest cipher pass / S3 key / S3
# secret would bypass the policy entirely — producing a green backup CronJob that
# cannot decrypt or reach the repo. Require each, by EXACT name, sourced from a
# secretKeyRef (ADR-0030 §1 / ADR-0029 §6). ---
required_backup_credential_envs := {
	"PGBACKREST_REPO1_CIPHER_PASS",
	"PGBACKREST_REPO1_S3_KEY",
	"PGBACKREST_REPO1_S3_KEY_SECRET",
}

container_has_secret_env(c, name) if {
	some e in object.get(c, "env", [])
	e.name == name
	e.valueFrom.secretKeyRef
	object.get(e, "value", null) == null
}

deny contains msg if {
	is_backup_cronjob(input)
	some c in backup_containers(input)
	some name in required_backup_credential_envs
	not container_has_secret_env(c, name)
	msg := sprintf("backup CronJob %q container %q must set %q from valueFrom.secretKeyRef (deleting/renaming the cipher pass or object-store credential must not silently pass; ADR-0030 §1 / ADR-0029 §6)", [input.metadata.name, c.name, name])
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
# BOTH halves of the S3 credential (the access key id AND the secret) are checked:
# `endswith(.., "S3_KEY")` is FALSE for `..S3_KEY_SECRET`, so a separation check on
# the key id alone would let the secret half point at the pgbackrest repo credential
# and pass. Match either suffix.
pcap_snapshot_s3_env(name) if {
	endswith(name, "S3_KEY")
}

pcap_snapshot_s3_env(name) if {
	endswith(name, "S3_KEY_SECRET")
}

deny contains msg if {
	is_pcap_snapshot(input)
	some c in pcap_snapshot_containers(input)
	some e in object.get(c, "env", [])
	pcap_snapshot_s3_env(e.name)
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
	# Presence is not enough: a lower role (e.g. `viewer`) would satisfy a bare
	# presence check while WEAKENING the gate. The restore must stay engineer+
	# (ADR-0023 §5), so assert the rendered value IS the engineer role.
	lower(sprintf("%v", [e.value])) == "engineer"
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

# RuntimeDefault seccomp parity: the other W5 backup/drill workloads (the backup
# CronJob, the PITR / neo4j / full-platform drills) all assert a RuntimeDefault
# seccompProfile; the pcap parity block omitted it, so a pcap pod could pass with no
# seccomp. Match container-level OR the pod-level (CronJob/Job) seccompProfile.
deny contains msg if {
	is_pcap_workload(input)
	some c in pcap_workload_containers(input)
	not pcap_workload_container_seccomp_set(input, c)
	msg := sprintf("pcap workload %q container %q must set a RuntimeDefault seccompProfile (ADR-0029 §3)", [input.metadata.name, c.name])
}

pcap_workload_container_seccomp_set(_, c) if {
	c.securityContext.seccompProfile.type == "RuntimeDefault"
}

pcap_workload_container_seccomp_set(obj, _) if {
	is_pcap_snapshot(obj)
	obj.spec.jobTemplate.spec.template.spec.securityContext.seccompProfile.type == "RuntimeDefault"
}

pcap_workload_container_seccomp_set(obj, _) if {
	is_pcap_drill(obj)
	pcap_drill_pod_spec(obj).securityContext.seccompProfile.type == "RuntimeDefault"
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

# ===========================================================================
# W5-T3 — Neo4j REBUILD-DRILL (ADR-0030 §2/§5.2; ADR-0005 D5)
#
# Neo4j has NO backup: DR is a full RE-PROJECTION from Postgres, never a graph
# dump/restore (ADR-0005 D5). The drill drops/recreates the projected graph,
# re-projects the whole Postgres inventory via the EXISTING engines/topology
# full-rebuild path (recording `topology_rebuild_seconds` — the topology-RTO),
# and asserts the rebuilt node/edge counts match the pre-wipe projection. These
# rules assert, on the RENDERED drill manifests, the policy-surface invariants the
# spec's `helm lint / kubeconform / conftest` gate requires:
#   - the drill credentials (Postgres password, Neo4j auth) are EXTERNAL-SECRET
#     refs (no inline `value:` secret);
#   - the suspended quarterly CronJob renders `suspend: true` (built P1, run P2 —
#     a drill that auto-fires in P1 is a regression, ADR-0030 §5.2 / P1-PLAN.md §6);
#   - the drill is P2-execution flagged (the `netops.io/execution-phase: P2` ann);
#   - the drill invokes the EXISTING full-rebuild + assertion harness
#     (`topology_rebuild.run_drill`) — a wipe with no reproject/assert is not a
#     rebuild-drill (ADR-0030 §5.2);
#   - the `neo4j-admin dump` fast-start is OPT-IN, OFF by default (true to D5 — the
#     projection is disposable; a stale dump could disagree with Postgres);
#   - the drill mounts NO persistentVolumeClaim — the rebuild is Postgres-sourced
#     into a CLEAN Neo4j, never a restore onto a live data volume;
#   - the drill pod is hardened the same as every backup/drill pod.
# The drill objects carry BOTH the `backup` component label AND a
# `netops.io/backup-type: neo4j-rebuild-drill` label; match on the latter to scope
# these rules (the W5-T1 full|incr cadence rules + the W5-T2 PITR `drill` rules
# exclude this backup-type by construction, so none mis-fire here).
# ===========================================================================

# A rendered Neo4j rebuild-drill object (Job OR CronJob) by its backup-type label.
is_neo4j_rebuild_drill(obj) if {
	obj.metadata.labels["netops.io/backup-type"] == "neo4j-rebuild-drill"
}

# The drill pod-template spec, normalized across Job and CronJob.
neo4j_drill_pod_spec(obj) := obj.spec.template.spec if {
	obj.kind == "Job"
}

neo4j_drill_pod_spec(obj) := obj.spec.jobTemplate.spec.template.spec if {
	obj.kind == "CronJob"
}

# --- secret-surface: any drill env whose NAME signals a credential (the Postgres
# password or the Neo4j auth) MUST come from a secretKeyRef and carry NO inline
# `value:` literal (ADR-0030 §1 / ADR-0029 §6). ---
neo4j_drill_credential_env(name) if {
	endswith(name, "POSTGRES_PASSWORD")
}

neo4j_drill_credential_env(name) if {
	endswith(name, "NEO4J_AUTH")
}

deny contains msg if {
	is_neo4j_rebuild_drill(input)
	some c in neo4j_drill_pod_spec(input).containers
	some e in object.get(c, "env", [])
	neo4j_drill_credential_env(e.name)
	object.get(e, "value", null) != null
	msg := sprintf("neo4j rebuild drill %q env %q must NOT carry an inline `value:` literal — the Postgres password / Neo4j auth are external-secret refs only (ADR-0030 §1 / ADR-0029 §6)", [input.metadata.name, e.name])
}

deny contains msg if {
	is_neo4j_rebuild_drill(input)
	some c in neo4j_drill_pod_spec(input).containers
	some e in object.get(c, "env", [])
	neo4j_drill_credential_env(e.name)
	not e.valueFrom.secretKeyRef
	msg := sprintf("neo4j rebuild drill %q env %q must be sourced from valueFrom.secretKeyRef (credentials are by-reference only; ADR-0030 §1)", [input.metadata.name, e.name])
}

# --- built P1, run P2: the quarterly drill CronJob MUST render suspended so K8s
# never auto-fires it in P1 (ADR-0030 §5.2 / P1-PLAN.md §6). ---
deny contains msg if {
	is_neo4j_rebuild_drill(input)
	input.kind == "CronJob"
	input.spec.suspend != true
	msg := sprintf("neo4j rebuild drill CronJob %q must render `suspend: true` — built P1, executed quarterly in P2; it must not auto-fire (ADR-0030 §5.2 / P1-PLAN.md §6)", [input.metadata.name])
}

# --- the drill must be P2-execution flagged (the W5-T5 evidence layer knows
# execution is deferred — ADR-0030 §5.2). ---
deny contains msg if {
	is_neo4j_rebuild_drill(input)
	object.get(input.metadata.annotations, "netops.io/execution-phase", "") != "P2"
	msg := sprintf("neo4j rebuild drill %q must carry the `netops.io/execution-phase: P2` annotation (built P1, executed quarterly in P2; ADR-0030 §5.2)", [input.metadata.name])
}

# --- the drill must invoke the EXISTING full-rebuild + assertion harness
# (`topology_rebuild.run_drill`), which re-projects from Postgres and asserts the
# node/edge counts + topology-RTO. A wipe with no reproject/assert is not a
# rebuild-drill (ADR-0030 §5.2). Asserted on the rendered argv text. ---
deny contains msg if {
	is_neo4j_rebuild_drill(input)
	some c in neo4j_drill_pod_spec(input).containers
	not container_runs_neo4j_rebuild_harness(c)
	msg := sprintf("neo4j rebuild drill %q container %q must invoke the full-rebuild + assertion harness (`topology_rebuild.run_drill`) — a wipe with no reproject/count-assert is not a rebuild-drill (ADR-0030 §5.2)", [input.metadata.name, c.name])
}

container_runs_neo4j_rebuild_harness(c) if {
	some arg in array.concat(object.get(c, "command", []), object.get(c, "args", []))
	contains(arg, "topology_rebuild.run_drill")
}

# --- `neo4j-admin dump` fast-start is OPT-IN, OFF by default (ADR-0005 D5 — the
# projection is disposable; a stale dump could disagree with the authoritative
# Postgres). The rendered TOPOLOGY_DUMP_ENABLED env must NOT be "true" on the
# default render. (An operator opting in flips backup.drills.neo4j.dump.enabled and
# consciously accepts this single failure, regenerating the G-REL evidence.) ---
deny contains msg if {
	is_neo4j_rebuild_drill(input)
	some c in neo4j_drill_pod_spec(input).containers
	some e in object.get(c, "env", [])
	e.name == "TOPOLOGY_DUMP_ENABLED"
	lower(sprintf("%v", [e.value])) == "true"
	msg := sprintf("neo4j rebuild drill %q must keep the `neo4j-admin dump` fast-start OFF by default (TOPOLOGY_DUMP_ENABLED=true found) — the dump is opt-in only; the projection is disposable and a stale dump could disagree with Postgres (ADR-0005 D5 / ADR-0030 §2)", [input.metadata.name])
}

# --- the drill rebuilds into a CLEAN Neo4j from Postgres — it must mount NO
# persistentVolumeClaim (no restore onto a live data volume; the projection is
# re-derived, never restored). Parity with the throwaway-only restore drills. ---
deny contains msg if {
	is_neo4j_rebuild_drill(input)
	some v in object.get(neo4j_drill_pod_spec(input), "volumes", [])
	v.persistentVolumeClaim
	msg := sprintf("neo4j rebuild drill %q must mount NO persistentVolumeClaim — the graph is RE-PROJECTED from Postgres into a clean Neo4j, never restored onto a live data volume (ADR-0005 D5)", [input.metadata.name])
}

# --- the drill pod talks to Postgres + Neo4j, not the K8s API:
# automountServiceAccountToken=false (parity with the backup/drill pods, ADR-0029 §5). ---
deny contains msg if {
	is_neo4j_rebuild_drill(input)
	neo4j_drill_pod_spec(input).automountServiceAccountToken != false
	msg := sprintf("neo4j rebuild drill %q pod must set automountServiceAccountToken=false — it talks to Postgres + Neo4j, not the K8s API (ADR-0029 §5)", [input.metadata.name])
}

# --- per-container hardening on the drill (the drill JOB is a separate kind from
# the platform Deployment/StatefulSet rules; assert the SAME ADR-0029 §3 controls
# on its containers so a hardening regression fails the gate too): drop ALL caps,
# add none, non-root, RO-rootfs, no-privesc, RuntimeDefault seccomp, requests AND
# limits, no `latest` tag. ---
deny contains msg if {
	is_neo4j_rebuild_drill(input)
	some c in neo4j_drill_pod_spec(input).containers
	not drops_all(c)
	msg := sprintf("neo4j rebuild drill %q container %q must drop ALL capabilities (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_neo4j_rebuild_drill(input)
	some c in neo4j_drill_pod_spec(input).containers
	some cap in object.get(object.get(object.get(c, "securityContext", {}), "capabilities", {}), "add", [])
	msg := sprintf("neo4j rebuild drill %q container %q must add NO capabilities (found %q; ADR-0029 §3)", [input.metadata.name, c.name, cap])
}

deny contains msg if {
	is_neo4j_rebuild_drill(input)
	some c in neo4j_drill_pod_spec(input).containers
	c.securityContext.runAsNonRoot != true
	msg := sprintf("neo4j rebuild drill %q container %q must set runAsNonRoot=true (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_neo4j_rebuild_drill(input)
	some c in neo4j_drill_pod_spec(input).containers
	c.securityContext.readOnlyRootFilesystem != true
	msg := sprintf("neo4j rebuild drill %q container %q must set readOnlyRootFilesystem=true (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_neo4j_rebuild_drill(input)
	some c in neo4j_drill_pod_spec(input).containers
	c.securityContext.allowPrivilegeEscalation != false
	msg := sprintf("neo4j rebuild drill %q container %q must set allowPrivilegeEscalation=false (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_neo4j_rebuild_drill(input)
	some c in neo4j_drill_pod_spec(input).containers
	not neo4j_drill_container_seccomp_set(input, c)
	msg := sprintf("neo4j rebuild drill %q container %q must set a RuntimeDefault seccompProfile (ADR-0029 §3)", [input.metadata.name, c.name])
}

neo4j_drill_container_seccomp_set(obj, c) if {
	c.securityContext.seccompProfile.type == "RuntimeDefault"
}

neo4j_drill_container_seccomp_set(obj, _) if {
	neo4j_drill_pod_spec(obj).securityContext.seccompProfile.type == "RuntimeDefault"
}

deny contains msg if {
	is_neo4j_rebuild_drill(input)
	some c in neo4j_drill_pod_spec(input).containers
	not c.resources.requests
	msg := sprintf("neo4j rebuild drill %q container %q must declare resource requests (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_neo4j_rebuild_drill(input)
	some c in neo4j_drill_pod_spec(input).containers
	not c.resources.limits
	msg := sprintf("neo4j rebuild drill %q container %q must declare resource limits (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_neo4j_rebuild_drill(input)
	some c in neo4j_drill_pod_spec(input).containers
	endswith(c.image, ":latest")
	msg := sprintf("neo4j rebuild drill %q image %q must not use the `latest` tag (ADR-0029 §5)", [input.metadata.name, c.image])
}

# ===========================================================================
# W5-T5 — FULL-PLATFORM DR drill (ADR-0030 §5.3/§6; ADR-0005 D5; ADR-0011 §1/§2)
#
# The COMPOSING drill: it restores Postgres from object storage ALONE onto a
# CLEAN target (emptyDir scratch — no live PVC) and CHAINS the three per-tier
# drills end-to-end (Postgres assert -> Neo4j rebuild over the RESTORED Postgres
# -> pcap spot-restore), aggregating their `DRILL ...` lines. These rules assert,
# on the RENDERED manifests, the policy-surface invariants the spec's gate
# requires — the SAME shape as the per-tier drills, scoped to this drill's
# backup-type so they cannot mis-fire elsewhere:
#   - ALL credential envs (DB password, Neo4j auth, backup + pcap S3 keys, repo
#     cipher pass, KEK reference) are EXTERNAL-SECRET refs (no inline `value:`);
#   - the suspended semiannual CronJob renders `suspend: true` (built P1, run P2);
#   - the drill is P2-execution flagged (`netops.io/execution-phase: P2`);
#   - the drill restores to a THROWAWAY emptyDir scratch, never a live PVC — the
#     from-backups-alone / clean-cluster guarantee (ADR-0030 §5.3);
#   - the drill actually RUNS the pgbackrest restore AND invokes the orchestrator
#     (`full_platform.run_drill`) — a restore with no chained assertions, or a
#     chain with no object-store restore, is not the G-REL drill;
#   - the drill pod is hardened identically to every backup/drill pod.
# Both objects carry the `backup` component label AND a
# `netops.io/backup-type: full-platform-drill` label; match on the latter to scope
# these rules (the W5-T1 full|incr cadence rules + the W5-T2/T3/T4 per-tier rules
# all scope to OTHER backup-types, so none mis-fire on this composing drill).
# ===========================================================================

# A rendered full-platform DR-drill object (Job OR suspended semiannual CronJob).
is_full_platform_drill(obj) if {
	obj.metadata.labels["netops.io/backup-type"] == "full-platform-drill"
}

# The drill pod spec, normalized across Job and CronJob.
fp_drill_pod_spec(obj) := obj.spec.template.spec if {
	obj.kind == "Job"
}

fp_drill_pod_spec(obj) := obj.spec.jobTemplate.spec.template.spec if {
	obj.kind == "CronJob"
}

# --- secret-surface: any drill env whose NAME signals a credential MUST come from
# a secretKeyRef and carry NO inline `value:` literal. This is the SECRET-SURFACE-
# bearing tier of the wave (it composes ALL three tiers' credentials), so the
# external-secret indirection is asserted strictly (ADR-0030 §1 / ADR-0029 §6). ---
fp_credential_env(name) if {
	endswith(name, "CIPHER_PASS")
}

fp_credential_env(name) if {
	endswith(name, "S3_KEY")
}

fp_credential_env(name) if {
	endswith(name, "S3_KEY_SECRET")
}

fp_credential_env(name) if {
	name == "PGPASSWORD"
}

fp_credential_env(name) if {
	endswith(name, "POSTGRES_PASSWORD")
}

fp_credential_env(name) if {
	endswith(name, "NEO4J_AUTH")
}

fp_credential_env(name) if {
	endswith(name, "KEK_REF")
}

deny contains msg if {
	is_full_platform_drill(input)
	some c in fp_drill_pod_spec(input).containers
	some e in object.get(c, "env", [])
	fp_credential_env(e.name)
	object.get(e, "value", null) != null
	msg := sprintf("full-platform DR drill %q env %q must NOT carry an inline `value:` literal — all credentials (DB password, Neo4j auth, backup + pcap S3 keys, repo cipher pass, KEK reference) are external-secret refs only (ADR-0030 §1 / ADR-0029 §6)", [input.metadata.name, e.name])
}

deny contains msg if {
	is_full_platform_drill(input)
	some c in fp_drill_pod_spec(input).containers
	some e in object.get(c, "env", [])
	fp_credential_env(e.name)
	not e.valueFrom.secretKeyRef
	msg := sprintf("full-platform DR drill %q env %q must be sourced from valueFrom.secretKeyRef (credentials are by-reference only; ADR-0030 §1 / ADR-0011 §4)", [input.metadata.name, e.name])
}

# --- built P1, run P2: the semiannual drill CronJob MUST render suspended so K8s
# never auto-fires it in P1 (ADR-0030 §5.3 / P1-PLAN.md §6). ---
deny contains msg if {
	is_full_platform_drill(input)
	input.kind == "CronJob"
	input.spec.suspend != true
	msg := sprintf("full-platform DR drill CronJob %q must render `suspend: true` — the drill is BUILT in P1 and EXECUTED >= twice yearly in P2; it must not auto-fire (ADR-0030 §5.3 / PRODUCTION.md §8)", [input.metadata.name])
}

# --- the drill must be P2-execution flagged so the W5-T5 evidence layer knows
# execution is deferred (ADR-0030 §5.3 — built P1, run P2). ---
deny contains msg if {
	is_full_platform_drill(input)
	object.get(input.metadata.annotations, "netops.io/execution-phase", "") != "P2"
	msg := sprintf("full-platform DR drill %q must carry the `netops.io/execution-phase: P2` annotation (built P1, executed >= twice yearly in P2; ADR-0030 §5.3)", [input.metadata.name])
}

# --- THROWAWAY / clean-cluster: the restore data dir must NOT be the live PGDATA
# path, and the restore volume must be an emptyDir scratch (the from-backups-alone
# guarantee — ADR-0030 §5.3). The live PGDATA path is `/var/lib/postgresql/data`. ---
deny contains msg if {
	is_full_platform_drill(input)
	some c in fp_drill_pod_spec(input).containers
	some e in object.get(c, "env", [])
	e.name == "DRILL_RESTORE_PATH"
	startswith(e.value, "/var/lib/postgresql/data")
	msg := sprintf("full-platform DR drill %q restore path %q must be a THROWAWAY scratch dir, NOT the live PGDATA path — DR must restore onto a CLEAN target, never production data (ADR-0030 §5.3)", [input.metadata.name, e.value])
}

deny contains msg if {
	is_full_platform_drill(input)
	some v in object.get(fp_drill_pod_spec(input), "volumes", [])
	v.name == "drill-restore"
	not v.emptyDir
	msg := sprintf("full-platform DR drill %q `drill-restore` volume must be an emptyDir scratch (throwaway), never a PVC — the clean-cluster property (ADR-0030 §5.3)", [input.metadata.name])
}

# --- the drill must mount NO persistentVolumeClaim at all — it restores from
# object storage ALONE into scratch; leaning on a live PVC would break the
# from-backups-alone / clean-cluster guarantee (ADR-0030 §5.3). ---
deny contains msg if {
	is_full_platform_drill(input)
	some v in object.get(fp_drill_pod_spec(input), "volumes", [])
	v.persistentVolumeClaim
	msg := sprintf("full-platform DR drill %q must mount NO persistentVolumeClaim — it restores from object storage ALONE onto a clean target (ADR-0030 §5.3)", [input.metadata.name])
}

# --- the drill must actually RESTORE from the object-store repo (`pgbackrest
# restore`) — a chain with no object-store restore is not the from-backups-alone
# drill (ADR-0030 §5.3). Asserted on the rendered argv text. ---
deny contains msg if {
	is_full_platform_drill(input)
	some c in fp_drill_pod_spec(input).containers
	not fp_container_runs_restore(c)
	msg := sprintf("full-platform DR drill %q container %q must run `pgbackrest restore` from the object-store repo — DR from backups ALONE requires the restore step (ADR-0030 §5.3)", [input.metadata.name, c.name])
}

fp_container_runs_restore(c) if {
	some arg in array.concat(object.get(c, "command", []), object.get(c, "args", []))
	contains(arg, "pgbackrest")
	contains(arg, "restore")
}

# --- the drill must invoke the orchestrator (`full_platform.run_drill`), which
# chains the three per-tier harnesses and aggregates their DRILL lines — a restore
# with no chained assertions is not a drill (ADR-0030 §5.3). ---
deny contains msg if {
	is_full_platform_drill(input)
	some c in fp_drill_pod_spec(input).containers
	not fp_container_runs_orchestrator(c)
	msg := sprintf("full-platform DR drill %q container %q must invoke the orchestrator (`full_platform.run_drill`) that chains + aggregates the three tiers — a restore with no chained assertions is not a drill (ADR-0030 §5.3)", [input.metadata.name, c.name])
}

fp_container_runs_orchestrator(c) if {
	some arg in array.concat(object.get(c, "command", []), object.get(c, "args", []))
	contains(arg, "full_platform.run_drill")
}

# --- the drill pod talks to Postgres + Neo4j + the object stores, not the K8s
# API: automountServiceAccountToken=false (parity with the backup/drill pods). ---
deny contains msg if {
	is_full_platform_drill(input)
	fp_drill_pod_spec(input).automountServiceAccountToken != false
	msg := sprintf("full-platform DR drill %q pod must set automountServiceAccountToken=false — it talks to the data stores + object storage, not the K8s API (ADR-0029 §5)", [input.metadata.name])
}

# --- per-container hardening on the drill (the drill JOB/CronJob nest containers
# under their own paths; assert the SAME ADR-0029 §3 controls here so a hardening
# regression fails the gate too): drop ALL caps, add none, non-root, RO-rootfs,
# no-privesc, RuntimeDefault seccomp, requests AND limits, no `latest` tag. ---
deny contains msg if {
	is_full_platform_drill(input)
	some c in fp_drill_pod_spec(input).containers
	not drops_all(c)
	msg := sprintf("full-platform DR drill %q container %q must drop ALL capabilities (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_full_platform_drill(input)
	some c in fp_drill_pod_spec(input).containers
	some cap in object.get(object.get(object.get(c, "securityContext", {}), "capabilities", {}), "add", [])
	msg := sprintf("full-platform DR drill %q container %q must add NO capabilities (found %q; ADR-0029 §3)", [input.metadata.name, c.name, cap])
}

deny contains msg if {
	is_full_platform_drill(input)
	some c in fp_drill_pod_spec(input).containers
	c.securityContext.runAsNonRoot != true
	msg := sprintf("full-platform DR drill %q container %q must set runAsNonRoot=true (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_full_platform_drill(input)
	some c in fp_drill_pod_spec(input).containers
	c.securityContext.readOnlyRootFilesystem != true
	msg := sprintf("full-platform DR drill %q container %q must set readOnlyRootFilesystem=true (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_full_platform_drill(input)
	some c in fp_drill_pod_spec(input).containers
	c.securityContext.allowPrivilegeEscalation != false
	msg := sprintf("full-platform DR drill %q container %q must set allowPrivilegeEscalation=false (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_full_platform_drill(input)
	some c in fp_drill_pod_spec(input).containers
	not fp_drill_container_seccomp_set(input, c)
	msg := sprintf("full-platform DR drill %q container %q must set a RuntimeDefault seccompProfile (ADR-0029 §3)", [input.metadata.name, c.name])
}

fp_drill_container_seccomp_set(obj, c) if {
	c.securityContext.seccompProfile.type == "RuntimeDefault"
}

fp_drill_container_seccomp_set(obj, _) if {
	fp_drill_pod_spec(obj).securityContext.seccompProfile.type == "RuntimeDefault"
}

deny contains msg if {
	is_full_platform_drill(input)
	some c in fp_drill_pod_spec(input).containers
	not c.resources.requests
	msg := sprintf("full-platform DR drill %q container %q must declare resource requests (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_full_platform_drill(input)
	some c in fp_drill_pod_spec(input).containers
	not c.resources.limits
	msg := sprintf("full-platform DR drill %q container %q must declare resource limits (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_full_platform_drill(input)
	some c in fp_drill_pod_spec(input).containers
	endswith(c.image, ":latest")
	msg := sprintf("full-platform DR drill %q image %q must not use the `latest` tag (ADR-0029 §5)", [input.metadata.name, c.image])
}

# ===========================================================================
# W4-T4 — api/worker↔postgres mTLS (ADR-0039 §3/§4/§5)
#
# Mutual TLS on the two DB links: Postgres presents a SERVER cert and REQUIRES +
# verifies the api/worker CLIENT certs (`hostssl … clientcert=verify-full`),
# REFUSING plaintext / untrusted-CA; the clients verify the server (verify-full)
# and present their cert. These rules assert, on the RENDERED manifests, that the
# control is wired AND not silently weakened. They only fire when the mTLS
# objects are present (mtls.postgres.enabled), so a default (mTLS-off) render is
# unaffected — the chart's existing posture is unchanged. NEVER weaken a rule to
# make it green; fix the manifest.
# ===========================================================================

# --- The Postgres pg_hba ConfigMap (postgres-tls-config) is the REFUSAL bite ---

is_postgres_tls_configmap(obj) if {
	obj.kind == "ConfigMap"
	endswith(obj.metadata.name, "-postgres-tls-config")
}

# The hba MUST carry a `hostssl … scram-sha-256 clientcert=verify-full` rule — TLS
# + the scram password layer + a verified client cert ALL REQUIRED. Its absence
# means the server does not require mutual TLS.
# M3 (PR#76): the auth METHOD must be `scram-sha-256` EXPLICITLY — the prior regex
# accepted ANY method before clientcert=verify-full, so `trust clientcert=verify-full`
# (which drops the password factor) would pass. Pin scram-sha-256 in the match so a
# weakened method fails the policy (mirrors the M2 template hardcode).
#
# R2 #26/#27 (PR#76 round 2): pg_hba is FIRST-MATCH-WINS. Proving a strict row
# merely EXISTS is insufficient — a WEAKER hostssl row placed ABOVE it (missing
# scram, missing clientcert, a different method) silently downgrades auth for the
# clients it matches first, yet the strict row still "exists" so the old rule
# passed (a false-green). We therefore assert BOTH polarities:
#   (a) at least one STRICT hostssl row exists (the control is wired), AND
#   (b) EVERY hostssl row is the strict form (no weaker row can win a match).
# `strict_hostssl_re` is deliberately TOLERANT of valid whitespace/column variation
# and optional trailing pg_hba options after clientcert=verify-full, so it does NOT
# false-reject EQUIVALENT secure rows (R2 #29 reconciliation).

# A `hostssl` row in the strict form: scram-sha-256 + clientcert=verify-full, with
# any benign inter-column whitespace and an OPTIONAL trailing option list. `$`
# anchors the END so `… verify-full-but-weaker` cannot sneak through (it must be
# end-of-line or a whitespace-separated option).
# R3 #12 (PR#76 round 3): tolerate leading whitespace (`^[ \t]*`) so an INDENTED
# but otherwise-strict hostssl row is NOT false-rejected as non-strict — pg_hba
# ignores leading whitespace, so an indented strict row is still strict.
strict_hostssl_re := `(?m)^[ \t]*hostssl\s+\S+\s+\S+\s+\S+\s+scram-sha-256\s+clientcert=verify-full(\s.*)?$`

# Any line that is a `hostssl` rule at all (used to enumerate rows to vet).
# R3 #11 (PR#76 round 3): tolerate leading whitespace (`^[ \t]*`) so an INDENTED
# weak hostssl row is still SEEN as a hostssl row and subjected to the per-row
# strictness check — otherwise a whitespace-prefixed downgraded auth rule bypasses
# the check (pg_hba ignores leading whitespace, so the indented row is live).
hostssl_line(line) if {
	regex.match(`^[ \t]*hostssl\s`, line)
}

# (a) at least one STRICT hostssl row exists — the mTLS refusal control is wired.
deny contains msg if {
	is_postgres_tls_configmap(input)
	hba := object.get(input.data, "pg_hba.conf", "")
	not regex.match(strict_hostssl_re, hba)
	msg := "postgres pg_hba.conf must carry a `hostssl … scram-sha-256 clientcert=verify-full` rule — TLS + the scram-sha-256 password layer + a verified client cert are ALL required (a weaker method like `trust` is denied) (ADR-0039 §3, M3/PR#76)"
}

# (b) EVERY hostssl row must be the strict form. pg_hba is first-match-wins, so a
# single weaker hostssl row (e.g. `trust clientcert=verify-full`, a missing
# clientcert, or a different method) placed ANYWHERE weakens auth for the clients
# it matches first — DENY if any hostssl row is not the strict form (R2 #26/#27).
deny contains msg if {
	is_postgres_tls_configmap(input)
	hba := object.get(input.data, "pg_hba.conf", "")
	some line in split(hba, "\n")
	hostssl_line(line)
	not regex.match(strict_hostssl_re, line)
	msg := sprintf("postgres pg_hba.conf hostssl row %q is NOT the strict form — pg_hba is first-match-wins, so a weaker hostssl row (missing scram-sha-256, missing clientcert=verify-full, or a different method) downgrades auth for the clients it matches first. EVERY hostssl row must be `hostssl <db> <user> <addr> scram-sha-256 clientcert=verify-full` (ADR-0039 §3, R2 #26/#27/PR#76)", [trim_space(line)])
}

# The hba MUST NOT carry a plaintext TCP line (`host …` / `hostnossl …`). Such a
# line would admit a non-TLS connection — exactly the plaintext path ADR-0039 §3
# refuses. Only `local` (unix socket) and `hostssl` lines are permitted.
deny contains msg if {
	is_postgres_tls_configmap(input)
	hba := object.get(input.data, "pg_hba.conf", "")
	# Intent (round-4 #05): deny the two PLAINTEXT-capable TCP connection types —
	# `host` (matches SSL *and* non-SSL, so it admits plaintext) and `hostnossl`
	# (explicitly non-TLS). `hostssl` (TLS-required) is the ONLY permitted TCP form
	# and is deliberately NOT matched here. This is NOT "deny any non-hostssl line":
	# `hostgssenc` (GSSAPI-encrypted) is a separate transport concern, out of scope of
	# this TLS-link rule (handle elsewhere if GSS is ever in scope). RE2 has no
	# negative lookahead, so the two plaintext types are matched by explicit
	# alternation. `^[ \t]*` tolerates leading whitespace — pg_hba ignores it, so an
	# indented `host`/`hostnossl` row is still a live non-TLS listener path (R3 #12).
	regex.match(`(?m)^[ \t]*(host|hostnossl)\s`, hba)
	msg := "postgres pg_hba.conf must NOT carry a plaintext `host` or non-TLS `hostnossl` line — a non-TLS listener path defeats the mTLS refusal; only `hostssl` (and `local`) are permitted (ADR-0039 §3, round-4 #05)"
}

# --- The Postgres StatefulSet must turn ssl on + point hba_file at the mounted
# pg_hba (so the refusal rule above is the file actually used) when mTLS material
# is mounted (the `db-tls-server` volume is the marker). ---

postgres_statefulset_has_db_tls(obj) if {
	obj.kind == "StatefulSet"
	obj.metadata.labels["app.kubernetes.io/component"] == "postgres"
	some v in obj.spec.template.spec.volumes
	v.name == "db-tls-server"
}

postgres_container_args(obj) := obj.spec.template.spec.containers[0].args

deny contains msg if {
	postgres_statefulset_has_db_tls(input)
	not "ssl=on" in postgres_container_args(input)
	msg := "postgres with mTLS material mounted must set `-c ssl=on` (ADR-0039 §3)"
}

deny contains msg if {
	postgres_statefulset_has_db_tls(input)
	not postgres_args_set_hba_file(input)
	msg := "postgres with mTLS material mounted must set `-c hba_file=` to the mounted pg_hba.conf so the clientcert=verify-full rule is the file in effect (ADR-0039 §3)"
}

postgres_args_set_hba_file(obj) if {
	some a in postgres_container_args(obj)
	startswith(a, "hba_file=")
}

# The server cert/key + the CA the server verifies CLIENT certs against must all
# be configured — a missing ssl_ca_file would mean the server cannot verify
# client certs (clientcert would have no trust anchor).
deny contains msg if {
	postgres_statefulset_has_db_tls(input)
	not postgres_args_have_prefix(input, "ssl_cert_file=")
	msg := "postgres mTLS must set `-c ssl_cert_file=` (the server cert; ADR-0039 §3)"
}

deny contains msg if {
	postgres_statefulset_has_db_tls(input)
	not postgres_args_have_prefix(input, "ssl_key_file=")
	msg := "postgres mTLS must set `-c ssl_key_file=` (the server key; ADR-0039 §3)"
}

deny contains msg if {
	postgres_statefulset_has_db_tls(input)
	not postgres_args_have_prefix(input, "ssl_ca_file=")
	msg := "postgres mTLS must set `-c ssl_ca_file=` (the CA it verifies client certs against; ADR-0039 §3)"
}

postgres_args_have_prefix(obj, prefix) if {
	some a in postgres_container_args(obj)
	startswith(a, prefix)
}

# The server cert/key volume must be mounted READ-ONLY (cert keys are mounted
# files, never writable in-pod; ADR-0039 §5).
# M8 (PR#76): `m.readOnly != true` is UNDEFINED (not true) when the field is
# ABSENT, so a mount that simply OMITS readOnly would slip past. object.get with a
# `false` default makes a missing field deterministic — an omitted readOnly is
# treated as NOT read-only and the deny fires.
deny contains msg if {
	postgres_statefulset_has_db_tls(input)
	some c in input.spec.template.spec.containers
	some m in c.volumeMounts
	m.name == "db-tls-server"
	object.get(m, "readOnly", false) != true
	msg := "postgres db-tls-server cert mount must be readOnly:true (ADR-0039 §5)"
}

# --- The api/worker CLIENT side must connect verify-full (mutual). The mTLS MARKER
# is the db-tls-client cert MOUNT (M9, PR#76): a Deployment that mounts the client
# cert material is doing mTLS and MUST carry NETOPS_DB_SSL_MODE=verify-full with a
# LITERAL value. Keying the requirement on the MOUNT (not on the env existing) closes
# the M9 gap where a Deployment mounted db-tls-client WITHOUT the env passed policy. ---

mtls_client_components := {"api", "worker"}

# The NETOPS_DB_SSL_MODE env entry (the object), present whether it carries a literal
# `value` OR a `valueFrom`. Used to test PRESENCE independent of the value source.
client_db_ssl_mode_entry(obj) := e if {
	some c in obj.spec.template.spec.containers
	some e in object.get(c, "env", [])
	e.name == "NETOPS_DB_SSL_MODE"
}

# True iff the workload sets NETOPS_DB_SSL_MODE as a LITERAL `value` of exactly
# "verify-full". M10 (PR#76): keyed on the literal `value` ONLY — a `valueFrom`
# (configMap/secret) indirection carries no `value`, so it does NOT satisfy this and
# cannot smuggle a weaker/absent mode past the verify-full requirement.
deployment_sets_verify_full_literal(obj) if {
	e := client_db_ssl_mode_entry(obj)
	object.get(e, "value", "") == "verify-full"
}

# A db-tls-client Deployment that does NOT set the literal verify-full mode is denied.
# Covers: missing env (M9), wrong mode, and a valueFrom-only env (M10 — no literal).
deny contains msg if {
	input.kind == "Deployment"
	mtls_client_components[input.metadata.labels["app.kubernetes.io/component"]]
	deployment_mounts_client_tls(input)
	not deployment_sets_verify_full_literal(input)
	msg := sprintf("%s mounts the db-tls-client cert material but does not set NETOPS_DB_SSL_MODE to a LITERAL \"verify-full\" — mutual TLS requires server identity verified + client cert presented, and a missing/valueFrom/weaker mode is denied (ADR-0039 §4, M9+M10/PR#76)", [input.metadata.labels["app.kubernetes.io/component"]])
}

# Symmetric guard: an api/worker that sets the mTLS client env MUST also mount the
# client cert material read-only — env without the mounted cert files cannot handshake.
deny contains msg if {
	input.kind == "Deployment"
	mtls_client_components[input.metadata.labels["app.kubernetes.io/component"]]
	client_db_ssl_mode_entry(input)
	not deployment_mounts_client_tls(input)
	msg := sprintf("%s sets NETOPS_DB_SSL_MODE but does not mount the db-tls-client cert material read-only (ADR-0039 §4/§5)", [input.metadata.labels["app.kubernetes.io/component"]])
}

deployment_mounts_client_tls(obj) if {
	some c in obj.spec.template.spec.containers
	some m in c.volumeMounts
	m.name == "db-tls-client"
	object.get(m, "readOnly", false) == true
}

# --- The dev/CI fallback TLS Secrets must be marked dev-convenience (so the
# existing "chart ships no unmarked credential Secret" rule does not fire) AND
# carry cert material under `data:` only (PEM bytes), NEVER an inlined literal in
# stringData. They are exempt from the platform-secret literal check by the
# dev-secret annotation; this rule asserts they actually carry that marker. ---
is_db_tls_secret(obj) if {
	obj.kind == "Secret"
	obj.metadata.labels["app.kubernetes.io/component"] == "mtls"
}

deny contains msg if {
	is_db_tls_secret(input)
	not is_dev_convenience_secret(input)
	msg := sprintf("db mTLS dev-fallback Secret %q must be annotated netops.io/dev-secret=true (cert-manager owns the production material; ADR-0039 §5)", [input.metadata.name])
}

# Cert material must never be inlined under stringData (it belongs under `data:`
# as base64 PEM, like the pgBackRest TLS precedent) — a stringData cert key is a
# plaintext-in-history regression.
deny contains msg if {
	is_db_tls_secret(input)
	some k, _ in object.get(input, "stringData", {})
	msg := sprintf("db mTLS Secret %q must carry cert material under `data:` (base64 PEM), not stringData key %q (ADR-0039 §5)", [input.metadata.name, k])
}

# ===========================================================================
# W1-T1 — CloudNativePG HA data tier (ADR-0042). The CNPG `Cluster` + PgBouncer
# `Pooler` + PriorityClass are CRDs; conftest still feeds each rendered document
# as `input`, so these rules assert the ADR-0042 contract SHAPE directly on the
# rendered manifests (helm template … | conftest test). They run ONLY when the
# opt-in tier is enabled (the manifests are absent on the default render, so the
# rules are vacuously satisfied then). NEVER weaken a rule to make it green — the
# manifest must satisfy the contract.
#
# What is asserted here vs elsewhere:
#   - sync-QUORUM shape (ANY 1, audit-path scoping) ........... here (render)
#   - PgBouncer transaction mode + connection budget ......... here (render)
#   - 1+2 instances, non-root, pgvector, PriorityClass ....... here (render)
#   - the per-transaction `SET LOCAL synchronous_commit` ..... W1-T2 (real PG)
#   - the live zero-audit-loss failover drill ................ W4-T3 (kind)
# ===========================================================================

is_cnpg_cluster(obj) if {
	obj.apiVersion == "postgresql.cnpg.io/v1"
	obj.kind == "Cluster"
}

is_cnpg_pooler(obj) if {
	obj.apiVersion == "postgresql.cnpg.io/v1"
	obj.kind == "Pooler"
}

# --- 1 primary + 2 streaming replicas (ADR-0042 §1). Exactly 3 instances: fewer
# than 3 cannot form the ANY-1-over-2 quorum nor CNPG failover quorum. ---
deny contains msg if {
	is_cnpg_cluster(input)
	input.spec.instances != 3
	msg := sprintf("CNPG Cluster %q must run exactly 3 instances (1 primary + 2 streaming replicas), got %v — ANY 1 quorum + failover quorum need 3 (ADR-0042 §1)", [input.metadata.name, input.spec.instances])
}

# --- QUORUM synchronous replication present (ADR-0042 §2). The cluster MUST
# declare a `synchronous` stanza so CNPG generates `synchronous_standby_names` —
# its ABSENCE means async-everywhere, the exact failure G-REL §316 forbids. ---
deny contains msg if {
	is_cnpg_cluster(input)
	not input.spec.postgresql.synchronous
	msg := sprintf("CNPG Cluster %q must declare spec.postgresql.synchronous (quorum sync for the audit write path) — its absence is async-everywhere, losing a committed audit row on a primary kill (ADR-0042 §2 / G-REL §316)", [input.metadata.name])
}

# --- the quorum method MUST be `any` (= `ANY q (...)`), NOT `first` (priority-
# based, which would require specific standbys and stall on one replica loss). ---
deny contains msg if {
	is_cnpg_cluster(input)
	input.spec.postgresql.synchronous.method != "any"
	msg := sprintf("CNPG Cluster %q synchronous.method must be `any` (ANY-q quorum, tolerates one replica loss), got %q — `first` turns a single replica outage into an audit-write stall (ADR-0042 §2 / Alt #4)", [input.metadata.name, input.spec.postgresql.synchronous.method])
}

# --- the quorum number MUST be 1 (= `ANY 1`): acknowledge once >=1 replica holds
# the WAL. `ANY 2`/higher converts a single replica loss into an audit-write
# outage (ADR-0042 §2 availability trade-off / Alt #4 rejected). ---
deny contains msg if {
	is_cnpg_cluster(input)
	input.spec.postgresql.synchronous.number != 1
	msg := sprintf("CNPG Cluster %q synchronous.number must be 1 (ANY 1 — one healthy replica suffices), got %v — requiring >1 standby stalls audit commits on a single replica loss (ADR-0042 §2 / Alt #4)", [input.metadata.name, input.spec.postgresql.synchronous.number])
}

# --- audit-path scoping REQUIRES an EXPLICIT async cluster default for
# `synchronous_commit` (ADR-0042 §2 / Alt #3). Once the `synchronous` stanza is
# present, CNPG populates `synchronous_standby_names`, so a transaction waits for
# the quorum iff ITS synchronous_commit resolves to on/remote_write/remote_apply.
# PostgreSQL's built-in default is `on`, and CNPG leaves an UNSET parameter at
# that default — so omitting synchronous_commit (or setting it to a forced value)
# forces the quorum round-trip onto EVERY discovery/config/telemetry write: the
# throughput collapse Alt #3 rejects. Scoping holds ONLY when the cluster DEFAULT
# is lowered to `local`/`off` (so non-audit writes ack locally) and W1-T2's per-
# txn `SET LOCAL synchronous_commit=remote_apply` raises it back for audit txns.
# The gate therefore demands the explicit async default; it does NOT accept the
# implicit PG default. (`forced_sync_commit_values` is retained for the explicit-
# forced message path so operators get the precise over-scoping diagnostic.) ---
async_sync_commit_values := {"local", "off"}

forced_sync_commit_values := {"on", "remote_apply", "remote_write"}

# DENY the explicit forced cluster default — the precise over-scoping diagnostic.
deny contains msg if {
	is_cnpg_cluster(input)
	sc := object.get(object.get(object.get(input.spec, "postgresql", {}), "parameters", {}), "synchronous_commit", "")
	forced_sync_commit_values[sc]
	msg := sprintf("CNPG Cluster %q must NOT set synchronous_commit=%q cluster-wide — that forces sync on ALL writes (throughput collapse); sync is scoped per-transaction to the audit path via W1-T2 `SET LOCAL` (ADR-0042 §2 / Alt #3)", [input.metadata.name, sc])
}

# DENY when the quorum `synchronous` stanza is configured but the cluster default
# `synchronous_commit` is NOT an explicit async value (`local`/`off`). This bites
# the IMPLICIT over-scoping: an unset synchronous_commit inherits the PG default
# `on`, forcing the quorum round-trip onto every write while the chart claims
# audit-path scoping. Audit-path scoping is real ONLY with an explicit async
# default + W1-T2's per-txn `SET LOCAL` (ADR-0042 §2 / Alt #3). ---
deny contains msg if {
	is_cnpg_cluster(input)
	input.spec.postgresql.synchronous
	sc := object.get(object.get(object.get(input.spec, "postgresql", {}), "parameters", {}), "synchronous_commit", "")
	not async_sync_commit_values[sc]
	not forced_sync_commit_values[sc]
	msg := sprintf("CNPG Cluster %q declares quorum `synchronous` but does NOT set an explicit async cluster default synchronous_commit (`local`/`off`) in spec.postgresql.parameters — an unset value inherits the PG default `on`, forcing the quorum round-trip onto EVERY write (throughput collapse). Set synchronous_commit=local so non-audit writes ack locally; W1-T2's per-txn `SET LOCAL synchronous_commit=remote_apply` scopes sync to the audit path (ADR-0042 §2 / Alt #3)", [input.metadata.name])
}

# --- failoverQuorum ON (ADR-0042 §2): a promoted replica is checked to hold the
# quorum-acked WAL before serving writes — the data-safety guarantee W4-T3 asserts. ---
deny contains msg if {
	is_cnpg_cluster(input)
	input.spec.postgresql.synchronous.failoverQuorum != true
	msg := sprintf("CNPG Cluster %q synchronous.failoverQuorum must be true — a promotion must verify the new primary holds every quorum-acked audit row (ADR-0042 §2, the W4-T3 zero-loss guarantee)", [input.metadata.name])
}

# --- pgvector present on the cluster (ADR-0042 §5). The post-init SQL must
# `CREATE EXTENSION … vector` so every instance (replicas inherit) carries it —
# a streaming replica that lacks pgvector breaks RAG reads routed to it. ---
cluster_creates_vector(c) if {
	some stmt in object.get(object.get(object.get(c.spec, "bootstrap", {}), "initdb", {}), "postInitSQL", [])
	# Require the actual CREATE EXTENSION … vector shape, not merely the words
	# "extension" + "vector" — `DROP EXTENSION vector` or a comment must NOT satisfy
	# this. `(?i)` = case-insensitive; allow an optional `IF NOT EXISTS` and an
	# optional quote around the extension name (ADR-0042 §5).
	regex.match(`(?i)\bcreate\s+extension\s+(if\s+not\s+exists\s+)?"?vector"?`, stmt)
}

deny contains msg if {
	is_cnpg_cluster(input)
	not cluster_creates_vector(input)
	msg := sprintf("CNPG Cluster %q must install pgvector via bootstrap.initdb.postInitSQL (`CREATE EXTENSION … vector`) so replicas inherit it — a replica without pgvector breaks RAG reads routed to it (ADR-0042 §5)", [input.metadata.name])
}

# --- pgvector image, never `latest`/tagless (ADR-0029 §5 parity for the operand
# image the Cluster pins). ---
deny contains msg if {
	is_cnpg_cluster(input)
	img := object.get(input.spec, "imageName", "")
	endswith(img, ":latest")
	msg := sprintf("CNPG Cluster %q imageName must not use the `latest` tag (ADR-0029 §5)", [input.metadata.name])
}

# A reference is PINNED iff it carries an explicit tag in the image-NAME segment
# (a `:` AFTER the last `/`, so a registry host:port does NOT count) OR an
# `@sha256:` digest. `registry.internal:5000/cloudnative-pg/postgresql` is tagless
# even though it contains a `:` (the host port) — it must NOT pass. ---
cnpg_image_pinned(img) if {
	contains(img, "@sha256:")
}

cnpg_image_pinned(img) if {
	# The image-name segment is everything after the last `/`; a `:` there is a tag.
	parts := split(img, "/")
	contains(parts[count(parts) - 1], ":")
}

deny contains msg if {
	is_cnpg_cluster(input)
	img := object.get(input.spec, "imageName", "")
	img != ""
	not cnpg_image_pinned(img)
	msg := sprintf("CNPG Cluster %q imageName %q must carry an explicit tag or digest in the image name (a registry host:port is NOT a tag) (ADR-0029 §5)", [input.metadata.name, img])
}

# --- secure-by-default: the cluster MUST run non-root. CNPG defaults to non-root,
# but ADR-0042 §4 requires it be EXPLICIT in the chart so a future edit cannot
# silently relax it (postgresql.runAsNonRoot must not be false). ---
deny contains msg if {
	is_cnpg_cluster(input)
	# Fail closed: deny unless postgresql.runAsNonRoot is EXPLICITLY `true`. A missing
	# field (default null) or any non-true value is rejected so omission cannot
	# silently relax the control (ADR-0042 §4 "must be EXPLICIT").
	object.get(object.get(input.spec, "postgresql", {}), "runAsNonRoot", null) != true
	msg := sprintf("CNPG Cluster %q must run non-root (postgresql.runAsNonRoot must be explicitly true) (ADR-0042 §4 / ADR-0029 §3)", [input.metadata.name])
}

# --- resource requests AND limits present on the Cluster (never absent, ADR-0029 §3). ---
deny contains msg if {
	is_cnpg_cluster(input)
	not input.spec.resources.requests
	msg := sprintf("CNPG Cluster %q must declare resource requests (ADR-0029 §3 — never absent)", [input.metadata.name])
}

deny contains msg if {
	is_cnpg_cluster(input)
	not input.spec.resources.limits
	msg := sprintf("CNPG Cluster %q must declare resource limits (ADR-0029 §3 — never absent)", [input.metadata.name])
}

# --- PriorityClass so Postgres outranks batch workers (ADR-0042 scope/§1). The
# Cluster MUST reference a non-empty priorityClassName. ---
deny contains msg if {
	is_cnpg_cluster(input)
	object.get(input.spec, "priorityClassName", "") == ""
	msg := sprintf("CNPG Cluster %q must set priorityClassName so Postgres outranks the unpriorited batch workers under node pressure (ADR-0042 §1)", [input.metadata.name])
}

# --- credentials by-reference: the Cluster must NOT inline a superuser password.
# CNPG references credentials via superuserSecret/bootstrap secret NAMES, never
# literal values — a literal here is a secret-in-manifest regression (ADR-0042 §1). ---
deny contains msg if {
	is_cnpg_cluster(input)
	object.get(object.get(input.spec, "superuserSecret", {}), "password", "") != ""
	msg := sprintf("CNPG Cluster %q must reference the superuser credential by Secret NAME, never inline a password (ADR-0042 §1 / ADR-0029 §6)", [input.metadata.name])
}

# ---------------------------------------------------------------------------
# PgBouncer Pooler — transaction mode + connection budget (ADR-0042 §4)
# ---------------------------------------------------------------------------

# --- transaction mode is MANDATORY (ADR-0042 §4): it is the connection-budget
# rationale AND the only mode under which the audit `SET LOCAL` (W1-T2) is
# correct. `session`/`statement` are REFUSED. ---
deny contains msg if {
	is_cnpg_pooler(input)
	object.get(object.get(input.spec, "pgbouncer", {}), "poolMode", "") != "transaction"
	msg := sprintf("CNPG Pooler %q must use poolMode `transaction` (the connection-budget + audit `SET LOCAL` correctness depend on it), got %q (ADR-0042 §4)", [input.metadata.name, object.get(object.get(input.spec, "pgbouncer", {}), "poolMode", "")])
}

# --- connection budget present (ADR-0042 §4 / G-SCA §330): the Pooler MUST set a
# bounded default_pool_size — an unbounded server-side pool defeats the whole
# point (Postgres connection exhaustion under the scaled-out api/worker tiers). ---
deny contains msg if {
	is_cnpg_pooler(input)
	not object.get(object.get(input.spec, "pgbouncer", {}), "parameters", {}).default_pool_size
	msg := sprintf("CNPG Pooler %q must set pgbouncer.parameters.default_pool_size (the bounded server-side pool — the connection budget that prevents Postgres exhaustion; ADR-0042 §4 / G-SCA §330)", [input.metadata.name])
}

deny contains msg if {
	is_cnpg_pooler(input)
	not object.get(object.get(input.spec, "pgbouncer", {}), "parameters", {}).max_client_conn
	msg := sprintf("CNPG Pooler %q must set pgbouncer.parameters.max_client_conn (the client-facing ceiling of the connection budget; ADR-0042 §4)", [input.metadata.name])
}

# --- the Pooler must front the read-write endpoint (type rw — the endpoint the
# app + the audit write path reach; PgBouncer re-points to the new primary on
# failover, ADR-0042 §3/§4). ---
deny contains msg if {
	is_cnpg_pooler(input)
	object.get(input.spec, "type", "rw") != "rw"
	msg := sprintf("CNPG Pooler %q must front the read-write endpoint (type rw) so the audit write path + failover re-point work through it (ADR-0042 §3/§4)", [input.metadata.name])
}

# ===========================================================================
# W1-T3 — Neo4j AUTOMATED-REBUILD reconciler (ADR-0005 D5; ADR-0029 §1/§3;
# PRODUCTION.md §3.2 — single Neo4j + automated rebuild)
#
# Distinct from the W5-T3 quarterly DRILL above (a suspended, P2-executed,
# manual destroy-and-rebuild assertion harness). This is the PRODUCTION recovery
# wiring: a frequent reconciler CronJob that, when the projected graph is empty
# or stale (the state a liveness-fail → container recreate leaves on the data
# PVC), RE-PROJECTS the whole topology from Postgres — the system of record —
# with NO manual step, then records the rebuild DURATION (the topology-RTO the
# W4-T4 drill compares against + the G-OBS freshness SLO reads). Neo4j Community
# has no clustering; this reconciler IS the designed HA mitigation (ADR-0005 §3.2).
#
# The reconciler objects carry the `netops.io/rebuild-role: neo4j-auto-rebuild`
# label; match on it to scope these rules (the W5-T3 drill carries
# `netops.io/backup-type: neo4j-rebuild-drill` instead, so the two rule sets are
# mutually exclusive by construction and never cross-fire).
# ===========================================================================

# A rendered automated-rebuild reconciler object (Job OR CronJob) by its role label.
is_neo4j_auto_rebuild(obj) if {
	obj.metadata.labels["netops.io/rebuild-role"] == "neo4j-auto-rebuild"
}

# The reconciler pod-template spec, normalized across Job and CronJob.
neo4j_auto_rebuild_pod_spec(obj) := obj.spec.template.spec if {
	obj.kind == "Job"
}

neo4j_auto_rebuild_pod_spec(obj) := obj.spec.jobTemplate.spec.template.spec if {
	obj.kind == "CronJob"
}

# Flattened command+args text of a reconciler container (the sh -c script body).
neo4j_auto_rebuild_argv(c) := array.concat(object.get(c, "command", []), object.get(c, "args", []))

# --- L3: the reconciler exec MUST be wrapped in `sh -c` so the in-script $VAR
# (the assembled DSN + the metric path) expand in the shell — a raw exec argv does
# NOT do $(VAR) substitution and would re-project against a literal `$(VAR)` host,
# silently mis-targeting (the spec's named L3 risk). ---
neo4j_auto_rebuild_uses_sh_c(c) if {
	cmd := object.get(c, "command", [])
	cmd[0] == "sh"
	cmd[1] == "-c"
}

deny contains msg if {
	is_neo4j_auto_rebuild(input)
	some c in neo4j_auto_rebuild_pod_spec(input).containers
	not neo4j_auto_rebuild_uses_sh_c(c)
	msg := sprintf("neo4j auto-rebuild %q container %q must wrap its exec in `sh -c` (L3 — a raw argv would not expand the in-script $(VAR) DSN/metric-path and would re-project against a literal host; ADR-0005 D5)", [input.metadata.name, c.name])
}

# --- the reconciler MUST re-project from Postgres via the EXISTING metric-emitting
# rebuild path: app.engines.topology.auto_rebuild is the thin operator CLI over
# app.engines.topology.metrics.timed_rebuild (→ rebuild() → projector.full_rebuild).
# A wipe with no Postgres re-projection is not a rebuild (Neo4j holds no
# un-rebuildable state — ADR-0005 D5). Asserted on the rendered argv text. ---
neo4j_auto_rebuild_runs_reprojection(c) if {
	some arg in neo4j_auto_rebuild_argv(c)
	contains(arg, "app.engines.topology.auto_rebuild")
}

deny contains msg if {
	is_neo4j_auto_rebuild(input)
	some c in neo4j_auto_rebuild_pod_spec(input).containers
	not neo4j_auto_rebuild_runs_reprojection(c)
	msg := sprintf("neo4j auto-rebuild %q container %q must re-project from Postgres via the metric-emitting full-rebuild path (app.engines.topology.metrics.timed_rebuild) — a wipe with no re-projection is not a rebuild (ADR-0005 D5)", [input.metadata.name, c.name])
}

# --- the rebuild DURATION metric MUST be emitted as a node_exporter TEXTFILE
# `.prom` (the established no-pushgateway pattern — a CronJob pod is not scrapable;
# the file survives the pod for the agent to collect). This value is the
# topology-RTO the W4-T4 drill compares against + the G-OBS freshness SLO reads;
# without it the recovery is invisible. Asserted on the script text. ---
neo4j_auto_rebuild_emits_metric(c) if {
	some arg in neo4j_auto_rebuild_argv(c)
	contains(arg, "topology_rebuild_seconds")
	contains(arg, ".prom")
}

deny contains msg if {
	is_neo4j_auto_rebuild(input)
	some c in neo4j_auto_rebuild_pod_spec(input).containers
	not neo4j_auto_rebuild_emits_metric(c)
	msg := sprintf("neo4j auto-rebuild %q container %q must emit the rebuild-DURATION metric as a node_exporter textfile (`topology_rebuild_seconds` in a `.prom` file) — it is the topology-RTO the W4-T4 drill + G-OBS freshness SLO read (PRODUCTION.md §3.2/§11)", [input.metadata.name, c.name])
}

# --- L5 belt-and-braces: the script MUST guard that the metric file was actually
# written non-empty (`test -s`), so a silently-empty metric write FAILS the run
# rather than passing with no topology-RTO recorded. ---
neo4j_auto_rebuild_guards_metric(c) if {
	some arg in neo4j_auto_rebuild_argv(c)
	contains(arg, "test -s")
}

deny contains msg if {
	is_neo4j_auto_rebuild(input)
	some c in neo4j_auto_rebuild_pod_spec(input).containers
	not neo4j_auto_rebuild_guards_metric(c)
	msg := sprintf("neo4j auto-rebuild %q container %q must assert the metric file is non-empty (`test -s`) so a silently-empty rebuild-duration write FAILS the run (L5)", [input.metadata.name, c.name])
}

# --- secret-surface: any reconciler env whose NAME signals a credential (the
# Postgres password or the Neo4j auth) MUST be a secretKeyRef with NO inline
# `value:` literal (ADR-0029 §6). Reuses the drill's credential-name predicate. ---
deny contains msg if {
	is_neo4j_auto_rebuild(input)
	some c in neo4j_auto_rebuild_pod_spec(input).containers
	some e in object.get(c, "env", [])
	neo4j_drill_credential_env(e.name)
	object.get(e, "value", null) != null
	msg := sprintf("neo4j auto-rebuild %q env %q must NOT carry an inline `value:` literal — the Postgres password / Neo4j auth are external-secret refs only (ADR-0029 §6)", [input.metadata.name, e.name])
}

deny contains msg if {
	is_neo4j_auto_rebuild(input)
	some c in neo4j_auto_rebuild_pod_spec(input).containers
	some e in object.get(c, "env", [])
	neo4j_drill_credential_env(e.name)
	not e.valueFrom.secretKeyRef
	msg := sprintf("neo4j auto-rebuild %q env %q must be sourced from valueFrom.secretKeyRef (credentials are by-reference only; ADR-0029 §6)", [input.metadata.name, e.name])
}

# --- the reconciler rebuilds into the LIVE Neo4j from Postgres — it carries no
# data PVC of its own (parity with the drill: the projection is re-derived, never
# restored onto a mounted data volume). ---
deny contains msg if {
	is_neo4j_auto_rebuild(input)
	some v in object.get(neo4j_auto_rebuild_pod_spec(input), "volumes", [])
	v.persistentVolumeClaim
	msg := sprintf("neo4j auto-rebuild %q must mount NO persistentVolumeClaim — the graph is RE-PROJECTED from Postgres, never restored onto a data volume (ADR-0005 D5)", [input.metadata.name])
}

# --- the reconciler talks to Postgres + Neo4j, not the K8s API:
# automountServiceAccountToken=false (parity with the backup/drill pods, ADR-0029 §5). ---
deny contains msg if {
	is_neo4j_auto_rebuild(input)
	neo4j_auto_rebuild_pod_spec(input).automountServiceAccountToken != false
	msg := sprintf("neo4j auto-rebuild %q pod must set automountServiceAccountToken=false — it talks to Postgres + Neo4j, not the K8s API (ADR-0029 §5)", [input.metadata.name])
}

# --- per-container hardening (the reconciler is a batch kind, separate from the
# platform Deployment/StatefulSet rules; assert the same ADR-0029 §3 controls):
# drop ALL caps, add none, non-root, RO-rootfs, no-privesc, requests AND limits. ---
deny contains msg if {
	is_neo4j_auto_rebuild(input)
	some c in neo4j_auto_rebuild_pod_spec(input).containers
	not drops_all(c)
	msg := sprintf("neo4j auto-rebuild %q container %q must drop ALL capabilities (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_neo4j_auto_rebuild(input)
	some c in neo4j_auto_rebuild_pod_spec(input).containers
	some cap in object.get(object.get(object.get(c, "securityContext", {}), "capabilities", {}), "add", [])
	msg := sprintf("neo4j auto-rebuild %q container %q must add NO capabilities (found %q; ADR-0029 §3)", [input.metadata.name, c.name, cap])
}

deny contains msg if {
	is_neo4j_auto_rebuild(input)
	some c in neo4j_auto_rebuild_pod_spec(input).containers
	c.securityContext.runAsNonRoot != true
	msg := sprintf("neo4j auto-rebuild %q container %q must set runAsNonRoot=true (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_neo4j_auto_rebuild(input)
	some c in neo4j_auto_rebuild_pod_spec(input).containers
	c.securityContext.readOnlyRootFilesystem != true
	msg := sprintf("neo4j auto-rebuild %q container %q must set readOnlyRootFilesystem=true (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_neo4j_auto_rebuild(input)
	some c in neo4j_auto_rebuild_pod_spec(input).containers
	c.securityContext.allowPrivilegeEscalation != false
	msg := sprintf("neo4j auto-rebuild %q container %q must set allowPrivilegeEscalation=false (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_neo4j_auto_rebuild(input)
	some c in neo4j_auto_rebuild_pod_spec(input).containers
	not c.resources.requests
	msg := sprintf("neo4j auto-rebuild %q container %q must declare resource requests (ADR-0029 §3)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_neo4j_auto_rebuild(input)
	some c in neo4j_auto_rebuild_pod_spec(input).containers
	not c.resources.limits
	msg := sprintf("neo4j auto-rebuild %q container %q must declare resource limits (ADR-0029 §3)", [input.metadata.name, c.name])
}

# ===========================================================================
# W1-T4 — Redis Sentinel HA tier (ADR-0044 §1, ADR-0008)
#
# The opt-in redisSentinel tier (default OFF) renders a Redis StatefulSet (1 seed
# primary + 2 replicas, component `redis`), a Sentinel StatefulSet (3 Sentinels,
# component `redis-sentinel`), a Redis config ConfigMap, and the Sentinel/Redis
# NetworkPolicy edges. The generic per-workload hardening rules above ALSO cover
# both StatefulSets by component label (`redis` and `redis-sentinel` are both in
# platform_workload_components), so drop-ALL / non-root / RO-rootfs / no-privesc /
# RuntimeDefault-seccomp / limits are already gated there — these rules add the
# Sentinel-SPECIFIC controls (ADR-0044 §1): AOF on, auth required + by-reference,
# 3 Sentinels at an odd quorum, and the failover-aware (sentinel-monitored) shape.
# They pass VACUOUSLY on the default single-instance render (no redis-sentinel
# objects there) and BITE on a non-compliant Sentinel render (ci/redis-sentinel/
# bite fixtures). The W1-T4 mutual-exclusion (redisSentinel + services.redis both
# on) is a Helm `fail` (redis-sentinel.yaml), proven by the bite script, not a rego
# rule (a `fail` never renders YAML to test).
# ===========================================================================

# True for the W1-T4 Redis config ConfigMap (carries the AOF + replication coords).
is_redis_sentinel_configmap(obj) if {
	obj.kind == "ConfigMap"
	obj.metadata.labels["app.kubernetes.io/component"] == "redis"
	endswith(obj.metadata.name, "-redis-sentinel-config")
}

# --- AOF ON (ADR-0044 §1): the Redis config MUST set `appendonly yes` so a
# full-shard restart recovers the last durable state rather than starting empty.
# A `appendonly no` (or a missing directive) defeats the persistence guarantee. ---
deny contains msg if {
	is_redis_sentinel_configmap(input)
	some k, v in object.get(input, "data", {})
	k == "redis.conf"
	# Match an ACTIVE `appendonly yes` line, not a commented `# appendonly yes`
	# (which `contains` would be fooled by even with `appendonly no` set).
	not regex.match(`(?m)^\s*appendonly\s+yes\s*(#.*)?$`, v)
	msg := sprintf("Redis Sentinel config %q must set `appendonly yes` — AOF persistence is required so a full-shard restart recovers durable state (ADR-0044 §1)", [input.metadata.name])
}

# --- the Redis config MUST NOT inline a password literal: requirepass/masterauth
# are injected at startup from the platform Secret env (sh -c expansion), NEVER
# baked into the ConfigMap (ADR-0029 §6 / ADR-0044 §1). A `requirepass <value>` or
# `masterauth <value>` directive in the .conf is a denied inline secret. ---
redis_config_inlines_secret(line) if {
	regex.match(`^\s*requirepass\s+\S`, line)
}

redis_config_inlines_secret(line) if {
	regex.match(`^\s*masterauth\s+\S`, line)
}

redis_config_inlines_secret(line) if {
	regex.match(`sentinel\s+auth-pass\s+\S+\s+\S`, line)
}

deny contains msg if {
	is_redis_sentinel_configmap(input)
	some _, v in object.get(input, "data", {})
	some line in split(v, "\n")
	redis_config_inlines_secret(line)
	msg := sprintf("Redis Sentinel config %q must NOT inline requirepass/masterauth/auth-pass — the password is supplied as REDIS_PASSWORD env from the Secret at startup, never baked into the ConfigMap (ADR-0029 §6 / ADR-0044 §1)", [input.metadata.name])
}

# True for the W1-T4 Redis (data) StatefulSet — component `redis` AND it mounts the
# `-redis-sentinel-config` ConfigMap. The serviceName-disambiguation matters: the
# DEFAULT single-instance services.redis StatefulSet ALSO carries component `redis`
# (and 1 replica), so the Sentinel rules below MUST NOT fire on it — they are scoped
# by the sentinel-config volume, which only the HA-tier StatefulSet mounts. This
# keeps the GA default render passing while biting on a non-compliant Sentinel tier.
is_redis_data_statefulset(obj) if {
	obj.kind == "StatefulSet"
	obj.metadata.labels["app.kubernetes.io/component"] == "redis"
	statefulset_mounts_sentinel_config(obj)
}

statefulset_mounts_sentinel_config(obj) if {
	some v in object.get(obj.spec.template.spec, "volumes", [])
	endswith(object.get(object.get(v, "configMap", {}), "name", ""), "-redis-sentinel-config")
}

# True for the W1-T4 Sentinel StatefulSet — component `redis-sentinel`.
is_redis_sentinel_statefulset(obj) if {
	obj.kind == "StatefulSet"
	obj.metadata.labels["app.kubernetes.io/component"] == "redis-sentinel"
}

# --- auth REQUIRED + by-reference: every Redis/Sentinel container MUST source a
# REDIS_PASSWORD env from a secretKeyRef and carry NO inline `value:` literal
# (ADR-0044 §1 secure-by-default auth / ADR-0029 §6). ---
redis_container_has_secret_password(c) if {
	some e in object.get(c, "env", [])
	e.name == "REDIS_PASSWORD"
	e.valueFrom.secretKeyRef
	object.get(e, "value", null) == null
}

deny contains msg if {
	is_redis_data_statefulset(input)
	some c in input.spec.template.spec.containers
	not redis_container_has_secret_password(c)
	msg := sprintf("Redis Sentinel data StatefulSet %q container %q must set REDIS_PASSWORD from valueFrom.secretKeyRef (auth required + by-reference; ADR-0044 §1 / ADR-0029 §6)", [input.metadata.name, c.name])
}

deny contains msg if {
	is_redis_sentinel_statefulset(input)
	some c in input.spec.template.spec.containers
	not redis_container_has_secret_password(c)
	msg := sprintf("Redis Sentinel StatefulSet %q container %q must set REDIS_PASSWORD from valueFrom.secretKeyRef (Sentinel auth-pass by-reference; ADR-0044 §1 / ADR-0029 §6)", [input.metadata.name, c.name])
}

# A REDIS_PASSWORD env carrying an inline `value:` literal is a denied inline secret.
deny contains msg if {
	is_redis_data_statefulset(input)
	some c in input.spec.template.spec.containers
	some e in object.get(c, "env", [])
	e.name == "REDIS_PASSWORD"
	object.get(e, "value", null) != null
	msg := sprintf("Redis Sentinel data StatefulSet %q env REDIS_PASSWORD must NOT carry an inline `value:` literal — it is an external-secret ref only (ADR-0029 §6)", [input.metadata.name])
}

deny contains msg if {
	is_redis_sentinel_statefulset(input)
	some c in input.spec.template.spec.containers
	some e in object.get(c, "env", [])
	e.name == "REDIS_PASSWORD"
	object.get(e, "value", null) != null
	msg := sprintf("Redis Sentinel StatefulSet %q env REDIS_PASSWORD must NOT carry an inline `value:` literal — it is an external-secret ref only (ADR-0029 §6)", [input.metadata.name])
}

# --- the seed Redis shard MUST have >= 3 instances (1 primary + 2 replicas,
# ADR-0044 §1 — 3 is the minimum for a meaningful replica set). ---
deny contains msg if {
	is_redis_data_statefulset(input)
	# Omitted spec.replicas defaults to 1 in K8s; `input.spec.replicas < 3` would be
	# UNDEFINED (fail-open) on omission, so default to 1 before comparing.
	replicas := object.get(input.spec, "replicas", 1)
	replicas < 3
	msg := sprintf("Redis Sentinel data StatefulSet %q must run >= 3 replicas (1 primary + 2 replicas; ADR-0044 §1), got %v", [input.metadata.name, replicas])
}

# --- there MUST be 3 Sentinels (ADR-0044 §1 — an odd quorum so a single Sentinel
# loss cannot deadlock the failover vote). Fewer than 3 cannot form the 2-of-3
# majority the design requires. ---
deny contains msg if {
	is_redis_sentinel_statefulset(input)
	# Omitted spec.replicas defaults to 1 in K8s; default to 1 before comparing so an
	# omitted count is treated as non-compliant rather than failing open.
	replicas := object.get(input.spec, "replicas", 1)
	replicas < 3
	msg := sprintf("Redis Sentinel StatefulSet %q must run >= 3 Sentinels (odd quorum, single-loss-tolerant; ADR-0044 §1), got %v", [input.metadata.name, replicas])
}

# --- the Sentinel container MUST actually run sentinel (a `--sentinel` flag or a
# `sentinel monitor` in its startup script): a Sentinel StatefulSet that runs a
# plain redis-server is not monitoring anything and provides NO failover. Asserted
# on the rendered command/args text. ---
deny contains msg if {
	is_redis_sentinel_statefulset(input)
	some c in input.spec.template.spec.containers
	not sentinel_runs_sentinel(c)
	msg := sprintf("Redis Sentinel StatefulSet %q container %q must run Sentinel (a `--sentinel` flag / `sentinel monitor` directive) — without it there is no monitoring or automatic failover (ADR-0044 §1)", [input.metadata.name, c.name])
}

sentinel_runs_sentinel(c) if {
	some arg in array.concat(object.get(c, "command", []), object.get(c, "args", []))
	# Require the actual `--sentinel` execution flag, not any "sentinel" substring (a
	# script that merely echoes `sentinel monitor ...` but runs `redis-server $CONF`
	# without `--sentinel` would otherwise pass while NOT starting Sentinel mode).
	regex.match(`(^|\s)--sentinel(\s|$)`, arg)
}

# --- the Sentinel startup MUST monitor the shard (a `sentinel monitor <name> ...
# <quorum>` line) — the monitor directive is the whole point. Asserted on argv. ---
deny contains msg if {
	is_redis_sentinel_statefulset(input)
	some c in input.spec.template.spec.containers
	not sentinel_has_monitor(c)
	msg := sprintf("Redis Sentinel StatefulSet %q container %q must declare a `sentinel monitor` directive (name + seed primary + quorum) — Sentinel must monitor the shard to drive failover (ADR-0044 §1)", [input.metadata.name, c.name])
}

sentinel_has_monitor(c) if {
	some arg in array.concat(object.get(c, "command", []), object.get(c, "args", []))
	contains(arg, "sentinel monitor")
}
