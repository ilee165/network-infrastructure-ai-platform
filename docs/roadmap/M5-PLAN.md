# M5 Build Plan — ChangeRequest workflow, DDI (Infoblox), packet analysis, Automation Agent

**Status:** PLANNED (2026-06-17). Not started.
**Authority:** Implements `docs/roadmap/MVP.md` §7 (final MVP milestone). Bound by `CLAUDE.md`, decisions D1–D16, and `ARCHITECTURE/REPO-STRUCTURE.md`. Build executed via the orchestrated wf-* workflow roster (`.claude/agents/`), mirroring M1/M3/M4.

## Goal

Close the loop: the platform can now **change** the network — but only through human-approved ChangeRequests. M5 delivers the full ChangeRequest lifecycle + four-eyes approval UI, the **Automation Agent** as sole executor of approved changes, `CONFIG_RESTORE`/`CONFIG_DEPLOY` on the three route/switch plugins, the **Infoblox** WAPI plugin (first API-based discovery) + **DDI Agent**, sandboxed **packet analysis** + **Packet Analysis Agent**, the DNS-dependency topology layer, incident-report generation, and an MVP security-hardening pass. **MVP is feature-complete at M5 exit.**

This is the **first write-path milestone**. Every change to a device or DDI record flows through a ChangeRequest with a different-user approval gate (D11, brief §7). Security review is heaviest here.

## Codebase baseline (verified 2026-06-17 — M4 lesson: verify before listing as new)

- `Capability` enum (`plugins/base.py`) **already declares** `CONFIG_RESTORE`, `CONFIG_DEPLOY`, `DDI_DNS/DHCP/IPAM`, `PACKET_CAPTURE`, `DISCOVERY_API`. These are enum values only — **no plugin implements the interfaces**. M5 builds the implementations, not the enum.
- `agents/framework/approval.py` is the M3 **agent-gate** (`ApprovalGate`/`DenyAllGate` — hard-rejects state-changing tools with an audit entry). There is **no ChangeRequest model, table, or service**. M5 adds the persistent ChangeRequest spine *and rewires the gate* from hard-reject → CR-creation.
- No `engines/packet/`, no `infoblox` plugin, no Automation/DDI/Packet Analysis agents. Supervisor router is **v4, 5-way** (discovery / troubleshooting / consultant / configuration / documentation). M5 takes it to **v5, 8-way**.
- `config_snapshots` exist (M4) — `CONFIG_RESTORE` restores from them; no new snapshot storage needed.

## Build approach

One orchestrated build workflow (mirrors M4's 18-task run): TDD per task, exactly one atomic commit per task, dual review (`wf-spec-reviewer` + `wf-quality-reviewer`) behind mechanical gates → `wf-fixer` (if findings) → `wf-verifier`. `agentType` model tiering; `resumeFromRunId` for restarts. Sequential where files overlap, parallel only within a task (the two reviews).

**Write-path escalation rule:** every task that touches a write path to a device/DDI record, the four-eyes gate, or config/DNS content feeding an LLM runs its reviewers on the **strong model** (`opts.model`). The Automation Agent (sole executor) gets a **strong implementer + dual strong reviewers**. Tagged ⚠️ below.

Maps onto the milestone template (`10-Templates/CLAUDE_CODE_MILESTONE_EXECUTION.md`): Phase 4 (Implementation) + Phase 6 (Validation). Phases 1/2/3/7/9 (discovery, branch, plan doc, vault update, final report) are the human-facing wrapper.

## Task waves (dependency-ordered)

Cx = complexity (S/M/L). Every task also runs dual review → `wf-fixer` (if findings) → `wf-verifier`. ⚠️ = reviewers escalated to strong model.

| # | Task | Wave | wf-* role | Cx |
|---|------|------|-----------|----|
| 1 | ADRs 0020–0023: ChangeRequest state machine + four-eyes + audited-transition model; config deploy/restore + structured-rollback semantics; Infoblox WAPI client + DDI capability interfaces + conformance; packet sandbox + pcap retention/security model | 0 plan | `wf-implementer` | M |
| 2 | Alembic 0007: `change_requests`, `approvals` (state enum, four-eyes constraint, before/after JSONB, reasoning-trace FK), `pcap_metadata` (+ retention/tombstone fields) | 1 | `wf-implementer` | M |
| 3 | **ChangeRequest service**: lifecycle `draft→pending_approval→approved→executing→completed\|failed→rolled_back`; transition guards; **four-eyes enforcement (approver ≠ requester, server-side, on by default)**; every transition audited with before/after + trace link ⚠️ | 2 | `wf-implementer` | L |
| 4 | Framework gate rewire: state-changing tools now **create a ChangeRequest** (was M3/M4 hard-reject `DenyAllGate`); non-`approved` state refuses execution; audited ⚠️ | 2 | `wf-implementer` | M |
| 5 | `CONFIG_RESTORE` + `CONFIG_DEPLOY` on `cisco_ios` (certified first vs conformance) + structured rollback step ⚠️ | 3 | `wf-implementer` | L |
| 6 | `CONFIG_RESTORE` + `CONFIG_DEPLOY` on `cisco_iosxe` + `eos` (mirror #5) ⚠️ | 3 | `wf-implementer-light` | M |
| 7 | `infoblox` plugin: WAPI via httpx — `DISCOVERY_API` + `DDI_DNS`/`DDI_DHCP`/`DDI_IPAM`; passes plugin conformance suite | 3 | `wf-implementer` | L |
| 8 | `engines/packet/`: capture orchestration (worker-side `tcpdump` + `eos` device monitor-session) + pcap upload/ingest + **sandboxed** tshark/pyshark analysis on the `packet` queue + pcap disk artifacts ⚠️ | 3 | `wf-implementer` | L |
| 9 | **Automation Agent**: sole executor of `approved` CRs — runs `CONFIG_RESTORE`/`CONFIG_DEPLOY` + DDI record changes; structured rollback per change; refuses anything not `approved` ⚠️ **strong implementer + dual strong reviewers** | 4 | `wf-implementer` (strong) | L |
| 10 | **DDI Agent**: DNS troubleshooting (zone/record lookup, delegation/resolution-path, mismatch vs inventory) + DHCP troubleshooting (scope util, lease lookup, conflict) read-only; record add/modify/delete tools **create CRs** | 4 | `wf-implementer` | L |
| 11 | **Packet Analysis Agent**: summarize capture (top talkers, protocols, errors/retransmissions), answer filter-style questions, attach findings to a troubleshooting session | 4 | `wf-implementer` | M |
| 12 | Documentation Agent **incident-report** extension: generate from a troubleshooting session (timeline, evidence links, findings, remediation CRs); store + embed in `documents` | 4 | `wf-implementer-light` | M |
| 13 | Topology **DNS-dependency layer**: `DnsZone`/`DnsRecord` nodes + `RESOLVES_TO` projected from Infoblox; topology API + projection extension | 4 | `wf-implementer` | M |
| 14 | Register Automation/DDI/Packet specialists with Master Architect; **routing prompt v5 (8-way) + sharpened specialist descriptions** ⚠️ | 5 | `wf-implementer` | M |
| 15 | API: ChangeRequest + approvals endpoints (`changes` router, RBAC: approve requires `engineer`+, four-eyes); packet capture/analysis endpoints — no new router beyond the fixed ten | 5 | `wf-implementer` | M |
| 16 | Frontend: **approval queue UI** — diff/intent preview, approve/reject with comment (the human change gate) ⚠️ | 5 | `wf-implementer` | M |
| 17 | Frontend: packet capture launch + analysis view; DNS-dependency topology layer toggle; incident-report view/download | 5 | `wf-implementer-light` | M |
| 18 | **M5 eval suite** (8 exit criteria) + **8-way real-LLM routing eval** (held-out) + packet top-talkers vs `tshark` ground-truth comparison + DDI golden-path integration test vs Infoblox mock | 6 | `wf-eval-designer` | L |
| 19 | MVP hardening: TLS for compose ingress + retention jobs (pcaps, raw artifacts) + **security review sign-off doc** (Dev Standards step 5) ⚠️ | 6 | `wf-implementer` | M |
| 20 | Full gates + live-lab validation + release branch `release/m5` | 6 | `wf-implementer` | M |

## Agent roster decision

**No new `wf-*` role this cycle.** M5's escalation is `opts.model = strong` on the security-critical reviewers (and a strong implementer + dual strong reviewers on the Automation Agent), *not* a new role type. The seven existing roles cover implement / review / fix / verify / eval. `wf-eval-designer` (added M4) owns #18 + the eval layer of #9/#14.

**Product agents (`backend/app/agents/`):** add exactly the three the roadmap specifies — **Automation Agent**, **DDI Agent**, **Packet Analysis Agent**. Extend **Documentation Agent** (incident reports, #12) and **Configuration Agent** (its `CONFIG_RESTORE`/`CONFIG_DEPLOY` tools now create CRs, executed by Automation). Roster after M5 = **8 specialists** → routing prompt v5.

## Risks → escalation & sequencing

1. **⚠️⚠️ First WRITE paths to real devices.** The Automation Agent (#9) is the single executor and the most security-critical task in the project. Mitigation: strong implementer + dual strong reviewers; rollback step mandatory per change; refuses any non-`approved` CR; four-eyes enforced upstream in the CR service (#3).
2. **Four-eyes integrity (#3).** Approver ≠ requester must be enforced **server-side**, not just in the UI; self-approval rejection under default config is exit criterion #2 with an automated test. Strong reviewers.
3. **Config/DNS content → LLM.** Any CR diff/intent preview (#16) or agent explanation of a config/DNS change (#9/#10) passes the A9 redaction layer (`llm/redaction.py`). Secret-touching ⇒ strong reviewers on #5/#6/#9/#16.
4. **8-way routing disambiguation (#14).** Largest router surface yet (config/docs + DDI/packet/automation on top of M3's four). Sharp descriptions + prompt v5 + held-out real-LLM eval (#18). Critical: a "change X" request must route to draft-a-CR, never straight to execution.
5. **Packet sandbox escape (#8).** tshark/pyshark parse untrusted pcaps in a worker — enforce sandbox per D14 (resource limits, no network, dropped capabilities). Covered by the security review (#19).
6. **pcap retention / payload sensitivity (#2/#8).** Captures hold packet payloads — retention job removes expired pcaps, metadata rows tombstoned + audited (exit criterion #5).

## Exit-criteria → task mapping (MVP.md §7)

| Exit criterion | Tasks |
|---|---|
| E2E golden path: DDI finds stale record → CR → *different* user approves → Automation executes via WAPI → verified → full audit chain | 3, 7, 9, 10, 15, 16, 18 |
| Non-`approved` CR cannot execute; self-approval rejected under default config | 3, 4, 18 |
| Config restore of a prior snapshot via a CR; device matches snapshot afterward | 5, 6, 9, 18 |
| UI capture → pcap → sandboxed tshark → top-talkers matches ground truth → opens in Wireshark | 8, 11, 17, 18 |
| Expired pcaps removed by retention job; metadata tombstoned + audited | 2, 8, 19 |
| Incident report (timeline, evidence links, trace refs) stored + embedded | 12, 18 |
| DNS-dependency layer visible in topology UI; `RESOLVES_TO` matches Infoblox zone data | 7, 13, 17 |
| Security review checklist signed off; Trivy zero critical CVEs; all M0 CI gates green | 19, 20 |

## Next step

Execute Wave 0 (ADRs 0020–0023) inline as the first workflow task, then launch the orchestrated build workflow for Waves 1–6 on branch `release/m5`. Update vault `00-STATUS` / `03-TASKS` as work progresses (vault = execution hub).
