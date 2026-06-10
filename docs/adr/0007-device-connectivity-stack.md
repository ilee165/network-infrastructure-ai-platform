# ADR-0007: Device Connectivity — netmiko + ntc-templates, pysnmp, httpx, Cloud SDKs

**Status:** Accepted | **Date:** 2026-06-09 | **Decision:** D7

## Context

CLAUDE.md's Discovery feature list requires **SNMP, SSH, APIs, LLDP, CDP, route collection, and interface inventory** across all 13 vendors. The vendor set splits by dominant access method:

- **SSH/CLI:** Cisco IOS, IOS-XE, NX-OS; Juniper JunOS; Arista EOS; (FortiOS partially).
- **REST/XML APIs:** Palo Alto PAN-OS (XML API), F5 BIG-IP (iControl REST), Infoblox (WAPI), BlueCat (REST), FortiOS (REST).
- **Cloud/virtualization SDKs:** AWS, Azure, VMware.
- **SNMP:** broadly available as a read-only fallback/enrichment channel on the network OSes.

Constraints from elsewhere in the architecture: every transport runs *inside* vendor plugins (ADR-0006), all raw output is stored verbatim before parsing (auditability), outputs must land as normalized Pydantic models, and blocking I/O must stay off the API event loop (ADR-0002) — device work executes in Celery workers (ADR-0008). M1 ships SSH + SNMP for Cisco IOS, IOS-XE, and Arista EOS with interfaces, routes, and LLDP/CDP.

## Decision

**One transport library per protocol family, chosen for vendor breadth, wrapped exclusively inside plugins** (brief §2 D7):

| Protocol family | Library | Used by (plugins) |
|---|---|---|
| SSH/CLI | **netmiko** | `cisco_ios`, `cisco_iosxe`, `cisco_nxos`, `junos`, `eos`, `fortios` (CLI paths) |
| CLI parsing | **ntc-templates (TextFSM)** | all SSH plugins: raw output → structured dicts → normalized Pydantic models |
| SNMP v2c/v3 | **pysnmp** | network-OS plugins implementing `DISCOVERY_SNMP` (sysinfo, interface tables, LLDP MIBs) |
| HTTP REST/XML | **httpx** | `panos` (XML API), `f5_bigip` (iControl REST), `infoblox` (WAPI), `bluecat` (REST), `fortios` (REST) |
| AWS | **boto3** | `aws` (EC2/VPC: VPCs, subnets, route tables, ENIs, security groups) |
| Azure | **azure SDK** (`azure-identity` + `azure-mgmt-network` — PROPOSED package split; brief says "azure SDK") | `azure` |
| VMware | **pyVmomi** | `vmware` (vSwitches/portgroups, VM NICs, hosts) |

Fixed patterns:

1. **Pipeline per capability call:** connect → execute → **persist raw output verbatim to `raw_artifacts`** → parse (ntc-templates/TextFSM for CLI; JSON/XML for APIs) → validate into normalized Pydantic models (`NormalizedInterface`, `NormalizedRoute`, `NormalizedNeighbor`, `NormalizedBgpPeer`, `NormalizedAclEntry`, `NormalizedDnsRecord`, …) → upsert `normalized_*` tables. Parsing failures still leave the raw artifact stored.
2. **Credentials** come only from the encrypted vault (`device_credentials`, D11) via the credentials service — plugins receive in-memory credential objects, never read the table, and never log secrets.
3. **Blocking-I/O placement:** netmiko, pysnmp (sync API), and pyVmomi are blocking; they run inside Celery worker tasks on the `discovery`/`config`/`packet` queues (ADR-0008), never in FastAPI handlers. httpx is used in its sync form inside workers for consistency (**PROPOSED** — the brief does not specify sync vs async httpx; sync-in-worker is the conservative uniform choice).
4. **SNMP scope:** v2c and v3 only (per D7). SNMPv3 authPriv is the documented default recommendation; v1 is unsupported.
5. **Connection hygiene (PROPOSED, brief silent):** per-device serialization of CLI sessions within a worker, bounded connect/read timeouts, and bounded retries with exponential backoff on transient transport errors — conservative defaults to avoid hammering production devices; exact values are set (and tuned) in `core/` config, not hard-coded in plugins.

## Consequences

**Positive**

- netmiko has the broadest battle-tested device coverage of any Python SSH library — every CLI vendor on our list is a supported device_type — and ntc-templates supplies hundreds of community-maintained TextFSM templates, dramatically cutting M1 parser effort for `show interfaces`, `show ip route`, `show lldp neighbors`, `show cdp neighbors`.
- One library per protocol family keeps the dependency surface small and the security-review scope (D16 Trivy, D11 review) tractable.
- Raw-first persistence means template/parser upgrades can re-process history, and every agent statement about a device traces to verbatim evidence.
- httpx covering all four API vendors (plus Route53 later via boto3) avoids per-vendor SDK sprawl in the core image.

**Negative**

- netmiko is synchronous and screen-scraping-based: throughput scales by worker process/thread count, not async multiplexing, and CLI output drift across OS versions breaks TextFSM templates (mitigated, not solved, by raw-first storage and template pinning).
- pysnmp's maintenance history is uneven and its performance for large table walks (full IF-MIB on big chassis) is modest; if it becomes a bottleneck the plugin-internal placement lets us swap implementations without touching the capability contract.
- Hand-rolling API clients on httpx (PAN-OS XML, iControl, WAPI, BlueCat) means we own pagination, auth-token refresh, and error mapping per vendor — deliberate cost, paid to keep the dependency set lean.
- Three cloud/virtualization SDKs (boto3, azure SDK, pyVmomi) ship in the single backend image (ADR-0001), inflating image size and CVE surface even for deployments that never touch cloud.

## Alternatives considered

1. **NAPALM as the unified connectivity + getter layer.**
   Rejected (same grounds as ADR-0006): driver coverage stops roughly at the classic network OSes — nothing for PAN-OS-as-firewall-policy, FortiOS, F5, DDI, or cloud — and its fixed getter schema is narrower than our `Capability` enum. Using it as *the* connectivity layer would still leave us building everything else; plugins may optionally use a NAPALM driver internally where it genuinely helps.

2. **scrapli (+ scrapli_community) instead of netmiko.**
   Genuinely attractive — faster, cleaner async support. Rejected for now: vendor breadth and community template/device-type coverage still trail netmiko, and our concurrency model already gets parallelism from Celery workers, so netmiko's sync nature costs little. Because transports are plugin-internal, migrating a hot plugin to scrapli later is a non-breaking change. Revisit if M1 discovery throughput disappoints.

3. **Official vendor SDKs everywhere (pan-os-python, f5-sdk/bigrest, infoblox-client, fortiosapi, …).**
   Rejected as the default: per-vendor SDKs of wildly varying quality and maintenance would multiply the dependency/CVE surface across 13 vendors, and several are effectively abandoned. A uniform httpx client per plugin with our own thin typed layer is more maintainable; an individual plugin may adopt a vendor SDK by amending this ADR if the API surface proves too complex (PAN-OS commit semantics are the likeliest candidate).

4. **Nornir as the device-task execution framework.**
   Rejected: Nornir solves inventory + concurrent task fan-out, which our stack already owns elsewhere — inventory lives in Postgres (`devices`), fan-out and queueing live in Celery (ADR-0008). Adding Nornir would create a second inventory model and a second concurrency layer for no new capability.
