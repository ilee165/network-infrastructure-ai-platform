import { Link } from "react-router-dom";

const CORE_AGENTS: { name: string; summary: string }[] = [
  { name: "Master Architect", summary: "Plans multi-step work and routes to specialists." },
  { name: "Consultant", summary: "Clarifies requirements when intent is ambiguous." },
  { name: "Discovery", summary: "Inventory, neighbors, routes via SSH/SNMP/API plugins." },
  { name: "Troubleshooting", summary: "BGP, OSPF, ACL, firewall, path analysis." },
  { name: "Packet Analysis", summary: "tcpdump/tshark capture and findings (engineer+)." },
  { name: "Configuration", summary: "Backup, restore, drift, compliance — changes need approval." },
  { name: "DDI", summary: "DNS/DHCP/IPAM via Infoblox, BlueCat, Route53." },
  { name: "Documentation", summary: "Runbooks, incident reports, inventories, diagrams." },
  { name: "Security", summary: "Policy and exposure analysis (firewall wave)." },
  { name: "Automation", summary: "Executes approved Change Requests only." },
];

const EXAMPLE_PROMPTS = [
  "Why is BGP down between core-a and core-b?",
  "Show the L2 path from host-web-01 to the firewall.",
  "Draft a ChangeRequest to open TCP 443 from DMZ to app-tier.",
  "Summarize discovery findings for site DFW1.",
];

export function SettingsAgentsSection() {
  return (
    <section
      aria-label="Agents and Chat setup"
      data-testid="settings-agents"
      className="flex flex-col gap-4"
    >
      <div className="panel p-4 flex flex-col gap-3">
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          Agents & Chat setup
        </h3>
        <p className="text-sm text-zinc-300">
          Chat is the AI Network Engineer console. The supervisor routes your
          question to specialist agents, streams a reasoning trace, and keeps
          write operations behind human approval.
        </p>
        <Link to="/chat" className="btn self-start text-xs">
          Open Chat
        </Link>
      </div>

      <div className="panel p-4 flex flex-col gap-3">
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          Prerequisites checklist
        </h3>
        <ol className="list-decimal space-y-2 pl-5 text-sm text-zinc-300">
          <li>
            <strong className="text-zinc-100">LLM ready</strong> — admins set the
            active profile under{" "}
            <Link to="/settings/llm" className="text-accent hover:underline">
              AI / LLM
            </Link>
            . Local uses Ollama; subscription providers need env API keys on the
            server (never pasted in the browser).
          </li>
          <li>
            <strong className="text-zinc-100">Device credentials</strong> —
            engineer+ create vault entries under{" "}
            <Link to="/settings/credentials" className="text-accent hover:underline">
              Credentials
            </Link>
            , then reference those names when launching discovery.
          </li>
          <li>
            <strong className="text-zinc-100">Inventory & topology</strong> — run
            discovery on{" "}
            <Link to="/devices" className="text-accent hover:underline">
              Devices
            </Link>
            , then open{" "}
            <Link to="/topology" className="text-accent hover:underline">
              Topology
            </Link>
            .
          </li>
          <li>
            <strong className="text-zinc-100">Change approval</strong> —
            engineer+ reviews drafts on{" "}
            <Link to="/changes" className="text-accent hover:underline">
              Changes
            </Link>
            . Agents do not push device changes without four-eyes approval.
          </li>
        </ol>
      </div>

      <div className="panel p-4 flex flex-col gap-3">
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          Core agents
        </h3>
        <ul className="grid gap-2 sm:grid-cols-2">
          {CORE_AGENTS.map((agent) => (
            <li
              key={agent.name}
              className="rounded border border-carbon-800 bg-carbon-950/50 px-3 py-2"
            >
              <p className="text-xs font-medium text-zinc-100">{agent.name}</p>
              <p className="mt-0.5 text-[11px] text-zinc-500">{agent.summary}</p>
            </li>
          ))}
        </ul>
      </div>

      <div className="panel p-4 flex flex-col gap-3">
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          Example prompts
        </h3>
        <ul className="space-y-1.5 text-sm text-zinc-300">
          {EXAMPLE_PROMPTS.map((prompt) => (
            <li key={prompt} className="font-mono text-xs text-zinc-400">
              “{prompt}”
            </li>
          ))}
        </ul>
      </div>

      <div className="panel p-4 flex flex-col gap-2">
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          Safety & trust
        </h3>
        <ul className="list-disc space-y-1.5 pl-5 text-sm text-zinc-300">
          <li>Vault secrets never enter LLM prompts; CLI output is redacted.</li>
          <li>
            External LLM profiles (Anthropic / OpenAI / Azure) imply data may leave
            the deployment — selection is audited.
          </li>
          <li>
            Every answer shows a reasoning trace (plan → tool calls → observations
            → conclusion). Expand it under each Chat reply.
          </li>
          <li>
            Roles: viewers can chat and read; engineers run captures and approve
            changes; admins manage users and LLM profile.
          </li>
        </ul>
      </div>
    </section>
  );
}
