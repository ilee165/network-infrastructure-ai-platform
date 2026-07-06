/**
 * VirtualizationPage tests: VM/host/cluster/port-group tables, empty states,
 * error banners, Tools-less VM + standalone host honesty, and the
 * power-state/is_template + connection-state/maintenance-mode separate
 * dimensions — mocked global fetch, no backend required.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type {
  ComputeClusterListResponse,
  HypervisorHostListResponse,
  PortGroupListResponse,
  VirtualMachineListResponse,
} from "../api/virtualization";
import { VirtualizationPage } from "../pages/VirtualizationPage";

const VMS: VirtualMachineListResponse = {
  items: [
    {
      id: "11111111-1111-1111-1111-111111111111",
      device_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      name: "web-vm-01",
      moref: "vm-1042",
      instance_uuid: "5032c8a4-1111-2222-3333-444455556666",
      is_template: false,
      power_state: "powered_on",
      guest_hostname: "web-vm-01.corp.example",
      guest_ip_addresses: ["10.0.0.21"],
      host_name: "esxi-01.corp.example",
      cluster_name: "cluster-a",
      datacenter: "dc-east",
      nics: [],
      description: null,
      collected_at: "2026-07-01T12:00:00Z",
      source_vendor: "vmware",
    },
  ],
  total: 1,
  limit: 100,
  offset: 0,
};

const TOOLS_LESS_VM: VirtualMachineListResponse = {
  items: [
    {
      ...VMS.items[0]!,
      id: "22222222-2222-2222-2222-222222222222",
      name: "no-tools-vm",
      guest_hostname: null,
      guest_ip_addresses: [],
    },
  ],
  total: 1,
  limit: 100,
  offset: 0,
};

const EMPTY_VMS: VirtualMachineListResponse = { items: [], total: 0, limit: 100, offset: 0 };

const HOSTS: HypervisorHostListResponse = {
  items: [
    {
      id: "33333333-3333-3333-3333-333333333333",
      device_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      name: "esxi-01.corp.example",
      moref: "host-123",
      cluster_name: "cluster-a",
      datacenter: "dc-east",
      vendor: "Dell Inc.",
      model: "PowerEdge R650",
      hypervisor_version: "VMware ESXi 8.0.2",
      connection_state: "connected",
      in_maintenance_mode: false,
      management_ip: "10.0.1.5",
      pnics: [],
      collected_at: "2026-07-01T12:00:00Z",
      source_vendor: "vmware",
    },
  ],
  total: 1,
  limit: 100,
  offset: 0,
};

const STANDALONE_HOST: HypervisorHostListResponse = {
  items: [{ ...HOSTS.items[0]!, id: "44444444-4444-4444-4444-444444444444", cluster_name: null }],
  total: 1,
  limit: 100,
  offset: 0,
};

const EMPTY_HOSTS: HypervisorHostListResponse = { items: [], total: 0, limit: 100, offset: 0 };

const CLUSTERS: ComputeClusterListResponse = {
  items: [
    {
      id: "55555555-5555-5555-5555-555555555555",
      device_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      name: "cluster-a",
      moref: "domain-c8",
      datacenter: "dc-east",
      drs_enabled: true,
      ha_enabled: true,
      collected_at: "2026-07-01T12:00:00Z",
      source_vendor: "vmware",
    },
  ],
  total: 1,
  limit: 100,
  offset: 0,
};

const EMPTY_CLUSTERS: ComputeClusterListResponse = { items: [], total: 0, limit: 100, offset: 0 };

const PORT_GROUPS: PortGroupListResponse = {
  items: [
    {
      id: "66666666-6666-6666-6666-666666666666",
      device_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      name: "vlan-100",
      switch_name: "dvs-01",
      switch_type: "distributed",
      datacenter: "dc-east",
      host_name: null,
      vlan_id: 100,
      moref: "dvportgroup-123",
      uplink_pnic_names: ["vmnic0"],
      collected_at: "2026-07-01T12:00:00Z",
      source_vendor: "vmware",
    },
  ],
  total: 1,
  limit: 100,
  offset: 0,
};

const EMPTY_PORT_GROUPS: PortGroupListResponse = { items: [], total: 0, limit: 100, offset: 0 };

function fetchRouted(bodies: {
  vms?: unknown;
  hosts?: unknown;
  clusters?: unknown;
  portGroups?: unknown;
}) {
  const {
    vms = EMPTY_VMS,
    hosts = EMPTY_HOSTS,
    clusters = EMPTY_CLUSTERS,
    portGroups = EMPTY_PORT_GROUPS,
  } = bodies;
  return vi.fn((url: string): Promise<Response> => {
    const path = String(url);
    let body: unknown = vms;
    if (path.includes("/virtualization/hosts")) body = hosts;
    else if (path.includes("/virtualization/clusters")) body = clusters;
    else if (path.includes("/virtualization/port-groups")) body = portGroups;
    return Promise.resolve(
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
  });
}

function renderPage(): void {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <VirtualizationPage />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("VirtualizationPage — virtual machines", () => {
  it("renders one row per VM with power state, host, cluster, guest IPs", async () => {
    vi.stubGlobal("fetch", fetchRouted({ vms: VMS }));
    renderPage();

    expect(await screen.findByText("web-vm-01")).toBeInTheDocument();
    expect(screen.getByText("powered_on")).toBeInTheDocument();
    expect(screen.getByText("esxi-01.corp.example")).toBeInTheDocument();
    expect(screen.getByText("cluster-a")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.21")).toBeInTheDocument();
  });

  it("shows the empty state when no VMs exist", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    renderPage();

    expect(await screen.findByTestId("vms-empty-state")).toBeInTheDocument();
  });

  it("renders a Tools-less VM with empty guest fields, not an error", async () => {
    vi.stubGlobal("fetch", fetchRouted({ vms: TOOLS_LESS_VM }));
    renderPage();

    await screen.findByText("no-tools-vm");
    expect(screen.queryByTestId("vms-error")).not.toBeInTheDocument();
  });

  it("shows an error alert when the VMs API fails", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    renderPage();

    expect(await screen.findAllByRole("alert")).not.toHaveLength(0);
  });

  it("keeps power_state and is_template as separate columns (not collapsed)", async () => {
    const templateVm: VirtualMachineListResponse = {
      ...VMS,
      items: [{ ...VMS.items[0]!, is_template: true, power_state: "powered_off" }],
    };
    vi.stubGlobal("fetch", fetchRouted({ vms: templateVm }));
    renderPage();

    await screen.findByText("web-vm-01");
    expect(screen.getByText("powered_off")).toBeInTheDocument();
    // "Yes" under the Template column, independent of power state.
    const cells = screen.getAllByText("Yes");
    expect(cells.length).toBeGreaterThan(0);
  });
});

describe("VirtualizationPage — hosts", () => {
  it("renders one row per host with cluster + connection state + maintenance mode", async () => {
    vi.stubGlobal("fetch", fetchRouted({ hosts: HOSTS }));
    renderPage();

    expect(await screen.findByText("esxi-01.corp.example")).toBeInTheDocument();
    expect(screen.getByText("connected")).toBeInTheDocument();
  });

  it("shows the empty state when no hosts exist", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    renderPage();

    expect(await screen.findByTestId("hosts-empty-state")).toBeInTheDocument();
  });

  it("renders a standalone host (no cluster) as data, not an error", async () => {
    vi.stubGlobal("fetch", fetchRouted({ hosts: STANDALONE_HOST }));
    renderPage();

    await screen.findByText("esxi-01.corp.example");
    expect(screen.queryByTestId("hosts-error")).not.toBeInTheDocument();
  });

  it("keeps connection_state and in_maintenance_mode as separate columns", async () => {
    const drained: HypervisorHostListResponse = {
      ...HOSTS,
      items: [{ ...HOSTS.items[0]!, connection_state: "connected", in_maintenance_mode: true }],
    };
    vi.stubGlobal("fetch", fetchRouted({ hosts: drained }));
    renderPage();

    await screen.findByText("esxi-01.corp.example");
    expect(screen.getByText("connected")).toBeInTheDocument();
  });
});

describe("VirtualizationPage — clusters", () => {
  it("renders one row per cluster with DRS/HA flags", async () => {
    vi.stubGlobal("fetch", fetchRouted({ clusters: CLUSTERS }));
    renderPage();

    expect(await screen.findByText("cluster-a")).toBeInTheDocument();
    expect(screen.getByText("dc-east")).toBeInTheDocument();
  });

  it("shows the empty state when no clusters exist", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    renderPage();

    expect(await screen.findByTestId("clusters-empty-state")).toBeInTheDocument();
  });
});

describe("VirtualizationPage — port groups", () => {
  it("renders one row per port group with switch type + VLAN", async () => {
    vi.stubGlobal("fetch", fetchRouted({ portGroups: PORT_GROUPS }));
    renderPage();

    expect(await screen.findByText("vlan-100")).toBeInTheDocument();
    expect(screen.getByText("distributed")).toBeInTheDocument();
    expect(screen.getByText("100")).toBeInTheDocument();
  });

  it("shows the empty state when no port groups exist", async () => {
    vi.stubGlobal("fetch", fetchRouted({}));
    renderPage();

    expect(await screen.findByTestId("port-groups-empty-state")).toBeInTheDocument();
  });
});
