import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import type { FormEvent } from "react";

import {
  createCredential,
  disableCredential,
  getRotationStatus,
  listCredentials,
  rotateCredential,
  type CredentialKind,
  type CredentialRead,
} from "../../api/credentials";
import { messageFor } from "../../components/ErrorBanner";
import { FormField } from "../../components/FormField";
import { Modal } from "../../components/Modal";
import { Pagination } from "../../components/Pagination";
import { Spinner } from "../../components/Skeleton";
import { StatusPill } from "../../components/StatusPill";
import { useAuthStore } from "../../stores/auth";
import { hasMinimumRole } from "../../stores/roles";

/** Page size for the credential vault table (server-side offset/limit). */
const CREDENTIALS_PAGE_SIZE = 50;

const CREDENTIAL_KINDS: { value: CredentialKind; label: string }[] = [
  { value: "ssh", label: "SSH" },
  { value: "snmp_v2c", label: "SNMP v2c" },
  { value: "snmp_v3", label: "SNMP v3" },
  { value: "oidc", label: "OIDC client secret" },
];

export function SettingsCredentialsSection() {
  const queryClient = useQueryClient();
  const canWrite = hasMinimumRole(useAuthStore((s) => s.user?.role), "engineer");

  const [offset, setOffset] = useState(0);
  const { data, isPending, error: loadError } = useQuery({
    queryKey: ["credentials", offset],
    queryFn: () => listCredentials({ limit: CREDENTIALS_PAGE_SIZE, offset }),
  });

  const {
    data: rotation,
    isPending: rotationPending,
    error: rotationError,
  } = useQuery({
    queryKey: ["credentials-rotation-status"],
    queryFn: getRotationStatus,
    // engineer+ only: viewers never mount this section (RoleRoute).
    enabled: canWrite,
  });

  const [name, setName] = useState("");
  const [kind, setKind] = useState<CredentialKind>("ssh");
  const [username, setUsername] = useState("");
  const [secret, setSecret] = useState("");
  const [scopeSite, setScopeSite] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [formSuccess, setFormSuccess] = useState<string | null>(null);

  const [rotateId, setRotateId] = useState<string | null>(null);
  const [rotateSecret, setRotateSecret] = useState("");
  const [rotateError, setRotateError] = useState<string | null>(null);
  const [rotateSuccess, setRotateSuccess] = useState<string | null>(null);

  const [disableTarget, setDisableTarget] = useState<CredentialRead | null>(null);
  const [disableError, setDisableError] = useState<string | null>(null);
  const [disableSuccess, setDisableSuccess] = useState<string | null>(null);

  const createMutation = useMutation({
    mutationFn: () =>
      createCredential({
        name: name.trim(),
        kind,
        username: username.trim() || null,
        secret,
        scope_site: scopeSite.trim() || null,
      }),
    onSuccess: (created) => {
      setFormSuccess(`Credential “${created.name}” created. The secret is not shown again.`);
      setFormError(null);
      setName("");
      setUsername("");
      setSecret("");
      setScopeSite("");
      setOffset(0);
      void queryClient.invalidateQueries({ queryKey: ["credentials"] });
    },
    onError: (err) => {
      setFormError(messageFor(err));
      setFormSuccess(null);
    },
  });

  const rotateMutation = useMutation({
    mutationFn: () => {
      if (!rotateId) {
        throw new Error("missing credential id");
      }
      return rotateCredential(rotateId, { secret: rotateSecret });
    },
    onSuccess: (updated) => {
      setRotateSuccess(`Rotated “${updated.name}”. The new secret is not shown again.`);
      setRotateError(null);
      setRotateId(null);
      setRotateSecret("");
      void queryClient.invalidateQueries({ queryKey: ["credentials"] });
    },
    onError: (err) => {
      setRotateError(messageFor(err));
      setRotateSuccess(null);
    },
  });

  const disableMutation = useMutation({
    mutationFn: () => {
      if (!disableTarget) {
        throw new Error("missing credential id");
      }
      return disableCredential(disableTarget.id);
    },
    onSuccess: () => {
      const label = disableTarget?.name ?? "credential";
      setDisableSuccess(
        `Disabled “${label}”. The name is free for a new vault entry; the secret cannot be used again.`,
      );
      setDisableError(null);
      setDisableTarget(null);
      void queryClient.invalidateQueries({ queryKey: ["credentials"] });
    },
    onError: (err) => {
      setDisableError(messageFor(err));
      setDisableSuccess(null);
    },
  });

  function handleCreate(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setFormError(null);
    setFormSuccess(null);
    if (!name.trim() || !secret) {
      setFormError("Name and secret are required.");
      return;
    }
    createMutation.mutate();
  }

  function handleRotate(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setRotateError(null);
    setRotateSuccess(null);
    if (!rotateSecret) {
      setRotateError("New secret is required.");
      return;
    }
    rotateMutation.mutate();
  }

  return (
    <section
      aria-label="Device credentials"
      data-testid="settings-credentials"
      className="flex flex-col gap-4"
    >
      <div className="panel p-4 flex flex-col gap-2">
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          Device credentials
        </h3>
        <p className="text-sm text-zinc-300">
          Vault entries used by discovery, config backup, and agent tools. Secrets
          are write-only: stored under envelope encryption and never returned by
          the API. Use the credential <em>name</em> when launching discovery on
          Devices.
        </p>
      </div>

      {canWrite && (
        <div
          className="panel p-4 flex flex-col gap-2"
          data-testid="credentials-kek-rotation"
        >
          <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
            KEK rotation status
          </h3>
          <p className="text-xs text-zinc-400">
            Envelope-key rewrap progress (versions and pending row count only —
            no key material).
          </p>
          {rotationPending && (
            <p role="status" className="text-xs text-zinc-500">
              Loading rotation status…
            </p>
          )}
          {rotationError && (
            <p role="alert" className="text-xs text-status-error">
              {messageFor(rotationError)}
            </p>
          )}
          {rotation && (
            <div className="flex flex-wrap items-center gap-2 text-xs text-zinc-300">
              <StatusPill
                variant={rotation.rows_pending > 0 ? "warn" : "ok"}
                data-testid="kek-rows-pending-pill"
              >
                {rotation.rows_pending > 0
                  ? `${rotation.rows_pending} pending`
                  : "fully wrapped"}
              </StatusPill>
              <span>
                Active KEK:{" "}
                <code className="font-mono text-zinc-200">{rotation.to_version}</code>
              </span>
              {rotation.from_version != null && (
                <span>
                  Migrating from:{" "}
                  <code className="font-mono text-zinc-200">
                    {rotation.from_version}
                  </code>
                </span>
              )}
            </div>
          )}
        </div>
      )}

      {isPending && (
        <p role="status" className="flex items-center gap-2 text-xs text-zinc-500">
          <Spinner /> Loading credentials…
        </p>
      )}
      {loadError && (
        <p role="alert" className="text-xs text-status-error">
          {messageFor(loadError)}
        </p>
      )}

      {data && (
        <div className="panel overflow-x-auto">
          <table className="w-full min-w-[32rem] text-left text-xs">
            <thead className="border-b border-carbon-800 font-mono text-[10px] uppercase tracking-widest text-zinc-500">
              <tr>
                <th className="px-3 py-2">Name</th>
                <th className="px-3 py-2">Kind</th>
                <th className="px-3 py-2">Username</th>
                <th className="px-3 py-2">Scope</th>
                <th className="px-3 py-2">Updated</th>
                {canWrite && <th className="px-3 py-2">Actions</th>}
              </tr>
            </thead>
            <tbody>
              {data.items.length === 0 ? (
                <tr>
                  <td
                    colSpan={canWrite ? 6 : 5}
                    className="px-3 py-6 text-center text-zinc-500"
                  >
                    No credentials yet. Create one below for discovery to use.
                  </td>
                </tr>
              ) : (
                data.items.map((row: CredentialRead) => (
                  <tr key={row.id} className="border-b border-carbon-900/80">
                    <td className="px-3 py-2 font-mono text-zinc-100">{row.name}</td>
                    <td className="px-3 py-2 text-zinc-400">{row.kind}</td>
                    <td className="px-3 py-2 text-zinc-400">{row.username ?? "—"}</td>
                    <td className="px-3 py-2 text-zinc-500">
                      {row.scope_site || row.scope_role || row.scope_device_group
                        ? [row.scope_site, row.scope_role, row.scope_device_group]
                            .filter(Boolean)
                            .join(" / ")
                        : "unscoped"}
                    </td>
                    <td className="px-3 py-2 font-mono text-[10px] text-zinc-500">
                      {new Date(row.updated_at).toLocaleString()}
                    </td>
                    {canWrite && (
                      <td className="px-3 py-2">
                        <div className="flex flex-wrap gap-2">
                          <button
                            type="button"
                            className="text-accent hover:underline"
                            onClick={() => {
                              setRotateId(row.id);
                              setRotateSecret("");
                              setRotateError(null);
                              setRotateSuccess(null);
                            }}
                          >
                            Rotate
                          </button>
                          <button
                            type="button"
                            className="text-status-error hover:underline"
                            data-testid={`credential-disable-${row.id}`}
                            onClick={() => {
                              setDisableTarget(row);
                              setDisableError(null);
                              setDisableSuccess(null);
                            }}
                          >
                            Disable
                          </button>
                        </div>
                      </td>
                    )}
                  </tr>
                ))
              )}
            </tbody>
          </table>
          <p className="border-t border-carbon-800 px-3 py-2 text-[11px] text-zinc-600">
            {data.total} total
          </p>
          <Pagination
            offset={offset}
            limit={CREDENTIALS_PAGE_SIZE}
            total={data.total}
            onChange={setOffset}
            label="credentials"
          />
        </div>
      )}

      {canWrite && rotateId && (
        <form
          onSubmit={handleRotate}
          className="panel p-4 flex flex-col gap-3"
          data-testid="credential-rotate-form"
          noValidate
        >
          <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
            Rotate secret
          </h3>
          <FormField label="New secret" required>
            {(cp) => (
              <input
                {...cp}
                type="password"
                autoComplete="new-password"
                className="input"
                value={rotateSecret}
                onChange={(e) => setRotateSecret(e.target.value)}
              />
            )}
          </FormField>
          {rotateError && (
            <p role="alert" className="text-xs text-status-error">
              {rotateError}
            </p>
          )}
          <div className="flex gap-2">
            <button type="submit" className="btn" disabled={rotateMutation.isPending}>
              {rotateMutation.isPending ? "Rotating…" : "Confirm rotate"}
            </button>
            <button
              type="button"
              className="rounded border border-carbon-700 px-3 py-1.5 text-xs text-zinc-400"
              onClick={() => setRotateId(null)}
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      {rotateSuccess && (
        <p className="text-xs text-status-ok" role="status">
          {rotateSuccess}
        </p>
      )}

      {canWrite && disableTarget && (
        <Modal aria-label="Confirm disable credential" data-testid="credential-disable-dialog">
            <p className="text-sm text-zinc-200">
              Disable credential “{disableTarget.name}”? It will disappear from
              this list, the name can be reused, and discovery/tools can no longer
              decrypt it. This does not hard-delete the vault row.
            </p>
            {disableError ? (
              <p role="alert" className="mt-3 text-xs text-status-error">
                {disableError}
              </p>
            ) : null}
            <div className="mt-5 flex justify-end gap-3">
              <button
                type="button"
                onClick={() => setDisableTarget(null)}
                disabled={disableMutation.isPending}
                className="rounded border border-carbon-700 px-3 py-1.5 text-xs text-zinc-400 transition-colors hover:border-carbon-600 hover:text-zinc-100 disabled:opacity-60"
              >
                Cancel
              </button>
              <button
                type="button"
                data-testid="confirm-disable-credential"
                onClick={() => disableMutation.mutate()}
                disabled={disableMutation.isPending}
                className="rounded bg-status-error px-3 py-1.5 text-xs font-medium text-white transition-opacity hover:opacity-90 disabled:opacity-60"
              >
                {disableMutation.isPending ? "Disabling…" : "Confirm disable"}
              </button>
            </div>
        </Modal>
      )}

      {disableSuccess && (
        <p className="text-xs text-status-ok" role="status">
          {disableSuccess}
        </p>
      )}

      {canWrite && (
        <form
          onSubmit={handleCreate}
          className="panel p-4 flex flex-col gap-3"
          data-testid="credential-create-form"
          noValidate
        >
          <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
            Create credential
          </h3>
          <FormField label="Name" required>
            {(cp) => (
              <input
                {...cp}
                className="input"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="prod-ssh"
                autoComplete="off"
              />
            )}
          </FormField>
          <FormField label="Kind" required>
            {(cp) => (
              <select
                {...cp}
                className="input"
                value={kind}
                onChange={(e) => setKind(e.target.value as CredentialKind)}
              >
                {CREDENTIAL_KINDS.map((k) => (
                  <option key={k.value} value={k.value}>
                    {k.label}
                  </option>
                ))}
              </select>
            )}
          </FormField>
          <FormField label="Username">
            {(cp) => (
              <input
                {...cp}
                className="input"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="off"
              />
            )}
          </FormField>
          <FormField label="Secret" required>
            {(cp) => (
              <input
                {...cp}
                type="password"
                className="input"
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                autoComplete="new-password"
              />
            )}
          </FormField>
          <FormField label="Scope site (optional)">
            {(cp) => (
              <input
                {...cp}
                className="input"
                value={scopeSite}
                onChange={(e) => setScopeSite(e.target.value)}
                placeholder="Leave empty for unscoped"
              />
            )}
          </FormField>
          {formError && (
            <p role="alert" className="text-xs text-status-error">
              {formError}
            </p>
          )}
          {formSuccess && (
            <p className="text-xs text-status-ok" role="status">
              {formSuccess}
            </p>
          )}
          <button type="submit" className="btn self-start" disabled={createMutation.isPending}>
            {createMutation.isPending ? "Creating…" : "Create credential"}
          </button>
        </form>
      )}
    </section>
  );
}
