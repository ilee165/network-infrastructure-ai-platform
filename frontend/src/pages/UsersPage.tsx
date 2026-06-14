/**
 * UsersPage (Auth & Account UI): admin-only account management.
 *
 * Placeholder shell introduced by the routing task (F2) so the ``/users`` route
 * resolves under ``RoleRoute("admin")``. The account table, create-with-temp-
 * password, role edit, activate/deactivate, reset password, and session revoke
 * controls are delivered by the user-management task.
 */

import { PageHeader } from "../components/PageHeader";

export function UsersPage() {
  return (
    <div className="flex flex-col gap-6" data-testid="users-page">
      <PageHeader
        title="Users"
        description="Create accounts, assign roles, and manage access (admin only)."
      />
    </div>
  );
}
