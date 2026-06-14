/**
 * ProfilePage (Auth & Account UI): self-service account view.
 *
 * Placeholder shell introduced by the routing task (F2) so the ``/profile``
 * route resolves. Profile info + edit, password change, sessions list/revoke,
 * and the own-audit view are delivered by the profile task.
 */

import { PageHeader } from "../components/PageHeader";

export function ProfilePage() {
  return (
    <div className="flex flex-col gap-6" data-testid="profile-page">
      <PageHeader
        title="Profile"
        description="Your account details, sessions, and password."
      />
    </div>
  );
}
