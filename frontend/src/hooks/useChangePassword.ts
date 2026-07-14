import { useMutation, useQueryClient } from "@tanstack/react-query";
import { changePassword, getMe } from "../api/auth";
import { useAuthStore } from "../stores/auth";
import { queryKeys } from "./queryKeys";

export const MIN_PASSWORD_LENGTH = 8;
export function validatePasswordChange(next: string, confirm: string): { next?: string; confirm?: string } {
  if (next.length < MIN_PASSWORD_LENGTH) return { next: `New password must be at least ${MIN_PASSWORD_LENGTH} characters.` };
  if (next !== confirm) return { confirm: "New password and confirmation do not match." };
  return {};
}

export function useChangePassword(options: { bestEffortRefresh?: boolean } = {}) {
  const setUser = useAuthStore((state) => state.setUser);
  const client = useQueryClient();
  return useMutation({
    mutationFn: async ({ current, next }: { current: string; next: string }) => {
      await changePassword(current, next);
      try {
        const user = await getMe();
        setUser(user);
        client.setQueryData(queryKeys.auth.me, user);
      } catch (error) {
        if (!options.bestEffortRefresh) throw error;
        const cached = useAuthStore.getState().user;
        if (cached) setUser({ ...cached, must_change_password: false });
      }
    },
  });
}
