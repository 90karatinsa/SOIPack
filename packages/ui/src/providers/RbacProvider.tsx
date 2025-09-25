import type { ReactNode } from 'react';
import { createContext, useContext, useMemo } from 'react';

type Role = string;

interface RbacContextValue {
  roles: Set<Role>;
}

const RbacContext = createContext<RbacContextValue>({ roles: new Set() });

export function RbacProvider({ roles = [], children }: { roles?: Role[]; children: ReactNode }) {
  const value = useMemo<RbacContextValue>(() => ({ roles: new Set(roles) }), [roles]);
  return <RbacContext.Provider value={value}>{children}</RbacContext.Provider>;
}

export function useRbac() {
  return useContext(RbacContext);
}

export function RoleGate({ role, children }: { role: Role | Role[]; children: ReactNode }) {
  const { roles } = useRbac();
  const required = Array.isArray(role) ? role : [role];
  const hasRoles = roles.size > 0;
  const isAllowed = required.some((item) => roles.has(item));
  if (!hasRoles || isAllowed) {
    return <>{children}</>;
  }
  return null;
}
