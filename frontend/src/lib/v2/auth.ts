import type { NextRequest } from "next/server";
import { UserRole } from "@prisma/client";
import { db } from "@/lib/db";
import { getAdminSessionFromRequest } from "@/lib/admin-auth";

export interface ActorContext {
  id: string;
  email: string;
  role: UserRole;
}

const SYSTEM_ACTOR: ActorContext = {
  id: "system",
  email: "anonymous@local",
  role: UserRole.VIEWER,
};

// Trusted upstream service (Network Scanner Pro, SIEM Léger) authenticated
// solely via the X-Internal-Auth shared secret, with no x-user-* identity.
// Granted the API role so service-to-service endpoints (e.g. /api/v2/sync/cpe)
// accept it. Its id is a pseudo-actor — see audit.ts PSEUDO_ACTOR_IDS.
const SERVICE_ACTOR: ActorContext = {
  id: "service",
  email: "service@local",
  role: UserRole.API,
};

/**
 * True only when the request carries an X-Internal-Auth header that matches
 * the configured INTERNAL_API_SHARED_SECRET. Unlike isInternalHeaderAuthorized,
 * this is strict in every environment: a missing/unset secret never matches.
 */
function internalSecretMatches(request: NextRequest): boolean {
  const expected = process.env.INTERNAL_API_SHARED_SECRET;
  if (!expected) return false;
  const provided = request.headers.get("x-internal-auth");
  return Boolean(provided) && provided === expected;
}

const IS_PROD = process.env.NODE_ENV === "production";

/**
 * In production, x-user-id / x-user-email are not trusted by themselves.
 * They must be accompanied by a shared internal secret (X-Internal-Auth)
 * to prove the headers come from a trusted upstream (e.g. an authenticated
 * service-mesh hop or an API gateway you control), not from the public edge
 * where Nginx strips them.
 *
 * In development they are allowed without the shared secret to keep the
 * existing tests and local tooling working.
 */
function isInternalHeaderAuthorized(request: NextRequest): boolean {
  if (!IS_PROD) return true;
  const provided = request.headers.get("x-internal-auth");
  const expected = process.env.INTERNAL_API_SHARED_SECRET;
  if (!expected) return false;
  return Boolean(provided) && provided === expected;
}

export async function getActor(request: NextRequest): Promise<ActorContext> {
  // 1) Admin session cookie (signed) always wins
  const adminSession = getAdminSessionFromRequest(request);
  if (adminSession) {
    return {
      id: "admin-session",
      email: `${adminSession.username}@local`,
      role: UserRole.ADMIN,
    };
  }

  // 2) Trusted service-to-service call: a valid X-Internal-Auth secret
  //    authenticates an upstream service (Scanner, SIEM) as an API actor,
  //    even when it carries no x-user-* identity headers.
  const serviceAuthenticated = internalSecretMatches(request);

  // 3) Header-based identity (only with a trusted shared secret in prod)
  if (!isInternalHeaderAuthorized(request)) {
    return SYSTEM_ACTOR;
  }

  const userId = request.headers.get("x-user-id");
  const email = request.headers.get("x-user-email");

  if (!userId && !email) {
    // No user identity supplied. If the request proved it came from a trusted
    // service via the shared secret, treat it as the API service principal;
    // otherwise it's anonymous.
    return serviceAuthenticated ? SERVICE_ACTOR : SYSTEM_ACTOR;
  }

  const user = await db.user.findFirst({
    where: {
      OR: [
        ...(userId ? [{ id: userId }] : []),
        ...(email ? [{ email }] : []),
      ],
    },
    select: {
      id: true,
      email: true,
      role: true,
    },
  });

  if (!user) {
    return SYSTEM_ACTOR;
  }

  return {
    id: user.id,
    email: user.email,
    role: user.role,
  };
}

export function hasRole(actor: ActorContext, roles: UserRole[]): boolean {
  return roles.includes(actor.role);
}
