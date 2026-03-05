import type { NextRequest } from "next/server";
import { UserRole } from "@prisma/client";
import { db } from "@/lib/db";

export interface ActorContext {
  id: string;
  email: string;
  role: UserRole;
}

const SYSTEM_ACTOR: ActorContext = {
  id: "system",
  email: "system@local",
  role: UserRole.ADMIN,
};

export async function getActor(request: NextRequest): Promise<ActorContext> {
  const userId = request.headers.get("x-user-id");
  const email = request.headers.get("x-user-email");

  if (!userId && !email) {
    return SYSTEM_ACTOR;
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

export function hasRole(actor: ActorContext, roles: UserRole[]) {
  return roles.includes(actor.role);
}
