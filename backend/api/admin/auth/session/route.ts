import { NextRequest, NextResponse } from "next/server";
import { getAdminSessionFromRequest } from "@/lib/admin-auth";

export async function GET(request: NextRequest) {
  const session = getAdminSessionFromRequest(request);
  if (!session) {
    return NextResponse.json({
      authenticated: false,
      username: null,
    });
  }

  return NextResponse.json({
    authenticated: true,
    username: session.username,
  });
}
