import { NextRequest, NextResponse } from "next/server";
import { isAdminAuthenticatedRequest } from "@/lib/admin-auth";
import { CSRF_COOKIE_NAME, csrfCookieOptions, issueCsrfToken } from "@/lib/csrf";

/**
 * Issues a CSRF token for the current admin session.
 * The frontend should call this once per page load (or per form mount)
 * and echo the returned token in the `x-csrf-token` header on every
 * subsequent state-changing request.
 */
export async function GET(request: NextRequest) {
  if (!isAdminAuthenticatedRequest(request)) {
    return NextResponse.json({ error: "Admin authentication required" }, { status: 401 });
  }

  const token = issueCsrfToken();
  const response = NextResponse.json({ token });
  response.cookies.set(CSRF_COOKIE_NAME, token, csrfCookieOptions());
  return response;
}
