import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { NextRequest } from "next/server";

/**
 * Double-submit cookie CSRF protection.
 *
 *  1. On any GET that an admin makes to a page that renders a form,
 *     call `issueCsrfCookie()` from the server component / route handler
 *     to set the `cve_csrf` cookie (readable by JS so the page can echo it
 *     back).
 *  2. The client must send the same value back in the `x-csrf-token` header
 *     on every state-changing request (POST/PUT/PATCH/DELETE).
 *  3. Use `verifyCsrf(request)` in mutating admin route handlers — it
 *     compares cookie and header in constant time, both signed with HMAC
 *     so an attacker can't forge a valid pair without the secret.
 *
 * Combined with `SameSite=Strict` on the session cookie this gives
 * defense-in-depth: SameSite blocks the cross-site request from carrying
 * the session, and the double-submit token blocks any leaked-cookie scenario.
 */

export const CSRF_COOKIE_NAME = "cve_csrf";
export const CSRF_HEADER_NAME = "x-csrf-token";

const TOKEN_LIFETIME_SECONDS = 8 * 60 * 60;
const IS_PROD = process.env.NODE_ENV === "production";

function getSecret(): string {
  const secret = process.env.CSRF_SECRET || process.env.ADMIN_AUTH_SECRET || process.env.NEXTAUTH_SECRET;
  if (!secret) {
    if (IS_PROD) throw new Error("[csrf] CSRF_SECRET (or ADMIN_AUTH_SECRET) is required in production");
    return "csrf-dev-secret-CHANGE-ME";
  }
  return secret;
}

function sign(payload: string): string {
  return createHmac("sha256", getSecret()).update(payload).digest("base64url");
}

export function issueCsrfToken(): string {
  const nonce = randomBytes(24).toString("base64url");
  return `${nonce}.${sign(nonce)}`;
}

export function csrfCookieOptions() {
  return {
    httpOnly: false, // client JS needs to read & re-send it
    secure: IS_PROD,
    sameSite: "strict" as const,
    path: "/",
    maxAge: TOKEN_LIFETIME_SECONDS,
  };
}

function isValidToken(token: string | null | undefined): boolean {
  if (!token || typeof token !== "string") return false;
  const [nonce, signature] = token.split(".");
  if (!nonce || !signature) return false;
  const expected = sign(nonce);
  const a = Buffer.from(signature, "base64url");
  const b = Buffer.from(expected, "base64url");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export function verifyCsrf(request: NextRequest): boolean {
  const method = request.method.toUpperCase();
  // Safe methods don't need CSRF protection
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") return true;

  const cookieToken = request.cookies.get(CSRF_COOKIE_NAME)?.value;
  const headerToken = request.headers.get(CSRF_HEADER_NAME);

  if (!cookieToken || !headerToken) return false;
  if (!isValidToken(cookieToken) || !isValidToken(headerToken)) return false;

  // Double-submit: cookie and header must match exactly
  const a = Buffer.from(cookieToken, "utf8");
  const b = Buffer.from(headerToken, "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
