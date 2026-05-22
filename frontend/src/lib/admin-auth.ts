import { createHmac, timingSafeEqual } from "node:crypto";
import type { NextRequest } from "next/server";

export const ADMIN_SESSION_COOKIE_NAME = "cve_admin_session";

const DEFAULT_ADMIN_USERNAME = "admin";
const DEV_ADMIN_PASSWORD = "admin123!";
const DEV_SECRET = "cve-tracker-admin-dev-secret-CHANGE-ME";
const ADMIN_SESSION_TTL_SECONDS = 8 * 60 * 60;

const IS_PROD = process.env.NODE_ENV === "production";

type AdminSessionPayload = {
  username: string;
  exp: number;
};

function getSecret(): string {
  const secret = process.env.ADMIN_AUTH_SECRET || process.env.NEXTAUTH_SECRET;
  if (!secret) {
    if (IS_PROD) {
      throw new Error(
        "[admin-auth] ADMIN_AUTH_SECRET (or NEXTAUTH_SECRET) is required in production"
      );
    }
    // Dev fallback only — never used in production
    console.warn(
      "[admin-auth] Using insecure DEV secret — set ADMIN_AUTH_SECRET in .env for any real deployment"
    );
    return DEV_SECRET;
  }
  if (secret.length < 32) {
    if (IS_PROD) {
      throw new Error("[admin-auth] ADMIN_AUTH_SECRET must be at least 32 chars in production");
    }
    console.warn("[admin-auth] ADMIN_AUTH_SECRET is shorter than 32 chars — use a longer one");
  }
  return secret;
}

function getAdminPassword(): string {
  const pw = process.env.ADMIN_PASSWORD;
  if (!pw) {
    if (IS_PROD) {
      throw new Error("[admin-auth] ADMIN_PASSWORD is required in production");
    }
    console.warn(
      "[admin-auth] Using default DEV admin password — set ADMIN_PASSWORD in .env for any real deployment"
    );
    return DEV_ADMIN_PASSWORD;
  }
  if (IS_PROD && pw.length < 12) {
    throw new Error("[admin-auth] ADMIN_PASSWORD must be at least 12 chars in production");
  }
  return pw;
}

export function getAdminUsername(): string {
  return process.env.ADMIN_USERNAME || DEFAULT_ADMIN_USERNAME;
}

function safeCompare(left: string, right: string): boolean {
  const secret = getSecret();
  const leftDigest = createHmac("sha256", secret).update(left).digest();
  const rightDigest = createHmac("sha256", secret).update(right).digest();
  return timingSafeEqual(leftDigest, rightDigest);
}

function encodePayload(payload: AdminSessionPayload): string {
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
}

function decodePayload(encoded: string): AdminSessionPayload | null {
  try {
    const raw = Buffer.from(encoded, "base64url").toString("utf8");
    const parsed = JSON.parse(raw) as AdminSessionPayload;
    if (!parsed || typeof parsed.username !== "string" || typeof parsed.exp !== "number") {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function sign(encodedPayload: string): string {
  return createHmac("sha256", getSecret()).update(encodedPayload).digest("base64url");
}

function parseSessionToken(token?: string | null): AdminSessionPayload | null {
  if (!token) return null;

  const [encodedPayload, signature] = token.split(".");
  if (!encodedPayload || !signature) return null;

  const expected = sign(encodedPayload);
  if (!safeCompare(signature, expected)) return null;

  const payload = decodePayload(encodedPayload);
  if (!payload) return null;

  if (payload.exp <= Date.now()) return null;
  return payload;
}

export function createAdminSessionToken(username: string): string {
  const payload: AdminSessionPayload = {
    username,
    exp: Date.now() + ADMIN_SESSION_TTL_SECONDS * 1000,
  };
  const encodedPayload = encodePayload(payload);
  const signature = sign(encodedPayload);
  return `${encodedPayload}.${signature}`;
}

export function verifyAdminCredentials(username: string, password: string): boolean {
  return safeCompare(username, getAdminUsername()) && safeCompare(password, getAdminPassword());
}

export function getAdminSessionFromRequest(request: NextRequest) {
  const token = request.cookies.get(ADMIN_SESSION_COOKIE_NAME)?.value;
  return parseSessionToken(token);
}

export function isAdminAuthenticatedRequest(request: NextRequest): boolean {
  return getAdminSessionFromRequest(request) !== null;
}

export function getAdminCookieOptions() {
  return {
    httpOnly: true,
    secure: IS_PROD,
    // Strict prevents cross-site form POST CSRF on admin endpoints
    sameSite: "strict" as const,
    path: "/",
    maxAge: ADMIN_SESSION_TTL_SECONDS,
  };
}
