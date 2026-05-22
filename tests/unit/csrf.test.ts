import { beforeAll, describe, expect, it } from "vitest";

beforeAll(() => {
  process.env.NODE_ENV = "test";
  process.env.CSRF_SECRET = "csrf-test-secret-also-32-chars-plus-please";
});

function buildRequest(opts: {
  method: string;
  cookieToken?: string;
  headerToken?: string;
}): import("next/server").NextRequest {
  // Tiny stub matching the NextRequest surface used by verifyCsrf
  const cookies = new Map<string, { value: string }>();
  if (opts.cookieToken) cookies.set("cve_csrf", { value: opts.cookieToken });

  const headers = new Map<string, string>();
  if (opts.headerToken) headers.set("x-csrf-token", opts.headerToken);

  return {
    method: opts.method,
    cookies: {
      get: (name: string) => cookies.get(name),
    },
    headers: {
      get: (name: string) => headers.get(name.toLowerCase()) ?? null,
    },
  } as unknown as import("next/server").NextRequest;
}

describe("csrf", () => {
  it("issues a token shaped like nonce.signature", async () => {
    const { issueCsrfToken } = await import("@/lib/csrf");
    const token = issueCsrfToken();
    expect(token.split(".")).toHaveLength(2);
  });

  it("accepts safe methods without a token", async () => {
    const { verifyCsrf } = await import("@/lib/csrf");
    expect(verifyCsrf(buildRequest({ method: "GET" }))).toBe(true);
    expect(verifyCsrf(buildRequest({ method: "HEAD" }))).toBe(true);
    expect(verifyCsrf(buildRequest({ method: "OPTIONS" }))).toBe(true);
  });

  it("rejects state-changing requests without tokens", async () => {
    const { verifyCsrf } = await import("@/lib/csrf");
    expect(verifyCsrf(buildRequest({ method: "POST" }))).toBe(false);
    expect(verifyCsrf(buildRequest({ method: "PUT" }))).toBe(false);
    expect(verifyCsrf(buildRequest({ method: "DELETE" }))).toBe(false);
  });

  it("rejects mismatched cookie/header tokens", async () => {
    const { issueCsrfToken, verifyCsrf } = await import("@/lib/csrf");
    const t1 = issueCsrfToken();
    const t2 = issueCsrfToken();
    expect(verifyCsrf(buildRequest({ method: "POST", cookieToken: t1, headerToken: t2 }))).toBe(false);
  });

  it("rejects forged tokens (good nonce, bad signature)", async () => {
    const { verifyCsrf } = await import("@/lib/csrf");
    const forged = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA.deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    expect(
      verifyCsrf(buildRequest({ method: "POST", cookieToken: forged, headerToken: forged }))
    ).toBe(false);
  });

  it("accepts a matching, signed token pair", async () => {
    const { issueCsrfToken, verifyCsrf } = await import("@/lib/csrf");
    const t = issueCsrfToken();
    expect(verifyCsrf(buildRequest({ method: "POST", cookieToken: t, headerToken: t }))).toBe(true);
  });
});
