import { beforeAll, describe, expect, it } from "vitest";

// Set env vars before importing the module under test
beforeAll(() => {
  process.env.NODE_ENV = "test";
  process.env.ADMIN_AUTH_SECRET = "test-secret-with-enough-length-32-chars-plus";
  process.env.ADMIN_USERNAME = "testadmin";
  process.env.ADMIN_PASSWORD = "test-password-1234";
});

describe("admin-auth", () => {
  it("creates and verifies a valid session token round-trip", async () => {
    const { createAdminSessionToken } = await import("@/lib/admin-auth");

    const token = createAdminSessionToken("testadmin");
    expect(token).toContain(".");

    const [encodedPayload, signature] = token.split(".");
    expect(encodedPayload).toBeTruthy();
    expect(signature).toBeTruthy();

    // Decode payload manually
    const raw = Buffer.from(encodedPayload, "base64url").toString("utf8");
    const payload = JSON.parse(raw);
    expect(payload.username).toBe("testadmin");
    expect(typeof payload.exp).toBe("number");
    expect(payload.exp).toBeGreaterThan(Date.now());
  });

  it("verifies credentials correctly (good & bad)", async () => {
    const { verifyAdminCredentials } = await import("@/lib/admin-auth");

    expect(verifyAdminCredentials("testadmin", "test-password-1234")).toBe(true);
    expect(verifyAdminCredentials("testadmin", "wrong-password")).toBe(false);
    expect(verifyAdminCredentials("wrong-user", "test-password-1234")).toBe(false);
    expect(verifyAdminCredentials("", "")).toBe(false);
  });
});
