const CSRF_COOKIE_NAME = "cve_csrf";
const CSRF_HEADER_NAME = "x-csrf-token";
const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

let csrfFetchPromise: Promise<string | null> | null = null;

function readCsrfCookie(): string | null {
  if (typeof document === "undefined") return null;
  const parts = document.cookie.split("; ");
  for (const p of parts) {
    const [k, v] = p.split("=");
    if (k === CSRF_COOKIE_NAME && v) return decodeURIComponent(v);
  }
  return null;
}

/**
 * Ensures we have a CSRF token in the cookie. Issued on demand from
 * /api/admin/csrf for authenticated admins. Cached as a promise to dedupe
 * concurrent calls during first render.
 */
async function ensureCsrfToken(): Promise<string | null> {
  const existing = readCsrfCookie();
  if (existing) return existing;
  if (csrfFetchPromise) return csrfFetchPromise;

  csrfFetchPromise = (async () => {
    try {
      const r = await fetch("/api/admin/csrf", { credentials: "same-origin" });
      if (!r.ok) return null;
      const json = (await r.json().catch(() => null)) as { token?: string } | null;
      return json?.token ?? readCsrfCookie();
    } catch {
      return null;
    } finally {
      // allow refresh on next call after this resolves
      setTimeout(() => {
        csrfFetchPromise = null;
      }, 1000);
    }
  })();
  return csrfFetchPromise;
}

export async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const method = (init?.method ?? "GET").toUpperCase();
  const headers = new Headers(init?.headers ?? {});
  if (!headers.has("Content-Type")) headers.set("Content-Type", "application/json");

  // Attach CSRF token on state-changing requests targeting our own admin API.
  if (MUTATING_METHODS.has(method) && url.startsWith("/api/admin/")) {
    const token = await ensureCsrfToken();
    if (token && !headers.has(CSRF_HEADER_NAME)) {
      headers.set(CSRF_HEADER_NAME, token);
    }
  }

  const response = await fetch(url, {
    ...init,
    headers,
    credentials: init?.credentials ?? "same-origin",
  });

  if (!response.ok) {
    const message = await safeReadError(response);
    throw new Error(message || `HTTP ${response.status}`);
  }

  return response.json() as Promise<T>;
}

async function safeReadError(response: Response) {
  try {
    const data = await response.json();
    if (typeof data?.error === "string") return data.error;
    if (typeof data?.message === "string") return data.message;
  } catch {
    return null;
  }
  return null;
}
