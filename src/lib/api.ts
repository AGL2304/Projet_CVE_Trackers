export async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
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
