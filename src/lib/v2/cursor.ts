const CURSOR_SEPARATOR = "::";

export interface CursorPayload {
  id: string;
  updatedAt: string;
}

export function encodeCursor(payload: CursorPayload): string {
  const raw = `${payload.id}${CURSOR_SEPARATOR}${payload.updatedAt}`;
  return Buffer.from(raw, "utf8").toString("base64url");
}

export function decodeCursor(cursor?: string | null): CursorPayload | null {
  if (!cursor) return null;

  try {
    const decoded = Buffer.from(cursor, "base64url").toString("utf8");
    const [id, updatedAt] = decoded.split(CURSOR_SEPARATOR);
    if (!id || !updatedAt) return null;
    return { id, updatedAt };
  } catch {
    return null;
  }
}

export function parsePositiveInt(value: string | null, fallback: number, max = 200) {
  if (!value) return fallback;
  const parsed = Number.parseInt(value, 10);
  if (Number.isNaN(parsed) || parsed <= 0) return fallback;
  return Math.min(parsed, max);
}
