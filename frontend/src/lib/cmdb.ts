type SupportedCriticality = "low" | "medium" | "high" | "critical";
type SupportedStatus = "active" | "inactive" | "retired";
type UnknownRecord = Record<string, unknown>;

export type CmdbAssetInput = {
  name: string;
  type: string;
  ip: string | null;
  hostname: string | null;
  description: string | null;
  criticality: SupportedCriticality;
  status: SupportedStatus;
};

function toNormalizedString(value: unknown) {
  if (typeof value === "string" && value.trim().length > 0) {
    return value.trim();
  }
  return "";
}

function toObjectLabel(value: unknown) {
  if (!value || typeof value !== "object") return "";
  const source = value as UnknownRecord;
  const keys = ["status_meta", "name", "label", "title", "value", "display_name"];

  for (const key of keys) {
    const found = toNormalizedString(source[key]);
    if (found) return found;
  }

  return "";
}

function firstString(source: UnknownRecord, keys: string[]) {
  for (const key of keys) {
    const fromValue = toNormalizedString(source[key]);
    if (fromValue) return fromValue;

    const fromObject = toObjectLabel(source[key]);
    if (fromObject) return fromObject;
  }
  return "";
}

function firstNestedString(source: UnknownRecord, paths: string[][]) {
  for (const path of paths) {
    let cursor: unknown = source;
    let broken = false;

    for (const segment of path) {
      if (!cursor || typeof cursor !== "object") {
        broken = true;
        break;
      }

      cursor = (cursor as UnknownRecord)[segment];
    }

    if (broken) continue;

    const fromValue = toNormalizedString(cursor);
    if (fromValue) return fromValue;

    const fromObject = toObjectLabel(cursor);
    if (fromObject) return fromObject;
  }
  return "";
}

function normalizeCriticality(value: string): SupportedCriticality {
  const lowered = value.toLowerCase();
  if (lowered.includes("critical")) return "critical";
  if (lowered.includes("high")) return "high";
  if (lowered.includes("low")) return "low";
  return "medium";
}

function normalizeStatus(value: string): SupportedStatus {
  const lowered = value.toLowerCase();
  if (lowered.includes("retired") || lowered.includes("decommissioned")) return "retired";
  if (lowered.includes("inactive") || lowered.includes("down")) return "inactive";
  return "active";
}

function getArrayPayload(payload: unknown) {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== "object") return [];
  const objectPayload = payload as Record<string, unknown>;

  const candidates = ["items", "assets", "data", "results", "records", "rows"];
  for (const key of candidates) {
    const candidate = objectPayload[key];
    if (Array.isArray(candidate)) return candidate;
  }
  return [];
}

function mapRawAsset(raw: unknown, index: number): CmdbAssetInput | null {
  if (!raw || typeof raw !== "object") return null;
  const source = raw as Record<string, unknown>;

  const nameFromNested =
    firstNestedString(source, [
      ["asset", "name"],
      ["model", "name"],
      ["asset_model", "name"],
      ["category", "name"],
    ]) || firstString(source, ["asset_tag", "serial", "id"]);

  const name =
    firstString(source, ["name", "asset_name", "assetName", "display_name", "displayName", "hostname"]) ||
    nameFromNested ||
    `cmdb-asset-${index + 1}`;
  const type =
    firstString(source, ["type", "asset_type", "assetType", "class", "category"]) ||
    firstNestedString(source, [
      ["model", "category", "name"],
      ["model", "name"],
      ["asset_model", "name"],
      ["category", "name"],
    ]) ||
    "hardware";
  const ip = firstString(source, ["ip", "ip_address", "ipAddress"]) || "";
  const hostname = firstString(source, ["hostname", "host", "dns", "fqdn", "asset_tag", "serial"]) || "";
  const description =
    firstString(source, ["description", "details", "notes", "note"]) ||
    firstNestedString(source, [
      ["model", "name"],
      ["status_label", "name"],
    ]) ||
    "";
  const criticality = normalizeCriticality(
    firstString(source, ["criticality", "priority", "impact", "business_impact", "businessImpact", "severity"]) ||
      "medium"
  );
  const status = normalizeStatus(
    firstNestedString(source, [
      ["status_label", "status_meta"],
      ["status_label", "name"],
    ]) || firstString(source, ["status", "state", "lifecycle"]) || "active"
  );

  return {
    name,
    type,
    ip: ip || null,
    hostname: hostname || null,
    description: description || null,
    criticality,
    status,
  };
}

function withDockerLocalhostFallback(endpoint: string) {
  try {
    const url = new URL(endpoint);
    const isLocalhost = ["localhost", "127.0.0.1", "::1"].includes(url.hostname);
    if (!isLocalhost) return [endpoint];

    const fallback = new URL(endpoint);
    fallback.hostname = "host.docker.internal";
    return [endpoint, fallback.toString()];
  } catch {
    return [endpoint];
  }
}

async function fetchPayload(endpoint: string, headers: HeadersInit) {
  const response = await fetch(endpoint, {
    method: "GET",
    headers,
    cache: "no-store",
  });

  if (!response.ok) {
    const responseText = await response.text().catch(() => "");
    const compactMessage = responseText.replace(/\s+/g, " ").trim().slice(0, 200);
    throw new Error(
      `CMDB endpoint returned HTTP ${response.status}${compactMessage ? `: ${compactMessage}` : ""}`
    );
  }

  return response.json();
}

export async function fetchCmdbAssets(input: {
  cmdbEndpoint: string;
  cmdbApiToken?: string;
}) {
  const headers: HeadersInit = {
    Accept: "application/json",
  };

  if (input.cmdbApiToken) {
    headers.Authorization = `Bearer ${input.cmdbApiToken}`;
    headers["X-API-Key"] = input.cmdbApiToken;
  }

  const endpoints = withDockerLocalhostFallback(input.cmdbEndpoint);
  let lastError: unknown;

  for (const endpoint of endpoints) {
    try {
      const payload = await fetchPayload(endpoint, headers);
      const rawAssets = getArrayPayload(payload);
      const assets = rawAssets
        .map((entry, index) => mapRawAsset(entry, index))
        .filter((entry): entry is CmdbAssetInput => Boolean(entry));

      return {
        rawCount: rawAssets.length,
        assets,
      };
    } catch (error) {
      lastError = error;
    }
  }

  if (lastError instanceof Error && endpoints.length > 1) {
    throw new Error(
      `${lastError.message}. Endpoint localhost non accessible depuis le conteneur app; utilisez host.docker.internal ou laissez le fallback automatique.`
    );
  }

  throw lastError instanceof Error ? lastError : new Error("Unknown CMDB fetch error");
}
