import { db } from "@/lib/db";

export type AppSettingsPayload = {
  language: "fr" | "en";
  nvdApiKey: string;
  cmdbEndpoint: string;
  cmdbApiToken: string;
  webhookUrl: string;
  cmdbEnabled: boolean;
  cmdbLastSyncAt: string | null;
  cmdbLastSyncStatus: string | null;
  cmdbLastSyncMessage: string | null;
};

const ENV_DEFAULTS = {
  nvdApiKey: process.env.NVD_API_KEY || "",
  cmdbEndpoint: process.env.CMDB_ENDPOINT || process.env.CMDB_API_ENDPOINT || "",
  cmdbApiToken: process.env.CMDB_API_TOKEN || process.env.CMDB_API_KEY || "",
  webhookUrl: process.env.WEBHOOK_URL || "",
};

function preferValue(value: string | null | undefined, fallback: string): string {
  const normalized = value?.trim();
  return normalized ? normalized : fallback;
}

const DEFAULT_SETTINGS: AppSettingsPayload = {
  language: "fr",
  nvdApiKey: ENV_DEFAULTS.nvdApiKey,
  cmdbEndpoint: ENV_DEFAULTS.cmdbEndpoint,
  cmdbApiToken: ENV_DEFAULTS.cmdbApiToken,
  webhookUrl: ENV_DEFAULTS.webhookUrl,
  cmdbEnabled: false,
  cmdbLastSyncAt: null,
  cmdbLastSyncStatus: null,
  cmdbLastSyncMessage: null,
};

const appSettings = (db as any).appSettings as {
  findUnique: (args: unknown) => Promise<any>;
  upsert: (args: unknown) => Promise<any>;
};

function mapRowToPayload(row: {
  language: string;
  nvdApiKey: string | null;
  cmdbEndpoint: string | null;
  cmdbApiToken: string | null;
  webhookUrl: string | null;
  cmdbEnabled: boolean;
  cmdbLastSyncAt: Date | null;
  cmdbLastSyncStatus: string | null;
  cmdbLastSyncMessage: string | null;
}): AppSettingsPayload {
  return {
    language: row.language === "en" ? "en" : "fr",
    nvdApiKey: preferValue(row.nvdApiKey, ENV_DEFAULTS.nvdApiKey),
    cmdbEndpoint: preferValue(row.cmdbEndpoint, ENV_DEFAULTS.cmdbEndpoint),
    cmdbApiToken: preferValue(row.cmdbApiToken, ENV_DEFAULTS.cmdbApiToken),
    webhookUrl: preferValue(row.webhookUrl, ENV_DEFAULTS.webhookUrl),
    cmdbEnabled: row.cmdbEnabled,
    cmdbLastSyncAt: row.cmdbLastSyncAt?.toISOString() ?? null,
    cmdbLastSyncStatus: row.cmdbLastSyncStatus,
    cmdbLastSyncMessage: row.cmdbLastSyncMessage,
  };
}

export async function getAppSettings(): Promise<AppSettingsPayload> {
  const row = await appSettings.findUnique({
    where: { id: 1 },
    select: {
      language: true,
      nvdApiKey: true,
      cmdbEndpoint: true,
      cmdbApiToken: true,
      webhookUrl: true,
      cmdbEnabled: true,
      cmdbLastSyncAt: true,
      cmdbLastSyncStatus: true,
      cmdbLastSyncMessage: true,
    },
  });

  if (!row) return DEFAULT_SETTINGS;
  return mapRowToPayload(row);
}

export async function saveAppSettings(input: {
  language: "fr" | "en";
  nvdApiKey: string;
  cmdbEndpoint: string;
  cmdbApiToken: string;
  webhookUrl: string;
  cmdbEnabled: boolean;
}) {
  const row = await appSettings.upsert({
    where: { id: 1 },
    update: {
      language: input.language,
      nvdApiKey: input.nvdApiKey || null,
      cmdbEndpoint: input.cmdbEndpoint || null,
      cmdbApiToken: input.cmdbApiToken || null,
      webhookUrl: input.webhookUrl || null,
      cmdbEnabled: input.cmdbEnabled,
    },
    create: {
      id: 1,
      language: input.language,
      nvdApiKey: input.nvdApiKey || null,
      cmdbEndpoint: input.cmdbEndpoint || null,
      cmdbApiToken: input.cmdbApiToken || null,
      webhookUrl: input.webhookUrl || null,
      cmdbEnabled: input.cmdbEnabled,
    },
    select: {
      language: true,
      nvdApiKey: true,
      cmdbEndpoint: true,
      cmdbApiToken: true,
      webhookUrl: true,
      cmdbEnabled: true,
      cmdbLastSyncAt: true,
      cmdbLastSyncStatus: true,
      cmdbLastSyncMessage: true,
    },
  });

  return mapRowToPayload(row);
}

export async function setCmdbSyncStatus(input: {
  status: "ok" | "error";
  message: string;
  at?: Date;
}) {
  const updated = await appSettings.upsert({
    where: { id: 1 },
    update: {
      cmdbLastSyncAt: input.at ?? new Date(),
      cmdbLastSyncStatus: input.status,
      cmdbLastSyncMessage: input.message,
    },
    create: {
      id: 1,
      cmdbLastSyncAt: input.at ?? new Date(),
      cmdbLastSyncStatus: input.status,
      cmdbLastSyncMessage: input.message,
    },
    select: {
      language: true,
      nvdApiKey: true,
      cmdbEndpoint: true,
      cmdbApiToken: true,
      webhookUrl: true,
      cmdbEnabled: true,
      cmdbLastSyncAt: true,
      cmdbLastSyncStatus: true,
      cmdbLastSyncMessage: true,
    },
  });

  return mapRowToPayload(updated);
}
