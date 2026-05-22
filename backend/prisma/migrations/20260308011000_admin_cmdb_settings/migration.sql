CREATE TABLE "AppSettings" (
    "id" INTEGER NOT NULL DEFAULT 1,
    "singleton" TEXT NOT NULL DEFAULT 'default',
    "language" TEXT NOT NULL DEFAULT 'fr',
    "nvdApiKey" TEXT,
    "cmdbEndpoint" TEXT,
    "cmdbApiToken" TEXT,
    "webhookUrl" TEXT,
    "cmdbEnabled" BOOLEAN NOT NULL DEFAULT false,
    "cmdbLastSyncAt" TIMESTAMP(3),
    "cmdbLastSyncStatus" TEXT,
    "cmdbLastSyncMessage" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AppSettings_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "AppSettings_singleton_key" ON "AppSettings"("singleton");
