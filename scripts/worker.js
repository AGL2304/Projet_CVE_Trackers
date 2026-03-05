/* eslint-disable no-console */
const { PrismaClient, ReportStatus, SyncJobStatus } = require("@prisma/client");

const prisma = new PrismaClient();
const POLL_INTERVAL_MS = Number(process.env.WORKER_POLL_INTERVAL_MS || 15000);

async function processReportJobs() {
  const jobs = await prisma.reportJob.findMany({
    where: { status: ReportStatus.QUEUED },
    orderBy: { createdAt: "asc" },
    take: 10,
  });

  for (const job of jobs) {
    await prisma.reportJob.update({
      where: { id: job.id },
      data: {
        status: ReportStatus.RUNNING,
      },
    });

    await prisma.reportJob.update({
      where: { id: job.id },
      data: {
        status: ReportStatus.COMPLETED,
        completedAt: new Date(),
        storagePath: job.storagePath || `reports/${job.id}.${job.format.toLowerCase()}`,
      },
    });
  }
}

async function processSyncJobs() {
  const jobs = await prisma.syncJob.findMany({
    where: { status: SyncJobStatus.QUEUED },
    orderBy: { createdAt: "asc" },
    take: 10,
  });

  for (const job of jobs) {
    await prisma.syncJob.update({
      where: { id: job.id },
      data: {
        status: SyncJobStatus.RUNNING,
      },
    });

    await prisma.syncJob.update({
      where: { id: job.id },
      data: {
        status: SyncJobStatus.COMPLETED,
        completedAt: new Date(),
      },
    });
  }
}

async function tick() {
  try {
    await processReportJobs();
    await processSyncJobs();
  } catch (error) {
    console.error("[worker] tick failed", error);
  }
}

async function main() {
  console.log(`[worker] started, polling every ${POLL_INTERVAL_MS}ms`);
  await tick();
  setInterval(tick, POLL_INTERVAL_MS);
}

main().catch((error) => {
  console.error("[worker] fatal error", error);
  process.exit(1);
});

process.on("SIGTERM", async () => {
  await prisma.$disconnect();
  process.exit(0);
});
