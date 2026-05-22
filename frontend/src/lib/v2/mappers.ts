import type { CVE, Severity } from "@prisma/client";

export function mapCveToJsonApiResource(cve: CVE) {
  return {
    type: "cves",
    id: cve.id,
    attributes: {
      cveId: cve.cveId,
      title: cve.title,
      description: cve.description,
      publishedAt: cve.publishedAt,
      modifiedAt: cve.modifiedAt,
      cvssV3Score: cve.cvssV3Score,
      cvssV3Vector: cve.cvssV3Vector,
      cvssV4Score: cve.cvssV4Score,
      epssScore: cve.epssScore,
      status: cve.status,
      severity: cve.severity,
      source: cve.source,
      rawData: cve.rawData,
      references: cve.references,
      vulnStatus: cve.vulnStatus,
      importedAt: cve.importedAt,
      version: cve.version,
      createdAt: cve.createdAt,
      updatedAt: cve.updatedAt,
    },
    links: {
      self: `/api/v2/cves/${cve.id}`,
    },
  };
}

export function mapCveToLegacy(cve: CVE) {
  return {
    id: cve.id,
    cveId: cve.cveId,
    title: cve.title,
    description: cve.description,
    severity: toLegacySeverity(cve.severity),
    cvssScore: cve.cvssScore ?? cve.cvssV3Score ?? null,
    cvssVector: cve.cvssVector ?? cve.cvssV3Vector ?? null,
    publishedDate: cve.publishedDate ?? cve.publishedAt ?? null,
    lastModifiedDate: cve.lastModifiedDate ?? cve.modifiedAt ?? null,
    references: cve.references,
    vulnStatus: cve.vulnStatus ?? cve.status,
    importedAt: cve.importedAt,
    createdAt: cve.createdAt,
    updatedAt: cve.updatedAt,
  };
}

function toLegacySeverity(value: Severity) {
  return value.toLowerCase();
}
