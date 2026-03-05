# Backend v2 Blueprint (Implemented Foundation)

## Data Model
- Prisma schema migrated to PostgreSQL provider.
- Core entities implemented:
  - `CVE`, `CWE`, `Product`, `ProductCVE`
  - `Asset`, `AssetProduct`
  - `User`, `Notification`
  - `AuditLog` (immutable by API design)
  - `SyncJob`, `ReportJob`
  - `Comment` (threaded), `Tag`, `CVETag`, `AssetTag`, `CVECWE`
- Business enums implemented:
  - `CVEStatus`: `NEW`, `ANALYZING`, `CONFIRMED`, `REMEDIATED`, `FALSE_POSITIVE`, `WONTFIX`
  - `Severity`: `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
  - Supporting enums for roles, sync, report formats/status.

## Business Rules Covered
- Severity is auto-calculated from CVSS in API services.
- Sync is idempotent with `upsert` on `cveId`.
- Audit entries are write-only from API handlers (no update/delete endpoints exposed).
- User deletion workflow is implemented as RGPD anonymization (`DELETE /api/v2/users/:id`).

## API v2 Routes
- `GET /api/v2` registry of links.
- `GET /api/v2/openapi` minimal OpenAPI 3.1 descriptor.
- `GET /api/v2/cves` cursor pagination + filters.
- `POST /api/v2/cves` strict Zod validation + upsert + NVD enrichment.
- `GET /api/v2/cves/:id` detailed resource with `?include=` relations.
- `PATCH /api/v2/cves/:id` optimistic locking via `version`.
- `POST /api/v2/sync/nvd` manual sync job.
- `GET /api/v2/sync/jobs/:id` sync job tracking.
- `GET /api/v2/analytics/dashboard` dashboard aggregates.
- `POST /api/v2/reports/generate` async report job generation.
- `GET /api/v2/reports/:id` report job status.
- `GET /api/v2/notifications` user notifications stream.
- `PATCH /api/v2/notifications/:id` read state update.
- `DELETE /api/v2/users/:id` anonymize user.

## Infra / DevOps Baseline
- `docker-compose.yml` upgraded to multi-services:
  - gateway (`nginx`)
  - app
  - worker
  - `postgres:16`
  - `pgbouncer`
  - `redis`
  - `elasticsearch`
  - optional `prometheus` + `grafana` profiles.
- Added `/health` and `/ready` endpoints.

## Notes
- Frontend legacy routes remain available for compatibility.
- Existing v1 endpoints can be progressively migrated to v2 consumers.
