# syntax=docker/dockerfile:1.7

# ─── Stage 1: Dependencies ───────────────────────────────────────────────────
FROM node:20-alpine AS deps

RUN apk add --no-cache libc6-compat openssl

WORKDIR /app

COPY package.json package-lock.json* ./
COPY backend/prisma ./backend/prisma

# Prefer reproducible install — falls back to install when lockfile absent
RUN if [ -f package-lock.json ]; then npm ci; else npm install --no-audit --no-fund; fi

# ─── Stage 2: Builder ────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

ENV NEXT_TELEMETRY_DISABLED=1

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Generate Prisma client + build Next standalone
RUN npx prisma generate --schema backend/prisma/schema.prisma \
 && npm run build

# ─── Stage 3: Runner ─────────────────────────────────────────────────────────
FROM node:20-alpine AS runner

WORKDIR /app

# wget is needed by HEALTHCHECK (busybox provides it in alpine, kept explicit
# for clarity). tini gives proper SIGTERM forwarding to the Node process.
RUN apk add --no-cache tini wget openssl

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

RUN addgroup --system --gid 1001 nodejs \
 && adduser --system --uid 1001 nextjs

COPY --from=builder --chown=nextjs:nodejs /app/package.json ./package.json
COPY --from=builder --chown=nextjs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nextjs:nodejs /app/frontend ./frontend
COPY --from=builder --chown=nextjs:nodejs /app/backend ./backend

USER nextjs

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=8s --start-period=40s --retries=5 \
  CMD wget --quiet --tries=1 --spider http://127.0.0.1:3000/health || exit 1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["npm", "run", "start"]
