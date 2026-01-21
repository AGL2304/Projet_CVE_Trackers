# Stage 1: Dependencies
FROM node:20-alpine AS deps

# Install system dependencies
RUN apk add --no-cache libc6-compat

WORKDIR /app

# Install dependencies
COPY package.json ./
RUN npm ci

# Stage 2: Builder
FROM node:20-alpine AS builder

WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Build application
RUN npm run build

# Stage 3: Runner
FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production

# Create necessary directories
RUN mkdir -p /app/db /app/logs

# Setup user
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

COPY --from=builder --chown=nextjs:nodejs /app/public ./public

# Setup database directory
RUN chown nextjs:nodejs db
RUN touch db/dev.db
RUN chown nextjs:nodejs db/dev.db

# Setup log directory
RUN chown nextjs:nodejs logs

# Copy application
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
COPY --from=builder --chown=nextjs:nodejs /app/prisma ./prisma
COPY --from=builder --chown=nextjs:nodejs /app/package.json ./package.json
COPY --from=builder --chown=nextjs:nodejs /app/node_modules/@prisma ./node_modules/@prisma

USER nextjs

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

CMD ["node", "server.js"]
