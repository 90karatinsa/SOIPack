# syntax=docker/dockerfile:1.5

FROM node:20-bookworm-slim AS builder
WORKDIR /app

# Install dependencies and prepare the workspace
COPY package.json package-lock.json tsconfig.json tsconfig.base.json tsconfig.build.json ./
COPY packages ./packages
COPY docs ./docs
COPY scripts ./scripts
COPY data ./data
COPY examples ./examples

RUN npm ci \
  && npm run build \
  && npm cache clean --force

FROM node:20-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production

# Copy the compiled application and production dependencies
COPY --from=builder /app /app

# Install Playwright browsers and required system dependencies
RUN npx playwright install --with-deps chromium \
  && rm -rf /var/lib/apt/lists/*

# Final runtime configuration
RUN mkdir -p /app/data \
  && chown -R node:node /app \
  && npm cache clean --force

VOLUME ["/app/data"]

ENV SOIPACK_STORAGE_DIR=/app/data \
    PORT=3000

EXPOSE 3000

USER node

ENTRYPOINT ["node", "node_modules/.bin/tsx", "packages/server/src/start.ts"]
