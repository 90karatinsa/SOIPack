# syntax=docker/dockerfile:1.5

FROM node:20-bookworm-slim AS builder
WORKDIR /app

COPY package.json package-lock.json ./
COPY tsconfig.json tsconfig.base.json tsconfig.build.json ./
COPY packages ./packages
COPY data ./data

RUN npm ci \
  && npm run build \
  && npm cache clean --force

FROM node:20-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production

COPY package.json package-lock.json ./
COPY packages/adapters/package.json packages/adapters/package.json
COPY packages/cli/package.json packages/cli/package.json
COPY packages/core/package.json packages/core/package.json
COPY packages/engine/package.json packages/engine/package.json
COPY packages/packager/package.json packages/packager/package.json
COPY packages/report/package.json packages/report/package.json
COPY packages/server/package.json packages/server/package.json
COPY scripts scripts

RUN npm ci --omit=dev \
  && npm cache clean --force

COPY --from=builder /app/packages/adapters/dist packages/adapters/dist
COPY --from=builder /app/packages/cli/dist packages/cli/dist
COPY --from=builder /app/packages/core/dist packages/core/dist
COPY --from=builder /app/packages/engine/dist packages/engine/dist
COPY --from=builder /app/packages/packager/dist packages/packager/dist
COPY --from=builder /app/packages/report/dist packages/report/dist
COPY --from=builder /app/packages/server/dist packages/server/dist
COPY --from=builder /app/data data
COPY packages/server/openapi.yaml packages/server/openapi.yaml

RUN mkdir -p /app/data \
  && chown -R node:node /app

VOLUME ["/app/data"]

ENV SOIPACK_STORAGE_DIR=/app/data \
    PORT=3000

EXPOSE 3000

USER node

ENTRYPOINT ["node", "packages/server/dist/start.js"]
