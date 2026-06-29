FROM node:22-alpine AS deps

WORKDIR /app
COPY docker/demo-api/package*.json ./
RUN if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev; fi

FROM node:22-alpine AS runtime

ENV NODE_ENV=production
ENV PORT=3000

WORKDIR /app
RUN addgroup -S parry && adduser -S parry -G parry

COPY --chown=parry:parry package.json ./package.json
COPY --chown=parry:parry src ./src
COPY --chown=parry:parry config ./config
COPY --chown=parry:parry constants ./constants
COPY --chown=parry:parry docker/demo-api ./docker/demo-api
COPY --from=deps --chown=parry:parry /app/node_modules ./node_modules

USER parry
EXPOSE 3000

CMD ["node", "docker/demo-api/server.js"]
