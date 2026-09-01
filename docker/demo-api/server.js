'use strict';

const { RedisStore } = require('../../src');
const { createDemoApp } = require('./app');

const port = Number(process.env.PORT || 3000);

main().catch((error) => {
  console.error('[parry-demo] fatal startup error', error);
  process.exit(1);
});

async function main() {
  const store = await createStore();
  const { app } = createDemoApp({ store });

  const server = app.listen(port, () => {
    console.log(`[parry-demo] listening on port ${port}`);
  });

  process.on('SIGTERM', () => shutdown(server, store));
  process.on('SIGINT', () => shutdown(server, store));
}

async function createStore() {
  if (process.env.PARRY_STORE !== 'redis') return null;

  if (!process.env.REDIS_URL) {
    console.warn(
      '[parry-demo] PARRY_STORE=redis set without REDIS_URL; falling back to MemoryStore'
    );
    return null;
  }

  const { createClient } = require('redis');
  const client = createClient({
    url: process.env.REDIS_URL,
    password: process.env.REDIS_AUTH_TOKEN || undefined,
  });

  client.on('error', (error) => {
    console.error('[parry-demo] redis client error', error.message);
  });

  try {
    await client.connect();
    return new RedisStore({
      client,
      prefix: process.env.PARRY_REDIS_PREFIX || 'parry',
      closeClient: true,
    });
  } catch (error) {
    console.error('[parry-demo] redis unavailable; falling back to MemoryStore', error.message);
    return null;
  }
}

function shutdown(server, store) {
  server.close(async () => {
    if (store && typeof store.close === 'function') {
      await store.close();
    }
    process.exit(0);
  });
}
