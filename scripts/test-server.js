'use strict';

/**
 * scripts/test-server.js
 * Minimum Express server requirements for manual and automated validation
 * It outlines routes with different attack surfaces to cover all vectors.
 */

const express = require('express');
const { createParry } = require('../src/middleware');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const parry = createParry({
  sql: true,
  xss: true,
  nosql: true,
  rateLimit: true,

  maxRequests: 30,
  windowMs: 60_000,

  suspiciousThreshold: 5,
  banDurationMs: 30_000,

  logThreats: true,
  onThreat(entry) {
    // Framework available for integration with SIEM / external alerts
    // console.log(‘[onThreat]’, JSON.stringify(entry, null, 2));
  },
});

app.use(parry.middleware());

app.get('/ping', (req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  res.json({ ok: true, echo: { username, password } });
});

app.get('/search', (req, res) => {
  res.json({ ok: true, query: req.query.q });
});

app.get('/user/:id', (req, res) => {
  res.json({ ok: true, id: req.params.id });
});

app.post('/filter', (req, res) => {
  res.json({ ok: true, filter: req.body.filter });
});

app.post('/comment', (req, res) => {
  res.json({ ok: true, comment: req.body.text });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🛡  Parry test-server listening on http://localhost:${PORT}`);
  console.log(`   Run: node scripts/run-tests.js\n`);
});
