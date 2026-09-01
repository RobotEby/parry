'use strict';

const express = require('express');
const { createParry } = require('../src');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const parry = createParry({
  sql: true,
  xss: true,
  nosql: true,
  rateLimit: true,

  maxRequests: 60,
  windowMs: 60_000,

  suspiciousThreshold: 3,
  banDurationMs: 5 * 60_000,

  logThreats: true,

  onThreat(_entry) {
    // Note to remind myself to include this in the future: SIEM, Slack webhook, PagerDuty, DataDog, etc.
  },
});

app.use(parry.middleware());

app.post('/login', (req, res) => {
  res.json({ ok: true, message: `Welcome, ${req.body.username}!` });
});

app.get('/search', (req, res) => {
  res.json({ results: [], query: req.query.q });
});

app.post('/comment', (req, res) => {
  res.json({ posted: true, comment: req.body.text });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n  Parry running on http://localhost:${PORT}\n`);
  console.log('Examples of attacks to test:\n');

  console.log(`SQL Injection:
  curl -X POST http://localhost:${PORT}/login \\
    -H "Content-Type: application/json" \\
    -d '{"username":"admin\\' OR 1=1 --","password":"x"}'\n`);

  console.log(`XSS:
  curl "http://localhost:${PORT}/search?q=<script>alert(1)</script>"\n`);

  console.log(`NoSQL Injection:
  curl -X POST http://localhost:${PORT}/login \\
    -H "Content-Type: application/json" \\
    -d '{"username":{"\\$gt":""},"password":{"\\$gt":""}}'\n`);
});
