// routes/threat.js
const express = require('express');
const axios   = require('axios');
const router  = express.Router();

// Simple in-memory cache so we don't burn API quota on repeated lookups
const cache = new Map();
const CACHE_TTL = 1000 * 60 * 60; // 1 hour

async function checkAbuseIPDB(ip) {
  const cached = cache.get(ip);
  if (cached && Date.now() - cached.ts < CACHE_TTL) return cached.data;

  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey || apiKey === 'your_api_key_here') {
    return { error: 'AbuseIPDB API key not configured', ip, mock: true, abuseConfidenceScore: 0 };
  }

  try {
    const res = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      headers: { Key: apiKey, Accept: 'application/json' },
      params: { ipAddress: ip, maxAgeInDays: 90, verbose: true }
    });
    const data = res.data.data;
    const result = {
      ip,
      abuseConfidenceScore: data.abuseConfidenceScore,
      totalReports: data.totalReports,
      countryCode: data.countryCode,
      usageType: data.usageType,
      isp: data.isp,
      domain: data.domain,
      isTor: data.isTor || false,
      lastReportedAt: data.lastReportedAt,
      isPublic: data.isPublic,
      riskLevel: data.abuseConfidenceScore >= 75 ? 'critical'
               : data.abuseConfidenceScore >= 40 ? 'high'
               : data.abuseConfidenceScore >= 10 ? 'medium' : 'low'
    };
    cache.set(ip, { ts: Date.now(), data: result });
    return result;
  } catch (err) {
    if (err.response?.status === 429) {
      return { ip, error: 'Rate limit reached (1000/day on free tier)', riskLevel: 'unknown' };
    }
    return { ip, error: err.message, riskLevel: 'unknown' };
  }
}

// POST /api/threat/check — check a list of IPs
router.post('/check', async (req, res) => {
  const { ips } = req.body;
  if (!ips || !Array.isArray(ips)) return res.status(400).json({ error: 'Send { ips: [...] }' });

  // Limit to 20 IPs per request to protect quota
  const limited = [...new Set(ips)].slice(0, 20);
  const results = await Promise.all(limited.map(checkAbuseIPDB));
  res.json({ results });
});

// GET /api/threat/check/:ip — single IP check
router.get('/check/:ip', async (req, res) => {
  const result = await checkAbuseIPDB(req.params.ip);
  res.json(result);
});

module.exports = router;
