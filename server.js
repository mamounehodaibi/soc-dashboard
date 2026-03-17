require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Ensure uploads dir exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

// Routes
app.use('/api/logs',    require('./routes/logs'));
app.use('/api/threat',  require('./routes/threat'));
app.use('/api/report',  require('./routes/report'));

// Fallback to index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n  SOC Dashboard running at http://localhost:${PORT}`);
  console.log(`  AbuseIPDB key: ${process.env.ABUSEIPDB_API_KEY ? 'configured' : 'MISSING — add to .env'}\n`);
});
