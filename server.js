
const express = require('express');
const dns = require('dns').promises;
const { SMTPConnection } = require('smtp-connection');
const cors = require('cors');
const LRU = require('lru-cache');

const app = express();
app.use(cors(), express.json());

const cache = new LRU({ max: 10000, ttl: 1000 * 60 * 60 });

function isValidFormat(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function hasMX(domain) {
  try {
    const mxRecords = await dns.resolveMx(domain);
    return mxRecords.length ? mxRecords.sort((a, b) => a.priority - b.priority) : [];
  } catch {
    return [];
  }
}

function smtpVerify(email, mxHost) {
  return new Promise((resolve) => {
    const conn = new SMTPConnection({
      host: mxHost,
      port: 25,
      tls: false,
      connectionTimeout: 8000,
      greetingTimeout: 8000,
      socketTimeout: 8000,
    });

    conn.connect(() => {
      conn.hello('localhost');
      conn.mail({ from: 'verify@yourdomain.com' });
      conn.rcpt({ to: email }, (err) => {
        conn.quit();
        resolve(!(err && err.code === 550));
      });
    });

    conn.on('error', () => resolve(false));
  });
}

app.post('/verify', async (req, res) => {
  const email = (req.body.email || '').toLowerCase();
  if (!email) return res.status(400).json({ error: 'email required' });

  if (cache.has(email)) return res.json(cache.get(email));

  const result = { email, valid_format: false, domain_has_mx: false, smtp_valid: false };
  result.valid_format = isValidFormat(email);

  if (result.valid_format) {
    const domain = email.split('@')[1];
    const mxRecords = await hasMX(domain);
    if (mxRecords.length) {
      result.domain_has_mx = true;
      result.smtp_valid = await smtpVerify(email, mxRecords[0].exchange);
    }
  }

  result.status = result.valid_format && result.domain_has_mx && result.smtp_valid ? 'valid' : 'invalid';
  cache.set(email, result);
  res.json(result);
});

app.listen(process.env.PORT || 5000, () => 
  console.log(`✅ Email verifier running on port ${process.env.PORT || 5000}`)
);
