const express = require('express');
const dns = require('dns').promises;
const SMTPConnection = require('smtp-connection');
const cors = require('cors');
const LRU = require('lru-cache');

const app = express();

// ✅ Allow all origins (or restrict to your Netlify domain)
app.use(cors({ origin: '*' }));
app.use(express.json());

// ✅ Email result cache
const cache = new LRU({ max: 10000, maxAge: 1000 * 60 * 60 });

function isValidFormat(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function getMXRecords(domain) {
  try {
    const mx = await dns.resolveMx(domain);
    return mx.sort((a, b) => a.priority - b.priority);
  } catch {
    return [];
  }
}

function smtpVerify(email, host, port = 25, useTLS = false, timeout = 8000) {
  return new Promise((resolve) => {
    const conn = new SMTPConnection({
      host,
      port,
      secure: false,
      tls: useTLS ? { rejectUnauthorized: false } : undefined,
      connectionTimeout: timeout,
      greetingTimeout: timeout,
      socketTimeout: timeout
    });

    conn.on('error', () => resolve({ success: false }));

    conn.connect(() => {
      conn.mail({ from: 'verify@yourdomain.com' });
      conn.rcpt({ to: email }, (err) => {
        conn.quit();
        resolve({ success: !err });
      });
    });
  });
}

async function verifyAllMX(email, mxRecords) {
  for (const mx of mxRecords) {
    for (const { port, tls } of [
      { port: 587, tls: true },
      { port: 25, tls: false }
    ]) {
      const result = await smtpVerify(email, mx.exchange, port, tls);
      if (result.success) return { success: true, mx: mx.exchange, port, tls };
    }
  }
  return { success: false };
}

async function isCatchAll(mxRecords, domain) {
  const testEmails = Array.from({ length: 2 }).map(
    (_, i) => `random${Date.now()}${i}@${domain}`
  );

  for (const email of testEmails) {
    const result = await verifyAllMX(email, mxRecords);
    if (!result.success) return false;
  }
  return true;
}

app.post('/verify', async (req, res) => {
  const email = (req.body.email || '').toLowerCase().trim();
  if (!email) return res.status(400).json({ error: 'Email required' });

  if (cache.has(email)) return res.json(cache.get(email));

  const result = {
    email,
    valid_format: false,
    domain_has_mx: false,
    smtp_valid: false,
    is_catch_all: false,
    status: 'invalid',
    warnings: [],
    confidence_score: 0
  };

  result.valid_format = isValidFormat(email);
  if (!result.valid_format) return res.json(result);

  const domain = email.split('@')[1];
  const mxRecords = await getMXRecords(domain);

  if (!mxRecords.length) {
    result.warnings.push('No MX records found');
    return res.json(result);
  }

  result.domain_has_mx = true;

  const catchAll = await isCatchAll(mxRecords, domain);
  result.is_catch_all = catchAll;

  if (catchAll) {
    result.status = 'unknown';
    result.confidence_score = 50;
    result.warnings.push('Catch-all domain — mailbox may or may not exist');
    cache.set(email, result);
    return res.json(result);
  }

  const smtpResult = await verifyAllMX(email, mxRecords);
  result.smtp_valid = smtpResult.success;

  if (smtpResult.success) {
    result.status = 'valid';
    result.confidence_score = 100;
  } else {
    result.status = 'likely_valid';
    result.confidence_score = 75;
    result.warnings.push('SMTP server did not confirm mailbox');
  }

  cache.set(email, result);
  res.json(result);
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`✅ Email verifier running on port ${PORT}`);
});
