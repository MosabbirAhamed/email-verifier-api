const express = require('express');
const dns = require('dns').promises;
const SMTPConnection = require('smtp-connection');
const cors = require('cors');
const LRU = require('lru-cache');

const app = express();

// ✅ Fix CORS for Netlify or any public frontend
const corsOptions = {
  origin: '*', // Or specify: 'https://your-site.netlify.app'
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type']
};
app.use(cors(corsOptions));
app.use(express.json());

// ✅ Cache responses to avoid rechecking same emails
const cache = new LRU({ max: 10000, maxAge: 1000 * 60 * 60 }); // 1 hour

function isValidFormat(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function getMXRecords(domain) {
  try {
    const mxRecords = await dns.resolveMx(domain);
    return mxRecords.sort((a, b) => a.priority - b.priority);
  } catch (err) {
    return [];
  }
}

function smtpVerify(email, mxHost, port = 25, useTLS = false, timeout = 8000) {
  return new Promise((resolve) => {
    const connection = new SMTPConnection({
      host: mxHost,
      port,
      secure: false,
      tls: useTLS ? { rejectUnauthorized: false } : undefined,
      connectionTimeout: timeout,
      greetingTimeout: timeout,
      socketTimeout: timeout,
    });

    connection.on('error', () => resolve({ success: false }));

    connection.connect(() => {
      connection.mail({ from: 'verify@yourdomain.com' });
      connection.rcpt({ to: email }, (err) => {
        connection.quit();
        resolve({ success: !err });
      });
    });
  });
}

async function verifyAllMX(email, mxRecords) {
  for (const mx of mxRecords) {
    const ports = [
      { port: 587, tls: true },
      { port: 25, tls: false }
    ];

    for (const { port, tls } of ports) {
      const result = await smtpVerify(email, mx.exchange, port, tls);
      if (result.success) {
        return { success: true, mx: mx.exchange, port, tls };
      }
    }
  }
  return { success: false };
}

async function isCatchAll(mxRecords, domain) {
  const randomEmails = Array.from({ length: 2 }).map(
    (_, i) => `nonexist${Date.now()}${i}@${domain}`
  );

  for (const fakeEmail of randomEmails) {
    const result = await verifyAllMX(fakeEmail, mxRecords);
    if (!result.success) return false;
  }
  return true;
}

app.post('/verify', async (req, res) => {
  const email = (req.body.email || '').toLowerCase().trim();
  if (!email) return res.status(400).json({ error: 'Email is required' });

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
  if (!result.valid_format) {
    cache.set(email, result);
    return res.json(result);
  }

  const domain = email.split('@')[1];
  const mxRecords = await getMXRecords(domain);
  if (!mxRecords.length) {
    result.warnings.push('No MX records found');
    cache.set(email, result);
    return res.json(result);
  }

  result.domain_has_mx = true;

  const isCatch = await isCatchAll(mxRecords, domain);
  result.is_catch_all = isCatch;

  if (isCatch) {
    result.status = 'unknown';
    result.confidence_score = 50;
    result.warnings.push('Catch-all domain — mailbox existence cannot be verified');
    cache.set(email, result);
    return res.json(result);
  }

  const smtpRes = await verifyAllMX(email, mxRecords);
  result.smtp_valid = smtpRes.success;

  if (smtpRes.success) {
    result.status = 'valid';
    result.confidence_score = 100;
  } else {
    result.status = 'likely_valid';
    result.confidence_score = 75;
    result.warnings.push('SMTP server did not confirm mailbox (could be greylisted, blocked, or deferred)');
  }

  cache.set(email, result);
  res.json(result);
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`✅ Email verifier running on port ${PORT}`);
});
