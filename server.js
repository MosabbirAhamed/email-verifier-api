const express = require('express');
const dns = require('dns').promises;
const SMTPConnection = require('smtp-connection');
const cors = require('cors');
const LRU = require('lru-cache');

const app = express();
app.use(cors(), express.json());

const cache = new LRU({ max: 10000, maxAge: 1000 * 60 * 60 }); // 1 hour cache

function isValidFormat(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function hasMX(domain) {
  try {
    const mxRecords = await dns.resolveMx(domain);
    // Sort by priority ascending
    return mxRecords.length ? mxRecords.sort((a, b) => a.priority - b.priority) : [];
  } catch (err) {
    console.error(`MX lookup error for domain "${domain}":`, err.message);
    return [];
  }
}

function smtpVerifySingle(email, mxHost, port, useTLS) {
  return new Promise((resolve) => {
    const conn = new SMTPConnection({
      host: mxHost,
      port,
      secure: false,
      tls: useTLS ? { rejectUnauthorized: false } : undefined,
      connectionTimeout: 10000,
      greetingTimeout: 10000,
      socketTimeout: 10000,
    });

    let resolved = false;

    conn.on('error', (e) => {
      if (!resolved) {
        // console.error(`SMTP error on ${mxHost}:${port} (TLS: ${useTLS}):`, e.message);
        resolved = true;
        resolve({ success: false, error: e.message });
      }
    });

    conn.connect(() => {
      conn.login({}, (loginErr) => {
        if (loginErr) {
          conn.quit();
          if (!resolved) {
            resolved = true;
            resolve({ success: false, error: loginErr.message });
          }
          return;
        }

        conn.mail({ from: 'verify@yourdomain.com' });
        conn.rcpt({ to: email }, (err) => {
          conn.quit();
          if (!resolved) {
            resolved = true;
            if (err) {
              // console.log(`RCPT TO rejected for ${email} at ${mxHost}:${port} (TLS: ${useTLS}):`, err.message);
              resolve({ success: false, error: err.message });
            } else {
              resolve({ success: true });
            }
          }
        });
      });
    });
  });
}

// Try all MX hosts with multiple ports and TLS options
async function smtpVerify(email, mxRecords) {
  for (const mx of mxRecords) {
    // Try ports in order with TLS first
    const attempts = [
      { port: 587, tls: true },
      { port: 25, tls: false }
    ];

    for (const attempt of attempts) {
      const res = await smtpVerifySingle(email, mx.exchange, attempt.port, attempt.tls);
      if (res.success) return { success: true, mx: mx.exchange, port: attempt.port, tls: attempt.tls };
      // else continue trying other ports or MX
    }
  }
  return { success: false };
}

app.post('/verify', async (req, res) => {
  const emailRaw = req.body.email || '';
  const email = emailRaw.toLowerCase().trim();

  if (!email) return res.status(400).json({ error: 'email required' });

  if (cache.has(email)) return res.json(cache.get(email));

  const result = {
    email,
    valid_format: false,
    domain_has_mx: false,
    smtp_valid: false,
    status: 'invalid',
    confidence_score: 0, // 0-100
    mx_records: [],
    smtp_details: null,
    warnings: [],
  };

  result.valid_format = isValidFormat(email);

  if (!result.valid_format) {
    result.warnings.push('Invalid email format.');
    cache.set(email, result);
    return res.json(result);
  }

  const domain = email.split('@')[1];
  const mxRecords = await hasMX(domain);

  if (mxRecords.length === 0) {
    result.warnings.push('No MX records found for domain.');
    cache.set(email, result);
    return res.json(result);
  }

  result.domain_has_mx = true;
  result.mx_records = mxRecords.map(mx => mx.exchange);

  const smtpRes = await smtpVerify(email, mxRecords);

  result.smtp_valid = smtpRes.success;
  result.smtp_details = smtpRes.success
    ? { verified_on: smtpRes.mx, port: smtpRes.port, tls: smtpRes.tls }
    : null;

  // Confidence score logic:
  // Format valid + MX present = 50 points
  // SMTP verification success = +50 points
  // If SMTP failed but MX + format good => 75 points and a warning about reliability

  if (result.valid_format) result.confidence_score += 50;
  if (result.domain_has_mx) result.confidence_score += 25;

  if (result.smtp_valid) {
    result.confidence_score += 25;
    result.status = 'valid';
  } else {
    result.status = 'likely_valid';
    result.warnings.push('SMTP verification failed or was unreliable.');
  }

  cache.set(email, result);
  res.json(result);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Email verifier running on port ${PORT}`);
});
