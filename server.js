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
    return mxRecords.length ? mxRecords.sort((a, b) => a.priority - b.priority) : [];
  } catch (err) {
    console.error(`MX lookup error for domain "${domain}":`, err.message);
    return [];
  }
}

function smtpVerify(email, mxHost) {
  return new Promise(async (resolve) => {
    const trySMTP = (port, useTLS) => {
      return new Promise((res) => {
        const conn = new SMTPConnection({
          host: mxHost,
          port,
          secure: false, // STARTTLS if available
          tls: useTLS ? { rejectUnauthorized: false } : undefined,
          connectionTimeout: 10000,
          greetingTimeout: 10000,
          socketTimeout: 10000,
        });

        let resolved = false;

        conn.on('error', (e) => {
          if (!resolved) {
            console.error(`SMTP error on ${mxHost}:${port} (TLS: ${useTLS}):`, e.message);
            resolved = true;
            res(false);
          }
        });

        conn.connect(() => {
          conn.login({}, (loginErr) => {
            if (loginErr) {
              console.error(`SMTP login error on ${mxHost}:${port} (TLS: ${useTLS}):`, loginErr.message);
              conn.quit();
              if (!resolved) {
                resolved = true;
                res(false);
              }
              return;
            }

            conn.mail({ from: 'verify@yourdomain.com' });
            conn.rcpt({ to: email }, (err) => {
              conn.quit();
              if (!resolved) {
                resolved = true;
                if (err) {
                  console.log(`RCPT TO rejected for ${email} at ${mxHost}:${port} (TLS: ${useTLS}):`, err.message);
                  res(false);
                } else {
                  res(true);
                }
              }
            });
          });
        });
      });
    };

    // Try STARTTLS on port 587 first
    let valid = await trySMTP(587, true);
    if (valid) return resolve(true);

    // Fallback to port 25 without TLS
    valid = await trySMTP(25, false);
    return resolve(valid);
  });
}

app.post('/verify', async (req, res) => {
  const email = (req.body.email || '').toLowerCase().trim();
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Email verifier running on port ${PORT}`);
});
