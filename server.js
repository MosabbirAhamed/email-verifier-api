const express = require('express');
const dns = require('dns').promises;
const SMTPConnection = require('smtp-connection');
const tls = require('tls');
const cors = require('cors');
const LRU = require('lru-cache');

const app = express();
app.use(cors(), express.json());

const cache = new LRU({ max: 10000, maxAge: 1000 * 60 * 60 }); // cache for 1 hour

function isValidFormat(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function getMXRecords(domain) {
  try {
    const mxRecords = await dns.resolveMx(domain);
    return mxRecords.length ? mxRecords.sort((a, b) => a.priority - b.priority) : [];
  } catch (err) {
    console.error(`MX lookup error for ${domain}:`, err.message);
    return [];
  }
}

function smtpVerify(email, mxHost, port, useTLS, timeout = 10000) {
  return new Promise((resolve) => {
    const options = {
      host: mxHost,
      port,
      secure: false,
      connectionTimeout: timeout,
      greetingTimeout: timeout,
      socketTimeout: timeout,
    };
    if (useTLS) {
      options.tls = { rejectUnauthorized: false };
    }

    const connection = new SMTPConnection(options);
    let done = false;

    connection.on('error', (err) => {
      if (!done) {
        done = true;
        // console.error(`SMTP error ${mxHost}:${port} TLS:${useTLS} - ${err.message}`);
        resolve({ success: false, error: err.message });
      }
    });

    connection.connect(() => {
      connection.login({}, (loginErr) => {
        if (loginErr) {
          connection.quit();
          if (!done) {
            done = true;
            resolve({ success: false, error: loginErr.message });
          }
          return;
        }
        connection.mail({ from: 'verify@yourdomain.com' });
        connection.rcpt({ to: email }, (rcptErr) => {
          connection.quit();
          if (!done) {
            done = true;
            if (rcptErr) {
              resolve({ success: false, error: rcptErr.message });
            } else {
              resolve({ success: true });
            }
          }
        });
      });
    });
  });
}

async function verifyAllMX(email, mxRecords) {
  // Try each MX host with ports in order and retries
  const ports = [
    { port: 587, tls: true },
    { port: 465, tls: true, ssl: true }, // will handle ssl manually below
    { port: 25, tls: false },
  ];

  for (const mx of mxRecords) {
    for (const { port, tls: useTLS, ssl } of ports) {
      try {
        if (ssl) {
          // SMTPS on 465 needs a special connection
          const result = await smtpVerifySMTPS(email, mx.exchange, port, 10000);
          if (result.success) return { success: true, mx: mx.exchange, port, tls: useTLS };
        } else {
          const result = await smtpVerify(email, mx.exchange, port, useTLS);
          if (result.success) return { success: true, mx: mx.exchange, port, tls: useTLS };
        }
      } catch (e) {
        // Ignore and try next
      }
    }
  }
  return { success: false };
}

// SMTPS on port 465 (SSL) requires different connection setup
function smtpVerifySMTPS(email, mxHost, port, timeout = 10000) {
  return new Promise((resolve) => {
    const socket = tls.connect(port, mxHost, { rejectUnauthorized: false, timeout }, () => {
      const conn = new SMTPConnection({
        socket,
        host: mxHost,
        port,
        secure: true,
        connectionTimeout: timeout,
        greetingTimeout: timeout,
        socketTimeout: timeout,
      });

      let done = false;

      conn.on('error', (err) => {
        if (!done) {
          done = true;
          resolve({ success: false, error: err.message });
        }
      });

      conn.connect(() => {
        conn.login({}, (loginErr) => {
          if (loginErr) {
            conn.quit();
            if (!done) {
              done = true;
              resolve({ success: false, error: loginErr.message });
            }
            return;
          }
          conn.mail({ from: 'verify@yourdomain.com' });
          conn.rcpt({ to: email }, (rcptErr) => {
            conn.quit();
            if (!done) {
              done = true;
              if (rcptErr) resolve({ success: false, error: rcptErr.message });
              else resolve({ success: true });
            }
          });
        });
      });
    });

    socket.on('error', (err) => {
      resolve({ success: false, error: err.message });
    });

    socket.setTimeout(timeout, () => {
      socket.destroy();
      resolve({ success: false, error: 'Timeout' });
    });
  });
}

app.post('/verify', async (req, res) => {
  const emailRaw = req.body.email || '';
  const email = emailRaw.toLowerCase().trim();
  const skipSMTP = req.query.skip_smtp === 'true';

  if (!email) return res.status(400).json({ error: 'email required' });

  const cacheKey = email + (skipSMTP ? '_skip' : '');
  if (cache.has(cacheKey)) return res.json(cache.get(cacheKey));

  const result = {
    email,
    valid_format: false,
    domain_has_mx: false,
    smtp_valid: null,
    status: 'invalid',
    confidence_score: 0,
    mx_records: [],
    smtp_details: null,
    warnings: [],
  };

  result.valid_format = isValidFormat(email);
  if (!result.valid_format) {
    result.warnings.push('Invalid email format');
    cache.set(cacheKey, result);
    return res.json(result);
  }

  const domain = email.split('@')[1];
  const mxRecords = await getMXRecords(domain);
  if (mxRecords.length === 0) {
    result.warnings.push('No MX records found for domain');
    cache.set(cacheKey, result);
    return res.json(result);
  }

  result.domain_has_mx = true;
  result.mx_records = mxRecords.map(mx => mx.exchange);

  if (skipSMTP) {
    result.smtp_valid = null;
    result.status = 'likely_valid';
    result.warnings.push('SMTP verification skipped by request');
    result.confidence_score = 75;
    cache.set(cacheKey, result);
    return res.json(result);
  }

  const smtpResult = await verifyAllMX(email, mxRecords);

  result.smtp_valid = smtpResult.success;
  if (smtpResult.success) {
    result.status = 'valid';
    result.confidence_score = 100;
    result.smtp_details = {
      mx_host: smtpResult.mx,
      port: smtpResult.port,
      tls: smtpResult.tls,
    };
  } else {
    result.status = 'likely_valid';
    result.confidence_score = 75;
    result.warnings.push('SMTP verification failed or was unreliable');
  }

  cache.set(cacheKey, result);
  res.json(result);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Email verifier running on port ${PORT}`);
});
