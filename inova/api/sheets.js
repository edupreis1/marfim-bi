export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { sheetId, tabName } = req.body;
  if (!sheetId || !tabName) return res.status(400).json({ error: 'sheetId e tabName são obrigatórios' });

  try {
    const token = await getAccessToken();
    const url = `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/${encodeURIComponent(tabName)}`;
    const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    if (!r.ok) {
      const txt = await r.text();
      return res.status(r.status).json({ error: `Sheets API: ${r.status} — ${txt.slice(0, 200)}` });
    }
    const data = await r.json();
    return res.status(200).json({ values: data.values || [] });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}

async function getAccessToken() {
  const clientEmail = process.env.GOOGLE_CLIENT_EMAIL;
  const privateKey   = process.env.GOOGLE_PRIVATE_KEY?.replace(/\\n/g, '\n');

  if (!clientEmail || !privateKey) throw new Error('GOOGLE_CLIENT_EMAIL ou GOOGLE_PRIVATE_KEY não configurados');

  const now = Math.floor(Date.now() / 1000);
  const header  = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = base64url(JSON.stringify({
    iss:   clientEmail,
    scope: 'https://www.googleapis.com/auth/spreadsheets.readonly',
    aud:   'https://oauth2.googleapis.com/token',
    exp:   now + 3600,
    iat:   now,
  }));

  const sigInput = `${header}.${payload}`;
  const keyBuffer = pemToBuffer(privateKey);

  const cryptoKey = await crypto.subtle.importKey(
    'pkcs8', keyBuffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false, ['sign']
  );

  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', cryptoKey, new TextEncoder().encode(sigInput));
  const sigB64 = base64url(Buffer.from(sig));
  const jwt = `${sigInput}.${sigB64}`;

  const resp = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`,
  });

  const d = await resp.json();
  if (!d.access_token) throw new Error('Token falhou: ' + JSON.stringify(d));
  return d.access_token;
}

function base64url(input) {
  const buf = typeof input === 'string' ? Buffer.from(input) : Buffer.from(input);
  return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function pemToBuffer(pem) {
  const b64 = pem.replace(/-----BEGIN[^-]*-----/g, '').replace(/-----END[^-]*-----/g, '').replace(/\s+/g, '');
  return Buffer.from(b64, 'base64');
}
