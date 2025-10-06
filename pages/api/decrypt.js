export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end('Method Not Allowed');

  try {
    const { iv, ct, ts } = req.body || {};
    if (!iv || !ct) return res.status(400).send('missing fields');
    if (!ts || Math.abs(Date.now() - ts) > 5 * 60 * 1000) return res.status(400).send('stale');

    const keyB64 = process.env.AES_KEY_B64;
    if (!keyB64) return res.status(500).send('server key missing');

    const b64ToU8 = b64 => Uint8Array.from(Buffer.from(b64, 'base64'));

    // Node 18+ hat WebCrypto global
    const key = await crypto.subtle.importKey('raw', b64ToU8(keyB64), 'AES-GCM', false, ['decrypt']);
    const ptBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64ToU8(iv) },
      key,
      b64ToU8(ct)
    );

    const json = new TextDecoder().decode(ptBuf);
    res.setHeader('content-type', 'application/json');
    return res.status(200).send(json);
  } catch {
    return res.status(400).send('bad payload');
  }
}
