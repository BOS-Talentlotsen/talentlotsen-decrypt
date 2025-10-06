export const runtime = 'edge'; // Web Crypto verfügbar

function b64ToU8(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

export async function POST(req) {
  try {
    const { iv, ct, ts } = await req.json();

    if (!iv || !ct) {
      return new Response('missing fields', { status: 400 });
    }

    // Anti-Replay: 5 Minuten
    if (!ts || Math.abs(Date.now() - ts) > 5 * 60 * 1000) {
      return new Response('stale', { status: 400 });
    }

    // In Next.js (Edge) wird process.env bei Build-Time ersetzt.
    const keyB64 = process.env.AES_KEY_B64;
    if (!keyB64) {
      return new Response('server key missing', { status: 500 });
    }

    const keyRaw = b64ToU8(keyB64);
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyRaw,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    const ivBuf = b64ToU8(iv);
    const ctBuf = b64ToU8(ct);

    const ptBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBuf },
      cryptoKey,
      ctBuf
    );

    const json = new TextDecoder().decode(ptBuf);

    return new Response(json, {
      status: 200,
      headers: { 'content-type': 'application/json' }
    });
  } catch {
    return new Response('bad payload', { status: 400 });
  }
}
