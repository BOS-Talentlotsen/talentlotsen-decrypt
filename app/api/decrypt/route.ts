export const runtime = 'edge'; // läuft als Edge Function (Web Crypto verfügbar)

type EncPayload = { iv: string; ct: string; ts?: number; v?: number };

function b64ToU8(b64: string) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

export async function POST(req: Request) {
  try {
    const { iv, ct, ts }: EncPayload = await req.json();

    // Basisprüfungen
    if (!iv || !ct) return new Response('missing fields', { status: 400 });

    // Anti-Replay: 5 Minuten Fenster
    if (!ts || Math.abs(Date.now() - ts) > 5 * 60 * 1000) {
      return new Response('stale', { status: 400 });
    }

    const keyB64 = process.env.AES_KEY_B64;
    if (!keyB64) return new Response('server key missing', { status: 500 });

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
      headers: { 'content-type': 'application/json' },
    });
  } catch {
    return new Response('bad payload', { status: 400 });
  }
}
