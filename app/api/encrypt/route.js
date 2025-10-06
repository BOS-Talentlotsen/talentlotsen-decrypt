export const runtime = 'edge'; // Läuft als Edge Function (Web Crypto verfügbar)

/**
 * Erwartet Body: { data: <beliebiges JSON> }
 * Antwort: { v: 1, iv: string(base64), ct: string(base64), ts: number }
 */

function b64ToU8(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}
function u8ToB64(u8) {
  return btoa(String.fromCharCode(...u8));
}

export async function POST(req) {
  try {
    const body = await req.json();
    if (!body || typeof body !== 'object' || !('data' in body)) {
      return new Response('missing data', { status: 400 });
    }

    const keyB64 = process.env.AES_KEY_B64;
    if (!keyB64) {
      return new Response('server key missing', { status: 500 });
    }

    const key = await crypto.subtle.importKey(
      'raw',
      b64ToU8(keyB64),
      'AES-GCM',
      false,
      ['encrypt']
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode(JSON.stringify(body.data));
    const ctBuf = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext)
    );

    const payload = {
      v: 1,
      iv: u8ToB64(iv),
      ct: u8ToB64(ctBuf),
      ts: Date.now()
    };

    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: { 'content-type': 'application/json' }
    });
  } catch {
    return new Response('bad payload', { status: 400 });
  }
}
