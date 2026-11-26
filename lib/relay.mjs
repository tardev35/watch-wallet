export const FORWARD_TIMEOUT_MS = 10_000;

const DROP = new Set(["host", "content-length", "connection", "keep-alive", "transfer-encoding", "upgrade", "te", "trailer", "expect",
  "proxy-authorization", "proxy-connection", "forwarded", "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-forwarded-port",
  "x-real-ip", "true-client-ip", "cdn-loop", "accept-encoding"]);

export function validForwardUrl(u) {
  try {
    const x = new URL(String(u));
    return !!x.hostname && (x.protocol === "https:" || (x.protocol === "http:" && process.env.WW_FORWARD_ALLOW_HTTP === "1"));
  } catch { return false; }
}

export const okStatus = (s) => s >= 200 && s < 300;

export async function forward(url, method, headers, raw) {
  const h = {};
  for (const [k, v] of Object.entries(headers || {})) {
    const key = k.toLowerCase();
    if (DROP.has(key) || key.startsWith("cf-")) continue;
    h[key] = Array.isArray(v) ? v.join(", ") : String(v);
  }
  const t0 = Date.now();
  try {
    const r = await fetch(url, { method, headers: h, body: raw.length ? raw : undefined, redirect: "manual", signal: AbortSignal.timeout(FORWARD_TIMEOUT_MS) });
    const body = Buffer.from(await r.arrayBuffer());
    const error = okStatus(r.status) ? "" : r.status >= 300 && r.status < 400 ? `ปลายทางเด้งไป ${r.headers.get("location") || "?"}` : `ปลายทางตอบ ${r.status}`;
    return { status: r.status, ms: Date.now() - t0, body, contentType: r.headers.get("content-type") || "", error };
  } catch (e) {
    const error = e?.name === "TimeoutError" ? `ปลายทางไม่ตอบใน ${FORWARD_TIMEOUT_MS / 1000} วินาที` : `ส่งไม่ถึงปลายทาง: ${e?.cause?.code || e?.message || e}`;
    return { status: 0, ms: Date.now() - t0, body: null, contentType: "", error };
  }
}
