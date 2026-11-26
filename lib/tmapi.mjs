import { createHmac, timingSafeEqual } from "node:crypto";

export const AMOUNT_DIVISOR = 100;

const fromB64url = (s) => Buffer.from(String(s), "base64url").toString("utf8");

export function decodeTmJwt(jwt, secret) {
  const parts = String(jwt ?? "").trim().split(".");
  if (parts.length !== 3) return { error: "ไม่พบ JWT ในฟิลด์ message" };
  let header, payload;
  try { header = JSON.parse(fromB64url(parts[0])); payload = JSON.parse(fromB64url(parts[1])); } catch { return { error: "ถอด JWT ไม่ได้" }; }
  if (!payload || typeof payload !== "object") return { header, error: "payload ของ JWT ไม่ใช่ JSON object" };
  if (!secret) return { header, payload, verified: false };
  if (header?.alg !== "HS256") return { header, payload, error: `alg ไม่ใช่ HS256 (${header?.alg})` };
  const want = createHmac("sha256", secret).update(parts[0] + "." + parts[1]).digest();
  const got = Buffer.from(parts[2], "base64url");
  if (got.length !== want.length || !timingSafeEqual(got, want)) return { header, payload, error: "ลายเซ็นไม่ถูกต้อง (secret ไม่ตรง)" };
  return { header, payload, verified: true };
}

export function parseTmPayload(p) {
  const type = String(p.event_type ?? p.Channel ?? "").toUpperCase();
  const amount = Math.round((Number(p.amount) / AMOUNT_DIVISOR) * 100) / 100;
  const id = p.unique_transid ?? p.transaction_id ?? null;
  const t = Date.parse(String(p.received_time ?? "").replace(/([+-]\d{2})(\d{2})$/, "$1:$2"));
  const at = Number.isFinite(t) ? new Date(t).toISOString() : null;
  const who = [p.sender_name, p.sender_mobile].filter(Boolean).join(" ");
  const note = String(p.message ?? "").replace(/\s+/g, " ").trim().slice(0, 300);
  const safe = { ...p };
  const text = [`TrueMoney API ${type || "?"}`, Number.isFinite(amount) ? `รับ ${amount.toFixed(2)} บาท` : "", who && `จาก ${who}`, p.transaction_id && `ref ${p.transaction_id}`, note && `ข้อความ: ${note}`].filter(Boolean).join(" · ");
  if (!(amount > 0) || id == null) return { ok: false, text, safe, id: id != null ? String(id) : null, at };
  return { ok: true, direction: "in", amount, balance: null, counterpart: who.slice(0, 40), id: String(id), at, text, safe, kind: /TOP/.test(type) ? "topup" : "receive" };
}
