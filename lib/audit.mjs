import { createHash } from "node:crypto";
import { db, now, bkkDay, bkkDayStartIso } from "./db.mjs";

const sha = (s) => createHash("sha256").update(String(s)).digest("hex");
const num = (s) => Number(String(s).replace(/,/g, ""));
const WINDOW_MIN = Number(process.env.WW_MATCH_WINDOW_MIN) || 10;

// รายการจากระบบจับคู่สลิปของแบรนด์ (วางมาจากหน้า "รายการเงินเข้า/ถอน") แต่ละบรรทัดต้องมี เวลา กับ ยอด · ทิศทางเดาจากคำ ไม่มีคำ = เงินเข้า
export function parseBackoffice(text, defaultDay) {
  const out = [];
  for (const [i, line0] of String(text ?? "").replace(/\r/g, "").split("\n").entries()) {
    const line = line0.trim(); if (!line) continue;
    const dt = /(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?/.exec(line) || /(\d{2})\/(\d{2})\/(\d{4})[ T,]*(\d{2}):(\d{2})(?::(\d{2}))?/.exec(line);
    const tOnly = !dt && /\b(\d{2}):(\d{2})(?::(\d{2}))?\b/.exec(line);
    let at = null;
    if (dt) {
      const ymd = dt[0].includes("/") ? [dt[3], dt[2], dt[1]] : [dt[1], dt[2], dt[3]];
      at = new Date(`${ymd[0]}-${ymd[1]}-${ymd[2]}T${dt[4]}:${dt[5]}:${dt[6] || "00"}+07:00`);
    } else if (tOnly && defaultDay) at = new Date(`${defaultDay}T${tOnly[1]}:${tOnly[2]}:${tOnly[3] || "00"}+07:00`);
    const amtM = [...line.matchAll(/(?:฿|THB)?\s*(\d{1,3}(?:,\d{3})+(?:\.\d{1,2})?|\d+\.\d{2}|\d+)(?=\s|$|บาท)/g)].map((m) => ({ v: num(m[1]), s: m[1] })).filter((x) => x.v > 0 && !/^\d{4}$/.test(x.s) && !/^0\d{9}$/.test(x.s) && x.v < 10_000_000);
    const amount = amtM.find((x) => x.s.includes(".") || x.s.includes(","))?.v ?? amtM.at(-1)?.v;
    const direction = /ถอน|เงินออก|โอนออก|withdraw|out\b/i.test(line) ? "out" : "in";
    const phone = /\b0\d{9}\b/.exec(line)?.[0] || "";
    const last4 = phone ? phone.slice(-4) : (/[…xX*]{2,}(\d{4})\b/.exec(line)?.[1] || "");
    const ref = /\b(TM[A-Z0-9]{6,}|[A-Z]{2,}\d{6,}|\d{12,})\b/.exec(line)?.[1] || "";
    if (!at || Number.isNaN(at.getTime()) || !amount) { out.push({ line: i + 1, status: "invalid", raw: line, reason: !at ? "ไม่พบเวลา" : "ไม่พบยอดเงิน" }); continue; }
    out.push({ line: i + 1, status: "ok", raw: line, at: at.toISOString(), day: bkkDay(at.toISOString()), direction, amount, last4, ref });
  }
  return out;
}

export function importBackoffice(rows) {
  const ins = db.prepare("INSERT OR IGNORE INTO backoffice_rows (day, at, direction, amount, last4, ref, raw, hash, imported_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
  let added = 0, dup = 0;
  const t = now();
  db.exec("BEGIN");
  try {
    for (const r of rows) { if (r.status !== "ok") continue; const info = ins.run(r.day, r.at, r.direction, r.amount, r.last4, r.ref, r.raw, sha(`${r.at}|${r.direction}|${r.amount}|${r.last4}|${r.ref}`), t); if (info.changes) added++; else dup++; }
    db.exec("COMMIT");
  } catch (e) { db.exec("ROLLBACK"); throw e; }
  return { added, dup };
}

export function runMatching(day) {
  const from = bkkDayStartIso(day), to = new Date(Date.parse(from) + 86400_000).toISOString();
  const devices = db.prepare("SELECT id, last4 FROM devices").all();
  const byLast4 = new Map(devices.filter((d) => d.last4).map((d) => [d.last4, d.id]));
  db.prepare("UPDATE backoffice_rows SET txn_id = NULL, status = 'pending', note = '' WHERE day = ?").run(day);
  db.prepare("UPDATE txns SET audit = '' WHERE at >= ? AND at < ?").run(from, to);
  const txns = db.prepare("SELECT id, device_id, at, direction, amount, kind FROM txns WHERE at >= ? AND at < ? AND kind <> 'fee' ORDER BY at").all(from, to);
  const used = new Set();
  const bo = db.prepare("SELECT * FROM backoffice_rows WHERE day = ? ORDER BY at").all(day);
  const setBo = db.prepare("UPDATE backoffice_rows SET txn_id = ?, status = ?, note = ? WHERE id = ?");
  const setTx = db.prepare("UPDATE txns SET audit = ? WHERE id = ?");
  const win = WINDOW_MIN * 60_000;
  const stats = { match: 0, review: 0, unmatched: 0, extra: 0 };
  db.exec("BEGIN");
  try {
    // รอบแรกจับเฉพาะยอดเท่ากันทั้งชุดก่อน ค่อยหา "ยอดไม่ตรง" ในรอบสอง ไม่งั้นแถวผีแถวเดียวจะแย่งรายการของแถวถัดไปแล้วผิดเป็นลูกโซ่ (เจอตอนทดสอบ 25 พ.ย. 2569)
    const cand = (b) => { const devId = byLast4.get(b.last4) ?? null; return txns.filter((t) => !used.has(t.id) && t.direction === b.direction && (!devId || t.device_id === devId) && Math.abs(Date.parse(t.at) - Date.parse(b.at)) <= win); };
    const left = [];
    for (const b of bo) {
      const exact = cand(b).filter((t) => Math.abs(t.amount - b.amount) < 0.005).sort((x, y) => Math.abs(Date.parse(x.at) - Date.parse(b.at)) - Math.abs(Date.parse(y.at) - Date.parse(b.at)))[0];
      if (exact) { used.add(exact.id); setBo.run(exact.id, "match", "ตรงกับมือถือ", b.id); setTx.run("match", exact.id); stats.match++; } else left.push(b);
    }
    for (const b of left) {
      const near = cand(b).sort((x, y) => Math.abs(x.amount - b.amount) - Math.abs(y.amount - b.amount) || Math.abs(Date.parse(x.at) - Date.parse(b.at)) - Math.abs(Date.parse(y.at) - Date.parse(b.at)))[0];
      if (near) { used.add(near.id); setBo.run(near.id, "review", `ยอดไม่ตรง (มือถือ ${near.amount.toLocaleString("en-US")})`, b.id); setTx.run("review", near.id); stats.review++; continue; }
      setBo.run(null, "unmatched", "ไม่พบรายการในมือถือ", b.id); stats.unmatched++;
    }
    for (const t of txns) if (!used.has(t.id)) { setTx.run("extra", t.id); stats.extra++; }
    db.exec("COMMIT");
  } catch (e) { db.exec("ROLLBACK"); throw e; }
  return stats;
}

export function auditRows(day, deviceId) {
  const from = bkkDayStartIso(day), to = new Date(Date.parse(from) + 86400_000).toISOString();
  const bo = db.prepare(`SELECT b.*, t.device_id, t.at txn_at, t.amount txn_amount, d.name device_name FROM backoffice_rows b LEFT JOIN txns t ON t.id = b.txn_id LEFT JOIN devices d ON d.id = t.device_id WHERE b.day = ? ${deviceId ? "AND (t.device_id = ? OR (t.device_id IS NULL AND b.last4 = (SELECT last4 FROM devices WHERE id = ?)))" : ""} ORDER BY b.at`).all(...(deviceId ? [day, deviceId, deviceId] : [day]));
  const extra = db.prepare(`SELECT t.*, d.name device_name, d.last4 FROM txns t JOIN devices d ON d.id = t.device_id WHERE t.at >= ? AND t.at < ? AND t.audit = 'extra' ${deviceId ? "AND t.device_id = ?" : ""} ORDER BY t.at`).all(...(deviceId ? [from, to, deviceId] : [from, to]));
  return { bo, extra };
}
