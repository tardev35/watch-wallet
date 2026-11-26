import express from "express";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { db, now, bkkDay, bkkDayStartIso } from "./lib/db.mjs";
import { parseText, extractMessage, maskPhones } from "./lib/parse.mjs";
import { runRules, todayStats, dailyReportText, sendTelegram } from "./lib/rules.mjs";
import { parseBackoffice, importBackoffice, runMatching, auditRows } from "./lib/audit.mjs";
import { decodeTmJwt, parseTmPayload } from "./lib/tmapi.mjs";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT) || 3960;
const app = express();
app.set("trust proxy", true);
app.use(express.json({ limit: "256kb", type: () => true }));
app.use(express.urlencoded({ extended: true, limit: "256kb" }));
app.use(express.static(path.join(ROOT, "public"), { extensions: ["html"] }));

const sha = (s) => createHash("sha256").update(String(s)).digest("hex");
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });
const deviceByToken = db.prepare("SELECT * FROM devices WHERE token_hash = ? AND active = 1");

// รายการเดียวกันอาจมาทั้งจาก SMS/notification ของมือถือและจาก Webhook API ของ TrueMoney ต้องนับครั้งเดียว:
// ทิศทางเดียวกัน ยอดเท่ากัน ห่างไม่เกิน 3 นาที จากคนละแหล่ง = รายการเดิม เก็บ event ไว้แต่ไม่เพิ่ม txn
const DUP_WINDOW_MS = 3 * 60_000;
function insertTxn(deviceId, eventId, at, p, source) {
  const twin = db.prepare(`SELECT t.id FROM txns t JOIN events e ON e.id = t.event_id WHERE t.device_id = ? AND t.direction = ? AND ABS(t.amount - ?) < 0.005 AND e.source <> ? AND t.at BETWEEN ? AND ? LIMIT 1`)
    .get(deviceId, p.direction, p.amount, source, new Date(Date.parse(at) - DUP_WINDOW_MS).toISOString(), new Date(Date.parse(at) + DUP_WINDOW_MS).toISOString());
  if (twin) { db.prepare("UPDATE events SET parsed = 2 WHERE id = ?").run(eventId); return { duplicate_of: twin.id }; }
  db.prepare("INSERT INTO txns (device_id, event_id, at, direction, amount, balance, counterpart, pattern, kind) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
    .run(deviceId, eventId, at, p.direction, p.amount, p.balance ?? null, p.counterpart || "", p.pattern || source, p.kind || "");
  db.prepare("UPDATE events SET parsed = 1 WHERE id = ?").run(eventId);
  return { inserted: true };
}

app.all("/tm/:token", (req, res) => {
  const d = deviceByToken.get(sha(req.params.token));
  if (!d) return bad(res, "token ไม่ถูกต้องหรือเครื่องถูกปิดใช้งาน", 401);
  if (req.method === "GET") return res.json({ ok: true, challenge: req.query.challenge ?? req.query.hub_challenge ?? null });
  const body = req.body && Object.keys(req.body).length ? req.body : req.query;
  const jwt = typeof body.message === "string" ? body.message.trim() : "";
  const t = now();
  const store = (text, raw, hash) => db.prepare("INSERT INTO events (device_id, received_at, source, sender, text, raw, hash) VALUES (?, ?, 'tm_api', 'TrueMoney Webhook', ?, ?, ?)")
    .run(d.id, t, text.slice(0, 2000), JSON.stringify(raw).slice(0, 8000), hash).lastInsertRowid;
  const rejectHash = sha("tm-reject:" + (jwt || JSON.stringify(body)));
  const j = decodeTmJwt(jwt, d.tm_secret);
  if (j.error) {
    const safe = j.payload ? parseTmPayload(j.payload) : null;
    try { store(`TrueMoney API ถูกปฏิเสธ: ${j.error}${safe ? " · " + safe.text : ""}`, { error: j.error, header: j.header ?? null, payload: safe?.safe ?? null, body_keys: Object.keys(body) }, rejectHash); }
    catch (e) { if (!String(e.message).includes("UNIQUE")) throw e; }
    return bad(res, j.error, 401);
  }
  db.prepare("UPDATE devices SET last_seen_at = ? WHERE id = ?").run(t, d.id);
  const p = parseTmPayload(j.payload);
  let eventId;
  try { eventId = store(p.text, { verified: j.verified, header: j.header, payload: p.safe }, sha("tm:" + (p.id ?? jwt))); }
  catch (e) { if (String(e.message).includes("UNIQUE")) return res.json({ ok: true, duplicate: true }); throw e; }
  db.prepare("UPDATE events SET parsed = 2 WHERE device_id = ? AND hash = ? AND parsed = 0").run(d.id, rejectHash);
  if (!p.ok) return res.json({ ok: true, parsed: false, verified: j.verified });
  const r = insertTxn(d.id, eventId, p.at || t, { ...p, pattern: "tm_api" }, "tm_api");
  res.json({ ok: true, parsed: true, verified: j.verified, ...r });
});

app.all("/hook/:token", (req, res) => {
  const d = deviceByToken.get(sha(req.params.token));
  if (!d) return bad(res, "token ไม่ถูกต้องหรือเครื่องถูกปิดใช้งาน", 401);
  const msg = extractMessage(req.body, req.query);
  const text = maskPhones(msg.text), sender = maskPhones(msg.sender), { source, when } = msg;
  if (!text) return bad(res, "ไม่พบข้อความในคำขอ");
  const t = now();
  const hash = sha(`${text}|${when || t.slice(0, 16)}`);
  db.prepare("UPDATE devices SET last_seen_at = ? WHERE id = ?").run(t, d.id);
  let eventId;
  try {
    eventId = db.prepare("INSERT INTO events (device_id, received_at, source, sender, text, raw, hash) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(d.id, t, source, sender, text.slice(0, 2000), maskPhones(JSON.stringify(req.body && Object.keys(req.body).length ? req.body : req.query)).slice(0, 8000), hash).lastInsertRowid;
  } catch (e) {
    if (String(e.message).includes("UNIQUE")) return res.json({ ok: true, duplicate: true });
    throw e;
  }
  const p = parseText(text);
  let r = {};
  if (p) { const at = when && !Number.isNaN(Date.parse(when)) ? new Date(when).toISOString() : t; r = insertTxn(d.id, eventId, at, p, source || "sms"); }
  res.json({ ok: true, parsed: !!p, ...(p || {}), ...r });
});

const dayArg = (q) => (/^\d{4}-\d{2}-\d{2}$/.test(String(q || "")) ? String(q) : bkkDay());
app.get("/api/state", (req, res) => {
  const day = dayArg(req.query.day);
  const devices = db.prepare("SELECT id, name, last4, brand, holder, daily_limit, token_hint, active, created_at, last_seen_at, tm_secret <> '' AS tm_secret_set, tm_secret_at FROM devices ORDER BY active DESC, name").all();
  const rows = devices.map((d) => {
    const s = todayStats(d.id, day);
    const lastHour = db.prepare("SELECT COALESCE(SUM(amount),0) a, COUNT(*) n FROM txns WHERE device_id = ? AND direction = 'in' AND at >= ?").get(d.id, new Date(Date.now() - 3600_000).toISOString());
    const unparsed = db.prepare("SELECT COUNT(*) n FROM events WHERE device_id = ? AND parsed = 0 AND received_at >= ?").get(d.id, new Date(Date.now() - 86400_000).toISOString()).n;
    const src = db.prepare("SELECT source, COUNT(*) n FROM events WHERE device_id = ? AND received_at >= ? GROUP BY source").all(d.id, new Date(Date.now() - 86400_000).toISOString());
    return { ...d, ...s, last_hour_amt: lastHour.a, last_hour_n: lastHour.n, unparsed_24h: unparsed, sources_24h: Object.fromEntries(src.map((x) => [x.source || "sms", x.n])) };
  });
  const totals = rows.reduce((a, r) => ({ in_amt: a.in_amt + r.in_amt, in_n: a.in_n + (r.in_n || 0), out_amt: a.out_amt + r.out_amt, out_n: a.out_n + (r.out_n || 0) }), { in_amt: 0, in_n: 0, out_amt: 0, out_n: 0 });
  const alerts = db.prepare("SELECT a.*, d.name device_name FROM alerts a LEFT JOIN devices d ON d.id = a.device_id ORDER BY a.id DESC LIMIT 50").all();
  const from = new Date(Date.parse(day + "T00:00:00+07:00")).toISOString(), to = new Date(Date.parse(from) + 86400_000).toISOString();
  const hourly = db.prepare(`SELECT strftime('%H', at, '+7 hours') h, direction, COALESCE(SUM(amount),0) amt, COUNT(*) n FROM txns WHERE at >= ? AND at < ? AND kind <> 'fee' GROUP BY 1, 2 ORDER BY 1`).all(from, to);
  const fees = db.prepare("SELECT COALESCE(SUM(amount),0) a, COUNT(*) n FROM txns WHERE at >= ? AND at < ? AND kind = 'fee'").get(from, to);
  const audit = db.prepare("SELECT status, COUNT(*) n FROM backoffice_rows WHERE day = ? GROUP BY status").all(day);
  const extra = db.prepare("SELECT COUNT(*) n FROM txns WHERE at >= ? AND at < ? AND audit = 'extra'").get(from, to).n;
  const open_alerts = db.prepare("SELECT COUNT(*) n FROM alerts WHERE closed_at IS NULL").get().n;
  const with_data = rows.filter((r) => (r.in_n || 0) + (r.out_n || 0) > 0).length;
  res.json({ day, devices: rows, totals, alerts, hourly, fees, audit: Object.fromEntries(audit.map((a) => [a.status, a.n])), extra, open_alerts, with_data, telegram: !!(process.env.WW_TG_TOKEN && process.env.WW_TG_CHAT) });
});

app.get("/api/txns", (req, res) => {
  const deviceId = Number(req.query.device) || null;
  const where = ["1=1"], args = [];
  if (deviceId) { where.push("t.device_id = ?"); args.push(deviceId); }
  if (req.query.direction === "in" || req.query.direction === "out") { where.push("t.direction = ?"); args.push(req.query.direction); }
  if (req.query.day) { const from = new Date(Date.parse(req.query.day + "T00:00:00+07:00")).toISOString(); where.push("t.at >= ? AND t.at < ?"); args.push(from, new Date(Date.parse(from) + 86400_000).toISOString()); }
  const rows = db.prepare(`SELECT t.*, d.name device_name, d.last4, e.text FROM txns t JOIN devices d ON d.id = t.device_id JOIN events e ON e.id = t.event_id WHERE ${where.join(" AND ")} ORDER BY t.at DESC LIMIT 500`).all(...args);
  res.json({ rows });
});
app.get("/api/unparsed", (_req, res) => {
  res.json({ rows: db.prepare("SELECT e.id, e.received_at, e.source, e.sender, e.text, d.name device_name FROM events e JOIN devices d ON d.id = e.device_id WHERE e.parsed = 0 ORDER BY e.id DESC LIMIT 200").all() });
});
app.get("/api/daily", (req, res) => {
  const days = Math.min(90, Number(req.query.days) || 30);
  const out = [];
  for (let i = 0; i < days; i++) {
    const day = bkkDay(new Date(Date.now() - i * 86400_000).toISOString());
    const per = db.prepare("SELECT id, name, last4, brand FROM devices WHERE active = 1").all().map((d) => ({ ...d, ...todayStats(d.id, day) }));
    out.push({ day, in_amt: per.reduce((a, r) => a + r.in_amt, 0), in_n: per.reduce((a, r) => a + (r.in_n || 0), 0), out_amt: per.reduce((a, r) => a + r.out_amt, 0), out_n: per.reduce((a, r) => a + (r.out_n || 0), 0), per });
  }
  res.json({ rows: out });
});
app.get("/api/daily-report", (req, res) => res.json({ text: dailyReportText(req.query.day || undefined) }));

app.post("/api/audit/import", (req, res) => {
  const day = dayArg(req.body?.day);
  const rows = parseBackoffice(req.body?.text, day);
  if (req.body?.dry_run) return res.json({ rows, summary: { lines: rows.length, ok: rows.filter((r) => r.status === "ok").length, invalid: rows.filter((r) => r.status === "invalid").length } });
  const r = importBackoffice(rows);
  const days = [...new Set(rows.filter((x) => x.status === "ok").map((x) => x.day))];
  const stats = days.map((d) => ({ day: d, ...runMatching(d) }));
  res.json({ ok: true, ...r, invalid: rows.filter((x) => x.status === "invalid"), stats });
});
app.post("/api/audit/run", (req, res) => { const day = dayArg(req.body?.day || req.query.day); res.json({ ok: true, day, ...runMatching(day) }); });
app.get("/api/audit", (req, res) => { const day = dayArg(req.query.day); res.json({ day, ...auditRows(day, Number(req.query.device) || null) }); });
app.delete("/api/audit/:day", (req, res) => {
  const day = dayArg(req.params.day);
  const n = db.prepare("DELETE FROM backoffice_rows WHERE day = ?").run(day).changes;
  db.prepare("UPDATE txns SET audit = '' WHERE at >= ? AND at < ?").run(bkkDayStartIso(day), new Date(Date.parse(bkkDayStartIso(day)) + 86400_000).toISOString());
  res.json({ ok: true, removed: n });
});

const RULE_LABEL = { limit80: "ใกล้วงเงิน 80%", limit95: "ถึงวงเงิน 95%", quiet: "วอเล็ตเงียบ", device_silent: "เครื่องเงียบ (ข้อมูลขาด)" };
app.get("/api/exceptions", (req, res) => {
  const day = dayArg(req.query.day);
  const from = bkkDayStartIso(day), to = new Date(Date.parse(from) + 86400_000).toISOString();
  const items = [];
  for (const b of db.prepare("SELECT b.*, d.name device_name FROM backoffice_rows b LEFT JOIN txns t ON t.id = b.txn_id LEFT JOIN devices d ON d.id = t.device_id WHERE b.day = ? AND b.status IN ('review','unmatched') ORDER BY b.at").all(day))
    items.push({ kind: b.status === "review" ? "ยอดไม่ตรง" : "หลังบ้านมี มือถือไม่มี", at: b.at, wallet: b.device_name || (b.last4 ? "…" + b.last4 : "ไม่ระบุ"), direction: b.direction, amount: b.amount, note: b.note, source: "backoffice", id: b.id });
  for (const t of db.prepare("SELECT t.*, d.name device_name FROM txns t JOIN devices d ON d.id = t.device_id WHERE t.at >= ? AND t.at < ? AND t.audit = 'extra' ORDER BY t.at").all(from, to))
    items.push({ kind: "มือถือมี หลังบ้านไม่มี", at: t.at, wallet: t.device_name, direction: t.direction, amount: t.amount, note: t.counterpart, source: "txn", id: t.id });
  for (const a of db.prepare("SELECT a.*, d.name device_name FROM alerts a LEFT JOIN devices d ON d.id = a.device_id WHERE a.at >= ? AND a.at < ? ORDER BY a.at").all(from, to))
    items.push({ kind: RULE_LABEL[a.rule] || a.rule, at: a.at, wallet: a.device_name || "", direction: "", amount: null, note: a.message, source: "alert", id: a.id, closed: !!a.closed_at });
  for (const e of db.prepare("SELECT e.*, d.name device_name FROM events e JOIN devices d ON d.id = e.device_id WHERE e.received_at >= ? AND e.received_at < ? AND e.parsed = 0 ORDER BY e.received_at").all(from, to))
    items.push({ kind: "ข้อความแยกไม่ออก", at: e.received_at, wallet: e.device_name, direction: "", amount: null, note: e.text.slice(0, 160), source: "event", id: e.id });
  items.sort((a, b) => a.at.localeCompare(b.at));
  res.json({ day, items });
});

app.get("/api/summary", (req, res) => {
  const day = dayArg(req.query.day);
  const from = bkkDayStartIso(day), to = new Date(Date.parse(from) + 86400_000).toISOString();
  const rows = db.prepare("SELECT id, name, last4, brand, holder, daily_limit FROM devices WHERE active = 1 ORDER BY brand, name").all().map((d) => {
    const s = todayStats(d.id, day);
    const fee = db.prepare("SELECT COALESCE(SUM(amount),0) a FROM txns WHERE device_id = ? AND at >= ? AND at < ? AND kind = 'fee'").get(d.id, from, to).a;
    const exc = db.prepare("SELECT COUNT(*) n FROM backoffice_rows b LEFT JOIN txns t ON t.id = b.txn_id WHERE b.day = ? AND b.status IN ('review','unmatched') AND (t.device_id = ? OR (t.device_id IS NULL AND b.last4 = ?))").get(day, d.id, d.last4).n
      + db.prepare("SELECT COUNT(*) n FROM txns WHERE device_id = ? AND at >= ? AND at < ? AND audit = 'extra'").get(d.id, from, to).n
      + db.prepare("SELECT COUNT(*) n FROM alerts WHERE device_id = ? AND at >= ? AND at < ?").get(d.id, from, to).n;
    return { ...d, ...s, out_amt: s.out_amt - fee, fee, exceptions: exc };
  });
  res.json({ day, rows });
});

app.post("/api/devices", (req, res) => {
  const b = req.body || {};
  const name = String(b.name ?? "").trim(); if (!name) return bad(res, "ต้องตั้งชื่อเครื่อง/วอเล็ต");
  const last4 = String(b.last4 ?? "").replace(/\D/g, "").slice(-4);
  const token = randomBytes(18).toString("base64url");
  const info = db.prepare("INSERT INTO devices (name, last4, brand, holder, daily_limit, token_hash, token_hint, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    .run(name, last4, String(b.brand ?? "").trim(), String(b.holder ?? "").trim(), Number(b.daily_limit) || 0, sha(token), token.slice(0, 4) + "…" + token.slice(-3), now());
  res.json({ ok: true, id: info.lastInsertRowid, token, hook: `/hook/${token}`, tm_hook: `/tm/${token}` });
});
app.put("/api/devices/:id", (req, res) => {
  const id = Number(req.params.id); const cur = db.prepare("SELECT * FROM devices WHERE id = ?").get(id);
  if (!cur) return bad(res, "ไม่พบเครื่องนี้", 404);
  const b = { ...cur, ...(req.body || {}) };
  db.prepare("UPDATE devices SET name = ?, last4 = ?, brand = ?, holder = ?, daily_limit = ?, active = ? WHERE id = ?")
    .run(String(b.name).trim(), String(b.last4 ?? "").replace(/\D/g, "").slice(-4), String(b.brand ?? "").trim(), String(b.holder ?? "").trim(), Number(b.daily_limit) || 0, b.active ? 1 : 0, id);
  if (typeof req.body?.tm_secret === "string") {
    const s = req.body.tm_secret.trim() === "-" ? "" : req.body.tm_secret.trim();
    if (req.body.tm_secret.trim()) db.prepare("UPDATE devices SET tm_secret = ?, tm_secret_at = ? WHERE id = ?").run(s, s ? now() : null, id);
  }
  res.json({ ok: true });
});
app.post("/api/devices/:id/rotate", (req, res) => {
  const id = Number(req.params.id); if (!db.prepare("SELECT 1 FROM devices WHERE id = ?").get(id)) return bad(res, "ไม่พบเครื่องนี้", 404);
  const token = randomBytes(18).toString("base64url");
  db.prepare("UPDATE devices SET token_hash = ?, token_hint = ? WHERE id = ?").run(sha(token), token.slice(0, 4) + "…" + token.slice(-3), id);
  res.json({ ok: true, token, hook: `/hook/${token}`, tm_hook: `/tm/${token}` });
});
app.post("/api/alerts/:id/close", (req, res) => { db.prepare("UPDATE alerts SET closed_at = ? WHERE id = ? AND closed_at IS NULL").run(now(), Number(req.params.id)); res.json({ ok: true }); });
function reparseUnparsed() {
  let n = 0;
  for (const e of db.prepare("SELECT id, device_id, received_at, source, text, raw FROM events WHERE parsed = 0 AND source <> 'tm_api' ORDER BY id").all()) {
    const p = parseText(e.text);
    if (!p) continue;
    let when = "";
    try { when = extractMessage(JSON.parse(e.raw), {}).when; } catch {}
    const at = when && !Number.isNaN(Date.parse(when)) ? new Date(when).toISOString() : e.received_at;
    insertTxn(e.device_id, e.id, at, p, e.source || "sms");
    n++;
  }
  return n;
}
app.post("/api/reparse", (_req, res) => res.json({ ok: true, parsed: reparseUnparsed() }));
app.post("/api/test-telegram", async (_req, res) => res.json({ ok: await sendTelegram("ทดสอบจาก wallet-watch " + new Date().toLocaleString("th-TH", { timeZone: "Asia/Bangkok" })) }));

app.use((err, _req, res, _next) => res.status(500).json({ error: "เกิดข้อผิดพลาดในระบบ: " + (err?.message || "ไม่ทราบสาเหตุ") }));

let lastDaily = "";
setInterval(async () => {
  try { await runRules(); } catch (e) { console.error("rules:", e.message); }
  const bkk = new Date(Date.now() + 7 * 3600_000);
  const key = bkk.toISOString().slice(0, 10);
  if (bkk.getUTCHours() === 0 && bkk.getUTCMinutes() >= 5 && lastDaily !== key) {
    lastDaily = key;
    try { await sendTelegram(dailyReportText()); } catch (e) { console.error("daily:", e.message); }
  }
}, 60_000);

const reparsed = reparseUnparsed();
if (reparsed) console.log(`อ่านข้อความที่ค้างใหม่ได้ ${reparsed} รายการ`);
app.listen(PORT, "127.0.0.1", () => console.log(`wallet-watch เปิดที่ http://localhost:${PORT}`));
