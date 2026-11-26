import { db, now, bkkDay, bkkDayStartIso } from "./db.mjs";

const TG_TOKEN = process.env.WW_TG_TOKEN || "";
const TG_CHAT = process.env.WW_TG_CHAT || "";
const QUIET_MIN = Number(process.env.WW_QUIET_MIN) || 20;
const DEVICE_SILENT_MIN = Number(process.env.WW_DEVICE_SILENT_MIN) || 30;
const ACTIVE_HOURS = [8, 26];

const fmt = (n) => Number(n ?? 0).toLocaleString("en-US", { maximumFractionDigits: 2 });
const bkkHour = (iso = now()) => (new Date(iso).getUTCHours() + 7) % 24;
const inActiveHours = () => { const h = bkkHour(); return h >= ACTIVE_HOURS[0] || h < ACTIVE_HOURS[1] - 24; };

export function todayStats(deviceId, day = bkkDay()) {
  const from = bkkDayStartIso(day), to = new Date(Date.parse(from) + 86400_000).toISOString();
  return db.prepare(`SELECT
      COALESCE(SUM(CASE WHEN direction='in' THEN amount END),0) in_amt, SUM(direction='in') in_n,
      COALESCE(SUM(CASE WHEN direction='out' THEN amount END),0) out_amt, SUM(direction='out' AND kind <> 'fee') out_n,
      MAX(CASE WHEN direction='in' THEN at END) last_in, MAX(at) last_any
    FROM txns WHERE device_id = ? AND at >= ? AND at < ?`).get(deviceId, from, to);
}

function openAlert(rule, deviceId, key, message) {
  const exists = db.prepare("SELECT id FROM alerts WHERE rule = ? AND key = ? AND closed_at IS NULL").get(rule, key);
  if (exists) return null;
  const info = db.prepare("INSERT INTO alerts (at, rule, device_id, key, message) VALUES (?, ?, ?, ?, ?)").run(now(), rule, deviceId, key, message);
  return info.lastInsertRowid;
}
function closeAlert(rule, key) {
  db.prepare("UPDATE alerts SET closed_at = ? WHERE rule = ? AND key = ? AND closed_at IS NULL").run(now(), rule, key);
}

export async function sendTelegram(text) {
  if (!TG_TOKEN || !TG_CHAT) return false;
  try {
    const r = await fetch(`https://api.telegram.org/bot${TG_TOKEN}/sendMessage`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ chat_id: TG_CHAT, text, disable_web_page_preview: true }) });
    return r.ok;
  } catch { return false; }
}

export async function runRules() {
  const devices = db.prepare("SELECT * FROM devices WHERE active = 1").all();
  const day = bkkDay();
  const nowMs = Date.now();
  const out = [];
  for (const d of devices) {
    const s = todayStats(d.id, day);
    const label = `${d.name}${d.last4 ? ` (…${d.last4})` : ""}${d.brand ? ` · ${d.brand}` : ""}`;

    if (d.daily_limit > 0) {
      const pct = s.in_amt / d.daily_limit;
      const lastHour = db.prepare("SELECT COALESCE(SUM(amount),0) a FROM txns WHERE device_id = ? AND direction = 'in' AND at >= ?").get(d.id, new Date(nowMs - 3600_000).toISOString()).a;
      const etaMin = lastHour > 0 ? Math.round((d.daily_limit - s.in_amt) / lastHour * 60) : null;
      const eta = etaMin != null && etaMin > 0 ? ` · อัตราชั่วโมงล่าสุด ${fmt(lastHour)}/ชม. คาดเต็มในอีก ${etaMin} นาที` : "";
      if (pct >= 0.95) openAlert("limit95", d.id, `${d.id}:${day}`, `⚠ ${label} รับแล้ว ${fmt(s.in_amt)} = ${Math.round(pct * 100)}% ของวงเงิน ${fmt(d.daily_limit)}${eta}`);
      else if (pct >= 0.8) openAlert("limit80", d.id, `${d.id}:${day}`, `${label} รับแล้ว ${fmt(s.in_amt)} = ${Math.round(pct * 100)}% ของวงเงิน ${fmt(d.daily_limit)}${eta}`);
    }

    if (inActiveHours()) {
      const sinceMs = nowMs - QUIET_MIN * 60_000;
      const recent = db.prepare("SELECT COUNT(*) n FROM txns WHERE device_id = ? AND direction = 'in' AND at >= ?").get(d.id, new Date(sinceMs).toISOString()).n;
      const base = db.prepare(`SELECT COUNT(*) n FROM txns WHERE device_id = ? AND direction = 'in' AND at >= ? AND at < ? AND
          ((CAST(strftime('%H', at, '+7 hours') AS INTEGER) * 60 + CAST(strftime('%M', at, '+7 hours') AS INTEGER)) BETWEEN ? AND ?)`)
        .get(d.id, new Date(nowMs - 7 * 86400_000).toISOString(), new Date(nowMs - 86400_000).toISOString(),
          Math.max(0, (bkkHour() * 60 + new Date().getUTCMinutes()) - QUIET_MIN), bkkHour() * 60 + new Date().getUTCMinutes()).n;
      const expected = base / 7;
      if (recent === 0 && expected >= 3) openAlert("quiet", d.id, `${d.id}:${day}:${s.last_in ?? "none"}`, `🔕 ${label} ไม่มีเงินเข้า ${QUIET_MIN} นาที ทั้งที่ช่วงเดียวกัน 7 วันก่อนเฉลี่ย ${fmt(expected)} รายการ · เงินเข้าล่าสุด ${s.last_in ? new Date(s.last_in).toLocaleTimeString("th-TH", { hour: "2-digit", minute: "2-digit", timeZone: "Asia/Bangkok" }) : "ยังไม่มีวันนี้"}`);
      else if (recent > 0) closeAlert("quiet", `${d.id}:${day}:${s.last_in ?? "none"}`);

      const seen = d.last_seen_at ? Date.parse(d.last_seen_at) : 0;
      if (nowMs - seen > DEVICE_SILENT_MIN * 60_000 && expected >= 1) openAlert("device_silent", d.id, `${d.id}:${day}`, `📵 เครื่อง ${label} ไม่ส่งข้อความใดๆ มา ${Math.round((nowMs - seen) / 60_000)} นาที (ข้อมูลขาด ไม่ใช่วอเล็ตเงียบ) ตรวจมือถือ/แอปส่งต่อ`);
      else if (nowMs - seen <= DEVICE_SILENT_MIN * 60_000) closeAlert("device_silent", `${d.id}:${day}`);
    }
  }
  const pending = db.prepare("SELECT a.*, d.name FROM alerts a LEFT JOIN devices d ON d.id = a.device_id WHERE a.sent_at IS NULL ORDER BY a.id").all();
  for (const a of pending) {
    const ok = await sendTelegram(a.message);
    db.prepare("UPDATE alerts SET sent_at = ? WHERE id = ?").run(ok ? now() : (TG_TOKEN ? null : now()), a.id);
    out.push(a);
  }
  return out;
}

export function dailyReportText(day = bkkDay(new Date(Date.now() - 86400_000).toISOString())) {
  const devices = db.prepare("SELECT * FROM devices WHERE active = 1 ORDER BY name").all();
  const rows = devices.map((d) => ({ d, s: todayStats(d.id, day) }));
  const tin = rows.reduce((a, r) => a + r.s.in_amt, 0), tn = rows.reduce((a, r) => a + (r.s.in_n || 0), 0);
  const tout = rows.reduce((a, r) => a + r.s.out_amt, 0), ton = rows.reduce((a, r) => a + (r.s.out_n || 0), 0);
  const full = rows.filter((r) => r.d.daily_limit > 0 && r.s.in_amt >= r.d.daily_limit * 0.95).map((r) => `${r.d.name} (…${r.d.last4}) ${fmt(r.s.in_amt)}`);
  const top = [...rows].sort((a, b) => b.s.in_amt - a.s.in_amt)[0];
  const byBrand = {}; for (const r of rows) byBrand[r.d.brand || "ไม่ระบุ"] = (byBrand[r.d.brand || "ไม่ระบุ"] || 0) + r.s.in_amt;
  const [dd, mm, yy] = [day.slice(8, 10), day.slice(5, 7), String(Number(day.slice(0, 4)) + 543).slice(2)];
  return [
    `วอเล็ต ${dd}/${mm}/${yy}`,
    `เงินเข้า ${devices.length} วอเล็ต ${fmt(tin)} บาท ${fmt(tn)} รายการ · เงินออก ${fmt(tout)} บาท ${fmt(ton)} รายการ`,
    full.length ? `ถึงวงเงิน 95% ขึ้นไป ${full.length} ใบ: ${full.join(" · ")}` : "ไม่มีวอเล็ตถึงวงเงิน",
    top && tin ? `รับมากสุด ${top.d.name} (…${top.d.last4}) ${fmt(top.s.in_amt)} (${Math.round(top.s.in_amt / tin * 100)}%)` : "",
    Object.entries(byBrand).sort((a, b) => b[1] - a[1]).map(([b, v]) => `${b} ${fmt(v)}`).join(" · "),
  ].filter(Boolean).join("\n");
}
