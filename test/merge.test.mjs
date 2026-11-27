import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHmac } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const DB = path.join(mkdtempSync(path.join(tmpdir(), "ww-merge-")), "t.db");
const PORT = 39632, BASE = `http://127.0.0.1:${PORT}`;

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const sign = (payload, secret) => { const h = b64({ alg: "HS256", typ: "JWT" }), p = b64(payload); return `${h}.${p}.${createHmac("sha256", secret).update(h + "." + p).digest("base64url")}`; };
const bkk = (min) => new Date(Date.UTC(2026, 10, 26, 13, 0) + min * 60_000 + 7 * 3600e3).toISOString().slice(0, 19);
const pay = (uid, baht, mobile, min) => ({ event_type: "P2P", received_time: bkk(min) + "+0700", amount: baht * 100, sender_mobile: mobile, message: "", Channel: "P2P", sender_name: "ทดสอบ ส***", transaction_id: "T" + uid, unique_transid: uid });
const api = (p, method = "GET", body) => fetch(BASE + p, { method, headers: { "Content-Type": "application/json" }, body: body && JSON.stringify(body) }).then(async (r) => ({ status: r.status, json: await r.json() }));
const tm = (tok, payload, secret = "S") => api(`/tm/${tok}`, "POST", { message: sign(payload, secret) });
const noti = (tok, baht, mobile, min, sec = 0) => api(`/hook/${tok}`, "POST", { text: `TrueMoney Wallet คุณได้รับเงิน ฿ ${baht} จาก ${mobile}`, timestamp: `${bkk(min).slice(0, 17)}${String(sec).padStart(2, "0")}+07:00` });
const all = (sql, ...a) => { const d = new DatabaseSync(DB, { readOnly: true }); try { return d.prepare(sql).all(...a); } finally { d.close(); } };

test("รวมวอเล็ตซ้ำ · กันนับซ้ำด้วยเบอร์ผู้โอน · handshake", async (t) => {
  const srv = spawn(process.execPath, ["--no-warnings", "server.mjs"], { cwd: ROOT, env: { ...process.env, PORT: String(PORT), WW_DB_FILE: DB, WW_TG_TOKEN: "", WW_TG_CHAT: "" }, stdio: ["ignore", "pipe", "inherit"] });
  t.after(() => srv.kill());
  await new Promise((r) => srv.stdout.on("data", (d) => String(d).includes("เปิดที่") && r()));

  const phone = (await api("/api/devices", "POST", { name: "PHONE" })).json;
  const apiDev = (await api("/api/devices", "POST", { name: "API" })).json;
  await api(`/api/devices/${apiDev.id}`, "PUT", { tm_secret: "S" });

  await t.test("handshake ตอบ 200 และไม่ขึ้นเป็นข้อความแยกไม่ออก", async () => {
    const r = await api(`/tm/${apiDev.token}`, "POST", { message: sign({ server: "handshake", iat: 1795703362 }, "S") });
    assert.equal(r.status, 200); assert.equal(r.json.handshake, true);
    assert.equal(all("SELECT COUNT(*) n FROM events WHERE parsed = 0")[0].n, 0);
  });

  await noti(phone.token, 50, "0811111111", 0);
  await noti(phone.token, 50, "0822222222", 2);
  await noti(phone.token, 20, "0833333333", 5);
  await noti(phone.token, 20, "0833333333", 6);
  await tm(apiDev.token, pay(1, 50, "0822222222", 2));
  await tm(apiDev.token, pay(2, 50, "0811111111", 0));
  await tm(apiDev.token, pay(3, 20, "0833333333", 5));
  await tm(apiDev.token, pay(4, 99, "0844444444", 8));

  await t.test("รวม API เข้าเครื่องมือถือ: รายการตรงคู่ด้วยเบอร์ · ไม่ทิ้งรายการยอดเท่ากันคนละเบอร์ · คนเดิมโอนซ้ำนับครบ", async () => {
    const r = await api(`/api/devices/${apiDev.id}/merge`, "POST", { into: phone.id });
    assert.equal(r.status, 200, JSON.stringify(r.json));
    assert.deepEqual([r.json.moved, r.json.duplicates], [1, 3]);
    const rows = all("SELECT amount, counterpart FROM txns WHERE device_id = ? ORDER BY at, id", phone.id);
    assert.deepEqual(rows.map((x) => x.amount), [50, 50, 20, 20, 99]);
    assert.equal(all("SELECT COUNT(*) n FROM devices")[0].n, 1);
  });

  await t.test("หลังรวม URL API เดิมยังใช้ได้ บันทึกเข้าเครื่องเดียว และกันซ้ำกับแจ้งเตือนที่มาทีหลัง", async () => {
    const r = await tm(apiDev.token, pay(5, 70, "0855555555", 10));
    assert.equal(r.status, 200); assert.equal(r.json.inserted, true);
    const n = await noti(phone.token, 70, "0855555555", 10, 12);
    assert.ok(n.json.duplicate_of, JSON.stringify(n.json));
    const s = (await api("/api/state")).json.devices;
    assert.equal(s.length, 1); assert.equal(s[0].tm_secret_set, 1); assert.ok(s[0].tm_token_hint);
  });

  await t.test("แจ้งเตือนรายการที่สองของคนเดิม (API ไม่ส่งมา) ไม่ถูกกลืนเข้ารายการที่จับคู่ไปแล้ว", async () => {
    const n = await noti(phone.token, 70, "0855555555", 11);
    assert.equal(n.json.inserted, true, JSON.stringify(n.json));
  });

  await t.test("ยอดเท่ากันคนละเบอร์ใน 3 นาที ไม่ถูกนับเป็นรายการซ้ำ", async () => {
    await tm(apiDev.token, pay(6, 30, "0866666666", 20));
    const n = await noti(phone.token, 30, "0877777777", 21);
    assert.equal(n.json.inserted, true, JSON.stringify(n.json));
  });
});
