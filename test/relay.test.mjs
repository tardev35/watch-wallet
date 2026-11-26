import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { createHmac } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const DB = path.join(mkdtempSync(path.join(tmpdir(), "ww-relay-")), "t.db");
const PORT = 39631, MOCK = 39711, BASE = `http://127.0.0.1:${PORT}`;

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const sign = (payload, secret) => { const h = b64({ alg: "HS256", typ: "JWT" }), p = b64(payload); return `${h}.${p}.${createHmac("sha256", secret).update(h + "." + p).digest("base64url")}`; };
const pay = (uid, amount) => ({ event_type: "P2P", received_time: new Date(Date.now() + 7 * 3600e3).toISOString().slice(0, 19) + "+0700", amount, sender_mobile: "0891234567", message: "ทดสอบ", Channel: "P2P", sender_name: "ทดสอบ ส***", transaction_id: "T" + uid, unique_transid: uid });
const api = (p, method, body) => fetch(BASE + p, { method, headers: { "Content-Type": "application/json" }, body: body && JSON.stringify(body) }).then(async (r) => ({ status: r.status, json: await r.json() }));
const tm = async (tok, rawBody) => { const r = await fetch(`${BASE}/tm/${tok}`, { method: "POST", headers: { "Content-Type": "application/json", "User-Agent": "TrueMoney-Webhook/1.0", "X-Tmn-Test": "abc" }, body: rawBody }); return { status: r.status, text: await r.text() }; };
const one = (sql, ...a) => { const d = new DatabaseSync(DB, { readOnly: true }); try { return d.prepare(sql).get(...a); } finally { d.close(); } };

test("API กลาง: ส่งต่อให้ผู้ให้บริการโดยไม่กระทบเส้นเดิม", async (t) => {
  let mode = { status: 200, delay: 0, location: "" };
  const got = [];
  const mock = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c)).on("end", () => {
      got.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks) });
      setTimeout(() => {
        if (mode.location) { res.writeHead(mode.status, { Location: mode.location }); return res.end(); }
        res.writeHead(mode.status, { "Content-Type": "application/json" }); res.end(JSON.stringify({ provider: true }));
      }, mode.delay);
    });
  }).listen(MOCK, "127.0.0.1");
  const srv = spawn(process.execPath, ["--no-warnings", "server.mjs"], { cwd: ROOT, env: { ...process.env, PORT: String(PORT), WW_DB_FILE: DB, WW_FORWARD_ALLOW_HTTP: "1", WW_TG_TOKEN: "", WW_TG_CHAT: "" }, stdio: ["ignore", "pipe", "inherit"] });
  t.after(() => { srv.kill(); mock.close(); });
  await new Promise((r) => srv.stdout.on("data", (d) => String(d).includes("เปิดที่") && r()));

  const { token: tok, id } = (await api("/api/devices", "POST", { name: "W1" })).json;

  await t.test("URL ปลายทางผิดรูปถูกปฏิเสธ", async () => assert.equal((await api(`/api/devices/${id}`, "PUT", { tm_forward_url: "ftp://x" })).status, 400));
  await api(`/api/devices/${id}`, "PUT", { tm_forward_url: `http://127.0.0.1:${MOCK}/external/truemoney?m=1`, tm_secret: "RIGHT" });

  await t.test("ผู้ให้บริการได้ body ทุกไบต์ + path/query + header เดิม และ TrueMoney ได้คำตอบของผู้ให้บริการ", async () => {
    const raw = `{ "message" :"${sign(pay(1001, 10000), "RIGHT")}"  }`;
    const r = await tm(tok, raw);
    const g = got.at(-1);
    assert.equal(r.status, 200); assert.match(r.text, /"provider":true/);
    assert.equal(Buffer.compare(g.body, Buffer.from(raw)), 0);
    assert.equal(g.url, "/external/truemoney?m=1"); assert.equal(g.method, "POST");
    assert.equal(g.headers["content-type"], "application/json"); assert.equal(g.headers["user-agent"], "TrueMoney-Webhook/1.0"); assert.equal(g.headers["x-tmn-test"], "abc");
    assert.ok(!("x-forwarded-for" in g.headers) && !("x-real-ip" in g.headers));
  });

  await t.test("secret ฝั่งเราผิดไม่กระทบผู้ให้บริการ และกู้รายการคืนได้เมื่อแก้ secret", async () => {
    const r = await tm(tok, JSON.stringify({ message: sign(pay(1002, 5000), "WRONG") }));
    assert.equal(r.status, 200);
    assert.equal(one("SELECT COUNT(*) n FROM events WHERE parsed = 0 AND text LIKE 'TrueMoney API ถูกปฏิเสธ%'").n, 1);
    assert.equal((await api(`/api/devices/${id}`, "PUT", { tm_secret: "WRONG" })).json.reparsed, 1);
    await api(`/api/devices/${id}`, "PUT", { tm_secret: "RIGHT" });
  });

  await t.test("ผู้ให้บริการล่ม → 502 ให้ TrueMoney ส่งซ้ำ · เตือน · ส่งซ้ำแล้วนับครั้งเดียว · เตือนปิดเอง", async () => {
    const raw = JSON.stringify({ message: sign(pay(1003, 2000), "RIGHT") });
    mode = { status: 500, delay: 0, location: "" };
    assert.equal((await tm(tok, raw)).status, 502);
    assert.ok((await api("/api/state", "GET")).json.alerts.some((a) => a.rule === "forward_fail" && !a.closed_at));
    mode = { status: 200, delay: 0, location: "" };
    const n = got.length;
    assert.equal((await tm(tok, raw)).status, 200);
    assert.equal(got.length, n + 1);
    assert.ok(!(await api("/api/state", "GET")).json.alerts.some((a) => a.rule === "forward_fail" && !a.closed_at));
    assert.equal(one("SELECT COUNT(*) n FROM txns t JOIN events e ON e.id = t.event_id WHERE e.text LIKE '%ref T1003%'").n, 1);
  });

  await t.test("ปลายทาง redirect → ไม่ตามไป ตอบ 502", async () => {
    mode = { status: 301, delay: 0, location: "https://elsewhere.example/x" };
    assert.equal((await tm(tok, JSON.stringify({ message: sign(pay(1004, 100), "RIGHT") }))).status, 502);
  });

  await t.test("ปลายทางช้าเกิน 10 วินาที → 502", async () => {
    mode = { status: 200, delay: 11_000, location: "" };
    const t0 = Date.now();
    assert.equal((await tm(tok, JSON.stringify({ message: sign(pay(1005, 100), "RIGHT") }))).status, 502);
    assert.ok(Date.now() - t0 < 12_000);
    mode = { status: 200, delay: 0, location: "" };
  });

  await t.test("body เพี้ยนก็ยังส่งต่อตรงทุกไบต์", async () => {
    assert.equal((await tm(tok, "not json at all")).status, 200);
    assert.equal(got.at(-1).body.toString(), "not json at all");
  });

  await t.test("GET ตอบเอง ไม่ส่งต่อ", async () => {
    const n = got.length;
    assert.equal((await fetch(`${BASE}/tm/${tok}?challenge=x`)).status, 200);
    assert.equal(got.length, n);
  });

  await t.test("ปิดวอเล็ตแล้วยังส่งต่อ", async () => {
    await api(`/api/devices/${id}`, "PUT", { active: 0 });
    const n = got.length;
    assert.equal((await tm(tok, JSON.stringify({ message: sign(pay(1006, 300), "RIGHT") }))).status, 200);
    assert.equal(got.length, n + 1);
    await api(`/api/devices/${id}`, "PUT", { active: 1 });
  });

  await t.test("ออก token ใหม่ต้องยืนยันพิเศษ · token ผิดไม่ส่งต่อ", async () => {
    assert.equal((await api(`/api/devices/${id}/rotate`, "POST", {})).status, 409);
    const n = got.length;
    assert.equal((await tm("wrong-token", "{}")).status, 401);
    assert.equal(got.length, n);
  });

  await t.test("ล้าง URL ปลายทางแล้วหยุดส่งต่อ", async () => {
    await api(`/api/devices/${id}`, "PUT", { tm_forward_url: "" });
    const n = got.length;
    assert.equal((await tm(tok, JSON.stringify({ message: sign(pay(1007, 100), "RIGHT") }))).status, 200);
    assert.equal(got.length, n);
  });
});
