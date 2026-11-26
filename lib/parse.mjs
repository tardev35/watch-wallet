const num = (s) => Number(String(s).replace(/,/g, ""));
const AMOUNT = "([0-9][0-9,]*(?:\\.[0-9]{1,2})?|\\.[0-9]{1,2})";

export const maskPhones = (s) => String(s ?? "").replace(/(?<!\d)(?:\+66|66|0)[689]\d(?:[-\s]?\d){7}(?!\d)/g, (m) => "…" + m.replace(/\D/g, "").slice(-4));

export const PATTERNS = [
  { name: "noti_fee", re: new RegExp(`คุณได้ชำระค่าธรรมเนียม\\S*\\s*฿\\s*${AMOUNT}`), direction: "out", kind: "fee" },
  { name: "noti_receive", re: new RegExp(`คุณได้รับเงิน\\s*฿\\s*${AMOUNT}(?:\\s*จาก\\s*(.+))?`), direction: "in", amtGroup: 1, cpGroup: 2 },
  { name: "tm_fee", re: new RegExp(`ค่าธรรมเนียม[^0-9+\\-฿.]*[-−]?\\s*฿?\\s*${AMOUNT}`), direction: "out", kind: "fee" },
  { name: "tm_receive_from", re: new RegExp(`รับเงินจาก\\s+(.+?)\\s*\\+?\\s*฿\\s*${AMOUNT}`), direction: "in", cpGroup: 1, amtGroup: 2 },
  { name: "tm_transfer_to", re: new RegExp(`โอนเงินให้\\s+(.+?)\\s*[-−]?\\s*฿\\s*${AMOUNT}`), direction: "out", cpGroup: 1, amtGroup: 2 },
  { name: "tm_plus", re: new RegExp(`\\+\\s*฿\\s*${AMOUNT}`), direction: "in" },
  { name: "tm_minus", re: new RegExp(`[-−]\\s*฿\\s*${AMOUNT}`), direction: "out" },
  { name: "tm_receive", re: new RegExp(`(?:คุณได้รับเงิน|ได้รับเงิน|รับเงิน|เงินเข้า)\\s*${AMOUNT}\\s*(?:บาท|บ\\.)`), direction: "in" },
  { name: "tm_send", re: new RegExp(`(?:โอนเงิน(?:สำเร็จ)?|จ่ายเงิน|ชำระเงิน|ถอนเงิน|เงินออก)\\s*${AMOUNT}\\s*(?:บาท|บ\\.)`), direction: "out" },
  { name: "generic_in", re: new RegExp(`(?:฿\\s*${AMOUNT}|${AMOUNT}\\s*(?:บาท|บ\\.|THB))`), direction: "in", when: /ได้รับ|รับเงิน|เข้า|received|credit/i },
  { name: "generic_out", re: new RegExp(`(?:฿\\s*${AMOUNT}|${AMOUNT}\\s*(?:บาท|บ\\.|THB))`), direction: "out", when: /โอน|จ่าย|ถอน|ชำระ|ออก|transfer|paid|debit|withdraw/i },
];
const BALANCE = new RegExp(`(?:คงเหลือ|ยอดคงเหลือ|balance)\\s*:?\\s*${AMOUNT}`, "i");
const COUNTERPART = /(?:จาก|ไปยัง|ไปที่|ถึง|from|to)\s*([0-9xX*-]{6,}|[^\s,]{3,40})/i;

export function parseText(text) {
  const t = String(text ?? "").replace(/\s+/g, " ").trim();
  if (!t) return null;
  for (const p of PATTERNS) {
    if (p.when && !p.when.test(t)) continue;
    const m = p.re.exec(t);
    if (!m) continue;
    const amount = num(p.amtGroup ? m[p.amtGroup] : (m[1] ?? m[2]));
    if (!(amount > 0)) continue;
    const b = BALANCE.exec(t);
    const c = COUNTERPART.exec(t);
    const counterpart = p.cpGroup ? String(m[p.cpGroup] ?? "").trim().slice(0, 40) : (c ? c[1].slice(0, 40) : "");
    return { direction: p.direction, amount, balance: b ? num(b[1]) : null, counterpart, pattern: p.name, kind: p.kind || (p.direction === "in" ? "receive" : "transfer") };
  }
  return null;
}

export function extractMessage(body, query) {
  const src = (body && typeof body === "object" && Object.keys(body).length) ? body : (query || {});
  const pick = (keys) => { for (const k of keys) { const v = src[k]; if (typeof v === "string" && v.trim()) return v; } return ""; };
  let text = pick(["text", "msg", "message", "content", "body", "sms", "notification", "title_body"]);
  const title = pick(["title", "subject", "app_name", "app"]);
  if (!text) {
    const strings = [];
    const walk = (v) => { if (typeof v === "string") strings.push(v); else if (v && typeof v === "object") Object.values(v).forEach(walk); };
    walk(src);
    text = strings.sort((a, b) => b.length - a.length)[0] || "";
  }
  const sender = pick(["from", "sender", "number", "phone", "address", "package", "pkg"]);
  const source = pick(["type", "source", "channel"]) || (sender.includes(".") ? "notification" : "sms");
  const when = pick(["time", "timestamp", "date", "received_at", "at"]);
  return { text: title && !text.includes(title) ? `${title} ${text}` : text, sender, source, when };
}
