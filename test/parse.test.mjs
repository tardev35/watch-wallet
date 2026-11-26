import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseText, maskPhones } from "../lib/parse.mjs";

const lines = readFileSync(new URL("./samples.txt", import.meta.url), "utf8").split(/\r?\n/).filter((l) => l.trim() && !l.startsWith("#"));

for (const line of lines) {
  const i = line.indexOf(" | ");
  const [dir, amount, kind, cp] = line.slice(0, i).trim().split(/\s+/);
  const text = line.slice(i + 3);
  test(text, () => {
    const p = parseText(maskPhones(text));
    if (dir === "none") return assert.equal(p, null);
    assert.ok(p, "แยกไม่ออก");
    assert.equal(p.direction, dir);
    assert.equal(p.amount, Number(amount));
    assert.equal(p.kind, kind);
    if (cp) assert.equal(p.counterpart, cp);
  });
}

test("ปิดเบอร์มือถือให้เหลือ 4 ตัวท้าย แต่ไม่แตะเลขอ้างอิงและยอดเงิน", () => {
  assert.equal(maskPhones("จาก 0891234567"), "จาก …4567");
  assert.equal(maskPhones("จาก 089-123-4567 และ +66891234567"), "จาก …4567 และ …4567");
  assert.equal(maskPhones("ref 50060961129941 ยอด 1,000,000.00"), "ref 50060961129941 ยอด 1,000,000.00");
  assert.equal(maskPhones("081-xxx-1234"), "081-xxx-1234");
});
