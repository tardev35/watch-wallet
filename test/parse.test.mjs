import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseText } from "../lib/parse.mjs";

const lines = readFileSync(new URL("./samples.txt", import.meta.url), "utf8").split(/\r?\n/).filter((l) => l.trim() && !l.startsWith("#"));

for (const line of lines) {
  const i = line.indexOf(" | ");
  const [dir, amount, kind, ...rest] = line.slice(0, i).trim().split(/\s+/);
  const cp = rest.join(" ");
  const text = line.slice(i + 3);
  test(text, () => {
    const p = parseText(text);
    if (dir === "none") return assert.equal(p, null);
    assert.ok(p, "แยกไม่ออก");
    assert.equal(p.direction, dir);
    assert.equal(p.amount, Number(amount));
    assert.equal(p.kind, kind);
    if (cp) assert.equal(p.counterpart, cp);
  });
}
