import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DB_FILE = process.env.WW_DB_FILE || path.join(ROOT, "data", "wallet-watch.db");
mkdirSync(path.dirname(DB_FILE), { recursive: true });

export const db = new DatabaseSync(DB_FILE);
db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");

const MIGRATIONS = [
  `CREATE TABLE devices (
     id          INTEGER PRIMARY KEY,
     name        TEXT NOT NULL,
     last4       TEXT NOT NULL DEFAULT '',
     brand       TEXT NOT NULL DEFAULT '',
     holder      TEXT NOT NULL DEFAULT '',
     daily_limit INTEGER NOT NULL DEFAULT 0,
     token_hash  TEXT NOT NULL UNIQUE,
     token_hint  TEXT NOT NULL,
     active      INTEGER NOT NULL DEFAULT 1,
     created_at  TEXT NOT NULL,
     last_seen_at TEXT
   );`,
  `CREATE TABLE events (
     id         INTEGER PRIMARY KEY,
     device_id  INTEGER NOT NULL REFERENCES devices(id),
     received_at TEXT NOT NULL,
     source     TEXT NOT NULL DEFAULT '',
     sender     TEXT NOT NULL DEFAULT '',
     text       TEXT NOT NULL,
     raw        TEXT NOT NULL,
     hash       TEXT NOT NULL,
     parsed     INTEGER NOT NULL DEFAULT 0
   );`,
  `CREATE UNIQUE INDEX ux_events_hash ON events (device_id, hash);`,
  `CREATE TABLE txns (
     id         INTEGER PRIMARY KEY,
     device_id  INTEGER NOT NULL REFERENCES devices(id),
     event_id   INTEGER NOT NULL REFERENCES events(id),
     at         TEXT NOT NULL,
     direction  TEXT NOT NULL,
     amount     REAL NOT NULL,
     balance    REAL,
     counterpart TEXT NOT NULL DEFAULT '',
     pattern    TEXT NOT NULL DEFAULT ''
   );`,
  `CREATE INDEX ix_txns_device_at ON txns (device_id, at);`,
  `CREATE TABLE alerts (
     id         INTEGER PRIMARY KEY,
     at         TEXT NOT NULL,
     rule       TEXT NOT NULL,
     device_id  INTEGER REFERENCES devices(id),
     key        TEXT NOT NULL,
     message    TEXT NOT NULL,
     sent_at    TEXT,
     closed_at  TEXT
   );`,
  `CREATE UNIQUE INDEX ux_alerts_open ON alerts (rule, key) WHERE closed_at IS NULL;`,
  `CREATE TABLE backoffice_rows (
     id         INTEGER PRIMARY KEY,
     day        TEXT NOT NULL,
     at         TEXT NOT NULL,
     direction  TEXT NOT NULL,
     amount     REAL NOT NULL,
     last4      TEXT NOT NULL DEFAULT '',
     ref        TEXT NOT NULL DEFAULT '',
     raw        TEXT NOT NULL,
     hash       TEXT NOT NULL UNIQUE,
     imported_at TEXT NOT NULL,
     txn_id     INTEGER REFERENCES txns(id),
     status     TEXT NOT NULL DEFAULT 'pending',
     note       TEXT NOT NULL DEFAULT ''
   );`,
  `CREATE INDEX ix_bo_day ON backoffice_rows (day, direction, amount);`,
  `ALTER TABLE txns ADD COLUMN kind TEXT NOT NULL DEFAULT '';`,
  `ALTER TABLE txns ADD COLUMN audit TEXT NOT NULL DEFAULT '';`,
  `ALTER TABLE devices ADD COLUMN tm_secret TEXT NOT NULL DEFAULT '';`,
  `ALTER TABLE devices ADD COLUMN tm_secret_at TEXT;`,
  `ALTER TABLE devices ADD COLUMN tm_forward_url TEXT NOT NULL DEFAULT '';`,
  `CREATE TABLE forwards (
     id         INTEGER PRIMARY KEY,
     device_id  INTEGER NOT NULL REFERENCES devices(id),
     at         TEXT NOT NULL,
     url_host   TEXT NOT NULL,
     transid    TEXT NOT NULL DEFAULT '',
     status     INTEGER NOT NULL DEFAULT 0,
     ms         INTEGER NOT NULL DEFAULT 0,
     error      TEXT NOT NULL DEFAULT ''
   );`,
  `CREATE INDEX ix_forwards_device_at ON forwards (device_id, at);`,
  `CREATE INDEX ix_txns_at ON txns (at);`,
];

db.exec("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);");
let version = db.prepare("SELECT version FROM schema_version").get()?.version;
if (version == null) { db.prepare("INSERT INTO schema_version (version) VALUES (0)").run(); version = 0; }
for (let i = version; i < MIGRATIONS.length; i++) {
  db.exec("BEGIN");
  try { db.exec(MIGRATIONS[i]); db.prepare("UPDATE schema_version SET version = ?").run(i + 1); db.exec("COMMIT"); }
  catch (e) { db.exec("ROLLBACK"); throw new Error(`ไมเกรชันรายการที่ ${i + 1} ล้มเหลว: ${e.message}`); }
}

export const now = () => new Date().toISOString();
export const bkkDay = (iso = now()) => new Date(new Date(iso).getTime() + 7 * 3600_000).toISOString().slice(0, 10);
export const bkkDayStartIso = (day) => new Date(Date.parse(day + "T00:00:00+07:00")).toISOString();
