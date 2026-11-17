"use strict";
/**
 * Emergency Blood - production server
 * Zero dependencies. Requires Node.js 18+.
 *
 * Environment variables:
 *   ADMIN_PASSWORD  (required)  password for the Admin dashboard and stock updates
 *   SESSION_SECRET  (optional)  random string used to sign admin tokens (auto-generated if missing)
 *   PORT            (optional)  default 3000
 *   DATA_DIR        (optional)  where db.json is stored, default ./data
 *   TRUST_PROXY     (optional)  set to 1 when behind nginx / a platform proxy (uses X-Forwarded-For)
 */
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = +process.env.PORT || 3000;
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, "data"));
const DB_FILE = path.join(DATA_DIR, "db.json");
const INDEX = path.join(__dirname, "public", "index.html");
const TRUST_PROXY = process.env.TRUST_PROXY === "1";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const TOKEN_TTL = 12 * 60 * 60 * 1000;
const GROUPS = ["A+", "A\u2212", "B+", "B\u2212", "AB+", "AB\u2212", "O+", "O\u2212"];

if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 8) {
  console.error("ERROR: set ADMIN_PASSWORD (at least 8 characters) before starting the server.");
  process.exit(1);
}

fs.mkdirSync(DATA_DIR, { recursive: true });
const SECRET = process.env.SESSION_SECRET || (() => {
  const f = path.join(DATA_DIR, ".secret");
  try { return fs.readFileSync(f, "utf8"); } catch (e) {}
  const s = crypto.randomBytes(32).toString("hex");
  fs.writeFileSync(f, s, { mode: 0o600 });
  return s;
})();

/* ---------- storage (JSON file, atomic writes) ---------- */
let db = { registrations: [], requests: [], messages: [], stock: {} };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(DB_FILE, "utf8"))); } catch (e) {}
let writing = Promise.resolve();
function persist() {
  const snapshot = JSON.stringify(db);
  writing = writing.then(async () => {
    const tmp = DB_FILE + "." + process.pid + ".tmp";
    await fs.promises.writeFile(tmp, snapshot);
    await fs.promises.rename(tmp, DB_FILE);
  }).catch(err => console.error("persist failed:", err));
  return writing;
}

/* ---------- helpers ---------- */
const SEC_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "same-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
};
function send(res, status, body, headers = {}) {
  const isObj = typeof body === "object" && !Buffer.isBuffer(body);
  res.writeHead(status, Object.assign(
    { "Content-Type": isObj ? "application/json; charset=utf-8" : "text/plain; charset=utf-8", "Cache-Control": "no-store" },
    SEC_HEADERS, headers));
  res.end(isObj ? JSON.stringify(body) : body);
}
const fail = (res, status, error) => send(res, status, { error });

function readJson(req, limit = 100 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", c => { size += c.length; if (size > limit) { reject({ status: 413, error: "Payload too large" }); req.destroy(); } else chunks.push(c); });
    req.on("end", () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}")); } catch (e) { reject({ status: 400, error: "Invalid JSON" }); } });
    req.on("error", () => reject({ status: 400, error: "Bad request" }));
  });
}
function clientIp(req) {
  if (TRUST_PROXY) { const x = req.headers["x-forwarded-for"]; if (x) return x.split(",")[0].trim(); }
  return req.socket.remoteAddress || "unknown";
}

/* rate limiting: sliding window in memory */
const hits = new Map();
function limited(key, max, windowMs) {
  const now = Date.now(), arr = (hits.get(key) || []).filter(t => now - t < windowMs);
  if (arr.length >= max) { hits.set(key, arr); return true; }
  arr.push(now); hits.set(key, arr); return false;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (!v.some(t => now - t < 3600e3)) hits.delete(k); }, 10 * 60e3).unref();

/* admin tokens: base64url(expiry).hmac */
const sign = p => crypto.createHmac("sha256", SECRET).update(p).digest("base64url");
function makeToken() { const p = Buffer.from(String(Date.now() + TOKEN_TTL)).toString("base64url"); return p + "." + sign(p); }
function safeEq(a, b) { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && crypto.timingSafeEqual(x, y); }
function isAdmin(req) {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization || ""); if (!m) return false;
  const [p, s] = m[1].split("."); if (!p || !s || !safeEq(s, sign(p))) return false;
  return +Buffer.from(p, "base64url").toString() > Date.now();
}

/* validation */
const str = (v, max, min = 1) => { if (typeof v !== "string") return null; const t = v.trim().replace(/[\u0000-\u001f\u007f]/g, " "); return t.length >= min && t.length <= max ? t : null; };
const int = (v, lo, hi) => { const n = Number(v); return Number.isFinite(n) && n >= lo && n <= hi ? n : null; };
const emailOk = e => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const phoneOk = p => /^[0-9+()\-\s]{7,20}$/.test(p);
const normGroup = g => (typeof g === "string" ? g.replace(/-/g, "\u2212") : "");
const groupOk = g => GROUPS.includes(g);

const SCHEMAS = {
  registrations(b) {
    const name = str(b.name, 100), phone = str(b.phone, 20), email = str(b.email, 120), city = str(b.city, 80), group = normGroup(b.group);
    const age = int(b.age, 1, 99), weight = int(b.weight, 20, 250), hemoglobin = int(b.hemoglobin, 3, 25);
    if (!name || !phone || !phoneOk(phone) || !email || !emailOk(email) || !city || !groupOk(group) || age == null || weight == null || hemoglobin == null) return null;
    const conditions = Array.isArray(b.conditions) ? b.conditions.slice(0, 10).map(c => str(c, 30)).filter(Boolean) : [];
    const reasons = Array.isArray(b.reasons) ? b.reasons.slice(0, 20).map(c => str(c, 200)).filter(Boolean) : [];
    const reports = Array.isArray(b.reports) ? b.reports.slice(0, 10).map(c => str(c, 200)).filter(Boolean) : [];
    const result = ["Not eligible", "Eligible later", "Likely eligible"].includes(b.result) ? b.result : "Likely eligible";
    return { name, phone, email, city, group, age, weight, hemoglobin, conditions, result, reasons, reports };
  },
  requests(b) {
    const patient = str(b.patient, 100), hospital = str(b.hospital, 160), city = str(b.city, 80), contact = str(b.contact, 100), phone = str(b.phone, 20);
    const group = normGroup(b.group), units = int(b.units, 1, 20);
    const urgency = ["Critical (within hours)", "Urgent (within 24 hours)", "Planned (within a week)"].includes(b.urgency) ? b.urgency : null;
    if (!patient || !hospital || !city || !contact || !phone || !phoneOk(phone) || !groupOk(group) || units == null || !urgency) return null;
    return { patient, group, units, urgency, hospital, city, contact, phone, reason: str(b.reason || "", 500, 0) || "" };
  },
  messages(b) {
    const name = str(b.name, 100), email = str(b.email, 120), message = str(b.message, 2000);
    if (!name || !email || !emailOk(email) || !message) return null;
    return { name, email, message };
  }
};
function cleanStock(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) return null;
  const out = {};
  for (const g of Object.keys(data)) {
    const gg = normGroup(g); if (!groupOk(gg)) return null;
    const u = int(data[g] && data[g].units, 0, 999); if (u == null) return null;
    const at = Number(data[g].at); out[gg] = { units: Math.round(u), at: Number.isFinite(at) && at > 0 ? at : Date.now() };
  }
  return out;
}

/* ---------- routing ---------- */
const COLLECTION_CAP = 50000;
async function handle(req, res) {
  const url = new URL(req.url, "http://x"), p = url.pathname, m = req.method;

  if (m === "GET" && p === "/healthz") return send(res, 200, { ok: true });
  if (m === "GET" && (p === "/" || p === "/index.html")) {
    return fs.readFile(INDEX, (err, buf) => err ? fail(res, 500, "Page unavailable")
      : send(res, 200, buf, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" }));
  }
  if (!p.startsWith("/api/")) return fail(res, 404, "Not found");

  const ip = clientIp(req);
  if (m !== "GET" && limited("w:" + ip, 30, 10 * 60e3)) return fail(res, 429, "Too many requests");

  if (m === "GET" && p === "/api/stock") return send(res, 200, { data: db.stock });

  if (m === "POST" && p === "/api/admin/login") {
    if (limited("login:" + ip, 8, 15 * 60e3)) return fail(res, 429, "Too many attempts");
    const b = await readJson(req);
    if (typeof b.password !== "string" || !safeEq(crypto.createHash("sha256").update(b.password).digest("hex"), crypto.createHash("sha256").update(ADMIN_PASSWORD).digest("hex")))
      return fail(res, 401, "Incorrect password");
    return send(res, 200, { token: makeToken() });
  }

  if (m === "GET" && p === "/api/admin/data") {
    if (!isAdmin(req)) return fail(res, 401, "Admin sign-in required");
    const sorted = k => db[k].slice().sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    return send(res, 200, { registrations: sorted("registrations"), requests: sorted("requests"), messages: sorted("messages") });
  }

  if (m === "PUT" && p === "/api/stock") {
    if (!isAdmin(req)) return fail(res, 401, "Admin sign-in required");
    const data = cleanStock((await readJson(req)).data);
    if (!data) return fail(res, 400, "Invalid stock data");
    db.stock = data; await persist();
    return send(res, 200, { data });
  }

  const col = /^\/api\/(registrations|requests|messages)$/.exec(p);
  if (m === "POST" && col) {
    if (limited("sub:" + ip, 10, 60 * 60e3)) return fail(res, 429, "Too many submissions. Please try later.");
    const rec = SCHEMAS[col[1]](await readJson(req));
    if (!rec) return fail(res, 400, "Please check the form and try again.");
    if (db[col[1]].length >= COLLECTION_CAP) return fail(res, 503, "Service busy");
    rec.id = crypto.randomUUID(); rec.createdAt = Date.now();
    db[col[1]].push(rec); await persist();
    return send(res, 201, { ok: true });
  }
  return fail(res, 404, "Not found");
}

const server = http.createServer((req, res) => {
  handle(req, res).catch(e => {
    if (e && e.status) return fail(res, e.status, e.error);
    console.error(e); fail(res, 500, "Server error");
  });
});
server.requestTimeout = 15000;
server.listen(PORT, () => console.log("Emergency Blood running on http://localhost:" + PORT));
process.on("SIGTERM", () => writing.then(() => process.exit(0)));
process.on("SIGINT", () => writing.then(() => process.exit(0)));
