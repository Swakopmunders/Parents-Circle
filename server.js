/**
 * Parent Circle — backend server
 * Zero external dependencies. Requires Node.js 18+.
 * Run: node server.js
 * Env vars:
 *   PORT            default 3000
 *   SESSION_SECRET  set this in production or sessions reset on every restart
 */
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "db.json");
const PUBLIC_DIR = path.join(__dirname, "public");

const ROOMS = [
  { id: "newborns", name: "Newborns & Infants", blurb: "0–12 months. Sleep, feeding, the fog." },
  { id: "toddlers", name: "Toddlers", blurb: "1–3 years. Tantrums, potty training, chaos." },
  { id: "school-age", name: "School-Age", blurb: "4–12 years. School, friendships, routines." },
  { id: "teens", name: "Teens", blurb: "13–18. Independence, conflict, staying connected." },
  { id: "special-needs", name: "Special Needs & Support", blurb: "Diagnoses, therapies, advocacy." },
  { id: "general", name: "General Chat", blurb: "Anything else, any hour." },
];
const ROOM_IDS = new Set(ROOMS.map((r) => r.id));
const MAX_ATTACHMENT_BYTES = 150 * 1024;
const MAX_BODY_BYTES = 400 * 1024;
const MAX_MESSAGES_PER_ROOM = 150;
const MAX_ATTACHMENTS_RETAINED = 25;
const SESSION_MAX_AGE = 30 * 24 * 60 * 60; // 30 days, seconds

/* ---------------- data store (flat JSON file, single-process) ---------------- */
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function loadDB() {
  if (!fs.existsSync(DATA_FILE)) {
    return { accounts: {}, mods: [], modRequests: [], banned: [], messages: {} };
  }
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
  } catch {
    return { accounts: {}, mods: [], modRequests: [], banned: [], messages: {} };
  }
}
let db = loadDB();
let saveQueued = false;
function saveDB() {
  if (saveQueued) return;
  saveQueued = true;
  setImmediate(() => {
    saveQueued = false;
    fs.writeFile(DATA_FILE, JSON.stringify(db), () => {});
  });
}
ROOMS.forEach((r) => { if (!db.messages[r.id]) db.messages[r.id] = []; });

/* ---------------- auth helpers ---------------- */
function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 32, "sha256").toString("hex");
}
function makeSalt() {
  return crypto.randomBytes(16).toString("hex");
}
function signSession(name) {
  const payload = Buffer.from(JSON.stringify({ name, exp: Date.now() + SESSION_MAX_AGE * 1000 })).toString("base64url");
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}
function verifySession(token) {
  if (!token || !token.includes(".")) return null;
  const [payload, sig] = token.split(".");
  const expected = crypto.createHmac("sha256", SESSION_SECRET).update(payload).digest("base64url");
  if (sig !== expected) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (data.exp < Date.now()) return null;
    return data.name;
  } catch {
    return null;
  }
}
function parseCookies(req) {
  const header = req.headers.cookie;
  const out = {};
  if (!header) return out;
  header.split(";").forEach((p) => {
    const idx = p.indexOf("=");
    if (idx === -1) return;
    out[p.slice(0, idx).trim()] = decodeURIComponent(p.slice(idx + 1).trim());
  });
  return out;
}
function currentUser(req) {
  const cookies = parseCookies(req);
  return verifySession(cookies.pc_session);
}
function isSecureReq(req) {
  return req.headers["x-forwarded-proto"] === "https" || req.socket.encrypted;
}
function setSessionCookie(req, res, name) {
  const token = signSession(name);
  const secure = isSecureReq(req) ? "; Secure" : "";
  res.setHeader("Set-Cookie", `pc_session=${token}; HttpOnly; Path=/; Max-Age=${SESSION_MAX_AGE}; SameSite=Lax${secure}`);
}
function clearSessionCookie(res) {
  res.setHeader("Set-Cookie", `pc_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax`);
}

/* ---------------- json helpers ---------------- */
function sendJSON(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Content-Length": Buffer.byteLength(body) });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) { reject(new Error("body too large")); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => {
      if (chunks.length === 0) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
      catch { reject(new Error("invalid json")); }
    });
    req.on("error", reject);
  });
}

/* ---------------- moderation / attachment pruning ---------------- */
function pruneRoom(roomId) {
  let list = db.messages[roomId];
  if (list.length > MAX_MESSAGES_PER_ROOM) list = list.slice(-MAX_MESSAGES_PER_ROOM);
  const withAttach = list.filter((m) => m.attachment && m.attachment.dataUrl);
  if (withAttach.length > MAX_ATTACHMENTS_RETAINED) {
    const toStrip = withAttach.slice(0, withAttach.length - MAX_ATTACHMENTS_RETAINED);
    const stripIds = new Set(toStrip.map((m) => m.id));
    list = list.map((m) =>
      stripIds.has(m.id) ? { ...m, attachment: { ...m.attachment, dataUrl: null, expired: true } } : m
    );
  }
  db.messages[roomId] = list;
}

/* ---------------- SSE broadcast ---------------- */
const roomStreams = {}; // roomId -> Set of res
ROOMS.forEach((r) => (roomStreams[r.id] = new Set()));
function broadcast(roomId, event, data) {
  const set = roomStreams[roomId];
  if (!set) return;
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of set) {
    try { res.write(payload); } catch {}
  }
}

/* ---------------- static file serving ---------------- */
const STATIC_TYPES = { ".html": "text/html", ".json": "application/json", ".js": "application/javascript", ".svg": "image/svg+xml" };
function serveStatic(req, res) {
  let reqPath = req.url.split("?")[0];
  if (reqPath === "/") reqPath = "/index.html";
  const filePath = path.join(PUBLIC_DIR, path.normalize(reqPath));
  if (!filePath.startsWith(PUBLIC_DIR)) { res.writeHead(403); res.end(); return; }
  fs.readFile(filePath, (err, content) => {
    if (err) { res.writeHead(404); res.end("Not found"); return; }
    const ext = path.extname(filePath);
    res.writeHead(200, { "Content-Type": STATIC_TYPES[ext] || "application/octet-stream" });
    res.end(content);
  });
}

/* ---------------- request handler ---------------- */
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const p = url.pathname;
  const method = req.method;

  try {
    /* ---- auth: register-or-login in one step ---- */
    if (p === "/api/auth" && method === "POST") {
      const { name, password } = await readBody(req);
      if (!name || typeof name !== "string" || name.length > 60) return sendJSON(res, 400, { error: "Invalid name." });
      if (!password || password.length < 6) return sendJSON(res, 400, { error: "Password must be at least 6 characters." });
      const existing = db.accounts[name];
      if (existing) {
        const hash = hashPassword(password, existing.salt);
        if (hash !== existing.hash) return sendJSON(res, 401, { error: "That name is taken and this password doesn't match it. Try a different name." });
      } else {
        const salt = makeSalt();
        db.accounts[name] = { salt, hash: hashPassword(password, salt), createdAt: Date.now() };
        saveDB();
      }
      setSessionCookie(req, res, name);
      return sendJSON(res, 200, { name, isMod: db.mods.includes(name) });
    }

    if (p === "/api/logout" && method === "POST") {
      clearSessionCookie(res);
      return sendJSON(res, 200, { ok: true });
    }

    if (p === "/api/me" && method === "GET") {
      const name = currentUser(req);
      if (!name) return sendJSON(res, 401, { error: "Not signed in." });
      return sendJSON(res, 200, { name, isMod: db.mods.includes(name), banned: db.banned.includes(name) });
    }

    if (p === "/api/rooms" && method === "GET") {
      return sendJSON(res, 200, ROOMS);
    }

    /* everything below requires a session */
    const user = currentUser(req);

    const roomMatch = p.match(/^\/api\/rooms\/([a-z-]+)\/messages\/?([\w-]+)?(\/pin)?$/);
    if (roomMatch) {
      const roomId = roomMatch[1];
      const msgId = roomMatch[2];
      const isPin = !!roomMatch[3];
      if (!ROOM_IDS.has(roomId)) return sendJSON(res, 404, { error: "Unknown room." });

      if (method === "GET" && !msgId) {
        return sendJSON(res, 200, db.messages[roomId]);
      }

      if (!user) return sendJSON(res, 401, { error: "Sign in first." });

      if (method === "POST" && !msgId) {
        if (db.banned.includes(user)) return sendJSON(res, 403, { error: "You've been removed from posting by a moderator." });
        const { text, attachment } = await readBody(req);
        const cleanText = (text || "").toString().slice(0, 4000).trim();
        let cleanAttachment = null;
        if (attachment && attachment.dataUrl) {
          const approxBytes = Math.ceil((attachment.dataUrl.length * 3) / 4);
          if (approxBytes > MAX_ATTACHMENT_BYTES) return sendJSON(res, 400, { error: `Attachments must be under ${Math.round(MAX_ATTACHMENT_BYTES / 1024)}KB.` });
          cleanAttachment = {
            name: (attachment.name || "file").toString().slice(0, 200),
            type: (attachment.type || "application/octet-stream").toString().slice(0, 100),
            size: attachment.size || approxBytes,
            dataUrl: attachment.dataUrl,
          };
        }
        if (!cleanText && !cleanAttachment) return sendJSON(res, 400, { error: "Empty message." });
        const msg = {
          id: `${Date.now()}-${crypto.randomBytes(4).toString("hex")}`,
          author: user,
          isMod: db.mods.includes(user),
          text: cleanText,
          attachment: cleanAttachment,
          ts: Date.now(),
          pinned: false,
        };
        db.messages[roomId].push(msg);
        pruneRoom(roomId);
        saveDB();
        broadcast(roomId, "message", msg);
        return sendJSON(res, 200, msg);
      }

      if (method === "DELETE" && msgId) {
        if (!db.mods.includes(user)) return sendJSON(res, 403, { error: "Moderators only." });
        db.messages[roomId] = db.messages[roomId].filter((m) => m.id !== msgId);
        saveDB();
        broadcast(roomId, "delete", { id: msgId });
        return sendJSON(res, 200, { ok: true });
      }

      if (method === "POST" && msgId && isPin) {
        if (!db.mods.includes(user)) return sendJSON(res, 403, { error: "Moderators only." });
        let pinnedId = null;
        db.messages[roomId] = db.messages[roomId].map((m) => {
          const pinned = m.id === msgId ? !m.pinned : false;
          if (pinned) pinnedId = m.id;
          return { ...m, pinned };
        });
        saveDB();
        broadcast(roomId, "pin", { id: pinnedId });
        return sendJSON(res, 200, { ok: true });
      }
    }

    if (p.match(/^\/api\/rooms\/([a-z-]+)\/stream$/) && method === "GET") {
      const roomId = p.split("/")[3];
      if (!ROOM_IDS.has(roomId)) { res.writeHead(404); return res.end(); }
      res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
      });
      res.write("retry: 3000\n\n");
      roomStreams[roomId].add(res);
      const keepAlive = setInterval(() => { try { res.write(": ping\n\n"); } catch {} }, 25000);
      req.on("close", () => { clearInterval(keepAlive); roomStreams[roomId].delete(res); });
      return;
    }

    if (p === "/api/mod/apply" && method === "POST") {
      if (!user) return sendJSON(res, 401, { error: "Sign in first." });
      const { message } = await readBody(req);
      if (db.mods.length === 0) {
        db.mods.push(user);
        saveDB();
        return sendJSON(res, 200, { status: "bootstrapped" });
      }
      db.modRequests = db.modRequests.filter((r) => r.name !== user);
      db.modRequests.push({ name: user, message: (message || "").toString().slice(0, 500), ts: Date.now() });
      db.modRequests = db.modRequests.slice(-100);
      saveDB();
      return sendJSON(res, 200, { status: "sent" });
    }

    if (p === "/api/mod/requests" && method === "GET") {
      if (!user || !db.mods.includes(user)) return sendJSON(res, 403, { error: "Moderators only." });
      return sendJSON(res, 200, db.modRequests);
    }

    const reqMatch = p.match(/^\/api\/mod\/requests\/([^/]+)\/(approve|deny)$/);
    if (reqMatch && method === "POST") {
      if (!user || !db.mods.includes(user)) return sendJSON(res, 403, { error: "Moderators only." });
      const targetName = decodeURIComponent(reqMatch[1]);
      db.modRequests = db.modRequests.filter((r) => r.name !== targetName);
      if (reqMatch[2] === "approve" && !db.mods.includes(targetName)) db.mods.push(targetName);
      saveDB();
      return sendJSON(res, 200, { ok: true });
    }

    if (p === "/api/mod/mods" && method === "GET") {
      if (!user) return sendJSON(res, 401, { error: "Sign in first." });
      return sendJSON(res, 200, db.mods);
    }

    if (p === "/api/mod/block" && method === "POST") {
      if (!user || !db.mods.includes(user)) return sendJSON(res, 403, { error: "Moderators only." });
      const { name } = await readBody(req);
      if (name && !db.banned.includes(name)) { db.banned.push(name); saveDB(); }
      return sendJSON(res, 200, { ok: true });
    }

    if (p.startsWith("/api/")) return sendJSON(res, 404, { error: "Unknown endpoint." });

    return serveStatic(req, res);
  } catch (err) {
    return sendJSON(res, 400, { error: err.message || "Bad request." });
  }
});

server.listen(PORT, () => {
  console.log(`Parent Circle server running on http://localhost:${PORT}`);
  if (!process.env.SESSION_SECRET) {
    console.log("NOTE: SESSION_SECRET not set — everyone will be logged out on the next restart. Set it in production.");
  }
});
