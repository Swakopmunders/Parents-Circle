/**
 * Parent Circle — backend server
 * Zero external dependencies (email sending uses Node's built-in fetch to call Resend's API).
 * Requires Node.js 18+.
 * Run: node server.js
 *
 * Env vars:
 *   PORT              default 3000
 *   SESSION_SECRET    set this in production or sessions reset on every restart
 *   RESEND_API_KEY    optional — enables document-upload email alerts (see README)
 *   ALERT_FROM_EMAIL  the "from" address for alert emails (must be verified in Resend)
 *   APP_URL           your public app URL, included in alert emails as a link (optional)
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
  { id: "important-documents", name: "Important Documents", blurb: "School notices, forms, and files. Uploading here emails everyone registered." },
  { id: "ieb", name: "IEB", blurb: "Independent Examinations Board updates and discussion." },
  { id: "cambridge", name: "Cambridge", blurb: "Cambridge curriculum updates and discussion." },
  { id: "chat-forum", name: "Chat Forum", blurb: "General discussion for parents." },
];
const ROOM_IDS = new Set(ROOMS.map((r) => r.id));
const ALERT_ROOM_ID = "important-documents";
const MAX_ATTACHMENT_BYTES = 150 * 1024;
const MAX_BODY_BYTES = 400 * 1024;
const MAX_MESSAGES_PER_ROOM = 150;
const MAX_ATTACHMENTS_RETAINED = 25;
const SESSION_MAX_AGE = 30 * 24 * 60 * 60; // 30 days, seconds
const VERIFY_TOKEN_MAX_AGE = 24 * 60 * 60 * 1000; // 24 hours, ms
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

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
function signSession(email) {
  const payload = Buffer.from(JSON.stringify({ email, exp: Date.now() + SESSION_MAX_AGE * 1000 })).toString("base64url");
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
    return data.email;
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
function setSessionCookie(req, res, email) {
  const token = signSession(email);
  const secure = isSecureReq(req) ? "; Secure" : "";
  res.setHeader("Set-Cookie", `pc_session=${token}; HttpOnly; Path=/; Max-Age=${SESSION_MAX_AGE}; SameSite=Lax${secure}`);
}
function clearSessionCookie(res) {
  res.setHeader("Set-Cookie", `pc_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax`);
}
function displayNameFor(email) {
  const acct = db.accounts[email];
  if (acct && acct.displayName) return acct.displayName;
  return email ? email.split("@")[0] : "Someone";
}
function makeVerifyToken() {
  return crypto.randomBytes(24).toString("hex");
}
function findAccountByToken(token) {
  for (const [email, acct] of Object.entries(db.accounts)) {
    if (acct.verifyToken === token && acct.verifyTokenExpires > Date.now()) return email;
  }
  return null;
}
function sendVerificationEmail(email) {
  const link = process.env.APP_URL
    ? `${process.env.APP_URL.replace(/\/$/, "")}/api/verify?token=${db.accounts[email].verifyToken}`
    : `[set APP_URL in your server's environment variables so this link works] /api/verify?token=${db.accounts[email].verifyToken}`;
  sendEmail(
    email,
    "Verify your Parent Circle email",
    `Welcome to Parent Circle. Confirm this is your email address to finish signing up:\n\n${link}\n\nThis link expires in 24 hours. Until you verify, you can browse but can't post, and won't receive document alerts.`
  );
}

/* ---------------- email alerts ---------------- */
async function sendEmail(to, subject, text) {
  if (!process.env.RESEND_API_KEY) {
    console.log(`[email skipped — no RESEND_API_KEY set] to=${to} subject="${subject}"`);
    return;
  }
  try {
    await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: process.env.ALERT_FROM_EMAIL || "alerts@example.com",
        to,
        subject,
        text,
      }),
    });
  } catch (err) {
    console.error("Email send failed:", err.message);
  }
}
function notifyDocumentUpload(roomId, msg, posterEmail) {
  if (roomId !== ALERT_ROOM_ID || !msg.attachment) return;
  const link = process.env.APP_URL ? `\n\nOpen Parent Circle: ${process.env.APP_URL}` : "";
  const subject = `New document in Important Documents: ${msg.attachment.name}`;
  const text = `${msg.author} just uploaded "${msg.attachment.name}" to Important Documents.${link}`;
  const recipients = Object.keys(db.accounts).filter((email) => email !== posterEmail && db.accounts[email].verified);
  recipients.forEach((email) => sendEmail(email, subject, text));
}

function verifyPage(success, message) {
  const color = success ? "#6FAFA0" : "#C97B84";
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Parent Circle</title>
  <style>
    body{background:#101B22;color:#ECE7DC;font-family:system-ui,sans-serif;height:100vh;margin:0;display:flex;align-items:center;justify-content:center;padding:24px;}
    .card{max-width:380px;background:#16232B;border:1px solid #2C4753;border-radius:16px;padding:32px;text-align:center;}
    .dot{width:10px;height:10px;border-radius:999px;background:${color};display:inline-block;margin-bottom:16px;}
    p{line-height:1.6;font-size:15px;}
  </style></head>
  <body><div class="card"><span class="dot"></span><p>${message}</p></div></body></html>`;
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
      const { email: rawEmail, password, displayName: rawDisplay } = await readBody(req);
      const email = (rawEmail || "").toString().trim().toLowerCase();
      const displayName = (rawDisplay || "").toString().trim().slice(0, 60);
      if (!EMAIL_RE.test(email)) return sendJSON(res, 400, { error: "Please enter a valid email address." });
      if (!password || password.length < 6) return sendJSON(res, 400, { error: "Password must be at least 6 characters." });
      const existing = db.accounts[email];
      if (existing) {
        const hash = hashPassword(password, existing.salt);
        if (hash !== existing.hash) return sendJSON(res, 401, { error: "That email is registered and this password doesn't match it." });
      } else {
        if (!displayName) return sendJSON(res, 400, { error: "Please choose a username." });
        const salt = makeSalt();
        db.accounts[email] = {
          salt,
          hash: hashPassword(password, salt),
          displayName,
          createdAt: Date.now(),
          verified: false,
          verifyToken: makeVerifyToken(),
          verifyTokenExpires: Date.now() + VERIFY_TOKEN_MAX_AGE,
        };
        saveDB();
        sendVerificationEmail(email);
      }
      setSessionCookie(req, res, email);
      return sendJSON(res, 200, { email, displayName: displayNameFor(email), isMod: db.mods.includes(email), verified: !!db.accounts[email].verified });
    }

    if (p === "/api/verify" && method === "GET") {
      const token = url.searchParams.get("token") || "";
      const email = findAccountByToken(token);
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      if (!email) {
        return res.end(verifyPage(false, "This verification link is invalid or has expired. Log in to the app and use \u201cResend verification email\u201d in Settings to get a new one."));
      }
      db.accounts[email].verified = true;
      db.accounts[email].verifyToken = null;
      db.accounts[email].verifyTokenExpires = null;
      saveDB();
      return res.end(verifyPage(true, "Your email is verified. You can close this tab and return to Parent Circle."));
    }

    if (p === "/api/resend-verification" && method === "POST") {
      const email = currentUser(req);
      if (!email) return sendJSON(res, 401, { error: "Sign in first." });
      if (db.accounts[email].verified) return sendJSON(res, 200, { ok: true, alreadyVerified: true });
      db.accounts[email].verifyToken = makeVerifyToken();
      db.accounts[email].verifyTokenExpires = Date.now() + VERIFY_TOKEN_MAX_AGE;
      saveDB();
      sendVerificationEmail(email);
      return sendJSON(res, 200, { ok: true });
    }

    if (p === "/api/logout" && method === "POST") {
      clearSessionCookie(res);
      return sendJSON(res, 200, { ok: true });
    }

    if (p === "/api/me" && method === "GET") {
      const email = currentUser(req);
      if (!email) return sendJSON(res, 401, { error: "Not signed in." });
      return sendJSON(res, 200, { email, displayName: displayNameFor(email), isMod: db.mods.includes(email), banned: db.banned.includes(email), verified: !!db.accounts[email]?.verified });
    }

    if (p === "/api/rooms" && method === "GET") {
      return sendJSON(res, 200, ROOMS);
    }

    /* everything below requires a session */
    const user = currentUser(req); // email, or null

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
        if (!db.accounts[user]?.verified) return sendJSON(res, 403, { error: "Please verify your email before posting — check your inbox, or resend it from Settings." });
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
          author: displayNameFor(user),
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
        notifyDocumentUpload(roomId, msg, user);
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
      db.modRequests = db.modRequests.filter((r) => r.email !== user);
      db.modRequests.push({ email: user, displayName: displayNameFor(user), message: (message || "").toString().slice(0, 500), ts: Date.now() });
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
      const targetEmail = decodeURIComponent(reqMatch[1]);
      db.modRequests = db.modRequests.filter((r) => r.email !== targetEmail);
      if (reqMatch[2] === "approve" && !db.mods.includes(targetEmail)) db.mods.push(targetEmail);
      saveDB();
      return sendJSON(res, 200, { ok: true });
    }

    if (p === "/api/mod/mods" && method === "GET") {
      if (!user) return sendJSON(res, 401, { error: "Sign in first." });
      return sendJSON(res, 200, db.mods.map((email) => displayNameFor(email)));
    }

    if (p === "/api/mod/block" && method === "POST") {
      if (!user || !db.mods.includes(user)) return sendJSON(res, 403, { error: "Moderators only." });
      const { authorDisplayName } = await readBody(req);
      // messages only carry display names, so resolve back to the matching account email
      const targetEmail = Object.keys(db.accounts).find((e) => displayNameFor(e) === authorDisplayName);
      if (targetEmail && !db.banned.includes(targetEmail)) { db.banned.push(targetEmail); saveDB(); }
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
  if (!process.env.RESEND_API_KEY) {
    console.log("NOTE: RESEND_API_KEY not set — document upload alert emails are disabled (logged to console instead).");
  }
});
