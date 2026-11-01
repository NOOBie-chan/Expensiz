// Expensiz account service. Holds the account list so no MEGA login ever sits in the app.
// Run: node server.js   (see the environment variables below)
const http = require("http"),
  crypto = require("crypto"),
  fs = require("fs");
const E = process.env,
  PORT = E.PORT || 8787,
  FILE = "expensiz-accounts.enc";
const ORIGINS = (E.ALLOWED_ORIGIN || "*")
  .split(",")
  .map((x) => x.trim().replace(/\/+$/, ""))
  .filter(Boolean); // set to your app's https address in production
const SECRET = E.SERVER_SECRET || crypto.randomBytes(32).toString("hex");
const KEY = E.ACCOUNTS_KEY ? Buffer.from(E.ACCOUNTS_KEY, "hex") : null; // 64 hex chars: encrypts the account file
let db = {},
  mega = null,
  file = null,
  writing = Promise.resolve();
const fails = {};
const path = require("path");
const enc = (o) => {
  const s = Buffer.from(JSON.stringify(o));
  if (!KEY) return s;
  const iv = crypto.randomBytes(12),
    c = crypto.createCipheriv("aes-256-gcm", KEY, iv);
  const ct = Buffer.concat([c.update(s), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]);
};
const dec = (b) => {
  if (!KEY) return JSON.parse(b.toString());
  const d = crypto.createDecipheriv("aes-256-gcm", KEY, b.subarray(0, 12));
  d.setAuthTag(b.subarray(12, 28));
  return JSON.parse(
    Buffer.concat([d.update(b.subarray(28)), d.final()]).toString(),
  );
};
async function init() {
  if (E.MEGA_EMAIL) {
    // your MEGA login lives only here, in the server's environment
    const { Storage } = require("megajs");
    mega = await new Storage({ email: E.MEGA_EMAIL, password: E.MEGA_PASSWORD })
      .ready;
    file = mega.root.children.find((c) => c.name === FILE && !c.directory);
    if (file) db = dec(await file.downloadBuffer());
  } else if (fs.existsSync(FILE)) db = dec(fs.readFileSync(FILE));
}
const persist = () =>
  (writing = writing
    .then(async () => {
      const b = enc(db);
      if (mega) {
        if (file) await file.delete(true);
        file = await mega.upload(FILE, b).complete;
      } else fs.writeFileSync(FILE, b);
    })
    .catch((e) => console.error("save failed", e.message)));

const fakeSalt = (email) =>
  crypto
    .createHmac("sha256", SECRET)
    .update(email)
    .digest()
    .subarray(0, 16)
    .toString("base64");
const same = (a, b) => {
  const x = Buffer.from(String(a)),
    y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
const isB64 = (s, max = 120) =>
  typeof s === "string" &&
  s.length > 8 &&
  s.length < max &&
  /^[A-Za-z0-9+/=]+$/.test(s);
const str = (s, n) =>
  typeof s === "string" && s.trim().length > 0 && s.length <= n;
const pub = (a) => ({
  first: a.first,
  last: a.last,
  email: a.email,
  cur: a.cur,
  salt: a.salt,
  ksalt: a.ksalt,
  created: a.created,
  devs: a.devs.map((d) => d.id),
});
const err = (code, error) => {
  const e = new Error(error);
  e.code = code;
  return e;
};

function limited(ip, email) {
  // 5 wrong passwords per 15 minutes per person and address
  const k = ip + "|" + email,
    now = Date.now();
  fails[k] = (fails[k] || []).filter((t) => now - t < 9e5);
  return fails[k].length >= 5;
}
const miss = (ip, email) => {
  (fails[ip + "|" + email] = fails[ip + "|" + email] || []).push(Date.now());
};
function check(ip, b) {
  const a = db[String(b.email || "").toLowerCase()];
  if (limited(ip, String(b.email)))
    throw err(429, "Too many attempts. Try again in 15 minutes.");
  if (!a || !same(b.proof, a.hash)) {
    miss(ip, String(b.email));
    throw err(401, "Email or password is incorrect.");
  }
  return a;
}
function addDev(a, dev) {
  if (!dev || !str(dev.id, 80) || a.devs.some((d) => d.id === dev.id))
    return false;
  if (a.devs.length >= 10)
    throw err(403, "This account is already on 10 devices. Remove one first.");
  a.devs.push({
    id: dev.id,
    name: String(dev.name || "device").slice(0, 60),
    added: new Date().toISOString(),
  });
  return true;
}
const routes = {
  "GET /salt": (q) => ({
    salt: db[q.email] ? db[q.email].salt : fakeSalt(q.email),
  }),
  "POST /signup": (q, b) => {
    const a = b.account || {},
      email = String(a.email || "").toLowerCase();
    if (
      !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) ||
      email.length > 120 ||
      !str(a.first, 60) ||
      !str(a.last, 60) ||
      !/^[A-Z]{3}$/.test(a.cur) ||
      !isB64(a.salt) ||
      !isB64(a.ksalt) ||
      !isB64(a.hash)
    )
      throw err(400, "Some account details are not valid.");
    if (db[email])
      throw err(
        409,
        "An account with that email already exists. Sign in instead.",
      );
    db[email] = {
      first: a.first.trim(),
      last: a.last.trim(),
      email,
      cur: a.cur,
      salt: a.salt,
      ksalt: a.ksalt,
      hash: a.hash,
      created: new Date().toISOString().slice(0, 10),
      devs: [],
    };
    addDev(db[email], b.dev);
    persist();
    return { ok: true };
  },
  "POST /login": (q, b, ip) => {
    const a = check(ip, b);
    if (addDev(a, b.dev)) persist();
    return { account: pub(a) };
  },
  "POST /profile": (q, b, ip) => {
    const a = check(ip, b);
    if (!str(b.first, 60) || !str(b.last, 60) || !/^[A-Z]{3}$/.test(b.cur))
      throw err(400, "Some details are not valid.");
    Object.assign(a, {
      first: b.first.trim(),
      last: b.last.trim(),
      cur: b.cur,
    });
    persist();
    return { account: pub(a) };
  },
};
const srv2 = http.createServer((req, res) => {
  const o = req.headers.origin,
    allow = ORIGINS.includes("*") ? "*" : ORIGINS.includes(o) ? o : ORIGINS[0];
  const h = {
    "Access-Control-Allow-Origin": allow,
    Vary: "Origin",
    "Access-Control-Allow-Headers": "Content-Type",
    "Content-Type": "application/json",
    "X-Content-Type-Options": "nosniff",
  };
  const send = (c, o) => {
    res.writeHead(c, h);
    res.end(JSON.stringify(o));
  };
  if (req.method === "OPTIONS") return send(204, {});
  const u = new URL(req.url, "http://x"),
    r = routes[req.method + " " + u.pathname];
  if (!r) return send(404, { error: "Not found." });
  let body = "";
  req.on("data", (c) => {
    body += c;
    if (body.length > 20000) req.destroy();
  });
  req.on("end", () => {
    try {
      const ip = (
        req.headers["x-forwarded-for"] ||
        req.socket.remoteAddress ||
        ""
      )
        .split(",")[0]
        .trim();
      send(
        200,
        r(Object.fromEntries(u.searchParams), body ? JSON.parse(body) : {}, ip),
      );
    } catch (e) {
      send(e.code || 400, { error: e.code ? e.message : "Bad request." });
    }
  });
});
init()
  .then(() =>
    srv2.listen(PORT, () =>
      console.log(
        "Expensiz server on port " +
          PORT +
          (KEY ? "" : " (account file NOT encrypted: set ACCOUNTS_KEY)"),
      ),
    ),
  )
  .catch((e) => {
    console.error("Start failed:", e.message);
    process.exit(1);
  });
