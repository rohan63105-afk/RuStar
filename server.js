// RuStar সার্ভার – কোনো বাইরের প্যাকেজ লাগে না (Node 22.5+)
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";

const DIR = path.dirname(fileURLToPath(import.meta.url));
try { // সাধারণ .env লোডার
  for (const l of fs.readFileSync(path.join(DIR, ".env"), "utf8").split("\n")) {
    const m = l.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^["']|["']$/g, "");
  }
} catch {}
const E = process.env, PROD = E.NODE_ENV === "production", PORT = +E.PORT || 3000;
const BASE = (E.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
if (PROD && (!E.APP_SECRET || E.APP_SECRET.length < 32)) throw new Error("APP_SECRET (কমপক্ষে ৩২ অক্ষর) দিতে হবে");
const SECRET = E.APP_SECRET || "dev-only-secret";
const MODE = E.PAYMENT_MODE || "mock";
const SSLC = E.SSLC_LIVE === "true" ? "https://securepay.sslcommerz.com" : "https://sandbox.sslcommerz.com";
const ADMINS = (E.ADMIN_PHONES || "").split(",").map(s => s.trim()).filter(Boolean);
if (PROD && MODE === "mock") console.warn("সতর্কতা: PAYMENT_MODE=mock – এটি আসল পেমেন্ট নয়!");

/* ---------- ডাটাবেস ---------- */
const db = new DatabaseSync(E.DB_FILE || path.join(DIR, "rustar.db"));
db.exec(`
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(phone TEXT PRIMARY KEY,name TEXT,role TEXT,salt TEXT,pwh TEXT,shop TEXT,job TEXT,wage INTEGER,created INTEGER);
CREATE TABLE IF NOT EXISTS otps(phone TEXT PRIMARY KEY,h TEXT,exp INTEGER,tries INTEGER);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY AUTOINCREMENT,by_phone TEXT,retailer TEXT,kind TEXT,amount INTEGER,commission INTEGER,pay_method TEXT,pay_status TEXT,tran_id TEXT,status TEXT,items TEXT,created INTEGER);
CREATE TABLE IF NOT EXISTS retailers(id INTEGER PRIMARY KEY AUTOINCREMENT,owner TEXT UNIQUE,shop TEXT,shop_key TEXT UNIQUE,license TEXT UNIQUE,area TEXT,address TEXT,status TEXT,note TEXT,created INTEGER,decided INTEGER,decided_by TEXT);
CREATE TABLE IF NOT EXISTS books(id INTEGER PRIMARY KEY AUTOINCREMENT,by_phone TEXT,target TEXT,txt TEXT,created INTEGER);
CREATE TABLE IF NOT EXISTS ads(id INTEGER PRIMARY KEY AUTOINCREMENT,by_phone TEXT,a TEXT,created INTEGER);`);
const q = (s, ...p) => db.prepare(s).get(...p), qa = (s, ...p) => db.prepare(s).all(...p), run = (s, ...p) => db.prepare(s).run(...p);

/* ---------- দাম (সার্ভার নিজে হিসাব করে, ক্লায়েন্টের দাম বিশ্বাস করে না) ---------- */
const PRICES = [14000, 9000, 560, 88000, 1850, 780, 6500, 4200];       // স্টোরের পণ্য (অ্যাপের ক্রম অনুযায়ী)
const STONE = [3400, 2900, 3100, 3100, 1700, 3400];                     // পাথর এজেন্সি অনুযায়ী প্রতি টন
const AREAS = ["খুলনা", "ঢাকা", "চট্টগ্রাম", "সিলেট", "রাজশাহী"];
const AGENCIES = ["সীমান্ত স্টোন এজেন্সি", "বর্ডার রক ট্রেডার্স", "পূর্বাশা এজেন্সি", "উত্তর স্টোন হাব", "সিলেট রক সাপ্লাই", "ভোলাগঞ্জ কোয়ারি ট্রেড"];
const ROLES = ["ক্রেতা", "রিটেইলার/ডিলার", "কর্মী", "আর্কিটেক্ট"];
const COMMISSION = 0.05;

/* ---------- নিরাপত্তা সহায়ক ---------- */
const b64 = b => Buffer.from(b).toString("base64url");
const hmac = s => crypto.createHmac("sha256", SECRET).update(s).digest("base64url");
const sign = (o, ttl = 30 * 864e5) => { const p = b64(JSON.stringify({ ...o, exp: Date.now() + ttl })); return p + "." + hmac(p); };
const verify = t => { const [p, s] = String(t || "").split("."); if (!p || !s) return null; const g = hmac(p);
  if (s.length !== g.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(g))) return null;
  try { const o = JSON.parse(Buffer.from(p, "base64url")); return o.exp > Date.now() ? o : null; } catch { return null; } };
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString("hex");
const eq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const clean = (s, n = 100) => String(s ?? "").replace(/[<>&"'`\\]/g, "").trim().slice(0, n);   // XSS প্রতিরোধ
const validPhone = p => /^01\d{9}$/.test(p);
const hits = new Map();
const limited = (k, max, win) => { const n = Date.now(), a = (hits.get(k) || []).filter(t => n - t < win); a.push(n); hits.set(k, a); return a.length > max; };
setInterval(() => { const n = Date.now(); for (const [k, a] of hits) if (!a.some(t => n - t < 36e5)) hits.delete(k); }, 6e5).unref();

const myShop = u => (q("SELECT shop FROM retailers WHERE owner=? AND status='approved'", u.phone) || {}).shop;
const userOut = u => ({ admin: ADMINS.includes(u.phone) || undefined, phone: u.phone, name: u.name, role: u.role, shop: u.shop || undefined, job: u.job || undefined, wage: u.wage || undefined });
const orderOut = o => ({ id: o.id, retailer: o.retailer, amount: o.amount, pay_method: o.pay_method, pay_status: o.pay_status, status: o.status, commission: o.commission, by: o.by_phone, created: o.created });

async function sendSms(to, msg) {
  if (!E.SMS_URL_TEMPLATE) { console.log(`[SMS-ডেভ] ${to}: ${msg}`); return false; }
  const url = E.SMS_URL_TEMPLATE.replace("{to}", encodeURIComponent(to)).replace("{msg}", encodeURIComponent(msg));
  const r = await fetch(url); if (!r.ok) throw new Error("SMS ব্যর্থ"); return true;
}

/* ---------- পেমেন্ট ---------- */
async function payInit(order, user) {
  const tran = `RS${order.id}-${crypto.randomBytes(4).toString("hex")}`;
  run("UPDATE orders SET tran_id=? WHERE id=?", tran, order.id);
  if (MODE === "mock") return { url: `${BASE}/pay/mock?t=${tran}`, mock: true };
  const f = new URLSearchParams({ store_id: E.SSLC_STORE_ID, store_passwd: E.SSLC_STORE_PASS, total_amount: String(order.amount), currency: "BDT", tran_id: tran,
    success_url: `${BASE}/pay/success`, fail_url: `${BASE}/pay/fail`, cancel_url: `${BASE}/pay/cancel`, ipn_url: `${BASE}/api/pay/ipn`,
    cus_name: user.name, cus_email: "noemail@rustar.app", cus_add1: "Bangladesh", cus_city: "Dhaka", cus_country: "Bangladesh", cus_phone: user.phone,
    shipping_method: "NO", product_name: "RuStar Order " + order.id, product_category: "Construction", product_profile: "general" });
  const r = await fetch(`${SSLC}/gwprocess/v4/api.php`, { method: "POST", body: f });
  const j = await r.json();
  if (j.status !== "SUCCESS" || !j.GatewayPageURL) throw new Error("গেটওয়ে চালু করা যায়নি");
  return { url: j.GatewayPageURL };
}
async function confirmPayment(tran, valId) {          // গেটওয়ের কাছে নিজে যাচাই করে – ব্রাউজারের কথা বিশ্বাস করে না
  const o = q("SELECT * FROM orders WHERE tran_id=?", tran);
  if (!o || o.pay_status === "paid") return o || null;
  if (MODE !== "mock") {
    const u = `${SSLC}/validator/api/validationserverAPI.php?val_id=${encodeURIComponent(valId)}&store_id=${encodeURIComponent(E.SSLC_STORE_ID)}&store_passwd=${encodeURIComponent(E.SSLC_STORE_PASS)}&format=json`;
    const j = await (await fetch(u)).json();
    const ok = ["VALID", "VALIDATED"].includes(j.status) && j.tran_id === tran && j.currency === "BDT" && Math.abs(Number(j.amount) - o.amount) < 0.01;
    if (!ok) return null;
  }
  run("UPDATE orders SET pay_status='paid' WHERE id=? AND pay_status!='paid'", o.id);
  return q("SELECT * FROM orders WHERE id=?", o.id);
}

/* ---------- রুট ---------- */
const routes = {};
const route = (m, p, fn) => routes[m + " " + p] = fn;
const need = (ctx) => { if (!ctx.user) throw Object.assign(new Error("লগইন করুন"), { code: 401 }); return ctx.user; };
const bad = (m, code = 400) => { throw Object.assign(new Error(m), { code }); };

route("GET", "/api/health", () => ({ ok: true, payment: MODE }));

route("POST", "/api/signup/otp", async (c, b) => {      // সাইন-আপের আগে নম্বর যাচাইয়ের OTP
  const phone = clean(b.phone, 11);
  if (!validPhone(phone)) bad("সঠিক ১১ সংখ্যার মোবাইল নম্বর দিন");
  if (q("SELECT 1 FROM users WHERE phone=?", phone)) bad("এই নম্বরে অ্যাকাউন্ট আছে", 409);
  if (limited("so:" + c.ip, 10, 36e5) || limited("so:" + phone, 3, 6e5)) bad("অনেকবার অনুরোধ হয়েছে, পরে চেষ্টা করুন", 429);
  const code = String(crypto.randomInt(100000, 1000000));
  run("INSERT OR REPLACE INTO otps VALUES(?,?,?,0)", "s:" + phone, hmac(code + phone + "s"), Date.now() + 3e5);
  await sendSms(phone, `RuStar সাইন-আপ OTP: ${code} (৫ মিনিট)`);
  return { ok: true, ...(PROD ? {} : { dev_code: code }) };
});

route("POST", "/api/signup", async (c, b) => {
  const phone = clean(b.phone, 11), name = clean(b.name, 60), role = ROLES.includes(b.role) ? b.role : bad("ভূমিকা ঠিক নয়");
  if (!name) bad("নাম দিন"); if (!validPhone(phone)) bad("সঠিক ১১ সংখ্যার মোবাইল নম্বর দিন");
  if (String(b.password || "").length < 6) bad("পাসওয়ার্ড কমপক্ষে ৬ অক্ষর");
  if (q("SELECT 1 FROM users WHERE phone=?", phone)) bad("এই নম্বরে অ্যাকাউন্ট আছে", 409);
  const so = q("SELECT * FROM otps WHERE phone=?", "s:" + phone);          // নম্বর যাচাই (OTP) বাধ্যতামূলক
  if (!so || so.exp < Date.now() || so.tries >= 5) bad("OTP মেয়াদোত্তীর্ণ বা অবৈধ", 401);
  run("UPDATE otps SET tries=tries+1 WHERE phone=?", "s:" + phone);
  if (!eq(hmac(String(b.otp || "") + phone + "s"), so.h)) bad("OTP ভুল", 401);
  run("DELETE FROM otps WHERE phone=?", "s:" + phone);
  const salt = crypto.randomBytes(16).toString("hex");
  run("INSERT INTO users VALUES(?,?,?,?,?,?,?,?,?)", phone, name, role, salt, hashPw(b.password, salt), clean(b.shop, 80) || null, clean(b.job, 40) || null, Math.max(0, +b.wage || 0), Date.now());
  const u = q("SELECT * FROM users WHERE phone=?", phone);
  return { token: sign({ p: phone }), user: userOut(u) };
});

route("POST", "/api/login", async (c, b) => {
  const phone = clean(b.phone, 11);
  if (limited("l:" + c.ip, 20, 6e5) || limited("l:" + phone, 8, 6e5)) bad("অনেকবার চেষ্টা হয়েছে, কিছুক্ষণ পরে চেষ্টা করুন", 429);
  const u = q("SELECT * FROM users WHERE phone=?", phone);
  const h = u ? hashPw(String(b.password || ""), u.salt) : hashPw("x", "0".repeat(32));
  if (!u || !eq(h, u.pwh)) bad("নম্বর বা পাসওয়ার্ড ভুল", 401);
  return { token: sign({ p: phone }), user: userOut(u) };
});

route("POST", "/api/otp/request", async (c, b) => {
  const phone = clean(b.phone, 11);
  if (!validPhone(phone)) bad("সঠিক নম্বর দিন");
  if (limited("o:" + c.ip, 10, 36e5) || limited("o:" + phone, 3, 6e5)) bad("অনেকবার অনুরোধ হয়েছে, পরে চেষ্টা করুন", 429);
  const code = String(crypto.randomInt(100000, 1000000));
  run("INSERT OR REPLACE INTO otps VALUES(?,?,?,0)", phone, hmac(code + phone), Date.now() + 3e5);
  if (q("SELECT 1 FROM users WHERE phone=?", phone)) await sendSms(phone, `RuStar OTP: ${code} (৫ মিনিট)`);
  return { ok: true, ...(PROD ? {} : { dev_code: code }) };     // উত্তরে কোড শুধু ডেভেলপমেন্টে
});

route("POST", "/api/otp/verify", async (c, b) => {
  const phone = clean(b.phone, 11), o = q("SELECT * FROM otps WHERE phone=?", phone);
  if (!o || o.exp < Date.now() || o.tries >= 5) bad("OTP মেয়াদোত্তীর্ণ বা অবৈধ", 401);
  run("UPDATE otps SET tries=tries+1 WHERE phone=?", phone);
  if (!eq(hmac(String(b.code || "") + phone), o.h)) bad("OTP ভুল", 401);
  run("DELETE FROM otps WHERE phone=?", phone);
  const u = q("SELECT * FROM users WHERE phone=?", phone); if (!u) bad("অ্যাকাউন্ট নেই", 404);
  return { token: sign({ p: phone }), user: userOut(u) };
});

route("GET", "/api/me", (c) => ({ user: userOut(need(c)) }));

route("POST", "/api/orders", (c, b) => {
  const u = need(c); let amount = 0, items = [], retailer, kind = b.kind === "stone" ? "stone" : "store";
  if (kind === "stone") {
    const a = +b.agency, t = Math.floor(+b.tons);
    if (!(a >= 0 && a < AGENCIES.length) || !(t >= 1 && t <= 1000)) bad("অর্ডার ঠিক নয়");
    amount = STONE[a] * t; retailer = AGENCIES[a]; items = [{ agency: a, tons: t }];
  } else {
    if (!Array.isArray(b.items) || !b.items.length || b.items.length > 20) bad("কার্ট খালি");
    for (const it of b.items) { const i = +it.i, n = Math.floor(+it.q);
      if (!(i >= 0 && i < PRICES.length) || !(n >= 1 && n <= 10000)) bad("পণ্য ঠিক নয়"); amount += PRICES[i] * n; items.push({ i, q: n }); }
    retailer = q("SELECT 1 FROM retailers WHERE shop=? AND status='approved'", String(b.retailer || "")) ? String(b.retailer) : bad("রিটেইলার ঠিক নয়");
  }
  const method = b.pay === "cod" ? "cod" : "online", com = method === "online" ? Math.round(amount * COMMISSION) : 0;
  const r = run("INSERT INTO orders(by_phone,retailer,kind,amount,commission,pay_method,pay_status,status,items,created) VALUES(?,?,?,?,?,?,?,?,?,?)",
    u.phone, retailer, kind, amount, com, method, method === "online" ? "unpaid" : "cod", "pending", JSON.stringify(items), Date.now());
  return { order: orderOut(q("SELECT * FROM orders WHERE id=?", r.lastInsertRowid)) };
});

route("GET", "/api/orders", (c) => {
  const u = need(c);
  const rows = ADMINS.includes(u.phone) ? qa("SELECT * FROM orders ORDER BY id DESC LIMIT 200")
    : myShop(u) ? qa("SELECT * FROM orders WHERE retailer=? OR by_phone=? ORDER BY id DESC LIMIT 200", myShop(u), u.phone)
    : qa("SELECT * FROM orders WHERE by_phone=? ORDER BY id DESC LIMIT 200", u.phone);
  return { orders: rows.map(orderOut) };
});

route("POST", "/api/orders/confirm", (c, b) => {
  const u = need(c), o = q("SELECT * FROM orders WHERE id=?", +b.id);
  if (!o) bad("অর্ডার নেই", 404);
  if (!(ADMINS.includes(u.phone) || myShop(u) === o.retailer)) bad("অনুমতি নেই", 403);
  run("UPDATE orders SET status='confirmed' WHERE id=?", o.id); return { ok: true };
});

/* ---------- রিটেইলার নিবন্ধন ---------- */
const adminOnly = c => { const u = need(c); if (!ADMINS.includes(u.phone)) bad("অনুমতি নেই", 403); return u; };
const rOut = r => r && ({ id: r.id, shop: r.shop, area: r.area, address: r.address, status: r.status, note: r.note || undefined });
route("POST", "/api/retailers/apply", (c, b) => {
  const u = need(c); if (u.role !== "রিটেইলার/ডিলার") bad("শুধু রিটেইলার আবেদন করতে পারবেন", 403);
  const shop = clean(b.shop, 60), lic = clean(b.license, 30).toUpperCase(), area = String(b.area || ""), addr = clean(b.address, 150);
  if (shop.length < 2) bad("দোকানের নাম দিন (কমপক্ষে ২ অক্ষর)");
  if (!/^[A-Z0-9][A-Z0-9\-\/]{4,29}$/.test(lic)) bad("ট্রেড লাইসেন্স নম্বর ঠিক নয়");
  if (!AREAS.includes(area)) bad("এলাকা ঠিক নয়");
  if (addr.length < 5) bad("ঠিকানা দিন (কমপক্ষে ৫ অক্ষর)");
  if (limited("ra:" + u.phone, 5, 36e5)) bad("ঘন্টায় ৫টির বেশি আবেদন নয়", 429);
  const old = q("SELECT * FROM retailers WHERE owner=?", u.phone);
  if (old && old.status === "approved") bad("আপনার আবেদন ইতিমধ্যে অনুমোদিত", 409);
  if (old && old.status === "pending") bad("আপনার আবেদন যাচাই চলছে", 409);
  const key = shop.toLowerCase();
  if (q("SELECT 1 FROM retailers WHERE (shop_key=? OR license=?) AND owner!=?", key, lic, u.phone)) bad("এই দোকানের নাম বা লাইসেন্স আগেই নিবন্ধিত", 409);
  if (old) run("UPDATE retailers SET shop=?,shop_key=?,license=?,area=?,address=?,status='pending',note=NULL,created=?,decided=NULL,decided_by=NULL WHERE owner=?", shop, key, lic, area, addr, Date.now(), u.phone);
  else run("INSERT INTO retailers(owner,shop,shop_key,license,area,address,status,created) VALUES(?,?,?,?,?,?,'pending',?)", u.phone, shop, key, lic, area, addr, Date.now());
  return { r: rOut(q("SELECT * FROM retailers WHERE owner=?", u.phone)) };
});
route("GET", "/api/retailers/me", c => ({ r: rOut(q("SELECT * FROM retailers WHERE owner=?", need(c).phone)) || null }));
route("GET", "/api/retailers", () => ({ retailers: qa("SELECT shop,area FROM retailers WHERE status='approved' ORDER BY shop") }));   // জনসাধারণের তালিকায় লাইসেন্স/ফোন নেই
route("GET", "/api/admin/retailers", c => { adminOnly(c);
  return { retailers: qa("SELECT r.id,r.shop,r.area,r.address,r.license,r.owner,u.name AS owner_name,r.created FROM retailers r JOIN users u ON u.phone=r.owner WHERE r.status='pending' ORDER BY r.id") }; });
route("POST", "/api/admin/retailers/decide", (c, b) => { const a = adminOnly(c), r = q("SELECT * FROM retailers WHERE id=?", +b.id);
  if (!r) bad("আবেদন নেই", 404); if (r.status !== "pending") bad("আবেদনটি আগেই নিষ্পন্ন হয়েছে", 409);
  const ok = b.approve === true;
  run("UPDATE retailers SET status=?,note=?,decided=?,decided_by=? WHERE id=?", ok ? "approved" : "rejected", ok ? null : clean(b.note, 150) || null, Date.now(), a.phone, r.id);
  if (ok) run("UPDATE users SET shop=? WHERE phone=?", r.shop, r.owner);
  return { ok: true }; });

route("POST", "/api/pay/init", async (c, b) => {
  const u = need(c), o = q("SELECT * FROM orders WHERE id=? AND by_phone=?", +b.orderId, u.phone);
  if (!o || o.pay_method !== "online" || o.pay_status === "paid") bad("পেমেন্ট করা যাবে না", 400);
  return await payInit(o, u);
});

route("POST", "/api/books", (c, b) => {
  const u = need(c), target = clean(b.target, 80), txt = clean(b.txt, 200); if (!target || !txt) bad("তথ্য দিন");
  run("INSERT INTO books(by_phone,target,txt,created) VALUES(?,?,?,?)", u.phone, target, txt, Date.now()); return { ok: true };
});
route("GET", "/api/books", (c) => { const u = need(c);
  return { books: qa("SELECT txt,created FROM books WHERE by_phone=? OR target=? ORDER BY id DESC LIMIT 100", u.phone, u.name).map(r => ({ txt: r.txt, t: r.created })) }; });

route("POST", "/api/ads", (c, b) => {
  const u = need(c), a = Array.isArray(b.a) ? b.a : bad("বিজ্ঞাপন ঠিক নয়");
  const t = ["ফ্ল্যাট", "অ্যাপার্টমেন্ট", "বাড়ি", "জমি", "শপ"], k = ["বিক্রয়", "ভাড়া"];
  if (!t.includes(a[0]) || !k.includes(a[1]) || !(+a[3] > 0)) bad("বিজ্ঞাপন ঠিক নয়");
  if (limited("ad:" + u.phone, 10, 36e5)) bad("ঘন্টায় ১০টির বেশি বিজ্ঞাপন নয়", 429);
  run("INSERT INTO ads(by_phone,a,created) VALUES(?,?,?)", u.phone, JSON.stringify([a[0], a[1], clean(a[2], 200), Math.round(+a[3]), clean(a[4], 30)]), Date.now()); return { ok: true };
});
route("GET", "/api/ads", () => ({ ads: qa("SELECT a,created FROM ads ORDER BY id DESC LIMIT 100").map(r => ({ a: JSON.parse(r.a), t: r.created })) }));

/* ---------- পেমেন্ট ফেরত পাতা ---------- */
const redirect = (res, to) => { res.writeHead(303, { Location: to }); res.end(); };
const page = (res, html) => { res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }); res.end(html); };
async function payPages(req, res, url, body) {
  const p = url.pathname;
  if (p === "/pay/success") { const o = await confirmPayment(clean(body.tran_id, 60), clean(body.val_id, 60)).catch(() => null);
    return redirect(res, `/?pay=${o && o.pay_status === "paid" ? "ok" : "fail"}`); }
  if (p === "/pay/fail" || p === "/pay/cancel") return redirect(res, "/?pay=fail");
  if (p === "/api/pay/ipn") { await confirmPayment(clean(body.tran_id, 60), clean(body.val_id, 60)).catch(() => {}); res.writeHead(200); return res.end("OK"); }
  if (MODE === "mock" && p === "/pay/mock") { const t = clean(url.searchParams.get("t"), 60), o = q("SELECT * FROM orders WHERE tran_id=?", t);
    return page(res, `<meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><body style="font:16px system-ui;max-width:420px;margin:40px auto;padding:0 16px"><h2>পরীক্ষামূলক পেমেন্ট (আসল টাকা কাটবে না)</h2><p>অর্ডার ${o ? o.id : "?"} · ৳${o ? o.amount : 0}</p><form method=post action=/pay/mock-done><input type=hidden name=t value="${t}"><button name=r value=ok style="padding:12px 20px">পেমেন্ট সফল ধরুন</button> <button name=r value=no style="padding:12px 20px">বাতিল</button></form>`); }
  if (MODE === "mock" && p === "/pay/mock-done") { const o = body.r === "ok" ? await confirmPayment(clean(body.t, 60), "mock") : null; return redirect(res, `/?pay=${o ? "ok" : "fail"}`); }
  return false;
}

/* ---------- সার্ভার ---------- */
const readBody = req => new Promise((ok, no) => { let n = 0; const c = [];
  req.on("data", d => { n += d.length; if (n > 1e5) { no(Object.assign(new Error("বড় অনুরোধ"), { code: 413 })); req.destroy(); } else c.push(d); });
  req.on("end", () => { const t = Buffer.concat(c).toString(); try { ok((req.headers["content-type"] || "").includes("json") ? JSON.parse(t || "{}") : Object.fromEntries(new URLSearchParams(t))); } catch { no(Object.assign(new Error("অনুরোধ ঠিক নয়"), { code: 400 })); } });
  req.on("error", no); });
const HDR = { "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
  "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'",
  ...(PROD ? { "Strict-Transport-Security": "max-age=31536000" } : {}) };
const INDEX = path.join(DIR, "public", "index.html");

export const server = http.createServer(async (req, res) => {
  for (const [k, v] of Object.entries(HDR)) res.setHeader(k, v);
  const url = new URL(req.url, BASE), ip = (PROD && req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
  try {
    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }); return res.end(fs.readFileSync(INDEX)); }
    const body = req.method === "POST" ? await readBody(req) : {};
    if (url.pathname.startsWith("/pay/") || url.pathname === "/api/pay/ipn") { if (await payPages(req, res, url, body) !== false) return; }
    const fn = routes[req.method + " " + url.pathname];
    if (!fn) { res.writeHead(404, { "Content-Type": "application/json" }); return res.end('{"error":"পাওয়া যায়নি"}'); }
    const tok = verify((req.headers.authorization || "").replace(/^Bearer /, ""));
    const user = tok ? q("SELECT * FROM users WHERE phone=?", tok.p) : null;
    const out = await fn({ user, ip }, body);
    res.writeHead(200, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }); res.end(JSON.stringify(out));
  } catch (e) {
    const code = e.code && e.code >= 400 && e.code < 600 ? e.code : 500;
    if (code === 500) console.error(e);
    res.writeHead(code, { "Content-Type": "application/json; charset=utf-8" }); res.end(JSON.stringify({ error: code === 500 ? "সার্ভারে সমস্যা হয়েছে" : e.message }));
  }
});
if (process.argv[1] === fileURLToPath(import.meta.url)) server.listen(PORT, () => console.log(`RuStar সার্ভার চালু: ${BASE} (পেমেন্ট: ${MODE})`));
