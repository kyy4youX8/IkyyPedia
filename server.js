require("dotenv").config();
const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const API_URL = process.env.INDOSMM_API_URL || "https://indosmm.id/api/v2";
const API_KEY = process.env.INDOSMM_API_KEY;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const MIN_TOPUP = Number(process.env.MIN_TOPUP || 10000);
const MAX_TOPUP = Number(process.env.MAX_TOPUP || 10000000);
const MARKUP_PERCENT = Math.max(0, Number(process.env.MARKUP_PERCENT || 0));
const REACTION_ENABLED = String(process.env.REACTION_ENABLED || "true").toLowerCase() === "true";
const REACTION_KEYWORDS = String(process.env.REACTION_KEYWORDS || "reaction,reactions,react,like reaction")
  .split(",")
  .map((x) => x.trim().toLowerCase())
  .filter(Boolean);

// Telegram
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "";
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || "";
const TELEGRAM_ENABLED = Boolean(TELEGRAM_BOT_TOKEN && TELEGRAM_CHAT_ID);

const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "panel-data.json");
fs.mkdirSync(DATA_DIR, { recursive: true });

function readDB() {
  try {
    const data = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
    if (!Array.isArray(data.users)) data.users = [];
    if (!Array.isArray(data.topups)) data.topups = [];
    if (!Array.isArray(data.orders)) data.orders = [];
    if (!Array.isArray(data.tickets)) data.tickets = [];
    return data;
  } catch {
    return { users: [], topups: [], orders: [], tickets: [] };
  }
}

let db = readDB();

function saveDB() {
  const tmp = DB_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, DB_FILE);
}

const sessions = new Map();
const appSecret = process.env.SESSION_SECRET;
if (!appSecret || appSecret.length < 32) {
  console.warn("PERINGATAN: isi SESSION_SECRET dengan nilai acak minimal 32 karakter di .env untuk keamanan.");
}

app.disable("x-powered-by");
app.use(express.json({ limit: "6mb" }));
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  next();
});
app.use(express.static(path.join(__dirname, "public")));

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  return `${salt}:${crypto.scryptSync(password, salt, 64).toString("hex")}`;
}

function checkPassword(password, stored) {
  try {
    const [salt, hex] = stored.split(":");
    const a = crypto.scryptSync(password, salt, 64);
    const b = Buffer.from(hex, "hex");
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function sessionUser(req) {
  const token = (req.headers.cookie || "")
    .split(";")
    .map((s) => s.trim())
    .find((s) => s.startsWith("ikyy_session="))
    ?.slice("ikyy_session=".length);
  return token ? sessions.get(token) : null;
}

function setSession(res, user) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, { id: user.id, role: user.role, username: user.username });
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  res.setHeader(
    "Set-Cookie",
    `ikyy_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800${secure}`
  );
}

function auth(req, res, next) {
  const u = sessionUser(req);
  if (!u) return res.status(401).json({ error: "Silakan login terlebih dahulu." });
  req.user = u;
  next();
}

function admin(req, res, next) {
  const u = sessionUser(req);
  if (!u || u.role !== "admin") return res.status(403).json({ error: "Khusus admin." });
  req.user = u;
  next();
}

function requireApiKey(res) {
  if (!API_KEY || API_KEY === "ISI_API_KEY_ANDA") {
    res.status(503).json({ error: "API Key IndoSMM belum diisi di file .env" });
    return false;
  }
  return true;
}

// ---- Telegram ----
async function sendTelegram(text) {
  if (!TELEGRAM_ENABLED) return false;
  try {
    const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
    const body = new URLSearchParams({
      chat_id: TELEGRAM_CHAT_ID,
      text: String(text).slice(0, 4000),
      parse_mode: "HTML",
      disable_web_page_preview: "true",
    });
    const r = await fetch(url, { method: "POST", body });
    return r.ok;
  } catch (e) {
    console.warn("Telegram gagal:", e.message);
    return false;
  }
}

// ---- Auth ----
app.get("/api/auth/me", (req, res) => {
  const u = sessionUser(req);
  if (!u) return res.json({ loggedIn: false });
  if (u.role === "admin") {
    return res.json({ loggedIn: true, user: { id: u.id, username: u.username, role: "admin", balance: null } });
  }
  const user = db.users.find((x) => x.id === u.id);
  res.json({
    loggedIn: true,
    user: { id: u.id, username: u.username, role: u.role, balance: user?.balance || 0 },
  });
});

app.post("/api/auth/register", (req, res) => {
  const username = String(req.body.username || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (!/^[a-z0-9_]{3,24}$/.test(username)) {
    return res.status(400).json({ error: "Username 3–24 karakter: huruf kecil, angka, garis bawah." });
  }
  if (password.length < 8 || password.length > 128) {
    return res.status(400).json({ error: "Password harus 8–128 karakter." });
  }
  if (db.users.some((u) => u.username === username) || (ADMIN_USERNAME && username === ADMIN_USERNAME.toLowerCase())) {
    return res.status(409).json({ error: "Username sudah digunakan." });
  }
  const user = {
    id: crypto.randomUUID(),
    username,
    passwordHash: hashPassword(password),
    role: "user",
    balance: 0,
    createdAt: new Date().toISOString(),
  };
  db.users.push(user);
  saveDB();
  setSession(res, user);
  res.json({ ok: true, username, role: "user", balance: 0 });
});

app.post("/api/auth/login", (req, res) => {
  const username = String(req.body.username || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  if (
    ADMIN_USERNAME &&
    ADMIN_PASSWORD &&
    username === ADMIN_USERNAME.toLowerCase() &&
    password === ADMIN_PASSWORD
  ) {
    const adminUser = { id: "admin", username: ADMIN_USERNAME, role: "admin" };
    setSession(res, adminUser);
    return res.json({ ok: true, username: ADMIN_USERNAME, role: "admin" });
  }

  const user = db.users.find((u) => u.username === username);
  if (!user || !checkPassword(password, user.passwordHash)) {
    return res.status(401).json({ error: "Username/password salah atau akun belum terdaftar." });
  }
  setSession(res, user);
  res.json({ ok: true, username: user.username, role: user.role, balance: user.balance });
});

app.post("/api/auth/logout", (req, res) => {
  const token = (req.headers.cookie || "")
    .split(";")
    .map((s) => s.trim())
    .find((s) => s.startsWith("ikyy_session="))
    ?.slice("ikyy_session=".length);
  if (token) sessions.delete(token);
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  res.setHeader("Set-Cookie", `ikyy_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure}`);
  res.json({ ok: true });
});

app.get("/api/account", auth, (req, res) => {
  if (req.user.role === "admin") return res.json({ username: req.user.username, role: "admin" });
  const u = db.users.find((x) => x.id === req.user.id);
  res.json({ username: u.username, role: u.role, balance: u.balance, createdAt: u.createdAt });
});

app.post("/api/account/password", auth, (req, res) => {
  if (req.user.role !== "user") {
    return res.status(403).json({ error: "Password admin dikelola melalui konfigurasi server (.env)." });
  }
  const current = String(req.body.currentPassword || "");
  const next = String(req.body.newPassword || "");
  if (next.length < 8 || next.length > 128) {
    return res.status(400).json({ error: "Password baru harus 8–128 karakter." });
  }
  const user = db.users.find((x) => x.id === req.user.id);
  if (!user || !checkPassword(current, user.passwordHash)) {
    return res.status(401).json({ error: "Password saat ini salah." });
  }
  user.passwordHash = hashPassword(next);
  saveDB();
  res.json({ ok: true });
});

// ---- Top Up ----
app.post("/api/topups", auth, (req, res) => {
  if (req.user.role !== "user") {
    return res.status(403).json({ error: "Admin tidak dapat membuat permintaan top up pengguna." });
  }
  const amount = Number(req.body.amount);
  const reference = String(req.body.reference || "").trim().slice(0, 100);
  const proofDataUrl = String(req.body.proofDataUrl || "");
  if (!Number.isSafeInteger(amount) || amount < MIN_TOPUP || amount > MAX_TOPUP) {
    return res.status(400).json({
      error: `Nominal top up harus Rp${MIN_TOPUP.toLocaleString("id-ID")}–Rp${MAX_TOPUP.toLocaleString("id-ID")}.`,
    });
  }
  if (reference.length < 4) {
    return res.status(400).json({ error: "Isi nomor referensi/berita pembayaran agar admin dapat memeriksa transaksi." });
  }
  const match = proofDataUrl.match(/^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/);
  if (!match) return res.status(400).json({ error: "Unggah bukti pembayaran berupa JPG, PNG, atau WEBP." });
  const imageBuffer = Buffer.from(match[2], "base64");
  if (imageBuffer.length < 100 || imageBuffer.length > 4 * 1024 * 1024) {
    return res.status(400).json({ error: "Ukuran bukti foto maksimal 4 MB." });
  }
  const proofDir = path.join(DATA_DIR, "proofs");
  fs.mkdirSync(proofDir, { recursive: true, mode: 0o700 });
  const proofFile = crypto.randomUUID() + "." + (match[1] === "jpeg" ? "jpg" : match[1]);
  fs.writeFileSync(path.join(proofDir, proofFile), imageBuffer, { mode: 0o600, flag: "wx" });
  const topup = {
    id: crypto.randomUUID(),
    userId: req.user.id,
    username: req.user.username,
    amount,
    reference,
    proofFile,
    status: "pending",
    createdAt: new Date().toISOString(),
    reviewedAt: null,
  };
  db.topups.unshift(topup);
  saveDB();

  sendTelegram(
    `💳 <b>Top Up Baru</b>\nUser: <code>${req.user.username}</code>\nNominal: <b>Rp${amount.toLocaleString("id-ID")}</b>\nRef: ${reference}\nStatus: PENDING — cek panel Admin`
  ).catch(() => {});

  res.json({ ok: true, topup });
});

app.get("/api/topups/mine", auth, (req, res) => {
  res.json(db.topups.filter((t) => t.userId === req.user.id));
});

app.get("/api/admin/topups", admin, (req, res) => res.json(db.topups));

app.get("/api/admin/topups/:id/proof", admin, (req, res) => {
  const t = db.topups.find((x) => x.id === req.params.id);
  if (!t || !t.proofFile) return res.status(404).send("Bukti pembayaran tidak ditemukan.");
  const file = path.join(DATA_DIR, "proofs", path.basename(t.proofFile));
  if (!fs.existsSync(file)) return res.status(404).send("File bukti pembayaran tidak ditemukan.");
  const ext = path.extname(file).toLowerCase();
  res.setHeader("Content-Type", ext === ".png" ? "image/png" : ext === ".webp" ? "image/webp" : "image/jpeg");
  res.setHeader("Cache-Control", "no-store");
  res.sendFile(file);
});

app.post("/api/admin/topups/:id/review", admin, (req, res) => {
  const t = db.topups.find((x) => x.id === req.params.id);
  if (!t) return res.status(404).json({ error: "Permintaan top up tidak ditemukan." });
  if (t.status !== "pending") return res.status(409).json({ error: "Top up ini sudah diproses." });
  const action = req.body.action;
  if (!["approve", "reject"].includes(action)) return res.status(400).json({ error: "Aksi tidak valid." });
  t.status = action === "approve" ? "approved" : "rejected";
  t.reviewedAt = new Date().toISOString();
  t.reviewedBy = req.user.username;
  if (action === "approve") {
    const user = db.users.find((x) => x.id === t.userId);
    if (!user) return res.status(404).json({ error: "Akun pengguna tidak ditemukan." });
    user.balance += t.amount;
  }
  saveDB();

  sendTelegram(
    `${action === "approve" ? "✅" : "❌"} <b>Top Up ${t.status.toUpperCase()}</b>\nUser: <code>${t.username}</code>\nNominal: Rp${Number(t.amount).toLocaleString("id-ID")}\nOleh: ${req.user.username}`
  ).catch(() => {});

  res.json({ ok: true, topup: t });
});

// ---- IndoSMM helper + services cache ----
let servicesCache = { data: null, at: 0 };

async function indosmm(action, params = {}) {
  const body = new URLSearchParams({
    key: API_KEY,
    action,
    ...Object.fromEntries(Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== "")),
  });
  const response = await fetch(API_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const text = await response.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(`Respons provider bukan JSON (HTTP ${response.status})`);
  }
  if (!response.ok) throw new Error(`Provider HTTP ${response.status}`);
  return data;
}

async function getServicesCached() {
  if (servicesCache.data && Date.now() - servicesCache.at < 90_000) return servicesCache.data;
  const data = await indosmm("services");
  const list = Array.isArray(data) ? data : data?.data || data?.services || [];
  servicesCache = { data: list, at: Date.now() };
  return list;
}

function findService(list, serviceId) {
  const id = String(serviceId);
  return list.find((s) => String(s.service) === id || String(s.service_id) === id);
}

function calcProviderCost(svc, quantity, comments) {
  const rate = Number(svc.rate || svc.price || 0);
  if (comments) {
    const lines = String(comments)
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean).length;
    const qty = lines > 0 ? lines : 1;
    return (qty / 1000) * rate;
  }
  const q = Number(quantity) || 0;
  return (q / 1000) * rate;
}

function applyMarkup(providerCost) {
  return providerCost * (1 + MARKUP_PERCENT / 100);
}

function normalizeStatus(raw) {
  if (raw == null) return "unknown";
  const s = String(raw).toLowerCase();
  if (["completed", "complete", "success", "sukses"].includes(s)) return "completed";
  if (["pending", "processing", "in progress", "inprogress"].includes(s)) return "pending";
  if (["partial", "partially completed"].includes(s)) return "partial";
  if (["canceled", "cancelled", "cancel", "refunded"].includes(s)) return "canceled";
  if (["error", "fail", "failed"].includes(s)) return "error";
  return s || "unknown";
}

// ---- Config & services ----
app.get("/api/panel-config", (req, res) =>
  res.json({
    minTopup: MIN_TOPUP,
    maxTopup: MAX_TOPUP,
    reactionEnabled: REACTION_ENABLED,
    reactionKeywords: REACTION_KEYWORDS,
    markupPercent: MARKUP_PERCENT,
    telegramEnabled: TELEGRAM_ENABLED,
    version: "X6",
  })
);

app.get("/api/services", async (req, res) => {
  if (!requireApiKey(res)) return;
  try {
    const list = await getServicesCached();
    res.json(list);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get("/api/balance", admin, async (req, res) => {
  if (!requireApiKey(res)) return;
  try {
    res.json(await indosmm("balance"));
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

// ---- Order ----
app.post("/api/order", auth, async (req, res) => {
  if (!requireApiKey(res)) return;

  const { service, link, quantity, comments, username } = req.body;
  if (!service || !link) return res.status(400).json({ error: "Service dan link wajib diisi." });
  if (!comments && (!quantity || Number(quantity) <= 0)) {
    return res.status(400).json({ error: "Quantity wajib diisi untuk layanan biasa." });
  }

  let services;
  try {
    services = await getServicesCached();
  } catch (err) {
    return res.status(502).json({ error: "Gagal mengambil daftar layanan: " + err.message });
  }

  const svc = findService(services, service);
  if (!svc) return res.status(400).json({ error: "Layanan tidak ditemukan di provider." });

  const providerCost = calcProviderCost(svc, quantity, comments);
  const chargeAmount = Math.ceil(applyMarkup(providerCost));

  if (chargeAmount <= 0) {
    return res.status(400).json({ error: "Tidak dapat menghitung harga layanan ini." });
  }

  let user = null;
  if (req.user.role === "user") {
    user = db.users.find((x) => x.id === req.user.id);
    if (!user) return res.status(404).json({ error: "Akun tidak ditemukan." });
    if (user.balance < chargeAmount) {
      return res.status(402).json({
        error: `Saldo tidak cukup. Dibutuhkan Rp${chargeAmount.toLocaleString("id-ID")}, saldo Anda Rp${user.balance.toLocaleString("id-ID")}.`,
        required: chargeAmount,
        balance: user.balance,
      });
    }
    user.balance -= chargeAmount;
    saveDB();
  }

  const params = { service, link };
  if (comments) params.comments = comments;
  else params.quantity = quantity;
  if (username) params.username = username;

  try {
    const result = await indosmm("add", params);
    if (result.order === undefined && result.order_id === undefined) {
      if (user) {
        user.balance += chargeAmount;
        saveDB();
      }
      return res.status(502).json({ error: result.error || "Provider tidak mengembalikan ID order." });
    }

    const providerOrderId = result.order ?? result.order_id;
    const orderRecord = {
      id: crypto.randomUUID(),
      providerOrderId: String(providerOrderId),
      userId: req.user.role === "user" ? req.user.id : null,
      username: req.user.username,
      role: req.user.role,
      serviceId: String(service),
      serviceName: svc.name || svc.service || String(service),
      category: svc.category || "",
      link: String(link).slice(0, 500),
      quantity: comments ? null : Number(quantity),
      comments: comments ? String(comments).slice(0, 2000) : null,
      providerCost: Math.round(providerCost * 100) / 100,
      chargeAmount,
      markupPercent: MARKUP_PERCENT,
      profit: Math.round((chargeAmount - providerCost) * 100) / 100,
      status: "pending",
      statusDetail: null,
      statusUpdatedAt: new Date().toISOString(),
      createdAt: new Date().toISOString(),
    };
    db.orders.unshift(orderRecord);
    if (db.orders.length > 5000) db.orders = db.orders.slice(0, 5000);
    saveDB();

    sendTelegram(
      `🛒 <b>Order Baru</b>\nUser: <code>${req.user.username}</code>\nLayanan: ${orderRecord.serviceName}\nQty: ${orderRecord.quantity ?? "custom"}\nCharge: <b>Rp${chargeAmount.toLocaleString("id-ID")}</b>\nProfit: Rp${orderRecord.profit.toLocaleString("id-ID")}\nID: <code>${providerOrderId}</code>`
    ).catch(() => {});

    res.json({
      order: providerOrderId,
      chargeAmount,
      balance: user ? user.balance : null,
      profit: orderRecord.profit,
      status: "pending",
    });
  } catch (err) {
    if (user) {
      user.balance += chargeAmount;
      saveDB();
    }
    res.status(502).json({ error: err.message });
  }
});

// Cek status 1 order + update di DB
app.post("/api/status", auth, async (req, res) => {
  if (!requireApiKey(res)) return;
  const { order, orders } = req.body;
  if (!order && !orders) return res.status(400).json({ error: "Masukkan ID order." });
  try {
    const data = await indosmm("status", { order, orders });
    const ids = order ? [String(order)] : String(orders || "").split(",").map((x) => x.trim()).filter(Boolean);
    const payload = Array.isArray(data) ? data : data?.orders ? Object.entries(data.orders).map(([id, v]) => ({ order: id, ...v })) : [data];

    for (const item of payload) {
      const oid = String(item.order || item.order_id || ids[0] || "");
      if (!oid) continue;
      const rec = db.orders.find((o) => String(o.providerOrderId) === oid);
      if (rec) {
        rec.status = normalizeStatus(item.status || item.order_status);
        rec.statusDetail = {
          charge: item.charge,
          start_count: item.start_count,
          remains: item.remains,
          currency: item.currency,
        };
        rec.statusUpdatedAt = new Date().toISOString();
      }
    }
    saveDB();
    res.json(data);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

// Refresh status banyak order (user: punya sendiri, admin: semua pending)
app.post("/api/orders/refresh-status", auth, async (req, res) => {
  if (!requireApiKey(res)) return;
  let list =
    req.user.role === "admin"
      ? db.orders.filter((o) => !["completed", "canceled"].includes(o.status)).slice(0, 40)
      : db.orders.filter((o) => o.userId === req.user.id && !["completed", "canceled"].includes(o.status)).slice(0, 20);

  if (!list.length) return res.json({ ok: true, updated: 0, orders: [] });

  const ids = list.map((o) => o.providerOrderId).join(",");
  try {
    const data = await indosmm("status", { orders: ids });
    const map = {};
    if (data && typeof data === "object" && !Array.isArray(data)) {
      if (data.orders && typeof data.orders === "object") {
        Object.assign(map, data.orders);
      } else {
        if (data.status) map[list[0].providerOrderId] = data;
        else Object.assign(map, data);
      }
    } else if (Array.isArray(data)) {
      for (const item of data) {
        const id = String(item.order || item.order_id || "");
        if (id) map[id] = item;
      }
    }

    let updated = 0;
    for (const rec of list) {
      const item = map[rec.providerOrderId];
      if (!item) continue;
      rec.status = normalizeStatus(item.status || item.order_status);
      rec.statusDetail = {
        charge: item.charge,
        start_count: item.start_count,
        remains: item.remains,
        currency: item.currency,
      };
      rec.statusUpdatedAt = new Date().toISOString();
      updated++;
    }
    saveDB();
    res.json({
      ok: true,
      updated,
      orders: list.map((o) => ({
        id: o.id,
        providerOrderId: o.providerOrderId,
        status: o.status,
        statusDetail: o.statusDetail,
        statusUpdatedAt: o.statusUpdatedAt,
      })),
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.post("/api/refill", auth, async (req, res) => {
  if (!requireApiKey(res)) return;
  const { order, orders } = req.body;
  if (!order && !orders) return res.status(400).json({ error: "Masukkan ID order." });
  try {
    res.json(await indosmm("refill", { order, orders }));
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.post("/api/cancel", auth, async (req, res) => {
  if (!requireApiKey(res)) return;
  const { orders } = req.body;
  if (!orders) return res.status(400).json({ error: "Masukkan ID order." });
  try {
    res.json(await indosmm("cancel", { orders }));
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

// ---- Orders list ----
app.get("/api/orders/mine", auth, (req, res) => {
  if (req.user.role === "admin") {
    return res.json(db.orders.slice(0, 200));
  }
  res.json(db.orders.filter((o) => o.userId === req.user.id).slice(0, 200));
});

app.get("/api/admin/orders", admin, (req, res) => {
  const limit = Math.min(500, Number(req.query.limit) || 200);
  res.json(db.orders.slice(0, limit));
});

app.get("/api/admin/stats", admin, (req, res) => {
  const orders = db.orders;
  const totalOrders = orders.length;
  const totalRevenue = orders.reduce((s, o) => s + (Number(o.chargeAmount) || 0), 0);
  const totalProviderCost = orders.reduce((s, o) => s + (Number(o.providerCost) || 0), 0);
  const totalProfit = orders.reduce((s, o) => s + (Number(o.profit) || 0), 0);
  const totalTopupApproved = db.topups
    .filter((t) => t.status === "approved")
    .reduce((s, t) => s + (Number(t.amount) || 0), 0);
  const totalUserBalance = db.users.reduce((s, u) => s + (Number(u.balance) || 0), 0);
  const openTickets = db.tickets.filter((t) => t.status === "open" || t.status === "in_progress").length;

  res.json({
    totalOrders,
    totalRevenue,
    totalProviderCost,
    totalProfit,
    totalTopupApproved,
    totalUserBalance,
    totalUsers: db.users.length,
    markupPercent: MARKUP_PERCENT,
    openTickets,
    telegramEnabled: TELEGRAM_ENABLED,
  });
});

app.get("/api/admin/users", admin, (req, res) => {
  res.json(
    db.users.map((u) => ({
      id: u.id,
      username: u.username,
      balance: u.balance,
      createdAt: u.createdAt,
    }))
  );
});

// ---- Tickets / Komplain ----
app.post("/api/tickets", auth, (req, res) => {
  if (req.user.role !== "user") {
    return res.status(403).json({ error: "Admin tidak membuat tiket lewat endpoint ini." });
  }
  const subject = String(req.body.subject || "").trim().slice(0, 120);
  const message = String(req.body.message || "").trim().slice(0, 2000);
  const orderId = String(req.body.orderId || "").trim().slice(0, 64);
  if (subject.length < 3) return res.status(400).json({ error: "Subjek minimal 3 karakter." });
  if (message.length < 10) return res.status(400).json({ error: "Isi komplain minimal 10 karakter." });

  if (orderId) {
    const owned = db.orders.find(
      (o) => o.userId === req.user.id && (o.providerOrderId === orderId || o.id === orderId)
    );
    if (!owned) {
      // izinkan tetap, tapi tandai
    }
  }

  const ticket = {
    id: crypto.randomUUID(),
    userId: req.user.id,
    username: req.user.username,
    subject,
    message,
    orderId: orderId || null,
    status: "open",
    adminReply: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  db.tickets.unshift(ticket);
  if (db.tickets.length > 2000) db.tickets = db.tickets.slice(0, 2000);
  saveDB();

  sendTelegram(
    `🆘 <b>KOMPLAIN BARU — IKYYPEDIA</b>\n\n━━━━━━━━━━━━━━━━━━\n👤 User     : <code>${req.user.username}</code>\n📌 Subjek   : ${subject}\n🛒 Order ID : ${orderId || "-"}\n\n━━━━━━━━━━━━━━━━━━\n💬 <b>ISI KOMPLAIN</b>\n${message.slice(0, 300)}\n\n🕒 Waktu: ${new Date().toLocaleString("id-ID", { timeZone: "Asia/Jakarta" })}\n\n⚠️ Mohon segera periksa komplain ini.`
  ).catch(() => {});

  res.json({ ok: true, ticket });
});

app.get("/api/tickets/mine", auth, (req, res) => {
  if (req.user.role === "admin") return res.json(db.tickets.slice(0, 100));
  res.json(db.tickets.filter((t) => t.userId === req.user.id).slice(0, 100));
});

app.get("/api/admin/tickets", admin, (req, res) => {
  res.json(db.tickets.slice(0, 200));
});

app.post("/api/admin/tickets/:id/reply", admin, (req, res) => {
  const t = db.tickets.find((x) => x.id === req.params.id);
  if (!t) return res.status(404).json({ error: "Tiket tidak ditemukan." });
  const reply = String(req.body.reply || "").trim().slice(0, 2000);
  const status = String(req.body.status || t.status);
  if (!["open", "in_progress", "resolved", "closed"].includes(status)) {
    return res.status(400).json({ error: "Status tidak valid." });
  }
  if (reply) t.adminReply = reply;
  t.status = status;
  t.updatedAt = new Date().toISOString();
  t.repliedBy = req.user.username;
  saveDB();
  res.json({ ok: true, ticket: t });
});

// Test telegram (admin)
app.post("/api/admin/telegram-test", admin, async (req, res) => {
  if (!TELEGRAM_ENABLED) {
    return res.status(400).json({ error: "Telegram belum dikonfigurasi (TELEGRAM_BOT_TOKEN & TELEGRAM_CHAT_ID)." });
  }
  const ok = await sendTelegram("✅ <b>Test Notifikasi</b>\nIkyyPediaa X6 terhubung dengan baik.");
  if (!ok) return res.status(502).json({ error: "Gagal mengirim ke Telegram. Cek token & chat id." });
  res.json({ ok: true });
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, () => {
  console.log(`IkyyPediaa X6 berjalan di http://localhost:${PORT}`);
  console.log(`Markup: ${MARKUP_PERCENT}% | Telegram: ${TELEGRAM_ENABLED ? "AKTIF" : "nonaktif"}`);
});
