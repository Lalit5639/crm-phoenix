const path = require("path");
const fs = require("fs/promises");
const os = require("os");
const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
require("dotenv").config();

const app = express();
const PORT = Number(process.env.PORT || 5501);
const HOST = process.env.HOST || "0.0.0.0";
const SESSION_TTL_MS = 1000 * 60 * 60 * 8;
const LOCK_TTL_SECONDS = 120;
const LEGACY_ADMIN_HASH = "$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi";
const sessions = new Map();
const PAGE_KEYS = ["dashboard", "sales", "orders", "dispatch", "delivery", "payments", "receipts", "recovery", "dealers", "employees", "products", "transporters", "stock", "ai", "users", "audit"];

const pool = mysql.createPool({
  host: process.env.DB_HOST || "127.0.0.1",
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "phoenix_crm",
  waitForConnections: true,
  connectionLimit: 10,
});
const PENDING_FILE = path.join(__dirname, "pending_saves.json");

app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(express.static(__dirname));
app.use((err, _req, res, next) => {
  if (err && err.type === "entity.parse.failed") {
    return res.status(400).json({ ok: false, message: "Invalid JSON body." });
  }
  return next(err);
});

function text(v) {
  return String(v ?? "").trim();
}

async function findIdByName(conn, table, idCol, nameCol, name) {
  const n = text(name);
  if (!n) return null;
  const [rows] = await conn.execute(
    `SELECT ${idCol} AS id FROM ${table} WHERE ${nameCol} = ? LIMIT 1`,
    [n]
  );
  return rows?.[0]?.id ?? null;
}

function isDbUnavailableError(err) {
  const code = String(err?.code || "");
  const msg = String(err?.message || "");
  return code === "ECONNREFUSED" || code === "PROTOCOL_CONNECTION_LOST" || msg.includes("ECONNREFUSED");
}

function getLanUrls() {
  const nets = os.networkInterfaces();
  const urls = [];
  for (const entries of Object.values(nets)) {
    for (const entry of entries || []) {
      const family = typeof entry.family === "string" ? entry.family : String(entry.family);
      if (family !== "IPv4" || entry.internal) continue;
      urls.push(`http://${entry.address}:${PORT}`);
    }
  }
  return [...new Set(urls)];
}

function createPasswordHash(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derived = crypto.scryptSync(String(password), salt, 64).toString("hex");
  return `scrypt$${salt}$${derived}`;
}

function verifyPassword(password, hash) {
  const normalized = String(hash || "");
  if (!normalized) return false;
  if (normalized.startsWith("scrypt$")) {
    const [, salt, stored] = normalized.split("$");
    if (!salt || !stored) return false;
    const derived = crypto.scryptSync(String(password), salt, 64).toString("hex");
    const a = Buffer.from(derived, "hex");
    const b = Buffer.from(stored, "hex");
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }
  if (normalized === LEGACY_ADMIN_HASH && String(password) === "admin123") {
    return true;
  }
  return false;
}

function createSession(user) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, {
    token,
    userId: Number(user.user_id),
    username: user.username,
    fullName: user.full_name || user.username,
    role: user.role || "Viewer",
    permissions: user.permissions || {},
    expiresAt: Date.now() + SESSION_TTL_MS,
  });
  return token;
}

function sanitizeSession(session) {
  return {
    userId: session.userId,
    username: session.username,
    fullName: session.fullName,
    role: session.role,
    permissions: session.permissions || {},
    expiresAt: session.expiresAt,
  };
}

function readBearerToken(req) {
  const header = String(req.headers.authorization || "");
  if (!header.toLowerCase().startsWith("bearer ")) return "";
  return header.slice(7).trim();
}

function cleanupExpiredSessions() {
  const now = Date.now();
  for (const [token, session] of sessions.entries()) {
    if (!session || session.expiresAt <= now) {
      sessions.delete(token);
    }
  }
}

function defaultPermissionsForRole(role) {
  const permissions = Object.fromEntries(PAGE_KEYS.map((page) => [page, { view: false, edit: false }]));
  if (role === "Admin") {
    for (const page of PAGE_KEYS) {
      permissions[page] = { view: true, edit: true };
    }
    return permissions;
  }
  if (role === "Staff") {
    for (const page of ["dashboard", "sales", "orders", "dispatch", "delivery", "payments", "receipts", "stock", "ai"]) {
      permissions[page] = { view: true, edit: ["orders", "dispatch", "delivery", "payments"].includes(page) };
    }
    return permissions;
  }
  if (role === "Viewer") {
    for (const page of ["dashboard", "sales", "orders", "dispatch", "delivery", "payments", "receipts", "recovery", "dealers", "employees", "products", "transporters", "stock", "ai"]) {
      permissions[page] = { view: true, edit: false };
    }
    return permissions;
  }
  for (const page of ["dashboard", "sales", "orders", "dispatch", "delivery", "payments", "receipts", "recovery", "dealers", "employees", "products", "transporters", "stock", "ai"]) {
    permissions[page] = { view: true, edit: false };
  }
  return permissions;
}

function normalizePermissions(input, role) {
  const defaults = defaultPermissionsForRole(role);
  const source = input && typeof input === "object" ? input : {};
  for (const page of PAGE_KEYS) {
    const row = source[page];
    if (row && typeof row === "object") {
      defaults[page] = { view: Boolean(row.view), edit: Boolean(row.edit) && Boolean(row.view) };
    }
  }
  if (role === "Admin") {
    for (const page of PAGE_KEYS) {
      defaults[page] = { view: true, edit: true };
    }
  }
  if (defaults.users.edit) defaults.users.view = true;
  if (defaults.audit.edit) defaults.audit.view = true;
  return defaults;
}

async function loadPermissions(userId, role) {
  const defaults = defaultPermissionsForRole(role);
  const [rows] = await pool.execute(
    `SELECT page_key, can_view, can_edit FROM user_page_permissions WHERE user_id=?`,
    [Number(userId)]
  );
  if (!rows?.length) {
    return defaults;
  }
  for (const row of rows) {
    if (!PAGE_KEYS.includes(row.page_key)) continue;
    defaults[row.page_key] = { view: Boolean(row.can_view), edit: Boolean(row.can_edit) && Boolean(row.can_view) };
  }
  return normalizePermissions(defaults, role);
}

async function savePermissions(userId, role, permissions) {
  const normalized = normalizePermissions(permissions, role);
  await pool.execute(`DELETE FROM user_page_permissions WHERE user_id=?`, [Number(userId)]);
  for (const page of PAGE_KEYS) {
    const perm = normalized[page] || { view: false, edit: false };
    await pool.execute(
      `INSERT INTO user_page_permissions (user_id, page_key, can_view, can_edit) VALUES (?,?,?,?)`,
      [Number(userId), page, perm.view ? 1 : 0, perm.edit ? 1 : 0]
    );
  }
  return normalized;
}

function canAccessType(auth, type, action = "edit") {
  if (auth?.role === "Admin") return true;
  const map = {
    orders: "orders",
    dispatch: "dispatch",
    payments: "payments",
    delivery: "delivery",
    dealers: "dealers",
    employees: "employees",
    products: "products",
    transporters: "transporters",
  };
  const page = map[type];
  if (!page) return false;
  const perms = auth?.permissions?.[page];
  return action === "view" ? Boolean(perms?.view) : Boolean(perms?.edit);
}

async function recordAudit(entry) {
  try {
    await pool.execute(
      `INSERT INTO audit_logs (user_id, username, action_type, entity_type, entity_id, details_json, created_at)
       VALUES (?,?,?,?,?,?,NOW())`,
      [
        Number(entry.userId || 0),
        entry.username || "",
        entry.actionType || "",
        entry.entityType || "",
        entry.entityId || "",
        JSON.stringify(entry.details || {}),
      ]
    );
  } catch (_err) {}
}

async function ensureSecurityTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      user_id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(50) NOT NULL UNIQUE,
      password_hash VARCHAR(255) NOT NULL,
      full_name VARCHAR(100) NOT NULL,
      email VARCHAR(100),
      role ENUM('Admin', 'Staff', 'Viewer', 'RDM', 'ZM', 'Finance', 'Logistics') DEFAULT 'Viewer',
      active_status ENUM('Y','N') DEFAULT 'Y',
      last_login DATETIME,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS edit_locks (
      lock_id INT AUTO_INCREMENT PRIMARY KEY,
      resource_type VARCHAR(50) NOT NULL,
      resource_id VARCHAR(100) NOT NULL,
      user_id INT NOT NULL,
      username VARCHAR(50) NOT NULL,
      acquired_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME NOT NULL,
      UNIQUE KEY uniq_resource_lock (resource_type, resource_id)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_page_permissions (
      permission_id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      page_key VARCHAR(50) NOT NULL,
      can_view TINYINT(1) DEFAULT 0,
      can_edit TINYINT(1) DEFAULT 0,
      UNIQUE KEY uniq_user_page (user_id, page_key)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      audit_id BIGINT AUTO_INCREMENT PRIMARY KEY,
      user_id INT,
      username VARCHAR(50) NOT NULL,
      action_type VARCHAR(50) NOT NULL,
      entity_type VARCHAR(50) NOT NULL,
      entity_id VARCHAR(100),
      details_json LONGTEXT,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_audit_created_at (created_at),
      INDEX idx_audit_user (user_id),
      INDEX idx_audit_entity (entity_type, entity_id)
    )
  `);
  const [rows] = await pool.query("SELECT COUNT(*) AS count FROM users");
  if (Number(rows?.[0]?.count || 0) === 0) {
    const [result] = await pool.execute(
      `INSERT INTO users (username, password_hash, full_name, email, role, active_status)
       VALUES (?,?,?,?,?,?)`,
      ["admin", createPasswordHash("admin123"), "System Administrator", "admin@phoenix.com", "Admin", "Y"]
    );
    await savePermissions(result.insertId, "Admin", defaultPermissionsForRole("Admin"));
  } else {
    const [users] = await pool.execute(`SELECT user_id, role FROM users`);
    for (const user of users) {
      const [countRows] = await pool.execute(`SELECT COUNT(*) AS count FROM user_page_permissions WHERE user_id=?`, [Number(user.user_id)]);
      if (Number(countRows?.[0]?.count || 0) === 0) {
        await savePermissions(user.user_id, user.role || "Viewer", defaultPermissionsForRole(user.role || "Viewer"));
      }
    }
  }
}

async function authRequired(req, res, next) {
  cleanupExpiredSessions();
  const token = readBearerToken(req);
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ ok: false, message: "Login required." });
  }
  const session = sessions.get(token);
  const [rows] = await pool.execute(`SELECT role, active_status FROM users WHERE user_id=? LIMIT 1`, [Number(session.userId)]);
  const userRow = rows?.[0];
  if (!userRow || userRow.active_status !== "Y") {
    sessions.delete(token);
    return res.status(401).json({ ok: false, message: "Session expired." });
  }
  session.role = userRow.role || session.role;
  session.permissions = await loadPermissions(session.userId, session.role);
  session.expiresAt = Date.now() + SESSION_TTL_MS;
  req.auth = sanitizeSession(session);
  req.sessionToken = token;
  return next();
}

function requireRoles(...roles) {
  return (req, res, next) => {
    if (!req.auth) {
      return res.status(401).json({ ok: false, message: "Login required." });
    }
    if (!roles.includes(req.auth.role)) {
      return res.status(403).json({ ok: false, message: "Aapke role ko is action ki permission nahi hai." });
    }
    return next();
  };
}

function getResourceId(type, payload) {
  switch (type) {
    case "orders":
    case "payments":
    case "delivery":
      return String(payload.id ?? "");
    case "dispatch":
      return String(payload.invoice ?? "");
    case "dealers":
    case "employees":
    case "products":
    case "transporters":
    case "users":
      return String(payload.id ?? payload.userId ?? "");
    default:
      return "";
  }
}

function canWriteType(role, type) {
  if (role === "Admin") return true;
  if (role === "Staff") {
    return ["orders", "dispatch", "payments", "delivery"].includes(type);
  }
  return false;
}

async function cleanupExpiredLocks() {
  await pool.execute("DELETE FROM edit_locks WHERE expires_at <= NOW()");
}

async function userOwnsLock(resourceType, resourceId, userId) {
  if (!resourceType || !resourceId) return false;
  await cleanupExpiredLocks();
  const [rows] = await pool.execute(
    `SELECT lock_id FROM edit_locks WHERE resource_type=? AND resource_id=? AND user_id=? LIMIT 1`,
    [resourceType, resourceId, Number(userId)]
  );
  return Boolean(rows?.length);
}

async function releaseLock(resourceType, resourceId, userId) {
  if (!resourceType || !resourceId || !userId) return;
  await pool.execute(
    `DELETE FROM edit_locks WHERE resource_type=? AND resource_id=? AND user_id=?`,
    [resourceType, resourceId, Number(userId)]
  );
}

async function readPendingQueue() {
  try {
    const raw = await fs.readFile(PENDING_FILE, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function writePendingQueue(items) {
  await fs.writeFile(PENDING_FILE, JSON.stringify(items, null, 2), "utf8");
}

async function enqueuePendingSave(body, reason) {
  const queue = await readPendingQueue();
  const item = {
    queueId: Date.now(),
    createdAt: new Date().toISOString(),
    reason: reason || "DB unavailable",
    body,
  };
  queue.push(item);
  await writePendingQueue(queue);
  return item;
}

app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const username = text(req.body?.username).toLowerCase();
    const password = String(req.body?.password || "");
    if (!username || !password) {
      return res.status(400).json({ ok: false, message: "Username aur password required hain." });
    }
    const [rows] = await pool.execute(
      `SELECT user_id, username, password_hash, full_name, email, role, active_status
       FROM users WHERE username=? LIMIT 1`,
      [username]
    );
    const user = rows?.[0];
    if (!user || user.active_status !== "Y" || !verifyPassword(password, user.password_hash)) {
      return res.status(401).json({ ok: false, message: "Invalid login details." });
    }
    if (user.password_hash === LEGACY_ADMIN_HASH) {
      await pool.execute(`UPDATE users SET password_hash=? WHERE user_id=?`, [createPasswordHash(password), Number(user.user_id)]);
    }
    await pool.execute(`UPDATE users SET last_login=NOW() WHERE user_id=?`, [Number(user.user_id)]);
    user.permissions = await loadPermissions(user.user_id, user.role || "Viewer");
    const token = createSession(user);
    return res.json({ ok: true, token, user: { userId: Number(user.user_id), username: user.username, fullName: user.full_name, role: user.role, permissions: user.permissions } });
  } catch (err) {
    return res.status(500).json({ ok: false, message: "Login failed.", error: err.message });
  }
});

app.get("/api/auth/me", authRequired, async (req, res) => {
  res.json({ ok: true, user: req.auth });
});

app.post("/api/auth/logout", authRequired, async (req, res) => {
  sessions.delete(req.sessionToken);
  res.json({ ok: true });
});

app.post("/api/auth/change-password", authRequired, async (req, res) => {
  try {
    const currentPassword = String(req.body?.currentPassword || "");
    const newPassword = String(req.body?.newPassword || "");
    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({ ok: false, message: "New password minimum 6 characters ka hona chahiye." });
    }
    const [rows] = await pool.execute(
      `SELECT password_hash FROM users WHERE user_id=? LIMIT 1`,
      [Number(req.auth.userId)]
    );
    const user = rows?.[0];
    if (!user || !verifyPassword(currentPassword, user.password_hash)) {
      return res.status(400).json({ ok: false, message: "Current password match nahi hua." });
    }
    await pool.execute(`UPDATE users SET password_hash=? WHERE user_id=?`, [createPasswordHash(newPassword), Number(req.auth.userId)]);
    await recordAudit({
      userId: req.auth.userId,
      username: req.auth.username,
      actionType: "change_password",
      entityType: "users",
      entityId: String(req.auth.userId),
      details: { bySelf: true },
    });
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ ok: false, message: "Password change failed.", error: err.message });
  }
});

app.get("/api/users", authRequired, requireRoles("Admin"), async (_req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT user_id, username, full_name, email, role, active_status, last_login, created_at
       FROM users ORDER BY username ASC`
    );
    const enriched = [];
    for (const row of rows) {
      enriched.push({
        ...row,
        permissions: await loadPermissions(row.user_id, row.role || "Viewer"),
      });
    }
    res.json({ ok: true, rows: enriched });
  } catch (err) {
    res.status(500).json({ ok: false, message: "Users load failed.", error: err.message });
  }
});

app.post("/api/users", authRequired, requireRoles("Admin"), async (req, res) => {
  try {
    const mode = text(req.body?.mode || "add");
    const payload = req.body?.payload || {};
    if (mode === "delete") {
      const userId = Number(payload.userId || payload.id || 0);
      if (!userId) return res.status(400).json({ ok: false, message: "User id required." });
      if (userId === Number(req.auth.userId)) {
        return res.status(400).json({ ok: false, message: "Apna khud ka admin account delete nahi kar sakte." });
      }
      await pool.execute(`DELETE FROM users WHERE user_id=?`, [userId]);
      await pool.execute(`DELETE FROM user_page_permissions WHERE user_id=?`, [userId]);
      await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "delete", entityType: "users", entityId: String(userId), details: { deletedUserId: userId } });
      return res.json({ ok: true, mode });
    }
    const username = text(payload.username).toLowerCase();
    const fullName = text(payload.fullName);
    const email = text(payload.email);
    const role = text(payload.role || "Staff") || "Staff";
    const active = text(payload.active || "Y") || "Y";
    const permissions = normalizePermissions(payload.permissions, role);
    if (!username || !fullName) {
      return res.status(400).json({ ok: false, message: "Username aur full name required hain." });
    }
    if (mode === "edit") {
      const userId = Number(payload.userId || payload.id || 0);
      if (!userId) return res.status(400).json({ ok: false, message: "User id required." });
      if (text(payload.password)) {
        await pool.execute(
          `UPDATE users SET username=?, full_name=?, email=?, role=?, active_status=?, password_hash=? WHERE user_id=?`,
          [username, fullName, email || null, role, active, createPasswordHash(payload.password), userId]
        );
      } else {
        await pool.execute(
          `UPDATE users SET username=?, full_name=?, email=?, role=?, active_status=? WHERE user_id=?`,
          [username, fullName, email || null, role, active, userId]
        );
      }
      await savePermissions(userId, role, permissions);
      await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "edit", entityType: "users", entityId: String(userId), details: { username, role, active, permissions } });
      return res.json({ ok: true, mode, userId });
    }
    if (!text(payload.password)) {
      return res.status(400).json({ ok: false, message: "New user ke liye password required hai." });
    }
    const [result] = await pool.execute(
      `INSERT INTO users (username, password_hash, full_name, email, role, active_status)
       VALUES (?,?,?,?,?,?)`,
      [username, createPasswordHash(payload.password), fullName, email || null, role, active]
    );
    await savePermissions(result.insertId, role, permissions);
    await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "add", entityType: "users", entityId: String(result.insertId), details: { username, role, active, permissions } });
    return res.json({ ok: true, mode, userId: result.insertId });
  } catch (err) {
    res.status(500).json({ ok: false, message: "User save failed.", error: err.message });
  }
});

app.post("/api/locks/acquire", authRequired, async (req, res) => {
  try {
    const resourceType = text(req.body?.resourceType);
    const resourceId = text(req.body?.resourceId);
    if (!resourceType || !resourceId) {
      return res.status(400).json({ ok: false, message: "resourceType aur resourceId required hain." });
    }
    await cleanupExpiredLocks();
    const [rows] = await pool.execute(
      `SELECT lock_id, user_id, username, expires_at
       FROM edit_locks WHERE resource_type=? AND resource_id=? LIMIT 1`,
      [resourceType, resourceId]
    );
    const lock = rows?.[0];
    const expiresAt = new Date(Date.now() + LOCK_TTL_SECONDS * 1000);
    if (lock && Number(lock.user_id) !== Number(req.auth.userId)) {
      return res.status(409).json({
        ok: false,
        message: `Ye record abhi ${lock.username} edit kar raha hai.`,
        lock: { username: lock.username, expiresAt: lock.expires_at },
      });
    }
    if (lock) {
      await pool.execute(`UPDATE edit_locks SET expires_at=? WHERE lock_id=?`, [expiresAt, Number(lock.lock_id)]);
    } else {
      await pool.execute(
        `INSERT INTO edit_locks (resource_type, resource_id, user_id, username, expires_at)
         VALUES (?,?,?,?,?)`,
        [resourceType, resourceId, Number(req.auth.userId), req.auth.username, expiresAt]
      );
    }
    return res.json({ ok: true, resourceType, resourceId, expiresAt: expiresAt.toISOString(), username: req.auth.username });
  } catch (err) {
    return res.status(500).json({ ok: false, message: "Lock acquire failed.", error: err.message });
  }
});

app.post("/api/locks/release", authRequired, async (req, res) => {
  try {
    await releaseLock(text(req.body?.resourceType), text(req.body?.resourceId), req.auth.userId);
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ ok: false, message: "Lock release failed.", error: err.message });
  }
});

app.get("/api/audit", authRequired, requireRoles("Admin"), async (req, res) => {
  try {
    const limit = Math.min(200, Math.max(1, Number(req.query.limit || 100)));
    const [rows] = await pool.execute(
      `SELECT audit_id, user_id, username, action_type, entity_type, entity_id, details_json, created_at
       FROM audit_logs ORDER BY audit_id DESC LIMIT ${limit}`
    );
    res.json({ ok: true, rows });
  } catch (err) {
    res.status(500).json({ ok: false, message: "Audit logs load failed.", error: err.message });
  }
});

app.get("/api/dashboard", authRequired, async (_req, res) => {
  try {
    const [rows] = await pool.execute("SELECT * FROM recovery_aging_view");
    res.json({ ok: true, rows });
  } catch (err) {
    res.status(500).json({ ok: false, message: "Query failed.", error: err.message });
  }
});

app.get("/api/db-status", authRequired, async (_req, res) => {
  try {
    await pool.query("SELECT 1 AS ok");
    res.json({ ok: true, db: "connected" });
  } catch (err) {
    res.status(503).json({ ok: false, db: "down", error: err.message });
  }
});

app.get("/api/pending", authRequired, requireRoles("Admin"), async (_req, res) => {
  const items = await readPendingQueue();
  res.json({ ok: true, count: items.length, items });
});

app.get("/api/runtime-config", async (_req, res) => {
  res.json({
    ok: true,
    host: HOST,
    port: PORT,
    localUrl: `http://localhost:${PORT}`,
    lanUrls: getLanUrls(),
    multiUserReady: true,
    message: "Open the CRM from one shared server URL so all members work on the same database.",
  });
});

app.get("/api/bootstrap", authRequired, async (_req, res) => {
  try {
    const [
      ordersRows,
      dispatchRows,
      paymentsRows,
      deliveryRows,
      dealersRows,
      employeesRows,
      productsRows,
      transportersRows,
      recoveryRows,
    ] = await Promise.all([
      pool.execute("SELECT * FROM orders ORDER BY order_id ASC"),
      pool.execute("SELECT * FROM dispatch ORDER BY dispatch_id ASC"),
      pool.execute("SELECT * FROM payments ORDER BY payment_id ASC"),
      pool.execute("SELECT * FROM delivery_proof ORDER BY proof_id ASC"),
      pool.execute("SELECT * FROM dealers ORDER BY dealer_id ASC"),
      pool.execute("SELECT * FROM employees ORDER BY emp_id ASC"),
      pool.execute("SELECT * FROM products ORDER BY product_id ASC"),
      pool.execute("SELECT * FROM transporters ORDER BY transporter_id ASC"),
      pool.execute("SELECT * FROM recovery_aging_view"),
    ]);

    const orders = ordersRows[0].map((r) => ({
      id: Number(r.order_id),
      date: r.order_date ? String(r.order_date).slice(0, 10) : "",
      dealer: r.dealer_name || "",
      dealerId: r.dealer_id || "",
      rdm: r.rdm_name || "",
      product: r.product_name || "",
      qty: Number(r.quantity || 0),
      rate: Number(r.rate || 0),
      amount: Number(r.amount || 0),
      payType: r.payment_type || "Credit",
      dueDate: r.due_date ? String(r.due_date).slice(0, 10) : "",
      payStatus: r.payment_status || "Pending",
      orderStatus: r.order_status || "Pending",
      notes: r.notes || "",
      received: Number(r.received_amount || 0),
      outstanding: Number(r.outstanding_amount || 0),
      deliveredQty: Number(r.delivered_quantity || 0),
      pendingQty: Number(r.pending_quantity || 0),
    }));

    const dispatch = dispatchRows[0].map((r) => ({
      invoice: r.invoice_no || "",
      orderId: Number(r.order_id || 0),
      date: r.dispatch_date ? String(r.dispatch_date).slice(0, 10) : "",
      status: r.status || "Dispatched",
      vehicle: r.vehicle_no || "",
      qty: Number(r.quantity || 0),
      transporter: r.transporter_name || "",
      driver: r.driver_name || "",
      driverPhone: r.driver_phone || "",
      lr: r.lr_number || "",
      eway: r.eway_bill_no || "",
      remarks: r.remarks || "",
    }));

    const payments = paymentsRows[0].map((r) => ({
      id: Number(r.payment_id),
      orderId: Number(r.order_id || 0),
      dealer: r.dealer_name || "",
      amount: Number(r.amount || 0),
      mode: r.payment_mode || "NEFT/RTGS",
      date: r.payment_date ? String(r.payment_date).slice(0, 10) : "",
      ref: r.reference_no || "",
      status: r.status || "Paid",
      notes: r.notes || "",
      rdm: r.rdm_name || "",
      incentive: Number(r.rdm_incentive || 0),
    }));

    const delivery = deliveryRows[0].map((r) => ({
      id: Number(r.proof_id),
      orderId: Number(r.order_id || 0),
      dispatchInvoice: "",
      dealer: r.dealer_name || "",
      deliveredQty: Number(r.delivered_quantity || 0),
      date: r.delivery_date ? String(r.delivery_date).slice(0, 10) : "",
      receiver: r.receiver_name || "",
      proofUrl: r.proof_image_url || "",
      status: r.verified_status || "Pending",
      remarks: r.remarks || "",
    }));

    const dealers = dealersRows[0].map((r) => ({
      id: r.dealer_id || "",
      name: r.dealer_name || "",
      phone: r.phone || "",
      address: r.address || "",
      district: r.district || "",
      state: r.state || "",
      credit: Number(r.credit_limit || 0),
      active: r.active_status || "Y",
    }));

    const employees = employeesRows[0].map((r) => ({
      id: r.emp_id || "",
      name: r.emp_name || "",
      role: r.role || "RDM",
      phone: r.phone || "",
      region: r.region || "",
      zm: "",
      active: r.active_status || "Y",
    }));

    const products = productsRows[0].map((r) => ({
      id: r.product_id || "",
      name: r.product_name || "",
      category: r.category || "",
      unit: r.unit || "Bags",
      mrp: Number(r.mrp || 0),
      rate: Number(r.rate || 0),
      gst: Number(r.gst_percent || 0),
      active: r.active_status || "Y",
    }));

    const transporters = transportersRows[0].map((r) => ({
      id: r.transporter_id || "",
      name: r.transporter_name || "",
      phone: r.phone || "",
      city: r.city || "",
      notes: r.address || "",
      active: r.active_status || "Y",
    }));

    const recovery = recoveryRows[0].map((r) => ({
      dealer: r.dealer_name || "",
      phone: r.phone || "",
      totalDue: Number(r.total_due || 0),
      notDue: 0,
      d0_7: Number(r.due_0_7_days || 0),
      d8_15: Number(r.due_8_15_days || 0),
      d16_30: Number(r.due_16_30_days || 0),
      d31plus: Number(r.due_31_plus_days || 0),
      reminderType: r.reminder_type || "Not Set",
      reminderStatus: r.reminder_status || "Not Sent",
    }));

    res.json({
      ok: true,
      syncedAt: new Date().toISOString(),
      data: { orders, dispatch, payments, delivery, dealers, employees, products, transporters, recovery },
    });
  } catch (err) {
    res.status(500).json({ ok: false, message: "Bootstrap failed.", error: err.message });
  }
});

app.post("/api/save", authRequired, async (req, res) => {
  const { type = "", mode = "add", payload = {} } = req.body || {};
  let conn = null;

  try {
    conn = await pool.getConnection();
    if (!type) {
      return res.status(400).json({ ok: false, message: "type is required" });
    }
    if (!canAccessType(req.auth, type, "edit")) {
      return res.status(403).json({ ok: false, message: "Aapke role ko is module me changes ki permission nahi hai." });
    }
    const resourceId = getResourceId(type, payload);
    if ((mode === "edit" || mode === "delete") && resourceId) {
      const ownsLock = await userOwnsLock(type, resourceId, req.auth.userId);
      if (!ownsLock) {
        return res.status(409).json({ ok: false, message: "Record lock missing hai. Pehle edit lock acquire karein." });
      }
    }

    switch (type) {
      case "orders": {
        const dealerName = text(payload.dealer);
        const rdmName = text(payload.rdm);
        const productName = text(payload.product);
        const dealerId = await findIdByName(conn, "dealers", "dealer_id", "dealer_name", dealerName);
        const rdmId = await findIdByName(conn, "employees", "emp_id", "emp_name", rdmName);
        const productId = await findIdByName(conn, "products", "product_id", "product_name", productName);

        if (mode === "delete") {
          await conn.execute(`DELETE FROM orders WHERE order_id=?`, [Number(payload.id || 0)]);
          await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "delete", entityType: type, entityId: String(payload.id || ""), details: { mode } });
          return res.json({ ok: true, type, mode });
        }
        if (mode === "edit") {
          await conn.execute(
            `UPDATE orders
             SET order_date=?, dealer_id=?, dealer_name=?, rdm_id=?, rdm_name=?, product_id=?, product_name=?,
                 quantity=?, rate=?, amount=?, payment_type=?, due_date=?, notes=?, pending_quantity=?
             WHERE order_id=?`,
            [
              payload.date || null, dealerId, dealerName, rdmId, rdmName, productId, productName,
              Number(payload.qty || 0), Number(payload.rate || 0), Number(payload.amount || 0),
              payload.payType || "Credit", payload.dueDate || null, payload.notes || "", Number(payload.pendingQty || 0),
              Number(payload.id || 0),
            ]
          );
          await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "edit", entityType: type, entityId: String(payload.id || ""), details: payload });
        } else {
          const [result] = await conn.execute(
            `INSERT INTO orders
             (order_date,dealer_id,dealer_name,rdm_id,rdm_name,product_id,product_name,quantity,rate,amount,payment_type,due_date,payment_status,order_status,notes,received_amount,outstanding_amount,delivered_quantity,pending_quantity,created_by)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
            [
              payload.date || null, dealerId, dealerName, rdmId, rdmName, productId, productName,
              Number(payload.qty || 0), Number(payload.rate || 0), Number(payload.amount || 0),
              payload.payType || "Credit", payload.dueDate || null, payload.payStatus || "Pending", payload.orderStatus || "Pending",
              payload.notes || "", Number(payload.received || 0), Number(payload.outstanding || 0),
              Number(payload.deliveredQty || 0), Number(payload.pendingQty || 0), req.auth.username,
            ]
          );
          await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "add", entityType: type, entityId: String(result.insertId), details: payload });
          return res.json({ ok: true, type, mode, insert_id: result.insertId });
        }
        return res.json({ ok: true, type, mode });
      }

      case "dispatch": {
        const transporterName = text(payload.transporter);
        const transporterId = await findIdByName(conn, "transporters", "transporter_id", "transporter_name", transporterName);
        if (mode === "delete") {
          await conn.execute(`DELETE FROM dispatch WHERE invoice_no=?`, [text(payload.invoice)]);
          await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "delete", entityType: type, entityId: String(payload.invoice || ""), details: { mode } });
          return res.json({ ok: true, type, mode });
        }
        if (mode === "edit") {
          await conn.execute(
            `UPDATE dispatch
             SET order_id=?, dispatch_date=?, status=?, vehicle_no=?, quantity=?, transporter_id=?, transporter_name=?, driver_name=?, driver_phone=?, lr_number=?, eway_bill_no=?, remarks=?
             WHERE invoice_no=?`,
            [
              Number(payload.orderId || 0), payload.date || null, payload.status || "Dispatched", payload.vehicle || "",
              Number(payload.qty || 0), transporterId, transporterName, payload.driver || "", payload.driverPhone || "",
              text(payload.lr), text(payload.eway), payload.remarks || "", text(payload.invoice),
            ]
          );
          await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "edit", entityType: type, entityId: String(payload.invoice || ""), details: payload });
          return res.json({ ok: true, type, mode });
        }
        const [result] = await conn.execute(
          `INSERT INTO dispatch
           (order_id,invoice_no,dispatch_date,status,vehicle_no,quantity,transporter_id,transporter_name,driver_name,driver_phone,lr_number,eway_bill_no,remarks,created_by)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
          [
            Number(payload.orderId || 0), text(payload.invoice), payload.date || null, payload.status || "Dispatched", payload.vehicle || "",
            Number(payload.qty || 0), transporterId, transporterName, payload.driver || "", payload.driverPhone || "",
            text(payload.lr), text(payload.eway), payload.remarks || "", req.auth.username,
          ]
        );
        await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "add", entityType: type, entityId: String(payload.invoice || result.insertId || ""), details: payload });
        return res.json({ ok: true, type, mode, insert_id: result.insertId });
      }

      case "payments": {
        const dealerName = text(payload.dealer);
        const rdmName = text(payload.rdm);
        const dealerId = await findIdByName(conn, "dealers", "dealer_id", "dealer_name", dealerName);
        const rdmId = await findIdByName(conn, "employees", "emp_id", "emp_name", rdmName);
        const zmIncentive = Number(payload.incentive || 0) / 2;
        if (mode === "delete") {
          await conn.execute(`DELETE FROM payments WHERE payment_id=?`, [Number(payload.id || 0)]);
          await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "delete", entityType: type, entityId: String(payload.id || ""), details: { mode } });
          return res.json({ ok: true, type, mode });
        }
        if (mode === "edit") {
          await conn.execute(
            `UPDATE payments
             SET order_id=?, dealer_id=?, dealer_name=?, rdm_id=?, rdm_name=?, amount=?, payment_mode=?, payment_date=?, reference_no=?, rdm_incentive=?, zm_incentive=?, status=?, notes=?
             WHERE payment_id=?`,
            [
              Number(payload.orderId || 0), dealerId, dealerName, rdmId, rdmName, Number(payload.amount || 0),
              payload.mode || "NEFT/RTGS", payload.date || null, text(payload.ref), Number(payload.incentive || 0), zmIncentive,
              payload.status || "Paid", payload.notes || "", Number(payload.id || 0),
            ]
          );
          await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "edit", entityType: type, entityId: String(payload.id || ""), details: payload });
          return res.json({ ok: true, type, mode });
        }
        const [result] = await conn.execute(
          `INSERT INTO payments
           (order_id,dealer_id,dealer_name,rdm_id,rdm_name,amount,payment_mode,payment_date,reference_no,rdm_incentive,zm_incentive,status,notes,created_by)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
          [
            Number(payload.orderId || 0), dealerId, dealerName, rdmId, rdmName, Number(payload.amount || 0),
            payload.mode || "NEFT/RTGS", payload.date || null, text(payload.ref), Number(payload.incentive || 0), zmIncentive,
            payload.status || "Paid", payload.notes || "", req.auth.username,
          ]
        );
        await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "add", entityType: type, entityId: String(result.insertId), details: payload });
        return res.json({ ok: true, type, mode, insert_id: result.insertId });
      }

      case "delivery": {
        const dealerName = text(payload.dealer);
        const dealerId = await findIdByName(conn, "dealers", "dealer_id", "dealer_name", dealerName);
        let dispatchId = null;
        if (text(payload.dispatchInvoice)) {
          const [rows] = await conn.execute("SELECT dispatch_id FROM dispatch WHERE invoice_no = ? LIMIT 1", [text(payload.dispatchInvoice)]);
          dispatchId = rows?.[0]?.dispatch_id ?? null;
        }
        if (mode === "delete") {
          await conn.execute(`DELETE FROM delivery_proof WHERE proof_id=?`, [Number(payload.id || 0)]);
          await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "delete", entityType: type, entityId: String(payload.id || ""), details: { mode } });
          return res.json({ ok: true, type, mode });
        }
        if (mode === "edit") {
          await conn.execute(
            `UPDATE delivery_proof
             SET order_id=?, dispatch_id=?, dealer_id=?, dealer_name=?, delivered_quantity=?, delivery_date=?, proof_image_url=?, receiver_name=?, verified_status=?, remarks=?
             WHERE proof_id=?`,
            [
              Number(payload.orderId || 0), dispatchId, dealerId, dealerName, Number(payload.deliveredQty || 0),
              payload.date || null, payload.proofUrl || "", payload.receiver || "", payload.status || "Pending", payload.remarks || "",
              Number(payload.id || 0),
            ]
          );
          await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "edit", entityType: type, entityId: String(payload.id || ""), details: payload });
          return res.json({ ok: true, type, mode });
        }
        const [result] = await conn.execute(
          `INSERT INTO delivery_proof
           (order_id,dispatch_id,dealer_id,dealer_name,delivered_quantity,delivery_date,proof_image_url,receiver_name,verified_status,remarks,verified_by)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
          [
            Number(payload.orderId || 0), dispatchId, dealerId, dealerName, Number(payload.deliveredQty || 0),
            payload.date || null, payload.proofUrl || "", payload.receiver || "", payload.status || "Pending", payload.remarks || "", req.auth.username,
          ]
        );
        await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "add", entityType: type, entityId: String(result.insertId), details: payload });
        return res.json({ ok: true, type, mode, insert_id: result.insertId });
      }

      case "dealers": {
        if (mode === "delete") {
          await conn.execute(`DELETE FROM dealers WHERE dealer_id=?`, [payload.id || ""]);
          await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "delete", entityType: type, entityId: String(payload.id || ""), details: { mode } });
          return res.json({ ok: true, type, mode });
        }
        if (mode === "edit") {
          await conn.execute(
            `UPDATE dealers SET dealer_name=?, phone=?, district=?, state=?, address=?, credit_limit=?, active_status=? WHERE dealer_id=?`,
            [payload.name || "", payload.phone || "", payload.district || "", payload.state || "HARYANA", payload.address || "", Number(payload.credit || 0), payload.active || "Y", payload.id || ""]
          );
          await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "edit", entityType: type, entityId: String(payload.id || ""), details: payload });
          return res.json({ ok: true, type, mode });
        }
        await conn.execute(
          `INSERT INTO dealers (dealer_id,dealer_name,phone,address,district,state,credit_limit,active_status,created_by)
           VALUES (?,?,?,?,?,?,?,?,?)`,
          [payload.id || "", payload.name || "", payload.phone || "", payload.address || "", payload.district || "", payload.state || "HARYANA", Number(payload.credit || 0), payload.active || "Y", req.auth.username]
        );
        await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "add", entityType: type, entityId: String(payload.id || ""), details: payload });
        return res.json({ ok: true, type, mode });
      }

      case "employees": {
        if (mode === "delete") {
          await conn.execute(`DELETE FROM employees WHERE emp_id=?`, [payload.id || ""]);
          await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "delete", entityType: type, entityId: String(payload.id || ""), details: { mode } });
          return res.json({ ok: true, type, mode });
        }
        if (mode === "edit") {
          await conn.execute(
            `UPDATE employees SET emp_name=?, role=?, phone=?, region=?, active_status=? WHERE emp_id=?`,
            [payload.name || "", payload.role || "RDM", payload.phone || "", payload.region || "", payload.active || "Y", payload.id || ""]
          );
          await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "edit", entityType: type, entityId: String(payload.id || ""), details: payload });
          return res.json({ ok: true, type, mode });
        }
        await conn.execute(
          `INSERT INTO employees (emp_id,emp_name,role,phone,region,active_status) VALUES (?,?,?,?,?,?)`,
          [payload.id || "", payload.name || "", payload.role || "RDM", payload.phone || "", payload.region || "", payload.active || "Y"]
        );
        await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "add", entityType: type, entityId: String(payload.id || ""), details: payload });
        return res.json({ ok: true, type, mode });
      }

      case "products": {
        if (mode === "delete") {
          await conn.execute(`DELETE FROM products WHERE product_id=?`, [payload.id || ""]);
          await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "delete", entityType: type, entityId: String(payload.id || ""), details: { mode } });
          return res.json({ ok: true, type, mode });
        }
        if (mode === "edit") {
          await conn.execute(
            `UPDATE products SET product_name=?, category=?, unit=?, mrp=?, rate=?, gst_percent=?, active_status=? WHERE product_id=?`,
            [payload.name || "", payload.category || "", payload.unit || "Bags", Number(payload.mrp || 0), Number(payload.rate || 0), Number(payload.gst || 5), payload.active || "Y", payload.id || ""]
          );
          await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "edit", entityType: type, entityId: String(payload.id || ""), details: payload });
          return res.json({ ok: true, type, mode });
        }
        await conn.execute(
          `INSERT INTO products (product_id,product_name,category,unit,mrp,rate,gst_percent,active_status) VALUES (?,?,?,?,?,?,?,?)`,
          [payload.id || "", payload.name || "", payload.category || "", payload.unit || "Bags", Number(payload.mrp || 0), Number(payload.rate || 0), Number(payload.gst || 5), payload.active || "Y"]
        );
        await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "add", entityType: type, entityId: String(payload.id || ""), details: payload });
        return res.json({ ok: true, type, mode });
      }

      case "transporters": {
        if (mode === "delete") {
          await conn.execute(`DELETE FROM transporters WHERE transporter_id=?`, [payload.id || ""]);
          await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "delete", entityType: type, entityId: String(payload.id || ""), details: { mode } });
          return res.json({ ok: true, type, mode });
        }
        if (mode === "edit") {
          await conn.execute(
            `UPDATE transporters SET transporter_name=?, phone=?, city=?, address=?, active_status=? WHERE transporter_id=?`,
            [payload.name || "", payload.phone || "", payload.city || "", payload.notes || "", payload.active || "Y", payload.id || ""]
          );
          await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "edit", entityType: type, entityId: String(payload.id || ""), details: payload });
          return res.json({ ok: true, type, mode });
        }
        await conn.execute(
          `INSERT INTO transporters (transporter_id,transporter_name,phone,city,address,active_status) VALUES (?,?,?,?,?,?)`,
          [payload.id || "", payload.name || "", payload.phone || "", payload.city || "", payload.notes || "", payload.active || "Y"]
        );
        await recordAudit({ userId: req.auth.userId, username: req.auth.username, actionType: "add", entityType: type, entityId: String(payload.id || ""), details: payload });
        return res.json({ ok: true, type, mode });
      }

      default:
        return res.status(400).json({ ok: false, message: `Unsupported save type: ${type}` });
    }
  } catch (err) {
    if (isDbUnavailableError(err)) {
      const queued = await enqueuePendingSave({ type, mode, payload }, err.message);
      return res.status(202).json({
        ok: true,
        queued: true,
        message: "Database unavailable. Saved in pending queue.",
        queueId: queued.queueId,
      });
    }
    return res.status(500).json({ ok: false, message: "Database write failed.", error: err.message });
  } finally {
    if (conn) conn.release();
  }
});

ensureSecurityTables()
  .then(() => {
    app.listen(PORT, HOST, () => {
      console.log(`CRM server running on http://localhost:${PORT}`);
      console.log(`Default admin login: admin / admin123`);
      const lanUrls = getLanUrls();
      if (lanUrls.length) {
        console.log(`LAN access URLs: ${lanUrls.join(", ")}`);
      }
    });
  })
  .catch((err) => {
    console.error("Security table setup failed:", err.message);
    process.exit(1);
  });
