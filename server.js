
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const path = require("path");

const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use(session({
  store: new PgSession({
    pool,
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET || "change-this-secret",
resave: false,
saveUninitialized: false,
proxy: true,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 8
  }
}));

async function setup() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS admins (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS packages (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      amount NUMERIC(12,2) NOT NULL,
      description TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  const email = process.env.ADMIN_EMAIL;
  const password = process.env.ADMIN_PASSWORD;

  if (!email || !password) {
    console.log("Admin credentials have not been configured.");
    return;
  }

  const existing = await pool.query(
    "SELECT id FROM admins WHERE email = $1",
    [email]
  );

  if (existing.rowCount === 0) {
    const hash = await bcrypt.hash(password, 12);
    await pool.query(
      "INSERT INTO admins (email, password) VALUES ($1, $2)",
      [email, hash]
    );
    console.log("Admin account created.");
  }
}

function requireAdmin(req, res, next) {
  if (!req.session.adminId) {
    return res.status(401).json({ error: "Please log in as admin." });
  }
  next();
}

app.post("/api/admin/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query(
      "SELECT * FROM admins WHERE email = $1",
      [email]
    );

    if (!result.rowCount ||
        !(await bcrypt.compare(password, result.rows[0].password))) {
      return res.status(401).json({ error: "Invalid login details." });
    }

    req.session.adminId = result.rows[0].id;
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: "Login failed." });
  }
});

app.post("/api/admin/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.get("/api/admin/me", (req, res) => {
  res.json({ loggedIn: Boolean(req.session.adminId) });
});

app.get("/api/packages", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name, amount, description FROM packages ORDER BY id"
    );
    res.json(result.rows);
  } catch {
    res.status(500).json({ error: "Could not load packages." });
  }
});

app.post("/api/admin/packages", requireAdmin, async (req, res) => {
  try {
    const { name, amount, description } = req.body;
    const price = Number(amount);

    if (!name || !Number.isFinite(price) || price <= 0) {
      return res.status(400).json({ error: "Enter a package name and valid amount." });
    }

    const result = await pool.query(
      "INSERT INTO packages (name, amount, description) VALUES ($1, $2, $3) RETURNING *",
      [name.trim(), price, description || ""]
    );
    res.json(result.rows[0]);
  } catch {
    res.status(500).json({ error: "Could not create package." });
  }
});

app.put("/api/admin/packages/:id", requireAdmin, async (req, res) => {
  try {
    const { name, amount, description } = req.body;
    const price = Number(amount);

    if (!name || !Number.isFinite(price) || price <= 0) {
      return res.status(400).json({ error: "Enter a package name and valid amount." });
    }

    const result = await pool.query(
      "UPDATE packages SET name = $1, amount = $2, description = $3 WHERE id = $4 RETURNING *",
      [name.trim(), price, description || "", req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Package not found." });
    }

    res.json(result.rows[0]);
  } catch {
    res.status(500).json({ error: "Could not update package." });
  }
});

app.delete("/api/admin/packages/:id", requireAdmin, async (req, res) => {
  try {
    await pool.query("DELETE FROM packages WHERE id = $1", [req.params.id]);
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: "Could not delete package." });
  }
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PORT = process.env.PORT || 3000;

setup()
  .then(() => app.listen(PORT, () => {
    console.log(`G TOP running on port ${PORT}`);
  }))
  .catch(error => {
    console.error("Startup error:", error);
    process.exit(1);
  });
