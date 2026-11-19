require("dotenv").config();

const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.set("trust proxy", 1);

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is required.");
  process.exit(1);
}
if (process.env.NODE_ENV === "production" &&
    (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) {
  console.error("Set a SESSION_SECRET of at least 32 characters.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "30kb" }));
app.use(express.urlencoded({ extended: false, limit: "30kb" }));
app.use(session({
  store: new PgSession({ pool, createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || "local-development-only-change-this-secret",
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

const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const emailOk = value => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || "").trim());
const money = value => Number.isFinite(Number(value)) && Number(value) > 0;
const clean = value => String(value || "").trim();

async function setup() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS admins (
      id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS customers (
      id SERIAL PRIMARY KEY, first_name TEXT NOT NULL, last_name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL, phone TEXT UNIQUE NOT NULL, country TEXT NOT NULL,
      password TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS plans (
      id SERIAL PRIMARY KEY, name TEXT NOT NULL UNIQUE,
      min_amount NUMERIC(14,2) NOT NULL, max_amount NUMERIC(14,2) NOT NULL,
      description TEXT DEFAULT '', active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS deposits (
      id SERIAL PRIMARY KEY, customer_id INTEGER NOT NULL REFERENCES customers(id),
      amount NUMERIC(14,2) NOT NULL, network TEXT NOT NULL,
      reference TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
      admin_note TEXT DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS investments (
      id SERIAL PRIMARY KEY, customer_id INTEGER NOT NULL REFERENCES customers(id),
      plan_id INTEGER NOT NULL REFERENCES plans(id), amount NUMERIC(14,2) NOT NULL,
      duration_days INTEGER NOT NULL CHECK(duration_days BETWEEN 4 AND 14),
      status TEXT NOT NULL DEFAULT 'active', started_at TIMESTAMPTZ DEFAULT NOW(),
      ends_at TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE IF NOT EXISTS performance (
      id SERIAL PRIMARY KEY, investment_id INTEGER NOT NULL REFERENCES investments(id),
      amount NUMERIC(14,2) NOT NULL, note TEXT NOT NULL,
      recorded_by INTEGER NOT NULL REFERENCES admins(id), created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS withdrawals (
      id SERIAL PRIMARY KEY, customer_id INTEGER NOT NULL REFERENCES customers(id),
      amount NUMERIC(14,2) NOT NULL, network TEXT NOT NULL,
      destination TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
      admin_note TEXT DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY, customer_id INTEGER NOT NULL REFERENCES customers(id),
      kind TEXT NOT NULL, amount NUMERIC(14,2) NOT NULL,
      reference TEXT NOT NULL, note TEXT DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
      id SERIAL PRIMARY KEY, actor_type TEXT NOT NULL, actor_id INTEGER,
      action TEXT NOT NULL, details TEXT DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY, value TEXT NOT NULL
    );
  `);

  const defaults = [
    ["Bronze", 50, 1999.99, "Starting range: $50–$1,999.99"],
    ["Silver", 2000, 9999.99, "Middle range: $2,000–$9,999.99"],
    ["Gold", 10000, 100000, "Upper range: $10,000–$100,000"]
  ];
  for (const p of defaults) {
    await pool.query(
      `INSERT INTO plans(name,min_amount,max_amount,description)
       VALUES($1,$2,$3,$4) ON CONFLICT(name) DO NOTHING`, p
    );
  }

  const email = clean(process.env.ADMIN_EMAIL).toLowerCase();
  const password = process.env.ADMIN_PASSWORD;
  if (email && password) {
    const found = await pool.query("SELECT id FROM admins WHERE email=$1", [email]);
    if (!found.rowCount) {
      const hash = await bcrypt.hash(password, 12);
      await pool.query("INSERT INTO admins(email,password) VALUES($1,$2)", [email, hash]);
      console.log("Initial admin account created.");
    }
  } else {
    console.log("ADMIN_EMAIL/ADMIN_PASSWORD not set; configure them in Render.");
  }
}

function csrfToken(req) {
  if (!req.session.csrf) req.session.csrf = crypto.randomBytes(32).toString("hex");
  return req.session.csrf;
}
function requireCsrf(req, res, next) {
  if (["GET","HEAD","OPTIONS"].includes(req.method)) return next();
  if (!req.session.csrf || req.get("x-csrf-token") !== req.session.csrf) {
    return res.status(403).json({ error: "Security token expired. Refresh and try again." });
  }
  next();
}
function requireCustomer(req,res,next) {
  if (!req.session.customerId) return res.status(401).json({error:"Please log in first."});
  next();
}
function requireAdmin(req,res,next) {
  if (!req.session.adminId) return res.status(401).json({error:"Administrator login required."});
  next();
}
async function log(actorType, actorId, action, details="") {
  await pool.query(
    "INSERT INTO audit_logs(actor_type,actor_id,action,details) VALUES($1,$2,$3,$4)",
    [actorType, actorId || null, action, String(details).slice(0,1000)]
  );
}
async function customerBalance(customerId) {
  const r = await pool.query(
    `SELECT
      COALESCE((SELECT SUM(amount) FROM deposits WHERE customer_id=$1 AND status='approved'),0)
      - COALESCE((SELECT SUM(amount) FROM investments WHERE customer_id=$1),0)
      - COALESCE((SELECT SUM(amount) FROM withdrawals WHERE customer_id=$1 AND status IN ('approved','paid')),0)
      AS balance`, [customerId]
  );
  return Number(r.rows[0].balance);
}
app.use("/api", requireCsrf);

app.get("/api/health", (req,res) => res.json({status:"ok", mode:"staging-test-only"}));
app.get("/api/csrf", (req,res) => res.json({csrfToken:csrfToken(req)}));

app.post("/api/customer/register", asyncRoute(async (req,res) => {
  const first = clean(req.body.firstName), last = clean(req.body.lastName);
  const email = clean(req.body.email).toLowerCase(), phone = clean(req.body.phone);
  const country = clean(req.body.country), password = String(req.body.password || "");
  if (!first || !last || !emailOk(email) || phone.length < 6 || !country || password.length < 10) {
    return res.status(400).json({error:"Enter all details correctly. Password must be at least 10 characters."});
  }
  if (password !== req.body.confirmPassword) return res.status(400).json({error:"Passwords do not match."});
  const hash = await bcrypt.hash(password,12);
  try {
    const r = await pool.query(
      `INSERT INTO customers(first_name,last_name,email,phone,country,password)
       VALUES($1,$2,$3,$4,$5,$6) RETURNING id,first_name,last_name,email,phone,country`,
      [first,last,email,phone,country,hash]
    );
    req.session.customerId = r.rows[0].id;
    req.session.role = "customer";
    csrfToken(req);
    await log("customer",r.rows[0].id,"account_registered");
    res.json({success:true,customer:r.rows[0]});
  } catch(e) {
    if (e.code === "23505") return res.status(409).json({error:"That email or phone number is already registered."});
    throw e;
  }
}));

app.post("/api/customer/login", asyncRoute(async (req,res) => {
  const identifier = clean(req.body.identifier).toLowerCase();
  const password = String(req.body.password || "");
  const r = await pool.query(
    "SELECT * FROM customers WHERE lower(email)= $1 OR phone=$2", [identifier,clean(req.body.identifier)]
  );
  if (!r.rowCount || r.rows[0].status !== "active" || !(await bcrypt.compare(password,r.rows[0].password))) {
    return res.status(401).json({error:"Invalid login details or account unavailable."});
  }
  req.session.customerId = r.rows[0].id;
  req.session.role = "customer";
  csrfToken(req);
  res.json({success:true});
}));

app.post("/api/admin/login", asyncRoute(async (req,res) => {
  const email = clean(req.body.email).toLowerCase(), password = String(req.body.password || "");
  const r = await pool.query("SELECT * FROM admins WHERE lower(email)=$1",[email]);
  if (!r.rowCount || !(await bcrypt.compare(password,r.rows[0].password))) {
    return res.status(401).json({error:"Invalid administrator login details."});
  }
  req.session.adminId = r.rows[0].id;
  req.session.role = "admin";
  csrfToken(req);
  res.json({success:true});
}));

app.post("/api/logout", (req,res) => {
  req.session.destroy(() => res.json({success:true}));
});
app.get("/api/me", asyncRoute(async (req,res) => {
  const token = csrfToken(req);
  if (req.session.customerId) {
    const r = await pool.query(
      "SELECT id,first_name,last_name,email,phone,country,status,created_at FROM customers WHERE id=$1",
      [req.session.customerId]
    );
    if (r.rowCount) return res.json({role:"customer",user:r.rows[0],csrfToken:token});
  }
  if (req.session.adminId) {
    const r = await pool.query("SELECT id,email FROM admins WHERE id=$1",[req.session.adminId]);
    if (r.rowCount) return res.json({role:"admin",user:r.rows[0],csrfToken:token});
  }
  res.json({role:"guest",csrfToken:token});
}));

app.get("/api/plans", asyncRoute(async (req,res) => {
  const r = await pool.query("SELECT id,name,min_amount,max_amount,description FROM plans WHERE active=TRUE ORDER BY min_amount");
  res.json(r.rows);
}));
app.get("/api/customer/summary", requireCustomer, asyncRoute(async (req,res) => {
  const id=req.session.customerId;
  const [balance, inv, dep, wd, tx] = await Promise.all([
    customerBalance(id),
    pool.query("SELECT i.*,p.name AS plan_name FROM investments i JOIN plans p ON p.id=i.plan_id WHERE i.customer_id=$1 ORDER BY i.id DESC",[id]),
    pool.query("SELECT id,amount,network,reference,status,created_at FROM deposits WHERE customer_id=$1 ORDER BY id DESC",[id]),
    pool.query("SELECT id,amount,network,destination,status,created_at FROM withdrawals WHERE customer_id=$1 ORDER BY id DESC",[id]),
    pool.query("SELECT id,kind,amount,reference,note,created_at FROM transactions WHERE customer_id=$1 ORDER BY id DESC LIMIT 50",[id])
  ]);
  const perf=await pool.query(
    `SELECT p.*,i.customer_id FROM performance p JOIN investments i ON i.id=p.investment_id
     WHERE i.customer_id=$1 ORDER BY p.id DESC`,[id]
  );
  res.json({balance,investments:inv.rows,deposits:dep.rows,withdrawals:wd.rows,transactions:tx.rows,performance:perf.rows});
}));

// All deposit records are simulated staging entries. No payment or blockchain transfer occurs.
app.post("/api/customer/deposits", requireCustomer, asyncRoute(async (req,res) => {
  const amount=Number(req.body.amount), network=clean(req.body.network), reference=clean(req.body.reference);
  if (!money(amount) || amount>100000 || !["BTC","USDT TRC20","TRON"].includes(network) || reference.length<4) {
    return res.status(400).json({error:"Enter a valid test amount, supported network and reference."});
  }
  const r=await pool.query(
    "INSERT INTO deposits(customer_id,amount,network,reference) VALUES($1,$2,$3,$4) RETURNING id",
    [req.session.customerId,amount,network,reference]
  );
  await log("customer",req.session.customerId,"test_deposit_submitted",`Deposit #${r.rows[0].id}`);
  res.json({success:true,message:"Test deposit request submitted for admin review.",id:r.rows[0].id});
}));

app.post("/api/customer/investments", requireCustomer, asyncRoute(async (req,res) => {
  const planId=Number(req.body.planId), amount=Number(req.body.amount), days=Number(req.body.durationDays);
  if (!Number.isInteger(days) || days<4 || days>14 || !money(amount)) return res.status(400).json({error:"Amount or duration is invalid. Duration must be 4–14 days."});
  const p=await pool.query("SELECT * FROM plans WHERE id=$1 AND active=TRUE",[planId]);
  if (!p.rowCount || amount<Number(p.rows[0].min_amount) || amount>Number(p.rows[0].max_amount)) return res.status(400).json({error:"Amount does not fit the selected plan."});
  const balance=await customerBalance(req.session.customerId);
  if (amount>balance) return res.status(400).json({error:"Insufficient test balance. Submit a test deposit and ask the administrator to approve it."});
  const end=new Date(Date.now()+days*86400000);
  const r=await pool.query(
    "INSERT INTO investments(customer_id,plan_id,amount,duration_days,ends_at) VALUES($1,$2,$3,$4,$5) RETURNING id",
    [req.session.customerId,planId,amount,days,end]
  );
  await pool.query(
    "INSERT INTO transactions(customer_id,kind,amount,reference,note) VALUES($1,'investment',$2,$3,$4)",
    [req.session.customerId,amount,`INV-${r.rows[0].id}`,"Staging test investment"]
  );
  await log("customer",req.session.customerId,"test_investment_created",`Investment #${r.rows[0].id}`);
  res.json({success:true,message:"Test investment created. This is a simulation, not a real investment."});
}));

app.post("/api/customer/withdrawals", requireCustomer, asyncRoute(async (req,res) => {
  const amount=Number(req.body.amount), network=clean(req.body.network), destination=clean(req.body.destination);
  if (!money(amount) || amount>100000 || !["BTC","USDT TRC20","TRON"].includes(network) || destination.length<8) {
    return res.status(400).json({error:"Enter a valid amount, network and destination for this test request."});
  }
  const balance=await customerBalance(req.session.customerId);
  if (amount>balance) return res.status(400).json({error:"Insufficient available test balance."});
  const r=await pool.query(
    "INSERT INTO withdrawals(customer_id,amount,network,destination) VALUES($1,$2,$3,$4) RETURNING id",
    [req.session.customerId,amount,network,destination]
  );
  await log("customer",req.session.customerId,"test_withdrawal_requested",`Withdrawal #${r.rows[0].id}`);
  res.json({success:true,message:"Test withdrawal request submitted. No funds will be sent."});
}));

// Admin APIs
app.get("/api/admin/overview",requireAdmin,asyncRoute(async(req,res)=>{
  const [customers,deposits,withdrawals,investments]=await Promise.all([
    pool.query("SELECT COUNT(*)::int AS n FROM customers"),
    pool.query("SELECT COUNT(*)::int AS n FROM deposits WHERE status='pending'"),
    pool.query("SELECT COUNT(*)::int AS n FROM withdrawals WHERE status='pending'"),
    pool.query("SELECT COUNT(*)::int AS n FROM investments WHERE status='active'")
  ]);
  res.json({customers:customers.rows[0].n,pendingDeposits:deposits.rows[0].n,pendingWithdrawals:withdrawals.rows[0].n,activeInvestments:investments.rows[0].n});
}));
app.get("/api/admin/customers",requireAdmin,asyncRoute(async(req,res)=>{
  const r=await pool.query("SELECT id,first_name,last_name,email,phone,country,status,created_at FROM customers ORDER BY id DESC LIMIT 300");
  res.json(r.rows);
}));
app.patch("/api/admin/customers/:id",requireAdmin,asyncRoute(async(req,res)=>{
  const status=req.body.status;
  if(!["active","suspended"].includes(status)) return res.status(400).json({error:"Invalid status."});
  await pool.query("UPDATE customers SET status=$1 WHERE id=$2",[status,req.params.id]);
  await log("admin",req.session.adminId,"customer_status_changed",`Customer ${req.params.id}: ${status}`);
  res.json({success:true});
}));
app.get("/api/admin/records",requireAdmin,asyncRoute(async(req,res)=>{
  const [deposits,withdrawals,investments,plans,logs]=await Promise.all([
    pool.query("SELECT d.*,c.email,c.first_name,c.last_name FROM deposits d JOIN customers c ON c.id=d.customer_id ORDER BY d.id DESC LIMIT 300"),
    pool.query("SELECT w.*,c.email FROM withdrawals w JOIN customers c ON c.id=w.customer_id ORDER BY w.id DESC LIMIT 300"),
    pool.query("SELECT i.*,c.email,p.name AS plan_name FROM investments i JOIN customers c ON c.id=i.customer_id JOIN plans p ON p.id=i.plan_id ORDER BY i.id DESC LIMIT 300"),
    pool.query("SELECT * FROM plans ORDER BY min_amount"),
    pool.query("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100")
  ]);
  res.json({deposits:deposits.rows,withdrawals:withdrawals.rows,investments:investments.rows,plans:plans.rows,logs:logs.rows});
}));
app.post("/api/admin/deposits/:id/review",requireAdmin,asyncRoute(async(req,res)=>{
  const status=req.body.status;
  if(!["approved","rejected"].includes(status)) return res.status(400).json({error:"Choose approve or reject."});
  const r=await pool.query("UPDATE deposits SET status=$1,admin_note=$2,reviewed_at=NOW() WHERE id=$3 AND status='pending' RETURNING *",
    [status,clean(req.body.note),req.params.id]);
  if(!r.rowCount) return res.status(404).json({error:"Pending test deposit not found."});
  if(status==="approved") await pool.query(
    "INSERT INTO transactions(customer_id,kind,amount,reference,note) VALUES($1,'test_deposit',$2,$3,$4)",
    [r.rows[0].customer_id,r.rows[0].amount,`DEP-${r.rows[0].id}`,"Admin-approved staging test credit"]
  );
  await log("admin",req.session.adminId,"test_deposit_reviewed",`Deposit ${req.params.id}: ${status}`);
  res.json({success:true});
}));
app.post("/api/admin/withdrawals/:id/review",requireAdmin,asyncRoute(async(req,res)=>{
  const status=req.body.status;
  if(!["approved","rejected","paid"].includes(status)) return res.status(400).json({error:"Invalid review status."});
  const r=await pool.query("UPDATE withdrawals SET status=$1,admin_note=$2,reviewed_at=NOW() WHERE id=$3 AND status='pending' RETURNING *",
    [status,clean(req.body.note),req.params.id]);
  if(!r.rowCount) return res.status(404).json({error:"Pending test withdrawal not found."});
  await log("admin",req.session.adminId,"test_withdrawal_reviewed",`Withdrawal ${req.params.id}: ${status}`);
  res.json({success:true});
}));
app.post("/api/admin/plans",requireAdmin,asyncRoute(async(req,res)=>{
  const name=clean(req.body.name), min=Number(req.body.minAmount), max=Number(req.body.maxAmount);
  if(!name || !money(min) || !money(max) || max<min) return res.status(400).json({error:"Enter a valid plan name and amount range."});
  try {
    await pool.query("INSERT INTO plans(name,min_amount,max_amount,description) VALUES($1,$2,$3,$4)",
      [name,min,max,clean(req.body.description)]);
    await log("admin",req.session.adminId,"plan_created",name);
    res.json({success:true});
  } catch(e) { if(e.code==="23505") return res.status(409).json({error:"A plan with that name already exists."}); throw e; }
}));
app.put("/api/admin/plans/:id",requireAdmin,asyncRoute(async(req,res)=>{
  const name=clean(req.body.name), min=Number(req.body.minAmount), max=Number(req.body.maxAmount);
  if(!name || !money(min) || !money(max) || max<min) return res.status(400).json({error:"Enter a valid plan name and amount range."});
  await pool.query("UPDATE plans SET name=$1,min_amount=$2,max_amount=$3,description=$4,active=$5 WHERE id=$6",
    [name,min,max,clean(req.body.description),req.body.active!==false,req.params.id]);
  await log("admin",req.session.adminId,"plan_updated",name);
  res.json({success:true});
}));
app.post("/api/admin/performance",requireAdmin,asyncRoute(async(req,res)=>{
  const investmentId=Number(req.body.investmentId), amount=Number(req.body.amount), note=clean(req.body.note);
  if(!Number.isInteger(investmentId) || !Number.isFinite(amount) || !note) return res.status(400).json({error:"Enter an investment, actual gain/loss amount and explanation."});
  const inv=await pool.query("SELECT id FROM investments WHERE id=$1",[investmentId]);
  if(!inv.rowCount) return res.status(404).json({error:"Investment not found."});
  await pool.query("INSERT INTO performance(investment_id,amount,note,recorded_by) VALUES($1,$2,$3,$4)",
    [investmentId,amount,note,req.session.adminId]);
  await log("admin",req.session.adminId,"actual_performance_recorded",`Investment ${investmentId}: ${amount}`);
  res.json({success:true});
}));

app.use("/api", (err,req,res,next)=>{
  console.error(err);
  if(res.headersSent) return next(err);
  res.status(500).json({error:"A server error occurred. Please try again."});
});
app.use(express.static(path.join(__dirname,"public")));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));

const PORT=process.env.PORT||3000;
setup().then(()=>app.listen(PORT,()=>console.log(`G TOP staging server running on ${PORT}`)))
  .catch(err=>{console.error("Startup error:",err);process.exit(1);});
