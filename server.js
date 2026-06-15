require("dotenv").config();
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { body, validationResult } = require("express-validator");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

// Підключення до твоєї бази Neon (береться з .env)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Захист Helmet + дозвіл на шрифти для нового дизайну
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
    }
  }
}));

// Захист від спам-запитів
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Забагато запитів, спробуйте пізніше."
});
app.use("/api", limiter);

// Вказуємо, що всі HTML/CSS/JS лежать у папці public
app.use(express.static(path.join(__dirname, "public")));

// --- Ініціалізація БД та автоматичне створення акаунтів ---
// --- Ініціалізація БД та автоматичне створення акаунтів ---
async function initDb() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY, username VARCHAR(255) UNIQUE NOT NULL, password TEXT NOT NULL, 
        role VARCHAR(50) DEFAULT 'user', createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS tickets (
        id SERIAL PRIMARY KEY, title VARCHAR(255) NOT NULL, description TEXT NOT NULL, 
        priority VARCHAR(50) NOT NULL, status VARCHAR(50) DEFAULT 'Відкритий', 
        createdBy INTEGER, assignedTo INTEGER, createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
        updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY, userId INTEGER, action TEXT, createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // 1. ПРИМУСОВО ВИДАЛЯЄМО СТАРОГО АДМІНА (щоб скинути базу)
    await pool.query("DELETE FROM users WHERE username = 'admin'");

    // 2. Список акаунтів з новим єдиним паролем 12345678
    const usersToCreate = [
      { username: 'admin', pass: '12345678', role: 'admin' },
      { username: 'user1', pass: '12345678', role: 'user' },
      { username: 'user2', pass: '12345678', role: 'user' }
    ];

    for (const u of usersToCreate) {
      const check = await pool.query("SELECT * FROM users WHERE username=$1", [u.username]);
      if (check.rows.length === 0) {
        const hash = await bcrypt.hash(u.pass, 10);
        await pool.query("INSERT INTO users(username, password, role) VALUES($1, $2, $3)", [u.username, hash, u.role]);
        console.log(`Створено/оновлено акаунт: ${u.username}`);
      }
    }
    console.log("База даних успішно очищена та ініціалізована.");
  } catch (err) {
    console.error("Помилка ініціалізації БД:", err);
  }
}
initDb();

// --- Допоміжні функції ---
async function logAction(userId, action) {
  try { await pool.query(`INSERT INTO audit_logs (userId, action) VALUES ($1, $2)`, [userId, action]); } 
  catch (err) {}
}

function authenticate(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: "Немає доступу" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    res.clearCookie("token");
    return res.status(401).json({ message: "Недійсний токен" });
  }
}

// --- Маршрути API ---
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query(`SELECT * FROM users WHERE username = $1`, [username]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ message: "Невірний логін або пароль" });
    }

    const token = jwt.sign({ id: user.id, role: user.role, username: user.username }, JWT_SECRET, { expiresIn: "8h" });
    logAction(user.id, "Logged in");

    res.cookie("token", token, { httpOnly: true, sameSite: "strict", secure: process.env.NODE_ENV === "production" });
    res.json({ message: "Успішний вхід" });
  } catch (err) {
    res.status(500).json({ message: "Помилка сервера" });
  }
});

app.get("/api/me", authenticate, (req, res) => res.json(req.user));

app.post("/api/logout", authenticate, (req, res) => {
  logAction(req.user.id, "Logged out");
  res.clearCookie("token");
  res.json({ message: "Вийшли з системи" });
});

app.get("/api/tickets", authenticate, async (req, res) => {
  try {
    const result = await pool.query(`SELECT * FROM tickets ORDER BY id DESC`);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ message: "Помилка БД" }); }
});

app.post("/api/tickets", authenticate, 
  body("title").notEmpty().trim().escape(),
  body("description").notEmpty().trim().escape(),
  body("priority").isIn(['Низький', 'Середній', 'Високий']),
async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json(errors);

  const { title, description, priority } = req.body;
  
  try {
    const result = await pool.query(
      `INSERT INTO tickets (title, description, priority, createdBy) VALUES ($1, $2, $3, $4) RETURNING id`, 
      [title, description, priority, req.user.id]
    );
    logAction(req.user.id, `Created ticket: ${result.rows[0].id}`);
    res.json({ message: "Тікет створено" });
  } catch (err) { res.status(500).json({ message: "Помилка БД" }); }
});

app.listen(PORT, () => console.log(`Сервер працює на порту ${PORT}`));