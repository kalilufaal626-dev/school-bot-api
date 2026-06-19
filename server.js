const express = require('express');
const { Pool } = require('pg');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
app.use(express.json());

// ─── Database Connection ───────────────────────────────────────────────────
const pool = new Pool({
  host:     process.env.DB_HOST,
  port:     process.env.DB_PORT || 5432,
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: { rejectUnauthorized: false }
});

// ─── Health Check (public) ────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ─── API Key Middleware ────────────────────────────────────────────────────
app.use((req, res, next) => {
  const key = req.headers['x-api-key'];
  if (key !== process.env.API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
});

// ══════════════════════════════════════════════════════════════════
//  STUDENTS
// ══════════════════════════════════════════════════════════════════

// GET all students
app.get('/students', async (req, res) => {
  const { class: studentClass, status } = req.query;
  let query = 'SELECT * FROM students WHERE 1=1';
  const params = [];

  if (studentClass) {
    params.push(studentClass);
    query += ` AND class ILIKE $${params.length}`;
  }
  if (status) {
    params.push(status);
    query += ` AND status = $${params.length}`;
  }

  query += ' ORDER BY full_name ASC';

  try {
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET student by phone (parent lookup)
app.get('/students/phone/:phone', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM students WHERE parent_phone ILIKE $1',
      [`%${req.params.phone}%`]
    );
    if (!rows.length) return res.status(404).json({ error: 'No student found for this phone number' });
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET single student by ID
app.get('/students/:id', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM students WHERE id = $1',
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Student not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST register student
app.post('/students', async (req, res) => {
  const { full_name, class: studentClass, date_of_birth, parent_phone, parent_name, gender } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO students (full_name, class, date_of_birth, parent_phone, parent_name, gender)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [full_name, studentClass || null, date_of_birth || null, parent_phone || null, parent_name || null, gender || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH update student
app.patch('/students/:id', async (req, res) => {
  const { full_name, class: studentClass, parent_phone, parent_name, status } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE students
       SET full_name = COALESCE($1, full_name),
           class = COALESCE($2, class),
           parent_phone = COALESCE($3, parent_phone),
           parent_name = COALESCE($4, parent_name),
           status = COALESCE($5, status)
       WHERE id = $6 RETURNING *`,
      [full_name || null, studentClass || null, parent_phone || null, parent_name || null, status || null, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Student not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════
//  FEES
// ══════════════════════════════════════════════════════════════════

// GET fees for a student
app.get('/fees', async (req, res) => {
  const { student_id, status, term } = req.query;
  let query = 'SELECT * FROM fees WHERE 1=1';
  const params = [];

  if (student_id) {
    params.push(student_id);
    query += ` AND student_id = $${params.length}`;
  }
  if (status) {
    params.push(status);
    query += ` AND status = $${params.length}`;
  }
  if (term) {
    params.push(`%${term}%`);
    query += ` AND term ILIKE $${params.length}`;
  }

  query += ' ORDER BY created_at DESC';

  try {
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST create fee record
app.post('/fees', async (req, res) => {
  const { student_id, term, academic_year, amount_due, due_date } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO fees (student_id, term, academic_year, amount_due, due_date)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [student_id, term, academic_year || null, amount_due, due_date || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH update fee payment
app.patch('/fees/:id/pay', async (req, res) => {
  const { amount_paid } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE fees
       SET amount_paid = amount_paid + $1,
           status = CASE WHEN amount_paid + $1 >= amount_due THEN 'paid' ELSE 'partial' END,
           paid_date = CASE WHEN amount_paid + $1 >= amount_due THEN NOW() ELSE paid_date END
       WHERE id = $2 RETURNING *`,
      [amount_paid, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Fee record not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════
//  ATTENDANCE
// ══════════════════════════════════════════════════════════════════

// GET attendance records
app.get('/attendance', async (req, res) => {
  const { student_id, date } = req.query;
  let query = 'SELECT * FROM attendance WHERE 1=1';
  const params = [];

  if (student_id) {
    params.push(student_id);
    query += ` AND student_id = $${params.length}`;
  }
  if (date) {
    params.push(date);
    query += ` AND date = $${params.length}`;
  }

  query += ' ORDER BY date DESC';

  try {
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST report absence
app.post('/attendance', async (req, res) => {
  const { student_id, date, status, reason } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO attendance (student_id, date, status, reason)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT DO NOTHING RETURNING *`,
      [student_id, date || new Date().toISOString().split('T')[0], status || 'absent', reason || null]
    );
    res.status(201).json(rows[0] || { message: 'Attendance already recorded for today' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════
//  ANNOUNCEMENTS
// ══════════════════════════════════════════════════════════════════

// GET all announcements
app.get('/announcements', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM announcements ORDER BY created_at DESC'
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST create announcement
app.post('/announcements', async (req, res) => {
  const { title, message, target } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO announcements (title, message, target)
       VALUES ($1, $2, $3) RETURNING *`,
      [title || null, message, target || 'all']
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════
//  SUBSCRIBERS (parents on WhatsApp)
// ══════════════════════════════════════════════════════════════════

// GET all subscribers
app.get('/subscribers', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM school_subscribers ORDER BY created_at DESC'
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST save subscriber
app.post('/subscribers', async (req, res) => {
  const { phone, parent_name, student_id } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO school_subscribers (phone, parent_name, student_id)
       VALUES ($1, $2, $3)
       ON CONFLICT (phone) DO UPDATE SET parent_name = COALESCE($2, school_subscribers.parent_name)
       RETURNING *`,
      [phone, parent_name || null, student_id || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Start Server ──────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`School Bot API running on port ${PORT}`));
