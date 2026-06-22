const express = require('express');
const { Pool } = require('pg');
const dotenv = require('dotenv');
const crypto = require('crypto');

dotenv.config();

const app = express();
app.use(express.json());
app.use(express.static('public'));

// CORS
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, x-api-key, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ─── Database Connection ───────────────────────────────────────────────────
const pool = new Pool({
  host:     process.env.DB_HOST,
  port:     process.env.DB_PORT || 5432,
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: { rejectUnauthorized: false }
});

// ─── Helpers ──────────────────────────────────────────────────────────────
const hashPassword = (password) =>
  crypto.createHash('sha256').update(password + process.env.API_KEY).digest('hex');

const generateToken = (teacher) =>
  Buffer.from(JSON.stringify({ id: teacher.id, role: teacher.role, email: teacher.email, exp: Date.now() + 86400000 })).toString('base64');

const verifyToken = (req, res, next) => {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = JSON.parse(Buffer.from(auth.replace('Bearer ', ''), 'base64').toString());
    if (decoded.exp < Date.now()) return res.status(401).json({ error: 'Token expired' });
    req.teacher = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

const isAdmin = (req, res, next) => {
  if (req.teacher.role !== 'admin' && req.teacher.role !== 'principal') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// ─── Health Check (public) ────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ─── API Key Middleware (for WhatsApp bot routes) ─────────────────────────
const apiKeyAuth = (req, res, next) => {
  const key = req.headers['x-api-key'];
  if (key !== process.env.API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
};

// ══════════════════════════════════════════════════════════════════
//  AUTH (public routes)
// ══════════════════════════════════════════════════════════════════

// POST login
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    const hashed = hashPassword(password);
    const { rows } = await pool.query(
      'SELECT * FROM teachers WHERE email = $1 AND password = $2',
      [email, hashed]
    );
    if (!rows.length) return res.status(401).json({ error: 'Invalid email or password' });
    const teacher = rows[0];
    const token = generateToken(teacher);
    res.json({
      token,
      teacher: {
        id: teacher.id,
        full_name: teacher.full_name,
        email: teacher.email,
        class: teacher.class,
        role: teacher.role
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST create first admin (setup only)
app.post('/auth/setup', async (req, res) => {
  const { full_name, email, password, secret } = req.body;
  if (secret !== process.env.API_KEY) return res.status(401).json({ error: 'Invalid setup secret' });
  try {
    const hashed = hashPassword(password);
    const { rows } = await pool.query(
      `INSERT INTO teachers (full_name, email, password, role)
       VALUES ($1, $2, $3, 'admin') RETURNING id, full_name, email, role`,
      [full_name, email, hashed]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════
//  TEACHERS (admin only)
// ══════════════════════════════════════════════════════════════════

// GET all teachers
app.get('/teachers', verifyToken, isAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, full_name, email, class, role, created_at FROM teachers ORDER BY full_name ASC'
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST create teacher
app.post('/teachers', verifyToken, isAdmin, async (req, res) => {
  const { full_name, email, password, class: teacherClass, role } = req.body;
  try {
    const hashed = hashPassword(password);
    const { rows } = await pool.query(
      `INSERT INTO teachers (full_name, email, password, class, role)
       VALUES ($1, $2, $3, $4, $5) RETURNING id, full_name, email, class, role`,
      [full_name, email, hashed, teacherClass || null, role || 'teacher']
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH update teacher
app.patch('/teachers/:id', verifyToken, isAdmin, async (req, res) => {
  const { full_name, class: teacherClass, role } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE teachers SET
        full_name = COALESCE($1, full_name),
        class = COALESCE($2, class),
        role = COALESCE($3, role)
       WHERE id = $4 RETURNING id, full_name, email, class, role`,
      [full_name || null, teacherClass || null, role || null, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Teacher not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE teacher
app.delete('/teachers/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM teachers WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════
//  STUDENTS
// ══════════════════════════════════════════════════════════════════

// GET all students (teacher sees only their class)
app.get('/students', verifyToken, async (req, res) => {
  try {
    let query = 'SELECT * FROM students WHERE 1=1';
    const params = [];

    // Teachers only see their class
    if (req.teacher.role === 'teacher') {
      const { rows: teacher } = await pool.query('SELECT class FROM teachers WHERE id = $1', [req.teacher.id]);
      if (teacher[0]?.class) {
        params.push(teacher[0].class);
        query += ` AND class = $${params.length}`;
      }
    }

    // Allow class filter from query
    if (req.query.class) {
      params.push(req.query.class);
      query += ` AND class ILIKE $${params.length}`;
    }

    query += ' ORDER BY full_name ASC';
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET student by phone (WhatsApp bot — API key)
app.get('/students/phone/:phone', apiKeyAuth, async (req, res) => {
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

// GET single student
app.get('/students/:id', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM students WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Student not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST register student (WhatsApp bot — API key OR dashboard)
app.post('/students', async (req, res) => {
  const apiKey = req.headers['x-api-key'];
  const auth = req.headers['authorization'];
  if (!apiKey && !auth) return res.status(401).json({ error: 'Unauthorized' });

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
app.patch('/students/:id', verifyToken, async (req, res) => {
  const { full_name, class: studentClass, parent_phone, parent_name, status } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE students SET
        full_name = COALESCE($1, full_name),
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
//  ATTENDANCE
// ══════════════════════════════════════════════════════════════════

// GET attendance
app.get('/attendance', verifyToken, async (req, res) => {
  const { student_id, date, class: className } = req.query;
  let query = `SELECT a.*, s.full_name, s.class 
               FROM attendance a 
               JOIN students s ON a.student_id = s.id 
               WHERE 1=1`;
  const params = [];

  if (student_id) {
    params.push(student_id);
    query += ` AND a.student_id = $${params.length}`;
  }
  if (date) {
    params.push(date);
    query += ` AND a.date = $${params.length}`;
  }
  if (className) {
    params.push(className);
    query += ` AND s.class = $${params.length}`;
  }

  // Teachers only see their class
  if (req.teacher.role === 'teacher') {
    const { rows: teacher } = await pool.query('SELECT class FROM teachers WHERE id = $1', [req.teacher.id]);
    if (teacher[0]?.class) {
      params.push(teacher[0].class);
      query += ` AND s.class = $${params.length}`;
    }
  }

  query += ' ORDER BY a.date DESC';

  try {
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST mark attendance (dashboard or WhatsApp bot)
app.post('/attendance', async (req, res) => {
  const apiKey = req.headers['x-api-key'];
  const auth = req.headers['authorization'];
  if (!apiKey && !auth) return res.status(401).json({ error: 'Unauthorized' });

  const { student_id, date, status, reason, teacher_id } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO attendance (student_id, date, status, reason, teacher_id)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (student_id, date) DO UPDATE 
       SET status = $3, reason = $4, teacher_id = $5
       RETURNING *`,
      [student_id, date || new Date().toISOString().split('T')[0], status || 'absent', reason || null, teacher_id || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST bulk attendance (teacher marks whole class at once)
app.post('/attendance/bulk', verifyToken, async (req, res) => {
  const { date, attendance } = req.body;
  // attendance = [{ student_id, status, reason }]
  try {
    const results = [];
    for (const record of attendance) {
      const { rows } = await pool.query(
        `INSERT INTO attendance (student_id, date, status, reason, teacher_id)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (student_id, date) DO UPDATE
         SET status = $3, reason = $4, teacher_id = $5
         RETURNING *`,
        [record.student_id, date, record.status || 'present', record.reason || null, req.teacher.id]
      );
      results.push(rows[0]);
    }
    res.json({ success: true, count: results.length, records: results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════
//  GRADES
// ══════════════════════════════════════════════════════════════════

// GET grades
app.get('/grades', verifyToken, async (req, res) => {
  const { student_id, term } = req.query;
  let query = `SELECT g.*, s.full_name, s.class, t.full_name as teacher_name
               FROM grades g
               JOIN students s ON g.student_id = s.id
               JOIN teachers t ON g.teacher_id = t.id
               WHERE 1=1`;
  const params = [];

  if (student_id) {
    params.push(student_id);
    query += ` AND g.student_id = $${params.length}`;
  }
  if (term) {
    params.push(term);
    query += ` AND g.term ILIKE $${params.length}`;
  }
  if (req.teacher.role === 'teacher') {
    params.push(req.teacher.id);
    query += ` AND g.teacher_id = $${params.length}`;
  }

  query += ' ORDER BY g.created_at DESC';

  try {
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST add grade
app.post('/grades', verifyToken, async (req, res) => {
  const { student_id, subject, score, grade, term, academic_year, notes } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO grades (student_id, teacher_id, subject, score, grade, term, academic_year, notes)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [student_id, req.teacher.id, subject, score || null, grade || null, term || null, academic_year || null, notes || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH update grade
app.patch('/grades/:id', verifyToken, async (req, res) => {
  const { score, grade, notes } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE grades SET
        score = COALESCE($1, score),
        grade = COALESCE($2, grade),
        notes = COALESCE($3, notes)
       WHERE id = $4 RETURNING *`,
      [score || null, grade || null, notes || null, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Grade not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════
//  TEACHER NOTES
// ══════════════════════════════════════════════════════════════════

// GET notes for a student
app.get('/notes', verifyToken, async (req, res) => {
  const { student_id } = req.query;
  let query = `SELECT n.*, s.full_name, t.full_name as teacher_name
               FROM teacher_notes n
               JOIN students s ON n.student_id = s.id
               JOIN teachers t ON n.teacher_id = t.id
               WHERE 1=1`;
  const params = [];

  if (student_id) {
    params.push(student_id);
    query += ` AND n.student_id = $${params.length}`;
  }
  if (req.teacher.role === 'teacher') {
    params.push(req.teacher.id);
    query += ` AND n.teacher_id = $${params.length}`;
  }

  query += ' ORDER BY n.created_at DESC';

  try {
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST add note
app.post('/notes', verifyToken, async (req, res) => {
  const { student_id, note } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO teacher_notes (student_id, teacher_id, note)
       VALUES ($1, $2, $3) RETURNING *`,
      [student_id, req.teacher.id, note]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════
//  FEES
// ══════════════════════════════════════════════════════════════════

// GET fees
app.get('/fees', async (req, res) => {
  const apiKey = req.headers['x-api-key'];
  const auth = req.headers['authorization'];
  if (!apiKey && !auth) return res.status(401).json({ error: 'Unauthorized' });

  const { student_id, status, term } = req.query;
  let query = 'SELECT * FROM fees WHERE 1=1';
  const params = [];

  if (student_id) { params.push(student_id); query += ` AND student_id = $${params.length}`; }
  if (status) { params.push(status); query += ` AND status = $${params.length}`; }
  if (term) { params.push(`%${term}%`); query += ` AND term ILIKE $${params.length}`; }

  query += ' ORDER BY created_at DESC';

  try {
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST create fee
app.post('/fees', verifyToken, isAdmin, async (req, res) => {
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

// PATCH pay fee
app.patch('/fees/:id/pay', apiKeyAuth, async (req, res) => {
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
//  ANNOUNCEMENTS
// ══════════════════════════════════════════════════════════════════

// GET announcements
app.get('/announcements', async (req, res) => {
  const apiKey = req.headers['x-api-key'];
  const auth = req.headers['authorization'];
  if (!apiKey && !auth) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const { rows } = await pool.query('SELECT * FROM announcements ORDER BY created_at DESC');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST create announcement (admin only)
app.post('/announcements', verifyToken, isAdmin, async (req, res) => {
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
//  SUBSCRIBERS (WhatsApp bot)
// ══════════════════════════════════════════════════════════════════

app.get('/subscribers', apiKeyAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM school_subscribers ORDER BY created_at DESC');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/subscribers', apiKeyAuth, async (req, res) => {
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

// ══════════════════════════════════════════════════════════════════
//  DASHBOARD STATS (admin only)
// ══════════════════════════════════════════════════════════════════

app.get('/stats', verifyToken, isAdmin, async (req, res) => {
  try {
    const [students, teachers, fees, todayAttendance] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM students WHERE status = $1', ['active']),
      pool.query('SELECT COUNT(*) FROM teachers'),
      pool.query(`SELECT 
        SUM(amount_due) as total_due, 
        SUM(amount_paid) as total_paid,
        COUNT(*) FILTER (WHERE status = 'paid') as paid_count,
        COUNT(*) FILTER (WHERE status = 'unpaid') as unpaid_count
        FROM fees`),
      pool.query(`SELECT 
        COUNT(*) FILTER (WHERE status = 'present') as present,
        COUNT(*) FILTER (WHERE status = 'absent') as absent
        FROM attendance WHERE date = CURRENT_DATE`)
    ]);

    res.json({
      total_students: parseInt(students.rows[0].count),
      total_teachers: parseInt(teachers.rows[0].count),
      fees: fees.rows[0],
      today_attendance: todayAttendance.rows[0]
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Start Server ──────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`School Bot API running on port ${PORT}`));
