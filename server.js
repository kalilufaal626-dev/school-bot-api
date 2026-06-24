const express = require('express');
const { Pool } = require('pg');
const dotenv = require('dotenv');
const crypto = require('crypto');

dotenv.config();

const app = express();
app.use(express.json());
app.use(express.static('public'));

// ─── CORS ─────────────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, x-api-key, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ─── DATABASE ─────────────────────────────────────────────────────────────────
const pool = new Pool({
  host:     process.env.DB_HOST,
  port:     process.env.DB_PORT || 5432,
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: { rejectUnauthorized: false }
});

// ─── HELPERS ──────────────────────────────────────────────────────────────────
const hashPassword = (password) =>
  crypto.createHash('sha256').update(password + process.env.API_KEY).digest('hex');

const generateToken = (teacher) =>
  Buffer.from(JSON.stringify({
    id:    teacher.id,
    role:  teacher.role,
    email: teacher.email,
    exp:   Date.now() + 86400000  // 24 hours
  })).toString('base64');

// Middleware: verify JWT token
const verifyToken = (req, res, next) => {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = JSON.parse(Buffer.from(auth.replace('Bearer ', ''), 'base64').toString());
    if (decoded.exp < Date.now()) return res.status(401).json({ error: 'Token expired, please log in again' });
    req.teacher = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Middleware: admin or principal only
const isAdmin = (req, res, next) => {
  if (req.teacher.role !== 'admin' && req.teacher.role !== 'principal') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Middleware: API key (for WhatsApp bot / n8n routes)
const apiKeyAuth = (req, res, next) => {
  const key = req.headers['x-api-key'];
  if (key !== process.env.API_KEY) {
    return res.status(401).json({ error: 'Invalid API key' });
  }
  next();
};

// Accept either JWT token OR API key
const verifyTokenOrApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (apiKey === process.env.API_KEY) return next();
  return verifyToken(req, res, next);
};

// ─── HEALTH CHECK ─────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ══════════════════════════════════════════════════════════════════════════════
//  AUTH
// ══════════════════════════════════════════════════════════════════════════════

// POST /auth/login
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  try {
    const hashed = hashPassword(password);
    const { rows } = await pool.query(
      'SELECT * FROM teachers WHERE LOWER(email) = LOWER($1) AND password = $2',
      [email, hashed]
    );
    if (!rows.length) return res.status(401).json({ error: 'Invalid email or password' });

    const teacher = rows[0];
    const token = generateToken(teacher);
    res.json({
      token,
      teacher: {
        id:        teacher.id,
        full_name: teacher.full_name,
        email:     teacher.email,
        class:     teacher.class,
        role:      teacher.role
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// POST /auth/setup — create first admin (protected by API key secret)
app.post('/auth/setup', async (req, res) => {
  const { full_name, email, password, secret } = req.body;
  if (secret !== process.env.API_KEY) return res.status(401).json({ error: 'Invalid setup secret' });

  try {
    const hashed = hashPassword(password);
    const { rows } = await pool.query(
      `INSERT INTO teachers (full_name, email, password, role)
       VALUES ($1, $2, $3, 'admin')
       RETURNING id, full_name, email, role`,
      [full_name, email, hashed]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error('Setup error:', err);
    res.status(500).json({ error: 'Server error during setup' });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  TEACHERS
// ══════════════════════════════════════════════════════════════════════════════

// GET /teachers — admin only
app.get('/teachers', verifyToken, isAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, full_name, email, class, role, created_at FROM teachers ORDER BY full_name ASC'
    );
    res.json(rows);
  } catch (err) {
    console.error('Get teachers error:', err);
    res.status(500).json({ error: 'Failed to fetch teachers' });
  }
});

// POST /teachers — admin only
app.post('/teachers', verifyToken, isAdmin, async (req, res) => {
  const { full_name, email, password, class: teacherClass, role } = req.body;
  if (!full_name || !email || !password) {
    return res.status(400).json({ error: 'full_name, email, and password are required' });
  }

  try {
    const hashed = hashPassword(password);
    const { rows } = await pool.query(
      `INSERT INTO teachers (full_name, email, password, class, role)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, full_name, email, class, role`,
      [full_name, email, hashed, teacherClass || null, role || 'teacher']
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    // Duplicate email
    if (err.code === '23505') return res.status(409).json({ error: 'A teacher with this email already exists' });
    console.error('Create teacher error:', err);
    res.status(500).json({ error: 'Failed to create teacher' });
  }
});

// PATCH /teachers/:id — admin only (update name, class, role)
app.patch('/teachers/:id', verifyToken, isAdmin, async (req, res) => {
  const { full_name, class: teacherClass, role } = req.body;

  try {
    const { rows } = await pool.query(
      `UPDATE teachers SET
        full_name  = COALESCE($1, full_name),
        class      = COALESCE($2, class),
        role       = COALESCE($3, role)
       WHERE id = $4
       RETURNING id, full_name, email, class, role`,
      [full_name || null, teacherClass || null, role || null, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Teacher not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('Update teacher error:', err);
    res.status(500).json({ error: 'Failed to update teacher' });
  }
});

// DELETE /teachers/:id — admin only
// BUG FIX: original did not return a clear response or reload the teacher count
app.delete('/teachers/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM teachers WHERE id = $1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Teacher not found' });
    res.json({ success: true, deleted_id: parseInt(req.params.id) });
  } catch (err) {
    console.error('Delete teacher error:', err);
    res.status(500).json({ error: 'Failed to delete teacher' });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  STUDENTS
// ══════════════════════════════════════════════════════════════════════════════

// GET /students
// BUG FIX: was using = (exact/case-sensitive), changed to ILIKE so "grade 7" matches "Grade 7"
// BUG FIX: teacher with no class set now sees ALL students instead of nothing
app.get('/students', verifyToken, async (req, res) => {
  try {
    let query = 'SELECT * FROM students WHERE 1=1';
    const params = [];

    // Teachers: filter to their class only — but ONLY if they have a class set
    if (req.teacher.role === 'teacher') {
      const { rows: teacherRows } = await pool.query(
        'SELECT class FROM teachers WHERE id = $1',
        [req.teacher.id]
      );
      const teacherClass = teacherRows[0]?.class;
      if (teacherClass) {
        // FIX: use ILIKE not = so "grade 7" matches "Grade 7"
        params.push(teacherClass);
        query += ` AND class ILIKE $${params.length}`;
      }
      // If no class set: fall through and return all students
      // (teacher sees everyone; admin should assign them a class)
    }

    // Optional class filter from query string
    if (req.query.class) {
      params.push(req.query.class);
      query += ` AND class ILIKE $${params.length}`;
    }

    // Optional status filter
    if (req.query.status) {
      params.push(req.query.status);
      query += ` AND status = $${params.length}`;
    }

    query += ' ORDER BY full_name ASC';
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    console.error('Get students error:', err);
    res.status(500).json({ error: 'Failed to fetch students' });
  }
});

// GET /students/phone/:phone — WhatsApp bot (API key)
app.get('/students/phone/:phone', apiKeyAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM students WHERE parent_phone ILIKE $1',
      [`%${req.params.phone}%`]
    );
    if (!rows.length) return res.status(404).json({ error: 'No student found for this phone number' });
    res.json(rows);
  } catch (err) {
    console.error('Student phone lookup error:', err);
    res.status(500).json({ error: 'Failed to lookup student' });
  }
});

// GET /students/:id
app.get('/students/:id', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM students WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Student not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('Get student error:', err);
    res.status(500).json({ error: 'Failed to fetch student' });
  }
});

// POST /students — dashboard (JWT) or WhatsApp bot (API key)
app.post('/students', verifyTokenOrApiKey, async (req, res) => {
  const {
    full_name, class: studentClass, date_of_birth,
    parent_phone, parent_name, parent_email, gender
  } = req.body;

  if (!full_name) return res.status(400).json({ error: 'full_name is required' });

  try {
    const { rows } = await pool.query(
      `INSERT INTO students (full_name, class, date_of_birth, parent_phone, parent_name, parent_email, gender)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [
        full_name,
        studentClass    || null,
        date_of_birth   || null,
        parent_phone    || null,
        parent_name     || null,
        parent_email    || null,
        gender          || null
      ]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error('Create student error:', err);
    res.status(500).json({ error: 'Failed to create student' });
  }
});

// PATCH /students/:id
app.patch('/students/:id', verifyToken, async (req, res) => {
  const {
    full_name, class: studentClass, parent_phone,
    parent_name, parent_email, status, gender, date_of_birth
  } = req.body;

  try {
    const { rows } = await pool.query(
      `UPDATE students SET
        full_name    = COALESCE($1,  full_name),
        class        = COALESCE($2,  class),
        parent_phone = COALESCE($3,  parent_phone),
        parent_name  = COALESCE($4,  parent_name),
        parent_email = COALESCE($5,  parent_email),
        status       = COALESCE($6,  status),
        gender       = COALESCE($7,  gender),
        date_of_birth= COALESCE($8,  date_of_birth)
       WHERE id = $9
       RETURNING *`,
      [
        full_name     || null,
        studentClass  || null,
        parent_phone  || null,
        parent_name   || null,
        parent_email  || null,
        status        || null,
        gender        || null,
        date_of_birth || null,
        req.params.id
      ]
    );
    if (!rows.length) return res.status(404).json({ error: 'Student not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('Update student error:', err);
    res.status(500).json({ error: 'Failed to update student' });
  }
});

// DELETE /students/:id — admin only
app.delete('/students/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM students WHERE id = $1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Student not found' });
    res.json({ success: true, deleted_id: parseInt(req.params.id) });
  } catch (err) {
    console.error('Delete student error:', err);
    res.status(500).json({ error: 'Failed to delete student' });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  ATTENDANCE
// ══════════════════════════════════════════════════════════════════════════════

// GET /attendance
// BUG FIX: class filter now uses ILIKE instead of =
app.get('/attendance', verifyToken, async (req, res) => {
  const { student_id, date, class: className } = req.query;

  let query = `
    SELECT a.*, s.full_name, s.class
    FROM attendance a
    JOIN students s ON a.student_id = s.id
    WHERE 1=1
  `;
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
    // FIX: ILIKE for case-insensitive class match
    query += ` AND s.class ILIKE $${params.length}`;
  }

  // Teachers: restrict to their class (if class is set)
  if (req.teacher.role === 'teacher') {
    const { rows: teacherRows } = await pool.query(
      'SELECT class FROM teachers WHERE id = $1',
      [req.teacher.id]
    );
    const teacherClass = teacherRows[0]?.class;
    if (teacherClass) {
      params.push(teacherClass);
      // FIX: ILIKE not =
      query += ` AND s.class ILIKE $${params.length}`;
    }
  }

  query += ' ORDER BY a.date DESC, s.full_name ASC';

  try {
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    console.error('Get attendance error:', err);
    res.status(500).json({ error: 'Failed to fetch attendance' });
  }
});

// POST /attendance — single record (dashboard or bot)
app.post('/attendance', verifyTokenOrApiKey, async (req, res) => {
  const { student_id, date, status, reason, teacher_id } = req.body;
  if (!student_id) return res.status(400).json({ error: 'student_id is required' });

  try {
    const { rows } = await pool.query(
      `INSERT INTO attendance (student_id, date, status, reason, teacher_id)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (student_id, date) DO UPDATE
         SET status     = EXCLUDED.status,
             reason     = EXCLUDED.reason,
             teacher_id = EXCLUDED.teacher_id
       RETURNING *`,
      [
        student_id,
        date       || new Date().toISOString().split('T')[0],
        status     || 'absent',
        reason     || null,
        teacher_id || null
      ]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error('Mark attendance error:', err);
    res.status(500).json({ error: 'Failed to mark attendance' });
  }
});

// POST /attendance/bulk — teacher marks whole class at once
app.post('/attendance/bulk', verifyToken, async (req, res) => {
  const { date, attendance } = req.body;
  if (!date) return res.status(400).json({ error: 'date is required' });
  if (!Array.isArray(attendance) || !attendance.length) {
    return res.status(400).json({ error: 'attendance array is required and must not be empty' });
  }

  try {
    const results = [];
    for (const record of attendance) {
      const { rows } = await pool.query(
        `INSERT INTO attendance (student_id, date, status, reason, teacher_id)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (student_id, date) DO UPDATE
           SET status     = EXCLUDED.status,
               reason     = EXCLUDED.reason,
               teacher_id = EXCLUDED.teacher_id
         RETURNING *`,
        [
          record.student_id,
          date,
          record.status || 'present',
          record.reason || null,
          req.teacher.id
        ]
      );
      results.push(rows[0]);
    }
    res.json({ success: true, count: results.length, records: results });
  } catch (err) {
    console.error('Bulk attendance error:', err);
    res.status(500).json({ error: 'Failed to save attendance' });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  GRADES
// ══════════════════════════════════════════════════════════════════════════════

// GET /grades
app.get('/grades', verifyToken, async (req, res) => {
  const { student_id, term, subject } = req.query;

  let query = `
    SELECT g.*, s.full_name, s.class, t.full_name AS teacher_name
    FROM grades g
    JOIN students s ON g.student_id = s.id
    JOIN teachers t ON g.teacher_id = t.id
    WHERE 1=1
  `;
  const params = [];

  if (student_id) {
    params.push(student_id);
    query += ` AND g.student_id = $${params.length}`;
  }
  if (term) {
    params.push(`%${term}%`);
    query += ` AND g.term ILIKE $${params.length}`;
  }
  if (subject) {
    params.push(`%${subject}%`);
    query += ` AND g.subject ILIKE $${params.length}`;
  }

  // Teachers see only grades they entered
  if (req.teacher.role === 'teacher') {
    params.push(req.teacher.id);
    query += ` AND g.teacher_id = $${params.length}`;
  }

  query += ' ORDER BY g.created_at DESC';

  try {
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    console.error('Get grades error:', err);
    res.status(500).json({ error: 'Failed to fetch grades' });
  }
});

// POST /grades
app.post('/grades', verifyToken, async (req, res) => {
  const { student_id, subject, score, grade, term, academic_year, notes } = req.body;
  if (!student_id || !subject) {
    return res.status(400).json({ error: 'student_id and subject are required' });
  }

  try {
    const { rows } = await pool.query(
      `INSERT INTO grades (student_id, teacher_id, subject, score, grade, term, academic_year, notes)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [
        student_id,
        req.teacher.id,
        subject,
        score         != null ? score : null,
        grade         || null,
        term          || null,
        academic_year || null,
        notes         || null
      ]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error('Create grade error:', err);
    res.status(500).json({ error: 'Failed to save grade' });
  }
});

// PATCH /grades/:id
app.patch('/grades/:id', verifyToken, async (req, res) => {
  const { score, grade, notes, subject, term } = req.body;

  try {
    const { rows } = await pool.query(
      `UPDATE grades SET
        score   = COALESCE($1, score),
        grade   = COALESCE($2, grade),
        notes   = COALESCE($3, notes),
        subject = COALESCE($4, subject),
        term    = COALESCE($5, term)
       WHERE id = $6
       RETURNING *`,
      [
        score   != null ? score : null,
        grade   || null,
        notes   || null,
        subject || null,
        term    || null,
        req.params.id
      ]
    );
    if (!rows.length) return res.status(404).json({ error: 'Grade not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('Update grade error:', err);
    res.status(500).json({ error: 'Failed to update grade' });
  }
});

// DELETE /grades/:id
app.delete('/grades/:id', verifyToken, async (req, res) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM grades WHERE id = $1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Grade not found' });
    res.json({ success: true });
  } catch (err) {
    console.error('Delete grade error:', err);
    res.status(500).json({ error: 'Failed to delete grade' });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  TEACHER NOTES
// ══════════════════════════════════════════════════════════════════════════════

// GET /notes
app.get('/notes', verifyToken, async (req, res) => {
  const { student_id } = req.query;

  let query = `
    SELECT n.*, s.full_name, t.full_name AS teacher_name
    FROM teacher_notes n
    JOIN students s ON n.student_id = s.id
    JOIN teachers t ON n.teacher_id = t.id
    WHERE 1=1
  `;
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
    console.error('Get notes error:', err);
    res.status(500).json({ error: 'Failed to fetch notes' });
  }
});

// POST /notes
app.post('/notes', verifyToken, async (req, res) => {
  const { student_id, note } = req.body;
  if (!student_id || !note) return res.status(400).json({ error: 'student_id and note are required' });

  try {
    const { rows } = await pool.query(
      `INSERT INTO teacher_notes (student_id, teacher_id, note)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [student_id, req.teacher.id, note]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error('Create note error:', err);
    res.status(500).json({ error: 'Failed to save note' });
  }
});

// DELETE /notes/:id
app.delete('/notes/:id', verifyToken, async (req, res) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM teacher_notes WHERE id = $1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Note not found' });
    res.json({ success: true });
  } catch (err) {
    console.error('Delete note error:', err);
    res.status(500).json({ error: 'Failed to delete note' });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  FEES
// ══════════════════════════════════════════════════════════════════════════════

// GET /fees — JWT or API key
app.get('/fees', verifyTokenOrApiKey, async (req, res) => {
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
    console.error('Get fees error:', err);
    res.status(500).json({ error: 'Failed to fetch fees' });
  }
});

// POST /fees — admin only
app.post('/fees', verifyToken, isAdmin, async (req, res) => {
  const { student_id, term, academic_year, amount_due, due_date } = req.body;
  if (!student_id || !term || !amount_due) {
    return res.status(400).json({ error: 'student_id, term, and amount_due are required' });
  }

  try {
    const { rows } = await pool.query(
      `INSERT INTO fees (student_id, term, academic_year, amount_due, due_date)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [student_id, term, academic_year || null, amount_due, due_date || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error('Create fee error:', err);
    res.status(500).json({ error: 'Failed to create fee record' });
  }
});

// PATCH /fees/:id — update general fee fields (admin)
app.patch('/fees/:id', verifyToken, isAdmin, async (req, res) => {
  const { term, academic_year, amount_due, due_date, status } = req.body;

  try {
    const { rows } = await pool.query(
      `UPDATE fees SET
        term          = COALESCE($1, term),
        academic_year = COALESCE($2, academic_year),
        amount_due    = COALESCE($3, amount_due),
        due_date      = COALESCE($4, due_date),
        status        = COALESCE($5, status)
       WHERE id = $6
       RETURNING *`,
      [
        term          || null,
        academic_year || null,
        amount_due    || null,
        due_date      || null,
        status        || null,
        req.params.id
      ]
    );
    if (!rows.length) return res.status(404).json({ error: 'Fee record not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('Update fee error:', err);
    res.status(500).json({ error: 'Failed to update fee record' });
  }
});

// PATCH /fees/:id/pay — record a payment (API key for bot, or admin JWT)
app.patch('/fees/:id/pay', verifyTokenOrApiKey, async (req, res) => {
  const { amount_paid } = req.body;
  if (!amount_paid || isNaN(amount_paid)) {
    return res.status(400).json({ error: 'amount_paid (number) is required' });
  }

  try {
    const { rows } = await pool.query(
      `UPDATE fees SET
        amount_paid = amount_paid + $1,
        status      = CASE
                        WHEN amount_paid + $1 >= amount_due THEN 'paid'
                        WHEN amount_paid + $1 > 0            THEN 'partial'
                        ELSE 'unpaid'
                      END,
        paid_date   = CASE
                        WHEN amount_paid + $1 >= amount_due THEN NOW()
                        ELSE paid_date
                      END
       WHERE id = $2
       RETURNING *`,
      [amount_paid, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Fee record not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('Pay fee error:', err);
    res.status(500).json({ error: 'Failed to record payment' });
  }
});

// DELETE /fees/:id — admin only
app.delete('/fees/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM fees WHERE id = $1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Fee record not found' });
    res.json({ success: true });
  } catch (err) {
    console.error('Delete fee error:', err);
    res.status(500).json({ error: 'Failed to delete fee record' });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  ANNOUNCEMENTS
// ══════════════════════════════════════════════════════════════════════════════

// GET /announcements — JWT or API key
app.get('/announcements', verifyTokenOrApiKey, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM announcements ORDER BY created_at DESC LIMIT 50'
    );
    res.json(rows);
  } catch (err) {
    console.error('Get announcements error:', err);
    res.status(500).json({ error: 'Failed to fetch announcements' });
  }
});

// POST /announcements — admin only
app.post('/announcements', verifyToken, isAdmin, async (req, res) => {
  const { title, message, target } = req.body;
  if (!message) return res.status(400).json({ error: 'message is required' });

  try {
    const { rows } = await pool.query(
      `INSERT INTO announcements (title, message, target)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [title || null, message, target || 'all']
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error('Create announcement error:', err);
    res.status(500).json({ error: 'Failed to create announcement' });
  }
});

// DELETE /announcements/:id — admin only
app.delete('/announcements/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM announcements WHERE id = $1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Announcement not found' });
    res.json({ success: true });
  } catch (err) {
    console.error('Delete announcement error:', err);
    res.status(500).json({ error: 'Failed to delete announcement' });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  SUBSCRIBERS (WhatsApp bot / n8n)
// ══════════════════════════════════════════════════════════════════════════════

// GET /subscribers — API key only
app.get('/subscribers', apiKeyAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM school_subscribers ORDER BY created_at DESC');
    res.json(rows);
  } catch (err) {
    console.error('Get subscribers error:', err);
    res.status(500).json({ error: 'Failed to fetch subscribers' });
  }
});

// POST /subscribers — API key only
app.post('/subscribers', apiKeyAuth, async (req, res) => {
  const { phone, parent_name, student_id } = req.body;
  if (!phone) return res.status(400).json({ error: 'phone is required' });

  try {
    const { rows } = await pool.query(
      `INSERT INTO school_subscribers (phone, parent_name, student_id)
       VALUES ($1, $2, $3)
       ON CONFLICT (phone) DO UPDATE
         SET parent_name = COALESCE($2, school_subscribers.parent_name),
             student_id  = COALESCE($3, school_subscribers.student_id)
       RETURNING *`,
      [phone, parent_name || null, student_id || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error('Create subscriber error:', err);
    res.status(500).json({ error: 'Failed to save subscriber' });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  STATS (admin dashboard)
// ══════════════════════════════════════════════════════════════════════════════

// GET /stats — admin only
app.get('/stats', verifyToken, isAdmin, async (req, res) => {
  try {
    const [students, teachers, fees, todayAtt, weekAtt] = await Promise.all([
      pool.query("SELECT COUNT(*) FROM students WHERE status = 'active' OR status IS NULL"),
      pool.query('SELECT COUNT(*) FROM teachers'),
      pool.query(`
        SELECT
          SUM(amount_due)                                    AS total_due,
          SUM(amount_paid)                                   AS total_paid,
          COUNT(*) FILTER (WHERE status = 'paid')            AS paid_count,
          COUNT(*) FILTER (WHERE status = 'partial')         AS partial_count,
          COUNT(*) FILTER (WHERE status = 'unpaid')          AS unpaid_count
        FROM fees
      `),
      pool.query(`
        SELECT
          COUNT(*) FILTER (WHERE status = 'present') AS present,
          COUNT(*) FILTER (WHERE status = 'absent')  AS absent
        FROM attendance
        WHERE date = CURRENT_DATE
      `),
      pool.query(`
        SELECT
          COUNT(*) FILTER (WHERE status = 'present') AS present,
          COUNT(*) FILTER (WHERE status = 'absent')  AS absent
        FROM attendance
        WHERE date >= CURRENT_DATE - INTERVAL '7 days'
      `)
    ]);

    res.json({
      total_students:    parseInt(students.rows[0].count),
      total_teachers:    parseInt(teachers.rows[0].count),
      fees:              fees.rows[0],
      today_attendance:  todayAtt.rows[0],
      week_attendance:   weekAtt.rows[0]
    });
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// ─── 404 catch-all ────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: `Route ${req.method} ${req.path} not found` });
});

// ─── Global error handler ─────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`School Portal API running on port ${PORT}`));
