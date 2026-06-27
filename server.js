const express  = require('express');
const { Pool } = require('pg');
const dotenv   = require('dotenv');
const crypto   = require('crypto');

dotenv.config();

const app = express();
app.use(express.json());
app.use(express.static('public'));

// ─── CORS ────────────────────────────────────────────────────────────────────
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
const hashPassword = (pw) =>
  crypto.createHash('sha256').update(pw + (process.env.API_KEY || 'secret')).digest('hex');

// Token payload includes: id, role, account_type ('staff' | 'student')
const generateToken = (user, account_type) =>
  Buffer.from(JSON.stringify({
    id:           user.id,
    role:         user.role || 'student',
    account_type,
    email:        user.email || null,
    student_id:   user.student_id || null,
    exp:          Date.now() + 86400000
  })).toString('base64');

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────

// Verify JWT (sets req.user)
const verifyToken = (req, res, next) => {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = JSON.parse(
      Buffer.from(auth.replace('Bearer ', ''), 'base64').toString()
    );
    if (decoded.exp < Date.now())
      return res.status(401).json({ error: 'Session expired — please log in again' });
    req.user = decoded;
    // Keep req.teacher as alias for backwards compat
    req.teacher = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Admin / Principal only
const isAdmin = (req, res, next) => {
  if (!['admin', 'principal'].includes(req.user.role))
    return res.status(403).json({ error: 'Admin access required' });
  next();
};

// Staff only (admin, principal, teacher)
const isStaff = (req, res, next) => {
  if (req.user.account_type !== 'staff')
    return res.status(403).json({ error: 'Staff access required' });
  next();
};

// API key (WhatsApp bot / n8n)
const apiKeyAuth = (req, res, next) => {
  if (req.headers['x-api-key'] !== process.env.API_KEY)
    return res.status(401).json({ error: 'Invalid API key' });
  next();
};

// JWT or API key
const verifyAny = (req, res, next) => {
  if (req.headers['x-api-key'] === process.env.API_KEY) return next();
  return verifyToken(req, res, next);
};

// ─── HEALTH ───────────────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ status: 'ok', ts: new Date().toISOString() }));


// ══════════════════════════════════════════════════════════════════════════════
//  AUTH — unified login for all roles
// ══════════════════════════════════════════════════════════════════════════════

/**
 * POST /auth/login
 * Body: { email, password }
 * Returns: { token, user: { id, full_name, email, role, account_type, class?, grade? } }
 *
 * Checks teachers table first (admin/principal/teacher),
 * then student_accounts table (student/parent).
 */
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email and password are required' });

  const hashed = hashPassword(password);

  try {
    // 1) Check staff (teachers table)
    const staff = await pool.query(
      'SELECT * FROM teachers WHERE LOWER(email) = LOWER($1) AND password = $2',
      [email.trim(), hashed]
    );
    if (staff.rows.length) {
      const u = staff.rows[0];
      return res.json({
        token: generateToken(u, 'staff'),
        user: {
          id:           u.id,
          full_name:    u.full_name,
          email:        u.email,
          role:         u.role,          // admin | principal | teacher
          account_type: 'staff',
          class:        u.class || null
        }
      });
    }

    // 2) Check student / parent accounts table
    const student = await pool.query(
      'SELECT * FROM student_accounts WHERE LOWER(email) = LOWER($1) AND password = $2',
      [email.trim(), hashed]
    );
    if (student.rows.length) {
      const u = student.rows[0];
      return res.json({
        token: generateToken(u, 'student'),
        user: {
          id:           u.id,
          full_name:    u.full_name,
          email:        u.email,
          role:         u.role,          // student | parent
          account_type: 'student',
          student_id:   u.student_id || null,   // for 'student' role
          grade:        u.grade || null,
          class:        u.class || null
        }
      });
    }

    return res.status(401).json({ error: 'Invalid email or password' });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error during login' });
  }
});

/**
 * POST /auth/register/student
 * Public route — student or parent creates their own account.
 * Body: { full_name, email, password, role ('student'|'parent'),
 *         grade, class, student_name (for parent linking) }
 *
 * For 'student': tries to auto-link to students table by full_name + class match.
 * For 'parent':  tries to auto-link to students table by student_name + class match.
 */
app.post('/auth/register/student', async (req, res) => {
  const {
    full_name, email, password, role,
    grade, class: className, student_name, courses,
    parent_name, parent_email, parent_phone
  } = req.body;

  if (!full_name || !email || !password || !role)
    return res.status(400).json({ error: 'full_name, email, password, and role are required' });
  if (!['student', 'parent'].includes(role))
    return res.status(400).json({ error: 'role must be "student" or "parent"' });

  try {
    const hashed = hashPassword(password);

    // ── SMART AUTO-LINK ──────────────────────────────────────────
    // The name to search for:
    //   student → their own full_name
    //   parent  → their child's name (student_name field)
    let student_id = null;
    const searchName = (role === 'student' ? full_name : student_name || '').trim();

    if (searchName) {
      // Step 1: try exact name + class match (best case)
      if (className) {
        const exact = await pool.query(
          `SELECT id FROM students
           WHERE LOWER(TRIM(full_name)) = LOWER(TRIM($1))
             AND LOWER(TRIM(class)) = LOWER(TRIM($2))
           LIMIT 1`,
          [searchName, className]
        );
        if (exact.rows.length) student_id = exact.rows[0].id;
      }

      // Step 2: if no exact match, try name only (ignore class)
      if (!student_id) {
        const byName = await pool.query(
          `SELECT id FROM students
           WHERE LOWER(TRIM(full_name)) = LOWER(TRIM($1))
           LIMIT 1`,
          [searchName]
        );
        if (byName.rows.length) student_id = byName.rows[0].id;
      }

      // Step 3: fuzzy match — name contains searchName (catches typos/partial)
      if (!student_id) {
        const fuzzy = await pool.query(
          `SELECT id, full_name FROM students
           WHERE LOWER(full_name) ILIKE LOWER($1)
           LIMIT 1`,
          [`%${searchName}%`]
        );
        if (fuzzy.rows.length) student_id = fuzzy.rows[0].id;
      }
    }
    // ─────────────────────────────────────────────────────────────

    const { rows } = await pool.query(
      `INSERT INTO student_accounts
         (full_name, email, password, role, grade, class, student_id, courses)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       RETURNING id, full_name, email, role, grade, class, student_id`,
      [
        full_name,
        email.trim().toLowerCase(),
        hashed,
        role,
        grade      || null,
        className  || null,
        student_id,
        courses    || null
      ]
    );

    // Also update the student record with parent info if provided
    if (student_id && role === 'student' && (parent_name || parent_email || parent_phone)) {
      await pool.query(
        `UPDATE students SET
           parent_name  = COALESCE($1, parent_name),
           parent_email = COALESCE($2, parent_email),
           parent_phone = COALESCE($3, parent_phone)
         WHERE id = $4`,
        [parent_name||null, parent_email||null, parent_phone||null, student_id]
      );
    }

    const u = rows[0];
    res.status(201).json({
      token: generateToken(u, 'student'),
      user: {
        id:           u.id,
        full_name:    u.full_name,
        email:        u.email,
        role:         u.role,
        account_type: 'student',
        grade:        u.grade,
        class:        u.class,
        student_id:   u.student_id
      },
      // Tell the frontend whether auto-link worked
      linked: !!student_id,
      message: student_id
        ? 'Account created and linked successfully!'
        : 'Account created. Please ask your admin to link your account.'
    });
  } catch (err) {
    if (err.code === '23505')
      return res.status(409).json({ error: 'An account with this email already exists' });
    console.error('Register student error:', err);
    res.status(500).json({ error: 'Failed to create account' });
  }
});

/**
 * POST /auth/setup — create first admin (secret required)
 */
app.post('/auth/setup', async (req, res) => {
  const { full_name, email, password, secret } = req.body;
  if (secret !== process.env.API_KEY)
    return res.status(401).json({ error: 'Invalid setup secret' });

  try {
    const { rows } = await pool.query(
      `INSERT INTO teachers (full_name, email, password, role)
       VALUES ($1,$2,$3,'admin')
       RETURNING id, full_name, email, role`,
      [full_name, email, hashPassword(password)]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23505')
      return res.status(409).json({ error: 'Email already exists' });
    res.status(500).json({ error: 'Setup failed' });
  }
});


// ══════════════════════════════════════════════════════════════════════════════
//  TEACHERS  (admin/principal only for mutations)
// ══════════════════════════════════════════════════════════════════════════════

app.get('/teachers', verifyToken, isAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, full_name, email, class, role, created_at FROM teachers ORDER BY full_name'
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch teachers' }); }
});

app.post('/teachers', verifyToken, isAdmin, async (req, res) => {
  const { full_name, email, password, class: cls, role } = req.body;
  if (!full_name || !email || !password)
    return res.status(400).json({ error: 'full_name, email, and password are required' });

  try {
    const { rows } = await pool.query(
      `INSERT INTO teachers (full_name, email, password, class, role)
       VALUES ($1,$2,$3,$4,$5)
       RETURNING id, full_name, email, class, role`,
      [full_name, email, hashPassword(password), cls || null, role || 'teacher']
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Email already in use' });
    res.status(500).json({ error: 'Failed to create teacher' });
  }
});

app.patch('/teachers/:id', verifyToken, isAdmin, async (req, res) => {
  const { full_name, class: cls, role } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE teachers SET
         full_name = COALESCE($1, full_name),
         class     = COALESCE($2, class),
         role      = COALESCE($3, role)
       WHERE id = $4
       RETURNING id, full_name, email, class, role`,
      [full_name || null, cls || null, role || null, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Teacher not found' });
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to update teacher' }); }
});

app.delete('/teachers/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM teachers WHERE id = $1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Teacher not found' });
    res.json({ success: true, deleted_id: parseInt(req.params.id) });
  } catch (err) { res.status(500).json({ error: 'Failed to delete teacher' }); }
});


// ══════════════════════════════════════════════════════════════════════════════
//  STUDENT ACCOUNTS  (admin can list/manage; public register is above)
// ══════════════════════════════════════════════════════════════════════════════

// Admin: list all student/parent accounts
app.get('/student-accounts', verifyToken, isAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT sa.id, sa.full_name, sa.email, sa.role, sa.grade, sa.class,
              sa.student_id, s.full_name AS linked_student, sa.created_at
       FROM student_accounts sa
       LEFT JOIN students s ON sa.student_id = s.id
       ORDER BY sa.full_name`
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch accounts' }); }
});

// Admin: manually link a student_account to a student record
app.patch('/student-accounts/:id', verifyToken, isAdmin, async (req, res) => {
  const { student_id, grade, class: cls } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE student_accounts SET
         student_id = COALESCE($1, student_id),
         grade      = COALESCE($2, grade),
         class      = COALESCE($3, class)
       WHERE id = $4
       RETURNING id, full_name, email, role, grade, class, student_id`,
      [student_id || null, grade || null, cls || null, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Account not found' });
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to update account' }); }
});

app.delete('/student-accounts/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM student_accounts WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete account' }); }
});


// ══════════════════════════════════════════════════════════════════════════════
//  STUDENTS  (the school record — separate from login accounts)
// ══════════════════════════════════════════════════════════════════════════════

app.get('/students', verifyToken, async (req, res) => {
  try {
    let query = 'SELECT * FROM students WHERE 1=1';
    const params = [];

    // STUDENT: can only see their own record
    if (req.user.role === 'student') {
      if (!req.user.student_id)
        return res.json([]); // not linked yet
      params.push(req.user.student_id);
      query += ` AND id = $${params.length}`;

    // PARENT: see children linked to their account
    } else if (req.user.role === 'parent') {
      const linked = await pool.query(
        'SELECT student_id FROM student_accounts WHERE id = $1', [req.user.id]
      );
      const sid = linked.rows[0]?.student_id;
      if (!sid) return res.json([]);
      params.push(sid);
      query += ` AND id = $${params.length}`;

    // TEACHER: see only their class (ILIKE for case-insensitive)
    } else if (req.user.role === 'teacher') {
      const tr = await pool.query('SELECT class FROM teachers WHERE id = $1', [req.user.id]);
      const cls = tr.rows[0]?.class;
      if (cls) {
        params.push(cls);
        query += ` AND class ILIKE $${params.length}`;
      }
      // no class set → see all (so teacher is never locked out)
    }
    // admin / principal → no filter, see all

    if (req.query.class && !['student','parent'].includes(req.user.role)) {
      params.push(req.query.class);
      query += ` AND class ILIKE $${params.length}`;
    }
    if (req.query.status) {
      params.push(req.query.status);
      query += ` AND status = $${params.length}`;
    }

    query += ' ORDER BY full_name ASC';
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    console.error('Get students:', err);
    res.status(500).json({ error: 'Failed to fetch students' });
  }
});

app.get('/students/phone/:phone', apiKeyAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM students WHERE parent_phone ILIKE $1', [`%${req.params.phone}%`]
    );
    if (!rows.length) return res.status(404).json({ error: 'No student found for this phone' });
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Lookup failed' }); }
});

app.get('/students/:id', verifyToken, async (req, res) => {
  try {
    // Students can only get their own record
    if (req.user.role === 'student' && req.user.student_id != req.params.id)
      return res.status(403).json({ error: 'Access denied' });

    const { rows } = await pool.query('SELECT * FROM students WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Student not found' });
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch student' }); }
});

// Only staff can create school student records
app.post('/students', verifyToken, isStaff, async (req, res) => {
  const { full_name, class: cls, date_of_birth, parent_phone, parent_name, parent_email, gender } = req.body;
  if (!full_name) return res.status(400).json({ error: 'full_name is required' });

  try {
    const { rows } = await pool.query(
      `INSERT INTO students (full_name, class, date_of_birth, parent_phone, parent_name, parent_email, gender)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [full_name, cls||null, date_of_birth||null, parent_phone||null, parent_name||null, parent_email||null, gender||null]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error('Create student:', err);
    res.status(500).json({ error: 'Failed to create student' });
  }
});

app.patch('/students/:id', verifyToken, isStaff, async (req, res) => {
  const { full_name, class: cls, parent_phone, parent_name, parent_email, status, gender, date_of_birth } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE students SET
         full_name     = COALESCE($1, full_name),
         class         = COALESCE($2, class),
         parent_phone  = COALESCE($3, parent_phone),
         parent_name   = COALESCE($4, parent_name),
         parent_email  = COALESCE($5, parent_email),
         status        = COALESCE($6, status),
         gender        = COALESCE($7, gender),
         date_of_birth = COALESCE($8, date_of_birth)
       WHERE id = $9 RETURNING *`,
      [full_name||null, cls||null, parent_phone||null, parent_name||null,
       parent_email||null, status||null, gender||null, date_of_birth||null, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Student not found' });
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to update student' }); }
});

app.delete('/students/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM students WHERE id = $1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Student not found' });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete student' }); }
});


// ══════════════════════════════════════════════════════════════════════════════
//  ATTENDANCE
// ══════════════════════════════════════════════════════════════════════════════

app.get('/attendance', verifyToken, async (req, res) => {
  const { student_id, date, class: cls } = req.query;

  let query = `
    SELECT a.*, s.full_name, s.class
    FROM attendance a
    JOIN students s ON a.student_id = s.id
    WHERE 1=1
  `;
  const params = [];

  // STUDENT: only their own attendance
  if (req.user.role === 'student') {
    if (!req.user.student_id) return res.json([]);
    params.push(req.user.student_id);
    query += ` AND a.student_id = $${params.length}`;

  // PARENT: only their child
  } else if (req.user.role === 'parent') {
    const linked = await pool.query(
      'SELECT student_id FROM student_accounts WHERE id = $1', [req.user.id]
    );
    const sid = linked.rows[0]?.student_id;
    if (!sid) return res.json([]);
    params.push(sid);
    query += ` AND a.student_id = $${params.length}`;

  // TEACHER: only their class
  } else if (req.user.role === 'teacher') {
    const tr = await pool.query('SELECT class FROM teachers WHERE id = $1', [req.user.id]);
    const teacherCls = tr.rows[0]?.class;
    if (teacherCls) {
      params.push(teacherCls);
      query += ` AND s.class ILIKE $${params.length}`;
    }
  }

  // Optional filters (staff only filters below)
  if (student_id && ['admin','principal'].includes(req.user.role)) {
    params.push(student_id);
    query += ` AND a.student_id = $${params.length}`;
  }
  if (date) {
    params.push(date);
    query += ` AND a.date = $${params.length}`;
  }
  if (cls && ['admin','principal'].includes(req.user.role)) {
    params.push(cls);
    query += ` AND s.class ILIKE $${params.length}`;
  }

  query += ' ORDER BY a.date DESC, s.full_name ASC';

  try {
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    console.error('Get attendance:', err);
    res.status(500).json({ error: 'Failed to fetch attendance' });
  }
});

app.post('/attendance', verifyAny, async (req, res) => {
  const { student_id, date, status, reason, teacher_id } = req.body;
  if (!student_id) return res.status(400).json({ error: 'student_id is required' });

  try {
    const { rows } = await pool.query(
      `INSERT INTO attendance (student_id, date, status, reason, teacher_id)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (student_id, date) DO UPDATE
         SET status = EXCLUDED.status, reason = EXCLUDED.reason, teacher_id = EXCLUDED.teacher_id
       RETURNING *`,
      [student_id, date || new Date().toISOString().split('T')[0], status||'absent', reason||null, teacher_id||null]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to mark attendance' }); }
});

app.post('/attendance/bulk', verifyToken, isStaff, async (req, res) => {
  const { date, attendance } = req.body;
  if (!date || !Array.isArray(attendance) || !attendance.length)
    return res.status(400).json({ error: 'date and non-empty attendance array required' });

  try {
    const results = [];
    for (const r of attendance) {
      const { rows } = await pool.query(
        `INSERT INTO attendance (student_id, date, status, reason, teacher_id)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (student_id, date) DO UPDATE
           SET status = EXCLUDED.status, reason = EXCLUDED.reason, teacher_id = EXCLUDED.teacher_id
         RETURNING *`,
        [r.student_id, date, r.status||'present', r.reason||null, req.user.id]
      );
      results.push(rows[0]);
    }
    res.json({ success: true, count: results.length, records: results });
  } catch (err) {
    console.error('Bulk attendance:', err);
    res.status(500).json({ error: 'Failed to save attendance' });
  }
});


// ══════════════════════════════════════════════════════════════════════════════
//  GRADES
// ══════════════════════════════════════════════════════════════════════════════

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

  // STUDENT: only their own grades
  if (req.user.role === 'student') {
    if (!req.user.student_id) return res.json([]);
    params.push(req.user.student_id);
    query += ` AND g.student_id = $${params.length}`;

  // PARENT: only their child's grades
  } else if (req.user.role === 'parent') {
    const linked = await pool.query(
      'SELECT student_id FROM student_accounts WHERE id = $1', [req.user.id]
    );
    const sid = linked.rows[0]?.student_id;
    if (!sid) return res.json([]);
    params.push(sid);
    query += ` AND g.student_id = $${params.length}`;

  // TEACHER: only grades THEY entered (for their students)
  } else if (req.user.role === 'teacher') {
    params.push(req.user.id);
    query += ` AND g.teacher_id = $${params.length}`;
  }

  // Optional filters
  if (student_id && ['admin','principal'].includes(req.user.role)) {
    params.push(student_id);
    query += ` AND g.student_id = $${params.length}`;
  }
  if (term) { params.push(`%${term}%`); query += ` AND g.term ILIKE $${params.length}`; }
  if (subject) { params.push(`%${subject}%`); query += ` AND g.subject ILIKE $${params.length}`; }

  query += ' ORDER BY g.created_at DESC';

  try {
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    console.error('Get grades:', err);
    res.status(500).json({ error: 'Failed to fetch grades' });
  }
});

app.post('/grades', verifyToken, isStaff, async (req, res) => {
  const { student_id, subject, score, grade, term, academic_year, notes } = req.body;
  if (!student_id || !subject)
    return res.status(400).json({ error: 'student_id and subject are required' });

  try {
    const { rows } = await pool.query(
      `INSERT INTO grades (student_id, teacher_id, subject, score, grade, term, academic_year, notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [student_id, req.user.id, subject, score??null, grade||null, term||null, academic_year||null, notes||null]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to save grade' }); }
});

app.patch('/grades/:id', verifyToken, isStaff, async (req, res) => {
  const { score, grade, notes, subject, term } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE grades SET
         score   = COALESCE($1, score),
         grade   = COALESCE($2, grade),
         notes   = COALESCE($3, notes),
         subject = COALESCE($4, subject),
         term    = COALESCE($5, term)
       WHERE id = $6 RETURNING *`,
      [score??null, grade||null, notes||null, subject||null, term||null, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Grade not found' });
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to update grade' }); }
});

app.delete('/grades/:id', verifyToken, isStaff, async (req, res) => {
  try {
    await pool.query('DELETE FROM grades WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete grade' }); }
});


// ══════════════════════════════════════════════════════════════════════════════
//  TEACHER NOTES
// ══════════════════════════════════════════════════════════════════════════════

app.get('/notes', verifyToken, isStaff, async (req, res) => {
  const { student_id } = req.query;
  let query = `
    SELECT n.*, s.full_name, t.full_name AS teacher_name
    FROM teacher_notes n
    JOIN students s ON n.student_id = s.id
    JOIN teachers t ON n.teacher_id = t.id
    WHERE 1=1
  `;
  const params = [];
  if (student_id) { params.push(student_id); query += ` AND n.student_id = $${params.length}`; }
  if (req.user.role === 'teacher') { params.push(req.user.id); query += ` AND n.teacher_id = $${params.length}`; }
  query += ' ORDER BY n.created_at DESC';

  try {
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch notes' }); }
});

app.post('/notes', verifyToken, isStaff, async (req, res) => {
  const { student_id, note } = req.body;
  if (!student_id || !note) return res.status(400).json({ error: 'student_id and note required' });
  try {
    const { rows } = await pool.query(
      'INSERT INTO teacher_notes (student_id, teacher_id, note) VALUES ($1,$2,$3) RETURNING *',
      [student_id, req.user.id, note]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to save note' }); }
});

app.delete('/notes/:id', verifyToken, isStaff, async (req, res) => {
  try {
    await pool.query('DELETE FROM teacher_notes WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete note' }); }
});


// ══════════════════════════════════════════════════════════════════════════════
//  FEES  —  admin/principal manage; teacher READ-ONLY for their class
// ══════════════════════════════════════════════════════════════════════════════

app.get('/fees', verifyAny, async (req, res) => {
  const { student_id, status, term } = req.query;
  let query = 'SELECT * FROM fees WHERE 1=1';
  const params = [];

  // Parent / student: only their own fees
  if (req.user?.role === 'parent' || req.user?.role === 'student') {
    const linked = await pool.query(
      'SELECT student_id FROM student_accounts WHERE id = $1', [req.user.id]
    );
    const sid = linked.rows[0]?.student_id;
    if (!sid) return res.json([]);
    params.push(sid);
    query += ` AND student_id = $${params.length}`;
  } else {
    // staff filters
    if (student_id) { params.push(student_id); query += ` AND student_id = $${params.length}`; }
    if (status)     { params.push(status);     query += ` AND status = $${params.length}`; }
    if (term)       { params.push(`%${term}%`); query += ` AND term ILIKE $${params.length}`; }
  }

  query += ' ORDER BY created_at DESC';
  try {
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch fees' }); }
});

// Only admin/principal can create fee records
app.post('/fees', verifyToken, isAdmin, async (req, res) => {
  const { student_id, term, academic_year, amount_due, due_date } = req.body;
  if (!student_id || !term || !amount_due)
    return res.status(400).json({ error: 'student_id, term, amount_due required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO fees (student_id, term, academic_year, amount_due, due_date)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [student_id, term, academic_year||null, amount_due, due_date||null]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to create fee' }); }
});

app.patch('/fees/:id', verifyToken, isAdmin, async (req, res) => {
  const { term, academic_year, amount_due, due_date, status } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE fees SET
         term=COALESCE($1,term), academic_year=COALESCE($2,academic_year),
         amount_due=COALESCE($3,amount_due), due_date=COALESCE($4,due_date), status=COALESCE($5,status)
       WHERE id=$6 RETURNING *`,
      [term||null, academic_year||null, amount_due||null, due_date||null, status||null, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Fee not found' });
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to update fee' }); }
});

app.patch('/fees/:id/pay', verifyAny, async (req, res) => {
  const { amount_paid } = req.body;
  if (!amount_paid) return res.status(400).json({ error: 'amount_paid required' });
  try {
    const { rows } = await pool.query(
      `UPDATE fees SET
         amount_paid = amount_paid + $1,
         status = CASE WHEN amount_paid+$1 >= amount_due THEN 'paid'
                       WHEN amount_paid+$1 > 0 THEN 'partial' ELSE 'unpaid' END,
         paid_date = CASE WHEN amount_paid+$1 >= amount_due THEN NOW() ELSE paid_date END
       WHERE id=$2 RETURNING *`,
      [amount_paid, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Fee not found' });
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to record payment' }); }
});

app.delete('/fees/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM fees WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete fee' }); }
});


// ══════════════════════════════════════════════════════════════════════════════
//  ANNOUNCEMENTS
// ══════════════════════════════════════════════════════════════════════════════

app.get('/announcements', verifyAny, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM announcements ORDER BY created_at DESC LIMIT 50'
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch announcements' }); }
});

// Only admin can post announcements
app.post('/announcements', verifyToken, isAdmin, async (req, res) => {
  const { title, message, target } = req.body;
  if (!message) return res.status(400).json({ error: 'message required' });

  try {
    // 1. Save announcement to DB
    const { rows } = await pool.query(
      `INSERT INTO announcements (title, message, target) VALUES ($1,$2,$3) RETURNING *`,
      [title||null, message, target||'all']
    );
    const announcement = rows[0];

    // 2. Respond to dashboard immediately (don't make admin wait)
    res.status(201).json(announcement);

    // 3. Fire-and-forget: notify n8n to broadcast to all WhatsApp subscribers
    if (process.env.N8N_ANNOUNCEMENT_WEBHOOK) {
      fetch(process.env.N8N_ANNOUNCEMENT_WEBHOOK, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title:   title   || 'School Announcement',
          message: message,
          sent_at: new Date().toISOString()
        })
      }).catch(err => console.error('n8n webhook failed:', err));
    }

  } catch (err) {
    console.error('Post announcement error:', err);
    res.status(500).json({ error: 'Failed to post announcement' });
  }
});

app.delete('/announcements/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM announcements WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete announcement' }); }
});


// ══════════════════════════════════════════════════════════════════════════════
//  SUBSCRIBERS (WhatsApp bot)
// ══════════════════════════════════════════════════════════════════════════════

app.get('/subscribers', apiKeyAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM school_subscribers ORDER BY created_at DESC');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch subscribers' }); }
});

app.post('/subscribers', apiKeyAuth, async (req, res) => {
  const { phone, parent_name, student_id } = req.body;
  if (!phone) return res.status(400).json({ error: 'phone required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO school_subscribers (phone, parent_name, student_id)
       VALUES ($1,$2,$3)
       ON CONFLICT (phone) DO UPDATE
         SET parent_name=COALESCE($2,school_subscribers.parent_name),
             student_id=COALESCE($3,school_subscribers.student_id)
       RETURNING *`,
      [phone, parent_name||null, student_id||null]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to save subscriber' }); }
});


// ══════════════════════════════════════════════════════════════════════════════
//  STATS  (admin / principal only)
// ══════════════════════════════════════════════════════════════════════════════

app.get('/stats', verifyToken, isAdmin, async (req, res) => {
  try {
    const [students, teachers, studentAccounts, fees, todayAtt, weekAtt] = await Promise.all([
      pool.query(`SELECT COUNT(*) FROM students WHERE status='active' OR status IS NULL`),
      pool.query(`SELECT COUNT(*) FROM teachers`),
      pool.query(`SELECT COUNT(*) FROM student_accounts`),
      pool.query(`
        SELECT SUM(amount_due) AS total_due, SUM(amount_paid) AS total_paid,
          COUNT(*) FILTER (WHERE status='paid')    AS paid_count,
          COUNT(*) FILTER (WHERE status='partial') AS partial_count,
          COUNT(*) FILTER (WHERE status='unpaid')  AS unpaid_count
        FROM fees`),
      pool.query(`
        SELECT COUNT(*) FILTER (WHERE status='present') AS present,
               COUNT(*) FILTER (WHERE status='absent')  AS absent
        FROM attendance WHERE date=CURRENT_DATE`),
      pool.query(`
        SELECT COUNT(*) FILTER (WHERE status='present') AS present,
               COUNT(*) FILTER (WHERE status='absent')  AS absent
        FROM attendance WHERE date >= CURRENT_DATE - INTERVAL '7 days'`)
    ]);

    res.json({
      total_students:      parseInt(students.rows[0].count),
      total_teachers:      parseInt(teachers.rows[0].count),
      total_accounts:      parseInt(studentAccounts.rows[0].count),
      fees:                fees.rows[0],
      today_attendance:    todayAtt.rows[0],
      week_attendance:     weekAtt.rows[0]
    });
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});


// ─── 404 & error handlers ────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: `${req.method} ${req.path} not found` }));
app.use((err, req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`School Portal API running on port ${PORT}`));
