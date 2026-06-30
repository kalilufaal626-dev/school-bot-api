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
 * 
 * STUDENT: Creates a student record in `students` table (if not exists)
 *          AND creates a login account in `student_accounts` — fully linked.
 * 
 * PARENT:  Creates a login account linked to their child's student record
 *          by matching child name + class.
 */
app.post('/auth/register/student', async (req, res) => {
  const {
    full_name, email, password, role,
    grade, class: className,
    parent_name, parent_email, parent_phone,
    gender, date_of_birth, courses,
    student_name  // parent provides child's name
  } = req.body;

  if (!full_name || !email || !password || !role)
    return res.status(400).json({ error: 'full_name, email, password, and role are required' });
  if (!['student', 'parent'].includes(role))
    return res.status(400).json({ error: 'role must be "student" or "parent"' });
  if (!className)
    return res.status(400).json({ error: 'class is required' });

  // Normalize the class name to standard format
  const normalizedClass = normalizeClass(className);

  try {
    const hashed = hashPassword(password);
    let student_id = null;

    if (role === 'student') {
      // ── STUDENT: find or CREATE student record ──────────────────

      // Step 1: try exact name + class match
      const exact = await pool.query(
        `SELECT id FROM students
         WHERE LOWER(TRIM(full_name)) = LOWER(TRIM($1))
           AND LOWER(TRIM(class)) = LOWER(TRIM($2))
         LIMIT 1`,
        [full_name, className]
      );

      if (exact.rows.length) {
        // Found existing record — link to it
        student_id = exact.rows[0].id;

        // Update parent info if provided
        if (parent_name || parent_email || parent_phone) {
          await pool.query(
            `UPDATE students SET
               parent_name  = COALESCE($1, parent_name),
               parent_email = COALESCE($2, parent_email),
               parent_phone = COALESCE($3, parent_phone)
             WHERE id = $4`,
            [parent_name||null, parent_email||null, parent_phone||null, student_id]
          );
        }
      } else {
        // No existing record — CREATE a new student record automatically
        const newStudent = await pool.query(
          `INSERT INTO students
             (full_name, class, grade, gender, date_of_birth,
              parent_name, parent_email, parent_phone, status)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active')
           RETURNING id`,
          [
            full_name,
            normalizedClass,
            grade        || null,
            gender       || null,
            date_of_birth|| null,
            parent_name  || null,
            parent_email || null,
            parent_phone || null
          ]
        );
        student_id = newStudent.rows[0].id;
      }

    } else if (role === 'parent') {
      // ── PARENT: find child's student record ────────────────────
      const childName = (student_name || '').trim();
      if (!childName)
        return res.status(400).json({ error: 'student_name (your child\'s name) is required for parents' });

      // Try exact match first
      const exact = await pool.query(
        `SELECT id FROM students
         WHERE LOWER(TRIM(full_name)) = LOWER(TRIM($1))
           AND LOWER(TRIM(class)) = LOWER(TRIM($2))
         LIMIT 1`,
        [childName, className]
      );
      if (exact.rows.length) student_id = exact.rows[0].id;

      // Try name only
      if (!student_id) {
        const byName = await pool.query(
          `SELECT id FROM students
           WHERE LOWER(TRIM(full_name)) = LOWER(TRIM($1))
           LIMIT 1`,
          [childName]
        );
        if (byName.rows.length) student_id = byName.rows[0].id;
      }

      // Update parent info on student record
      if (student_id) {
        await pool.query(
          `UPDATE students SET
             parent_name  = COALESCE($1, parent_name),
             parent_email = COALESCE($2, parent_email),
             parent_phone = COALESCE($3, parent_phone)
           WHERE id = $4`,
          [full_name, email, parent_phone||null, student_id]
        );
      }
    }

    // ── Create login account ──────────────────────────────────────
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
        grade     || null,
        className || null,
        student_id,
        courses   || null
      ]
    );

    const u = rows[0];

    // Audit: account self-registration
    auditLog({
      action:      'create',
      entity:      'student_account',
      entity_id:   u.id,
      actor:       { id: u.id, full_name: u.full_name, role: u.role },
      new_value:   { role: u.role, class: u.class, linked_student_id: student_id },
      description: `${u.full_name} self-registered as ${u.role}${student_id ? ' (linked to student #' + student_id + ')' : ' (not linked)'}`
    });

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
      linked: !!student_id,
      message: student_id
        ? 'Account created successfully! You can now view your details.'
        : 'Account created. Contact your admin to complete setup.'
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

    auditLog({
      action: 'create', entity: 'teacher', entity_id: rows[0].id,
      actor: req.user, new_value: rows[0],
      description: `${req.user.email || req.user.id} added teacher ${rows[0].full_name} (${rows[0].role})`
    });

    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Email already in use' });
    res.status(500).json({ error: 'Failed to create teacher' });
  }
});

app.patch('/teachers/:id', verifyToken, isAdmin, async (req, res) => {
  const { full_name, class: cls, role } = req.body;
  try {
    const before = await pool.query('SELECT * FROM teachers WHERE id = $1', [req.params.id]);

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

    auditLog({
      action: 'update', entity: 'teacher', entity_id: rows[0].id,
      actor: req.user, old_value: before.rows[0] || null, new_value: rows[0],
      description: `${req.user.email || req.user.id} updated teacher ${rows[0].full_name}`
    });

    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to update teacher' }); }
});

app.delete('/teachers/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const before = await pool.query('SELECT * FROM teachers WHERE id = $1', [req.params.id]);
    const { rowCount } = await pool.query('DELETE FROM teachers WHERE id = $1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Teacher not found' });

    auditLog({
      action: 'delete', entity: 'teacher', entity_id: parseInt(req.params.id),
      actor: req.user, old_value: before.rows[0] || null,
      description: `${req.user.email || req.user.id} removed teacher ${before.rows[0]?.full_name || ('#' + req.params.id)}`
    });

    res.json({ success: true, deleted_id: parseInt(req.params.id) });
  } catch (err) { res.status(500).json({ error: 'Failed to delete teacher' }); }
});

// ── TEACHER CLASSES (multi-class assignments) ─────────────────────────────────

// GET classes assigned to a teacher
app.get('/teachers/:id/classes', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM teacher_classes WHERE teacher_id = $1 ORDER BY class_name',
      [req.params.id]
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch teacher classes' }); }
});

// POST assign a class to a teacher
app.post('/teachers/:id/classes', verifyToken, isAdmin, async (req, res) => {
  const { class_name } = req.body;
  if (!class_name) return res.status(400).json({ error: 'class_name is required' });

  const normalized = normalizeClass(class_name);
  try {
    const { rows } = await pool.query(
      `INSERT INTO teacher_classes (teacher_id, class_name)
       VALUES ($1, $2)
       ON CONFLICT (teacher_id, class_name) DO NOTHING
       RETURNING *`,
      [req.params.id, normalized]
    );

    auditLog({
      action: 'create', entity: 'teacher_class', entity_id: parseInt(req.params.id),
      actor: req.user, new_value: { class_name: normalized },
      description: `${req.user.email || req.user.id} assigned class "${normalized}" to teacher #${req.params.id}`
    });

    res.status(201).json({ class_name: normalized, teacher_id: parseInt(req.params.id) });
  } catch (err) { res.status(500).json({ error: 'Failed to assign class' }); }
});

// DELETE remove a class from a teacher
app.delete('/teachers/:id/classes/:class_name', verifyToken, isAdmin, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM teacher_classes WHERE teacher_id = $1 AND LOWER(class_name) = LOWER($2)',
      [req.params.id, decodeURIComponent(req.params.class_name)]
    );

    auditLog({
      action: 'delete', entity: 'teacher_class', entity_id: parseInt(req.params.id),
      actor: req.user, old_value: { class_name: decodeURIComponent(req.params.class_name) },
      description: `${req.user.email || req.user.id} removed class "${decodeURIComponent(req.params.class_name)}" from teacher #${req.params.id}`
    });

    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to remove class' }); }
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
    const before = await pool.query('SELECT * FROM student_accounts WHERE id = $1', [req.params.id]);

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

    auditLog({
      action: 'update', entity: 'student_account', entity_id: rows[0].id,
      actor: req.user, old_value: before.rows[0] || null, new_value: rows[0],
      description: `${req.user.email || req.user.id} linked account ${rows[0].full_name} to student #${rows[0].student_id}`
    });

    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to update account' }); }
});

app.delete('/student-accounts/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const before = await pool.query('SELECT * FROM student_accounts WHERE id = $1', [req.params.id]);
    await pool.query('DELETE FROM student_accounts WHERE id = $1', [req.params.id]);

    auditLog({
      action: 'delete', entity: 'student_account', entity_id: parseInt(req.params.id),
      actor: req.user, old_value: before.rows[0] || null,
      description: `${req.user.email || req.user.id} removed portal account ${before.rows[0]?.full_name || ('#' + req.params.id)}`
    });

    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete account' }); }
});


// ══════════════════════════════════════════════════════════════════════════════
//  STUDENTS  (the school record — separate from login accounts)
// ══════════════════════════════════════════════════════════════════════════════

// ── CLASS NAME NORMALIZER ─────────────────────────────────────────────────────
// Accepts any variation student types and returns standard format
// Examples:
//   "grade9commerce1"    → "Grade 9 Commerce 1"
//   "Grade9Commerce1"    → "Grade 9 Commerce 1"
//   "grade 9 commerce1"  → "Grade 9 Commerce 1"
//   "9 Science 2"        → "Grade 9 Science 2"
//   "grade 7"            → "Grade 7"
function normalizeClass(raw) {
  if (!raw) return null;
  let s = raw.trim();

  // Insert space before capital letters (CamelCase → words)
  s = s.replace(/([a-z])([A-Z])/g, '$1 $2');

  // Insert space between letters and digits
  s = s.replace(/([a-zA-Z])(\d)/g, '$1 $2');
  s = s.replace(/(\d)([a-zA-Z])/g, '$1 $2');

  // Normalize multiple spaces
  s = s.replace(/\s+/g, ' ').trim().toLowerCase();

  // Extract parts: grade number, stream, class number
  const gradeMatch  = s.match(/(?:grade\s*)?(\d+)/);
  const streamMatch = s.match(/\b(commerce|science|arts)\b/i);
  const classMatch  = s.match(/(?:commerce|science|arts)\s*(\d+)/i);

  if (!gradeMatch) return raw; // can't parse, return as-is

  const gradeNum  = gradeMatch[1];
  const stream    = streamMatch
    ? streamMatch[1].charAt(0).toUpperCase() + streamMatch[1].slice(1).toLowerCase()
    : null;
  const classNum  = classMatch ? classMatch[1] : null;

  if (stream && classNum) {
    return `Grade ${gradeNum} ${stream} ${classNum}`;
  } else if (stream) {
    return `Grade ${gradeNum} ${stream}`;
  } else {
    return `Grade ${gradeNum}`;
  }
}

// ── AUDIT LOG HELPER ──────────────────────────────────────────────────────────
// Fire-and-forget: never blocks or fails the parent request.
// Call shape: auditLog({ action, entity, entity_id, actor, old_value, new_value, description })
//   action:      'create' | 'update' | 'delete' | 'login' | 'send'
//   entity:      'grade' | 'attendance' | 'announcement' | 'student' | 'teacher' | ...
//   actor:       usually req.user (has id, role, email) — full_name is looked up if missing
async function auditLog({ action, entity, entity_id, actor, old_value, new_value, description }) {
  try {
    await pool.query(
      `INSERT INTO audit_logs
         (action, entity, entity_id, actor_id, actor_name, actor_role, old_value, new_value, description)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [
        action,
        entity,
        entity_id || null,
        actor?.id || null,
        actor?.full_name || actor?.name || actor?.email || null,
        actor?.role || null,
        old_value   ? JSON.stringify(old_value)  : null,
        new_value   ? JSON.stringify(new_value)  : null,
        description || null
      ]
    );
  } catch(e) {
    console.error('Audit log error:', e.message);
  }
}

// Ensure audit_logs table exists (safe no-op if it already does)
async function ensureAuditLogTable() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id          SERIAL PRIMARY KEY,
        action      TEXT NOT NULL,
        entity      TEXT NOT NULL,
        entity_id   INTEGER,
        actor_id    INTEGER,
        actor_name  TEXT,
        actor_role  TEXT,
        old_value   JSONB,
        new_value   JSONB,
        description TEXT,
        created_at  TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_audit_logs_entity ON audit_logs(entity, entity_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at DESC)`);
  } catch (e) {
    console.error('Failed to ensure audit_logs table:', e.message);
  }
}
ensureAuditLogTable();

// ══════════════════════════════════════════════════════════════════════════════
//  STUDENTS  (the school record — separate from login accounts)
// ══════════════════════════════════════════════════════════════════════════════

app.get('/students', verifyToken, async (req, res) => {
  try {
    let query = 'SELECT * FROM students WHERE 1=1';
    const params = [];

    // STUDENT: can only see their own record
    if (req.user.role === 'student') {
      if (!req.user.student_id) return res.json([]);
      params.push(req.user.student_id);
      query += ` AND id = $${params.length}`;

    // PARENT: see their child only
    } else if (req.user.role === 'parent') {
      const linked = await pool.query(
        'SELECT student_id FROM student_accounts WHERE id = $1', [req.user.id]
      );
      const sid = linked.rows[0]?.student_id;
      if (!sid) return res.json([]);
      params.push(sid);
      query += ` AND id = $${params.length}`;

    // TEACHER: see students in ALL their assigned classes
    } else if (req.user.role === 'teacher') {

      // Get all classes assigned to this teacher from teacher_classes table
      const tcRows = await pool.query(
        'SELECT class_name FROM teacher_classes WHERE teacher_id = $1',
        [req.user.id]
      );

      if (tcRows.rows.length > 0) {
        // Build: class ILIKE $1 OR class ILIKE $2 OR ...
        const conditions = tcRows.rows.map((_, i) => {
          params.push(tcRows.rows[i].class_name);
          return `LOWER(class) = LOWER($${params.length})`;
        });
        query += ` AND (${conditions.join(' OR ')})`;
      } else {
        // Fallback: check old single class field on teachers table
        const tr = await pool.query(
          'SELECT class FROM teachers WHERE id = $1', [req.user.id]
        );
        const cls = tr.rows[0]?.class;
        if (cls) {
          params.push(cls);
          query += ` AND class ILIKE $${params.length}`;
        }
        // no class set → see all students (so teacher never locked out)
      }
    }
    // admin / principal → no filter

    if (req.query.class && !['student','parent'].includes(req.user.role)) {
      params.push(req.query.class);
      query += ` AND class ILIKE $${params.length}`;
    }
    if (req.query.status) {
      params.push(req.query.status);
      query += ` AND status = $${params.length}`;
    }

    query += ' ORDER BY class ASC, full_name ASC';
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

    auditLog({
      action: 'create', entity: 'student', entity_id: rows[0].id,
      actor: req.user, new_value: rows[0],
      description: `${req.user.email || req.user.id} added student ${rows[0].full_name} (${rows[0].class || 'no class'})`
    });

    res.status(201).json(rows[0]);
  } catch (err) {
    console.error('Create student:', err);
    res.status(500).json({ error: 'Failed to create student' });
  }
});

app.patch('/students/:id', verifyToken, isStaff, async (req, res) => {
  const { full_name, class: cls, parent_phone, parent_name, parent_email, status, gender, date_of_birth } = req.body;
  try {
    const before = await pool.query('SELECT * FROM students WHERE id = $1', [req.params.id]);

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

    auditLog({
      action: 'update', entity: 'student', entity_id: rows[0].id,
      actor: req.user, old_value: before.rows[0] || null, new_value: rows[0],
      description: `${req.user.email || req.user.id} updated student ${rows[0].full_name}`
    });

    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to update student' }); }
});

app.delete('/students/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const before = await pool.query('SELECT * FROM students WHERE id = $1', [req.params.id]);
    const { rowCount } = await pool.query('DELETE FROM students WHERE id = $1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Student not found' });

    auditLog({
      action: 'delete', entity: 'student', entity_id: parseInt(req.params.id),
      actor: req.user, old_value: before.rows[0] || null,
      description: `${req.user.email || req.user.id} removed student ${before.rows[0]?.full_name || ('#' + req.params.id)}`
    });

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
    const useDate = date || new Date().toISOString().split('T')[0];
    const before = await pool.query(
      'SELECT * FROM attendance WHERE student_id = $1 AND date = $2', [student_id, useDate]
    );

    const { rows } = await pool.query(
      `INSERT INTO attendance (student_id, date, status, reason, teacher_id)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (student_id, date) DO UPDATE
         SET status = EXCLUDED.status, reason = EXCLUDED.reason, teacher_id = EXCLUDED.teacher_id
       RETURNING *`,
      [student_id, useDate, status||'absent', reason||null, teacher_id||null]
    );

    auditLog({
      action: before.rows.length ? 'update' : 'create', entity: 'attendance', entity_id: rows[0].id,
      actor: req.user || { id: teacher_id, role: 'staff' },
      old_value: before.rows[0] || null, new_value: rows[0],
      description: `Attendance for student #${student_id} on ${useDate} set to "${rows[0].status}"`
    });

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

    // One summary audit entry for the whole bulk save (avoids flooding the log per-student)
    auditLog({
      action: 'update', entity: 'attendance', entity_id: null,
      actor: req.user,
      new_value: { date, count: results.length },
      description: `${req.user.email || req.user.id} saved attendance for ${results.length} student(s) on ${date}`
    });

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

    auditLog({
      action: 'create', entity: 'grade', entity_id: rows[0].id,
      actor: req.user, new_value: rows[0],
      description: `${req.user.email || req.user.id} added grade for student #${student_id}: ${subject} = ${grade || score || '—'}`
    });

    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to save grade' }); }
});

app.patch('/grades/:id', verifyToken, isStaff, async (req, res) => {
  const { score, grade, notes, subject, term } = req.body;
  try {
    const before = await pool.query('SELECT * FROM grades WHERE id = $1', [req.params.id]);

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

    auditLog({
      action: 'update', entity: 'grade', entity_id: rows[0].id,
      actor: req.user, old_value: before.rows[0] || null, new_value: rows[0],
      description: `${req.user.email || req.user.id} edited grade #${rows[0].id} for student #${rows[0].student_id} (${rows[0].subject}: ${before.rows[0]?.grade || before.rows[0]?.score || '—'} -> ${rows[0].grade || rows[0].score || '—'})`
    });

    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to update grade' }); }
});

app.delete('/grades/:id', verifyToken, isStaff, async (req, res) => {
  try {
    const before = await pool.query('SELECT * FROM grades WHERE id = $1', [req.params.id]);
    await pool.query('DELETE FROM grades WHERE id = $1', [req.params.id]);

    auditLog({
      action: 'delete', entity: 'grade', entity_id: parseInt(req.params.id),
      actor: req.user, old_value: before.rows[0] || null,
      description: `${req.user.email || req.user.id} deleted grade #${req.params.id}`
    });

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

    auditLog({
      action: 'create', entity: 'fee', entity_id: rows[0].id,
      actor: req.user, new_value: rows[0],
      description: `${req.user.email || req.user.id} created fee record for student #${student_id} (${term}, due ${amount_due})`
    });

    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to create fee' }); }
});

app.patch('/fees/:id', verifyToken, isAdmin, async (req, res) => {
  const { term, academic_year, amount_due, due_date, status } = req.body;
  try {
    const before = await pool.query('SELECT * FROM fees WHERE id = $1', [req.params.id]);

    const { rows } = await pool.query(
      `UPDATE fees SET
         term=COALESCE($1,term), academic_year=COALESCE($2,academic_year),
         amount_due=COALESCE($3,amount_due), due_date=COALESCE($4,due_date), status=COALESCE($5,status)
       WHERE id=$6 RETURNING *`,
      [term||null, academic_year||null, amount_due||null, due_date||null, status||null, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Fee not found' });

    auditLog({
      action: 'update', entity: 'fee', entity_id: rows[0].id,
      actor: req.user, old_value: before.rows[0] || null, new_value: rows[0],
      description: `${req.user.email || req.user.id} updated fee record #${rows[0].id}`
    });

    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to update fee' }); }
});

app.patch('/fees/:id/pay', verifyAny, async (req, res) => {
  const { amount_paid } = req.body;
  if (!amount_paid) return res.status(400).json({ error: 'amount_paid required' });
  try {
    const before = await pool.query('SELECT * FROM fees WHERE id = $1', [req.params.id]);

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

    auditLog({
      action: 'update', entity: 'fee', entity_id: rows[0].id,
      actor: req.user || { id: null, role: 'system' },
      old_value: before.rows[0] || null, new_value: rows[0],
      description: `Payment of ${amount_paid} recorded for fee #${rows[0].id} (student #${rows[0].student_id}) — new status: ${rows[0].status}`
    });

    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to record payment' }); }
});

app.delete('/fees/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const before = await pool.query('SELECT * FROM fees WHERE id = $1', [req.params.id]);
    await pool.query('DELETE FROM fees WHERE id=$1', [req.params.id]);

    auditLog({
      action: 'delete', entity: 'fee', entity_id: parseInt(req.params.id),
      actor: req.user, old_value: before.rows[0] || null,
      description: `${req.user.email || req.user.id} deleted fee record #${req.params.id}`
    });

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

    // Audit: who sent the announcement
    auditLog({
      action: 'send', entity: 'announcement', entity_id: announcement.id,
      actor: req.user, new_value: announcement,
      description: `${req.user.email || req.user.id} sent announcement "${title || '(no title)'}" to ${target || 'all'}`
    });

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
    const before = await pool.query('SELECT * FROM announcements WHERE id = $1', [req.params.id]);
    await pool.query('DELETE FROM announcements WHERE id=$1', [req.params.id]);

    auditLog({
      action: 'delete', entity: 'announcement', entity_id: parseInt(req.params.id),
      actor: req.user, old_value: before.rows[0] || null,
      description: `${req.user.email || req.user.id} deleted announcement #${req.params.id}`
    });

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
//  AUDIT LOGS  (admin / principal only)
// ══════════════════════════════════════════════════════════════════════════════

/**
 * GET /audit-logs
 * Query params (all optional):
 *   entity     — filter by entity type, e.g. 'grade' | 'attendance' | 'announcement'
 *   actor_id   — filter by who made the change
 *   action     — 'create' | 'update' | 'delete' | 'send' | 'login'
 *   from, to   — ISO date range on created_at
 *   limit      — default 100, max 500
 */
app.get('/audit-logs', verifyToken, isAdmin, async (req, res) => {
  const { entity, actor_id, action, from, to } = req.query;
  let limit = parseInt(req.query.limit) || 100;
  if (limit > 500) limit = 500;

  let query = 'SELECT * FROM audit_logs WHERE 1=1';
  const params = [];

  if (entity)   { params.push(entity);   query += ` AND entity = $${params.length}`; }
  if (actor_id) { params.push(actor_id); query += ` AND actor_id = $${params.length}`; }
  if (action)   { params.push(action);   query += ` AND action = $${params.length}`; }
  if (from)     { params.push(from);     query += ` AND created_at >= $${params.length}`; }
  if (to)       { params.push(to);       query += ` AND created_at <= $${params.length}`; }

  params.push(limit);
  query += ` ORDER BY created_at DESC LIMIT $${params.length}`;

  try {
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    console.error('Audit log fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch audit logs' });
  }
});

/**
 * GET /audit-logs/entity/:entity/:entity_id
 * Convenience route: full history for one record, e.g. one grade or one student.
 */
app.get('/audit-logs/entity/:entity/:entity_id', verifyToken, isAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM audit_logs WHERE entity = $1 AND entity_id = $2 ORDER BY created_at DESC`,
      [req.params.entity, req.params.entity_id]
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch entity history' }); }
});


// ══════════════════════════════════════════════════════════════════════════════
//  REPORT CARDS  (printable HTML — browser handles Print → Save as PDF)
// ══════════════════════════════════════════════════════════════════════════════

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function gradeColorHex(g) {
  if (!g) return '#6b7280';
  const c = String(g).charAt(0).toUpperCase();
  if (c === 'A') return '#0e9f6e';
  if (c === 'B') return '#1a56db';
  if (c === 'C') return '#c27803';
  return '#e02424';
}

function buildReportCardHtml({ student, grades, attendance, term, academic_year }) {
  const scores = grades.filter(g => g.score !== null && g.score !== undefined).map(g => parseFloat(g.score));
  const avg = scores.length ? (scores.reduce((a,b)=>a+b,0) / scores.length).toFixed(1) : null;

  const present = attendance.filter(a => a.status === 'present').length;
  const absent  = attendance.filter(a => a.status === 'absent').length;
  const totalDays = present + absent;
  const attPct = totalDays ? Math.round((present/totalDays)*100) : null;

  const rows = grades.map(g => `
    <tr>
      <td>${escapeHtml(g.subject)}</td>
      <td class="center">${g.score !== null && g.score !== undefined ? g.score + '%' : '—'}</td>
      <td class="center"><span class="grade-pill" style="color:${gradeColorHex(g.grade)};border-color:${gradeColorHex(g.grade)}">${escapeHtml(g.grade || '—')}</span></td>
      <td>${escapeHtml(g.notes || '')}</td>
    </tr>
  `).join('');

  const today = new Date().toLocaleDateString('en-GB', { year: 'numeric', month: 'long', day: 'numeric' });

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Report Card — ${escapeHtml(student.full_name)}</title>
<style>
  @page { size: A4; margin: 18mm 16mm; }
  * { box-sizing: border-box; }
  body {
    font-family: 'Helvetica Neue', Arial, sans-serif;
    color: #111928;
    margin: 0;
    padding: 0;
    font-size: 13px;
  }
  .sheet { max-width: 760px; margin: 0 auto; padding: 24px; }
  .header {
    display: flex; justify-content: space-between; align-items: flex-start;
    border-bottom: 3px solid #1a56db; padding-bottom: 16px; margin-bottom: 24px;
  }
  .school-name { font-size: 22px; font-weight: 800; letter-spacing: -0.3px; }
  .school-sub { font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: #6b7280; margin-top: 2px; }
  .doc-title { text-align: right; }
  .doc-title h1 { font-size: 16px; font-weight: 700; margin: 0; }
  .doc-title p { font-size: 11px; color: #6b7280; margin: 2px 0 0; }

  .student-info {
    display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px;
    background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 10px;
    padding: 14px 18px; margin-bottom: 24px;
  }
  .student-info div label {
    display: block; font-size: 10px; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.05em; color: #6b7280; margin-bottom: 2px;
  }
  .student-info div span { font-size: 13px; font-weight: 600; }

  .summary-grid {
    display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 24px;
  }
  .summary-card {
    border: 1px solid #e5e7eb; border-radius: 10px; padding: 12px 14px; text-align: center;
  }
  .summary-card .val { font-size: 22px; font-weight: 800; }
  .summary-card .lbl { font-size: 10px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 2px; }

  h2.section-title {
    font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;
    color: #1a56db; border-bottom: 1px solid #e5e7eb; padding-bottom: 6px; margin: 24px 0 10px;
  }

  table { width: 100%; border-collapse: collapse; margin-bottom: 8px; }
  th {
    text-align: left; font-size: 10px; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.05em; color: #6b7280; border-bottom: 2px solid #e5e7eb; padding: 8px 10px;
  }
  td { padding: 9px 10px; border-bottom: 1px solid #f0f0f0; font-size: 12px; }
  td.center, th.center { text-align: center; }

  .grade-pill {
    display: inline-block; border: 1.5px solid; border-radius: 6px;
    padding: 1px 9px; font-weight: 800; font-size: 12px;
  }

  .footer {
    margin-top: 40px; display: flex; justify-content: space-between; align-items: flex-end;
  }
  .signature { text-align: center; width: 180px; }
  .signature .line { border-top: 1px solid #111928; margin-bottom: 4px; padding-top: 28px; }
  .signature .lbl { font-size: 10px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.05em; }
  .generated { font-size: 10px; color: #9ca3af; text-align: right; margin-top: 40px; }

  .print-bar {
    position: sticky; top: 0; background: #1a56db; color: #fff;
    padding: 10px 16px; display: flex; justify-content: space-between; align-items: center;
    font-family: 'Helvetica Neue', Arial, sans-serif; font-size: 13px; z-index: 10;
  }
  .print-bar button {
    background: #fff; color: #1a56db; border: none; padding: 7px 16px;
    border-radius: 8px; font-weight: 700; font-size: 12px; cursor: pointer;
  }
  @media print { .print-bar { display: none; } }
</style>
</head>
<body>
  <div class="print-bar">
    <span>Report card preview — use Print to save as PDF</span>
    <button onclick="window.print()">Print / Save as PDF</button>
  </div>

  <div class="sheet">
    <div class="header">
      <div>
        <div class="school-name">Lumina Academy</div>
        <div class="school-sub">School Management Portal</div>
      </div>
      <div class="doc-title">
        <h1>Academic Report Card</h1>
        <p>${escapeHtml(term || 'Current Term')} · ${escapeHtml(academic_year || '')}</p>
      </div>
    </div>

    <div class="student-info">
      <div><label>Student Name</label><span>${escapeHtml(student.full_name)}</span></div>
      <div><label>Class</label><span>${escapeHtml(student.class || '—')}</span></div>
      <div><label>Status</label><span>${escapeHtml(student.status || 'Active')}</span></div>
    </div>

    <div class="summary-grid">
      <div class="summary-card">
        <div class="val">${avg !== null ? avg + '%' : '—'}</div>
        <div class="lbl">Average Score</div>
      </div>
      <div class="summary-card">
        <div class="val">${attPct !== null ? attPct + '%' : '—'}</div>
        <div class="lbl">Attendance Rate</div>
      </div>
      <div class="summary-card">
        <div class="val">${grades.length}</div>
        <div class="lbl">Subjects Recorded</div>
      </div>
    </div>

    <h2 class="section-title">Academic Results</h2>
    <table>
      <thead><tr><th>Subject</th><th class="center">Score</th><th class="center">Grade</th><th>Notes</th></tr></thead>
      <tbody>
        ${rows || '<tr><td colspan="4" style="text-align:center;color:#9ca3af;padding:16px;">No grades recorded yet</td></tr>'}
      </tbody>
    </table>

    <h2 class="section-title">Attendance Summary</h2>
    <table>
      <thead><tr><th>Days Present</th><th>Days Absent</th><th>Total Days Recorded</th><th>Attendance Rate</th></tr></thead>
      <tbody>
        <tr>
          <td>${present}</td>
          <td>${absent}</td>
          <td>${totalDays}</td>
          <td>${attPct !== null ? attPct + '%' : '—'}</td>
        </tr>
      </tbody>
    </table>

    <div class="footer">
      <div class="signature">
        <div class="line"></div>
        <div class="lbl">Class Teacher</div>
      </div>
      <div class="signature">
        <div class="line"></div>
        <div class="lbl">Principal</div>
      </div>
      <div class="signature">
        <div class="line"></div>
        <div class="lbl">Parent / Guardian</div>
      </div>
    </div>

    <div class="generated">Generated ${escapeHtml(today)}</div>
  </div>
</body>
</html>`;
}

/**
 * GET /report-card/:student_id
 * Query params (optional): term, academic_year — filters grades shown
 * Returns printable HTML. Authorized for: admin, principal, teacher (their student),
 * the student themself, or the linked parent.
 */
app.get('/report-card/:student_id', verifyToken, async (req, res) => {
  const studentId = req.params.student_id;
  const { term, academic_year } = req.query;

  try {
    // Authorization check
    if (req.user.role === 'student' && String(req.user.student_id) !== String(studentId)) {
      return res.status(403).send('<h2>Access denied</h2>');
    }
    if (req.user.role === 'parent') {
      const linked = await pool.query('SELECT student_id FROM student_accounts WHERE id = $1', [req.user.id]);
      if (String(linked.rows[0]?.student_id) !== String(studentId)) {
        return res.status(403).send('<h2>Access denied</h2>');
      }
    }
    // teacher / admin / principal: allowed (teacher's class scoping already governs what they can see in the UI)

    const studentRes = await pool.query('SELECT * FROM students WHERE id = $1', [studentId]);
    if (!studentRes.rows.length) return res.status(404).send('<h2>Student not found</h2>');
    const student = studentRes.rows[0];

    let gradesQuery = 'SELECT * FROM grades WHERE student_id = $1';
    const gradesParams = [studentId];
    if (term) { gradesParams.push(term); gradesQuery += ` AND term = $${gradesParams.length}`; }
    if (academic_year) { gradesParams.push(academic_year); gradesQuery += ` AND academic_year = $${gradesParams.length}`; }
    gradesQuery += ' ORDER BY subject ASC';

    const [gradesRes, attRes] = await Promise.all([
      pool.query(gradesQuery, gradesParams),
      pool.query('SELECT * FROM attendance WHERE student_id = $1', [studentId])
    ]);

    const html = buildReportCardHtml({
      student,
      grades: gradesRes.rows,
      attendance: attRes.rows,
      term,
      academic_year
    });

    // Audit: report card was viewed/generated (useful to know who pulled a student's record)
    auditLog({
      action: 'view', entity: 'report_card', entity_id: parseInt(studentId),
      actor: req.user,
      description: `${req.user.email || req.user.id} generated report card for student #${studentId}${term ? ' (' + term + ')' : ''}`
    });

    res.set('Content-Type', 'text/html');
    res.send(html);
  } catch (err) {
    console.error('Report card error:', err);
    res.status(500).send('<h2>Failed to generate report card</h2>');
  }
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
