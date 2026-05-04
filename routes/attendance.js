// routes/attendance.js
const express = require("express");
const db = require("../config/db");
const { authenticate, authorize } = require("../middleware/auth");
const { createError } = require("../middleware/errorHandler");

const router = express.Router();
router.use(authenticate);

// ══════════════════════════════════════════════════════════
//  ATTENDANCE SESSIONS  (teacher opens/closes a register)
// ══════════════════════════════════════════════════════════

// ── GET /api/attendance/sessions ────────────────────────────
// Teacher: sessions for subjects they teach
// Student: sessions for their class
router.get("/sessions", async (req, res, next) => {
  try {
    const { id, role, class_id } = req.user;
    const { date, subject_id } = req.query;

    let query, params;

    if (role === "teacher" || role === "admin") {
      query = `
        SELECT s.*, sub.name AS subject_name,
               c.name AS class_name, c.section,
               u.full_name AS teacher_name,
               COUNT(ar.id) AS total_marked
        FROM attendance_sessions s
        JOIN subjects  sub ON sub.id = s.subject_id
        JOIN classes   c   ON c.id   = s.class_id
        JOIN users     u   ON u.id   = s.teacher_id
        LEFT JOIN attendance_records ar ON ar.session_id = s.id
        WHERE s.teacher_id = ?
          ${subject_id ? "AND s.subject_id = ?" : ""}
          ${date ? "AND s.date = ?" : ""}
        GROUP BY s.id
        ORDER BY s.date DESC`;
      params = [
        id,
        ...(subject_id ? [subject_id] : []),
        ...(date ? [date] : []),
      ];
    } else {
      // Student sees sessions for their class
      query = `
        SELECT s.*, sub.name AS subject_name,
               u.full_name AS teacher_name,
               ar.status AS my_status
        FROM attendance_sessions s
        JOIN subjects sub ON sub.id = s.subject_id AND sub.class_id = ?
        JOIN users    u   ON u.id   = s.teacher_id
        LEFT JOIN attendance_records ar
               ON ar.session_id = s.id AND ar.student_id = ?
        ${date ? "WHERE s.date = ?" : ""}
        ORDER BY s.date DESC`;
      params = [class_id, id, ...(date ? [date] : [])];
    }

    const [rows] = await db.query(query, params);
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// ── POST /api/attendance/sessions ───────────────────────────
// Teacher opens a new attendance session
router.post(
  "/sessions",
  authorize("teacher", "admin"),
  async (req, res, next) => {
    try {
      const { subject_id, date, period } = req.body;
      if (!subject_id || !date) {
        throw createError(400, "subject_id and date are required.");
      }

      // Confirm teacher owns this subject
      const [subjects] = await db.query(
        "SELECT id, class_id FROM subjects WHERE id = ? AND teacher_id = ?",
        [subject_id, req.user.id],
      );
      if (!subjects.length)
        throw createError(403, "You do not teach this subject.");

      const class_id = subjects[0].class_id;

      const [result] = await db.query(
        `INSERT INTO attendance_sessions (subject_id, teacher_id, class_id, date, period)
       VALUES (?, ?, ?, ?, ?)`,
        [subject_id, req.user.id, class_id, date, period || null],
      );

      // Auto-create an 'absent' record for every student in the class
      // so the teacher only needs to mark present/late
      const [students] = await db.query(
        `SELECT id FROM users WHERE class_id = ? AND role = 'student' AND is_active = 1`,
        [class_id],
      );

      if (students.length) {
        const records = students.map((s) => [result.insertId, s.id, "absent"]);
        await db.query(
          "INSERT IGNORE INTO attendance_records (session_id, student_id, status) VALUES ?",
          [records],
        );
      }

      res.status(201).json({
        message: "Attendance session opened.",
        session_id: result.insertId,
        students_pre_filled: students.length,
      });
    } catch (err) {
      next(err);
    }
  },
);

// ── PUT /api/attendance/sessions/:id/close ───────────────────
router.put(
  "/sessions/:id/close",
  authorize("teacher", "admin"),
  async (req, res, next) => {
    try {
      const [rows] = await db.query(
        "SELECT id FROM attendance_sessions WHERE id = ? AND teacher_id = ?",
        [req.params.id, req.user.id],
      );
      if (!rows.length)
        throw createError(404, "Session not found or not yours.");

      await db.query(
        "UPDATE attendance_sessions SET is_closed = 1 WHERE id = ?",
        [req.params.id],
      );
      res.json({ message: "Session closed." });
    } catch (err) {
      next(err);
    }
  },
);

// ══════════════════════════════════════════════════════════
//  ATTENDANCE RECORDS  (mark individual students)
// ══════════════════════════════════════════════════════════

// ── GET /api/attendance/sessions/:sessionId/records ──────────
// Teacher views the full register for a session
router.get(
  "/sessions/:sessionId/records",
  authorize("teacher", "admin"),
  async (req, res, next) => {
    try {
      const [rows] = await db.query(
        `SELECT ar.id, ar.status, ar.note, ar.marked_at,
              u.id AS student_id, u.full_name AS student_name, u.email
       FROM attendance_records ar
       JOIN users u ON u.id = ar.student_id
       WHERE ar.session_id = ?
       ORDER BY u.full_name ASC`,
        [req.params.sessionId],
      );
      res.json(rows);
    } catch (err) {
      next(err);
    }
  },
);

// ── PUT /api/attendance/sessions/:sessionId/mark ─────────────
// Teacher marks one or many students in a session
// Body: { records: [{ student_id, status, note? }] }
router.put(
  "/sessions/:sessionId/mark",
  authorize("teacher", "admin"),
  async (req, res, next) => {
    try {
      const { records } = req.body;
      if (!Array.isArray(records) || !records.length) {
        throw createError(400, "records[] array is required.");
      }

      // Verify session belongs to this teacher
      const [sessions] = await db.query(
        "SELECT id, is_closed FROM attendance_sessions WHERE id = ? AND teacher_id = ?",
        [req.params.sessionId, req.user.id],
      );
      if (!sessions.length)
        throw createError(404, "Session not found or not yours.");
      if (sessions[0].is_closed)
        throw createError(400, "This session is already closed.");

      // Upsert each record
      for (const r of records) {
        await db.query(
          `INSERT INTO attendance_records (session_id, student_id, status, note)
         VALUES (?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE status = VALUES(status), note = VALUES(note), marked_at = NOW()`,
          [
            req.params.sessionId,
            r.student_id,
            r.status || "absent",
            r.note || null,
          ],
        );
      }

      res.json({ message: `${records.length} record(s) updated.` });
    } catch (err) {
      next(err);
    }
  },
);

// ── GET /api/attendance/student/:studentId/summary ───────────
// Summary: attendance % per subject for one student
router.get("/student/:studentId/summary", async (req, res, next) => {
  try {
    const { id, role, class_id } = req.user;

    // Students can only view their own summary
    if (role === "student" && +req.params.studentId !== id) {
      throw createError(403, "Access denied.");
    }

    const [rows] = await db.query(
      `SELECT sub.name AS subject_name,
              COUNT(ar.id)                                          AS total_classes,
              SUM(ar.status = 'present')                           AS present,
              SUM(ar.status = 'late')                              AS late,
              SUM(ar.status = 'absent')                            AS absent,
              SUM(ar.status = 'excused')                           AS excused,
              ROUND(
                (SUM(ar.status = 'present') + SUM(ar.status = 'late')) /
                COUNT(ar.id) * 100, 1
              )                                                     AS attendance_pct
       FROM attendance_records ar
       JOIN attendance_sessions s   ON s.id  = ar.session_id
       JOIN subjects            sub ON sub.id = s.subject_id
       WHERE ar.student_id = ?
       GROUP BY sub.id, sub.name
       ORDER BY sub.name`,
      [req.params.studentId],
    );

    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// ── GET /api/attendance/class/:classId/report ────────────────
// Full attendance report for a whole class (teacher/admin)
router.get(
  "/class/:classId/report",
  authorize("teacher", "admin"),
  async (req, res, next) => {
    try {
      const { term_start, term_end } = req.query; // optional date range

      const [rows] = await db.query(
        `SELECT u.id AS student_id, u.full_name AS student_name,
              sub.name AS subject_name,
              COUNT(ar.id)                      AS total_classes,
              SUM(ar.status = 'present')        AS present,
              SUM(ar.status = 'late')           AS late,
              SUM(ar.status = 'absent')         AS absent,
              ROUND(
                (SUM(ar.status = 'present') + SUM(ar.status = 'late'))
                / COUNT(ar.id) * 100, 1
              )                                 AS attendance_pct
       FROM users u
       JOIN attendance_records  ar  ON ar.student_id  = u.id
       JOIN attendance_sessions s   ON s.id            = ar.session_id
                                   AND s.class_id      = ?
                                   ${term_start ? "AND s.date >= ?" : ""}
                                   ${term_end ? "AND s.date <= ?" : ""}
       JOIN subjects sub ON sub.id = s.subject_id
       WHERE u.role = 'student' AND u.is_active = 1
       GROUP BY u.id, sub.id
       ORDER BY u.full_name, sub.name`,
        [
          req.params.classId,
          ...(term_start ? [term_start] : []),
          ...(term_end ? [term_end] : []),
        ],
      );

      res.json(rows);
    } catch (err) {
      next(err);
    }
  },
);

module.exports = router;
