// routes/dashboard.js
// Teacher dashboard: add/remove students, class overview, stats
const express = require("express");
const db = require("../config/db");
const { authenticate, authorize } = require("../middleware/auth");
const { createError } = require("../middleware/errorHandler");

const router = express.Router();
router.use(authenticate);

// ══════════════════════════════════════════════════════════
//  TEACHER DASHBOARD — OVERVIEW
// ══════════════════════════════════════════════════════════

// ── GET /api/dashboard/teacher ──────────────────────────────
// Returns everything a teacher needs on their home screen
router.get(
  "/teacher",
  authorize("teacher", "admin"),
  async (req, res, next) => {
    try {
      const teacherId = req.user.id;

      // Subjects + classes this teacher handles
      const [subjects] = await db.query(
        `SELECT s.id, s.name AS subject_name,
              c.id AS class_id, c.name AS class_name, c.section,
              COUNT(DISTINCT u.id) AS student_count
       FROM subjects s
       JOIN classes c ON c.id = s.class_id
       LEFT JOIN users u ON u.class_id = c.id AND u.role = 'student' AND u.is_active = 1
       WHERE s.teacher_id = ?
       GROUP BY s.id`,
        [teacherId],
      );

      // Pending submissions to grade
      const [pendingGrades] = await db.query(
        `SELECT COUNT(*) AS count
       FROM submissions sub
       JOIN assignments a ON a.id = sub.assignment_id AND a.teacher_id = ?
       WHERE sub.status = 'submitted'`,
        [teacherId],
      );

      // Recent assignments (last 5)
      const [recentAssignments] = await db.query(
        `SELECT a.id, a.title, a.due_date, s.name AS subject_name,
              c.name AS class_name, c.section,
              COUNT(sub.id)                               AS total_submissions,
              SUM(sub.status = 'graded')                  AS graded,
              SUM(sub.status = 'submitted')               AS pending
       FROM assignments a
       JOIN subjects s ON s.id = a.subject_id
       JOIN classes  c ON c.id = s.class_id
       LEFT JOIN submissions sub ON sub.assignment_id = a.id
       WHERE a.teacher_id = ?
       GROUP BY a.id
       ORDER BY a.created_at DESC
       LIMIT 5`,
        [teacherId],
      );

      // Attendance sessions opened today
      const [todaySessions] = await db.query(
        `SELECT att.id, att.date, att.is_closed, att.period,
              sub.name AS subject_name,
              c.name AS class_name, c.section,
              SUM(ar.status = 'present') AS present,
              SUM(ar.status = 'absent')  AS absent,
              COUNT(ar.id)               AS total
       FROM attendance_sessions att
       JOIN subjects sub ON sub.id = att.subject_id
       JOIN classes  c   ON c.id   = att.class_id
       LEFT JOIN attendance_records ar ON ar.session_id = att.id
       WHERE att.teacher_id = ? AND att.date = CURDATE()
       GROUP BY att.id`,
        [teacherId],
      );

      // Unread announcements count
      const [announcements] = await db.query(
        `SELECT COUNT(*) AS count FROM announcements
       WHERE author_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)`,
        [teacherId],
      );

      res.json({
        subjects,
        stats: {
          pending_grades: pendingGrades[0].count,
          subjects_taught: subjects.length,
          announcements_this_week: announcements[0].count,
        },
        recent_assignments: recentAssignments,
        today_attendance: todaySessions,
      });
    } catch (err) {
      next(err);
    }
  },
);

// ── GET /api/dashboard/student ───────────────────────────────
// Student home screen overview
router.get("/student", authorize("student"), async (req, res, next) => {
  try {
    const { id, class_id } = req.user;

    // Pending assignments (not yet submitted)
    const [pendingAssignments] = await db.query(
      `SELECT a.id, a.title, a.due_date, s.name AS subject_name,
              sub.status AS my_status
       FROM assignments a
       JOIN subjects s ON s.id = a.subject_id AND s.class_id = ?
       LEFT JOIN submissions sub ON sub.assignment_id = a.id AND sub.student_id = ?
       WHERE (sub.status IS NULL OR sub.status = 'pending')
         AND a.due_date >= NOW()
       ORDER BY a.due_date ASC
       LIMIT 5`,
      [class_id, id],
    );

    // Recent results (last 5)
    const [recentResults] = await db.query(
      `SELECT r.total, r.grade, r.term, r.session,
              s.name AS subject_name
       FROM results r
       JOIN subjects s ON s.id = r.subject_id
       WHERE r.student_id = ?
       ORDER BY r.created_at DESC
       LIMIT 5`,
      [id],
    );

    // Attendance summary
    const [attendanceSummary] = await db.query(
      `SELECT
         COUNT(ar.id)                   AS total_classes,
         SUM(ar.status = 'present')     AS present,
         SUM(ar.status = 'absent')      AS absent,
         SUM(ar.status = 'late')        AS late,
         ROUND(
           (SUM(ar.status = 'present') + SUM(ar.status = 'late'))
           / COUNT(ar.id) * 100, 1
         )                              AS overall_attendance_pct
       FROM attendance_records ar
       JOIN attendance_sessions s ON s.id = ar.session_id AND s.class_id = ?
       WHERE ar.student_id = ?`,
      [class_id, id],
    );

    // Recent announcements
    const [announcementRows] = await db.query(
      `SELECT a.id, a.title, a.created_at, u.full_name AS author_name
       FROM announcements a
       JOIN users u ON u.id = a.author_id
       WHERE a.audience = 'all'
          OR (a.audience = 'class' AND a.class_id = ?)
       ORDER BY a.created_at DESC
       LIMIT 4`,
      [class_id],
    );

    res.json({
      pending_assignments: pendingAssignments,
      recent_results: recentResults,
      attendance: attendanceSummary[0] || {},
      announcements: announcementRows,
    });
  } catch (err) {
    next(err);
  }
});

// ══════════════════════════════════════════════════════════
//  STUDENT MANAGEMENT  (teacher adds/removes students)
// ══════════════════════════════════════════════════════════

// ── GET /api/dashboard/classes/:classId/students ─────────────
// List all students in a class with their enrolment info
router.get(
  "/classes/:classId/students",
  authorize("teacher", "admin"),
  async (req, res, next) => {
    try {
      const [rows] = await db.query(
        `SELECT u.id, u.full_name, u.email, u.profile_pic, u.created_at AS registered_at,
              e.enrolled_at, e.is_active AS is_enrolled,
              enroller.full_name AS enrolled_by_name
       FROM users u
       LEFT JOIN class_enrolments e
              ON e.student_id = u.id AND e.class_id = ? AND e.is_active = 1
       LEFT JOIN users enroller ON enroller.id = e.enrolled_by
       WHERE u.class_id = ? AND u.role = 'student'
       ORDER BY u.full_name ASC`,
        [req.params.classId, req.params.classId],
      );
      res.json(rows);
    } catch (err) {
      next(err);
    }
  },
);

// ── POST /api/dashboard/classes/:classId/students ────────────
// Teacher adds an existing user as a student to their class
// Body: { student_id } or { email } to find by email
router.post(
  "/classes/:classId/students",
  authorize("teacher", "admin"),
  async (req, res, next) => {
    try {
      const { student_id, email } = req.body;
      if (!student_id && !email) {
        throw createError(400, "Provide student_id or email.");
      }

      let userId = student_id;

      // Look up by email if no ID given
      if (!userId && email) {
        const [users] = await db.query(
          `SELECT id FROM users WHERE email = ? AND role = 'student'`,
          [email],
        );
        if (!users.length)
          throw createError(404, "No student found with that email.");
        userId = users[0].id;
      }

      // Verify student exists and is a student
      const [students] = await db.query(
        'SELECT id FROM users WHERE id = ? AND role = "student"',
        [userId],
      );
      if (!students.length) throw createError(404, "Student not found.");

      // Update class_id on the user
      await db.query("UPDATE users SET class_id = ? WHERE id = ?", [
        req.params.classId,
        userId,
      ]);

      // Record the enrolment
      await db.query(
        `INSERT INTO class_enrolments (student_id, class_id, enrolled_by)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE
         is_active = 1, left_at = NULL, enrolled_by = VALUES(enrolled_by), enrolled_at = NOW()`,
        [userId, req.params.classId, req.user.id],
      );

      res.status(201).json({ message: "Student added to class." });
    } catch (err) {
      next(err);
    }
  },
);

// ── POST /api/dashboard/students/register ────────────────────
// Teacher/admin creates a brand new student account and assigns to class
// Body: { full_name, email, password, class_id }
router.post(
  "/students/register",
  authorize("teacher", "admin"),
  async (req, res, next) => {
    try {
      const bcrypt = require("bcrypt");
      const { full_name, email, password, class_id } = req.body;

      if (!full_name || !email || !password || !class_id) {
        throw createError(
          400,
          "full_name, email, password, and class_id are required.",
        );
      }

      // Check email not already taken
      const [existing] = await db.query(
        "SELECT id FROM users WHERE email = ?",
        [email],
      );
      if (existing.length) throw createError(409, "Email already registered.");

      const hash = await bcrypt.hash(password, 12);

      const [result] = await db.query(
        `INSERT INTO users (full_name, email, password_hash, role, class_id)
       VALUES (?, ?, ?, 'student', ?)`,
        [full_name, email, hash, class_id],
      );

      // Record enrolment
      await db.query(
        `INSERT INTO class_enrolments (student_id, class_id, enrolled_by)
       VALUES (?, ?, ?)`,
        [result.insertId, class_id, req.user.id],
      );

      res.status(201).json({
        message: "Student account created and enrolled.",
        student_id: result.insertId,
      });
    } catch (err) {
      next(err);
    }
  },
);

// ── DELETE /api/dashboard/classes/:classId/students/:studentId
// Remove student from class (does not delete the user account)
router.delete(
  "/classes/:classId/students/:studentId",
  authorize("teacher", "admin"),
  async (req, res, next) => {
    try {
      // Remove class_id from user
      await db.query(
        "UPDATE users SET class_id = NULL WHERE id = ? AND class_id = ?",
        [req.params.studentId, req.params.classId],
      );

      // Mark enrolment as inactive
      await db.query(
        `UPDATE class_enrolments
       SET is_active = 0, left_at = NOW()
       WHERE student_id = ? AND class_id = ?`,
        [req.params.studentId, req.params.classId],
      );

      res.json({ message: "Student removed from class." });
    } catch (err) {
      next(err);
    }
  },
);

// ── GET /api/dashboard/classes ───────────────────────────────
// List all classes a teacher is assigned to
router.get(
  "/classes",
  authorize("teacher", "admin"),
  async (req, res, next) => {
    try {
      const [rows] = await db.query(
        `SELECT c.id, c.name, c.section,
              COUNT(DISTINCT u.id) AS student_count,
              GROUP_CONCAT(DISTINCT sub.name ORDER BY sub.name SEPARATOR ', ') AS subjects
       FROM subjects s
       JOIN classes c ON c.id = s.class_id
       LEFT JOIN users    u   ON u.class_id = c.id AND u.role = 'student' AND u.is_active = 1
       LEFT JOIN subjects sub ON sub.class_id = c.id AND sub.teacher_id = ?
       WHERE s.teacher_id = ?
       GROUP BY c.id
       ORDER BY c.name, c.section`,
        [req.user.id, req.user.id],
      );
      res.json(rows);
    } catch (err) {
      next(err);
    }
  },
);

module.exports = router;
