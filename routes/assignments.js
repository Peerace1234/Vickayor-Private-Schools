// routes/assignments.js
const express = require("express");
const multer = require("multer");
const path = require("path");
const db = require("../config/db");
const { authenticate, authorize } = require("../middleware/auth");
const { createError } = require("../middleware/errorHandler");

const router = express.Router();
router.use(authenticate);

// ── File upload config ──────────────────────────────────────
const storage = multer.diskStorage({
  destination: "uploads/assignments/",
  filename: (req, file, cb) => {
    const unique = `${Date.now()}-${Math.round(Math.random() * 1e6)}`;
    cb(null, unique + path.extname(file.originalname));
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB
  fileFilter: (req, file, cb) => {
    const allowed = /pdf|doc|docx|jpg|jpeg|png/;
    cb(null, allowed.test(path.extname(file.originalname).toLowerCase()));
  },
});

// ── GET /api/assignments ─────────────────────────────────────
// Teacher: all assignments they created.
// Student: all assignments for their class subjects.
router.get("/", async (req, res, next) => {
  try {
    const { id, role, class_id } = req.user;
    let rows;

    if (role === "teacher" || role === "admin") {
      [rows] = await db.query(
        `SELECT a.*, s.name AS subject_name, s.class_id, c.name AS class_name
         FROM assignments a
         JOIN subjects s ON s.id = a.subject_id
         JOIN classes  c ON c.id = s.class_id
         WHERE a.teacher_id = ?
         ORDER BY a.created_at DESC`,
        [id],
      );
    } else {
      [rows] = await db.query(
        `SELECT a.*, s.name AS subject_name, s.class_id,
                u.full_name AS teacher_name, c.name AS class_name
         FROM assignments a
         JOIN subjects s ON s.id = a.subject_id AND s.class_id = ?
         JOIN users u ON u.id = a.teacher_id
         JOIN classes c ON c.id = s.class_id
         ORDER BY a.created_at DESC`,
        [class_id],
      );
    }

    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// ── GET /api/assignments/:id ─────────────────────────────────
router.get("/:id", async (req, res, next) => {
  try {
    const { id: userId, role, class_id } = req.user;
    const [rows] = await db.query(
      `SELECT a.*, s.name AS subject_name, s.class_id,
              u.full_name AS teacher_name
       FROM assignments a
       JOIN subjects s ON s.id = a.subject_id
       JOIN users    u ON u.id = a.teacher_id
       WHERE a.id = ?`,
      [req.params.id],
    );
    if (!rows.length) throw createError(404, "Assignment not found.");

    const assignment = rows[0];
    // Students can only view assignments for their class
    if (role === "student" && assignment.class_id !== class_id) {
      throw createError(403, "Access denied.");
    }

    res.json(assignment);
  } catch (err) {
    next(err);
  }
});

// ── POST /api/assignments ────────────────────────────────────
// Teacher only
router.post(
  "/",
  authorize("teacher", "admin"),
  upload.single("file"),
  async (req, res, next) => {
    try {
      const { title, description, subject_id, due_date, max_score } = req.body;
      if (!title || !subject_id || !due_date) {
        throw createError(400, "title, subject_id, and due_date are required.");
      }

      // Verify teacher owns this subject
      const [subjects] = await db.query(
        "SELECT id FROM subjects WHERE id = ? AND teacher_id = ?",
        [subject_id, req.user.id],
      );
      if (!subjects.length) throw createError(403, "Not authorized.");

      const fileUrl = req.file
        ? `/uploads/assignments/${req.file.filename}`
        : null;
      const [result] = await db.query(
        `INSERT INTO assignments
         (title, description, subject_id, teacher_id, due_date, max_score, file_url)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          title,
          description || "",
          subject_id,
          req.user.id,
          due_date,
          max_score || 100,
          fileUrl,
        ],
      );

      res
        .status(201)
        .json({ message: "Assignment created.", id: result.insertId });
    } catch (err) {
      next(err);
    }
  },
);

// ── PUT /api/assignments/:id ─────────────────────────────────
router.put(
  "/:id",
  authorize("teacher", "admin"),
  upload.single("file"),
  async (req, res, next) => {
    try {
      const [rows] = await db.query(
        "SELECT * FROM assignments WHERE id = ? AND teacher_id = ?",
        [req.params.id, req.user.id],
      );
      if (!rows.length) throw createError(403, "Not authorized.");

      const { title, description, due_date, max_score } = req.body;
      const fileUrl = req.file
        ? `/uploads/assignments/${req.file.filename}`
        : rows[0].file_url;

      await db.query(
        `UPDATE assignments
       SET title = ?, description = ?, due_date = ?, max_score = ?, file_url = ?
       WHERE id = ?`,
        [
          title || rows[0].title,
          description || rows[0].description,
          due_date || rows[0].due_date,
          max_score || rows[0].max_score,
          fileUrl,
          req.params.id,
        ],
      );

      res.json({ message: "Assignment updated." });
    } catch (err) {
      next(err);
    }
  },
);

// ── DELETE /api/assignments/:id ──────────────────────────────
router.delete("/:id", authorize("teacher", "admin"), async (req, res, next) => {
  try {
    const [rows] = await db.query(
      "SELECT id FROM assignments WHERE id = ? AND teacher_id = ?",
      [req.params.id, req.user.id],
    );
    if (!rows.length) throw createError(403, "Not authorized.");

    await db.query("DELETE FROM assignments WHERE id = ?", [req.params.id]);
    res.json({ message: "Assignment deleted." });
  } catch (err) {
    next(err);
  }
});

// ── POST /api/assignments/:id/submit ────────────────────────
// Student submits
router.post(
  "/:id/submit",
  authorize("student"),
  upload.single("file"),
  async (req, res, next) => {
    try {
      const studentId = req.user.id;
      const assignmentId = req.params.id;

      // Check assignment exists and belongs to student's class
      const [assignments] = await db.query(
        `SELECT a.id FROM assignments a
       JOIN subjects s ON s.id = a.subject_id AND s.class_id = ?
       WHERE a.id = ?`,
        [req.user.class_id, assignmentId],
      );
      if (!assignments.length) throw createError(404, "Assignment not found.");

      const fileUrl = req.file
        ? `/uploads/submissions/${req.file.filename}`
        : null;

      await db.query(
        `INSERT INTO submissions (assignment_id, student_id, content, file_url, status, submitted_at)
       VALUES (?, ?, ?, ?, 'submitted', NOW())
       ON DUPLICATE KEY UPDATE
         content = VALUES(content),
         file_url = VALUES(file_url),
         status = 'submitted',
         submitted_at = NOW()`,
        [assignmentId, studentId, req.body.content || null, fileUrl],
      );

      res.json({ message: "Submission received." });
    } catch (err) {
      next(err);
    }
  },
);

// ── GET /api/assignments/:id/submissions ─────────────────────
// Teacher views all submissions for an assignment
router.get(
  "/:id/submissions",
  authorize("teacher", "admin"),
  async (req, res, next) => {
    try {
      const [rows] = await db.query(
        `SELECT s.*, u.full_name AS student_name, u.email AS student_email
       FROM submissions s
       JOIN users u ON u.id = s.student_id
       JOIN assignments a ON a.id = s.assignment_id AND a.teacher_id = ?
       WHERE a.id = ?
       ORDER BY s.submitted_at DESC`,
        [req.user.id, req.params.id],
      );
      res.json(rows);
    } catch (err) {
      next(err);
    }
  },
);

// ── PUT /api/assignments/:id/submissions/:studentId/grade ────
// Teacher grades a submission
router.put(
  "/:id/submissions/:studentId/grade",
  authorize("teacher", "admin"),
  async (req, res, next) => {
    try {
      const { score, feedback } = req.body;
      await db.query(
        `UPDATE submissions
       SET score = ?, feedback = ?, status = 'graded'
       WHERE assignment_id = ? AND student_id = ?`,
        [score || 0, feedback || "", req.params.id, req.params.studentId],
      );
      res.json({ message: "Submission graded." });
    } catch (err) {
      next(err);
    }
  },
);

module.exports = router;
