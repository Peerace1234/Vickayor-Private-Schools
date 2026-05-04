// routes/results.js
const express = require("express");
const db = require("../config/db");
const { authenticate, authorize } = require("../middleware/auth");
const { createError } = require("../middleware/errorHandler");

const router = express.Router();
router.use(authenticate);

// ── Grade calculator helper ──────────────────────────────────
function computeGrade(total) {
  if (total >= 70) return { grade: "A", remark: "Excellent" };
  if (total >= 60) return { grade: "B", remark: "Very Good" };
  if (total >= 50) return { grade: "C", remark: "Good" };
  if (total >= 45) return { grade: "D", remark: "Pass" };
  if (total >= 40) return { grade: "E", remark: "Fair" };
  return { grade: "F", remark: "Fail" };
}

// ── GET /api/results ─────────────────────────────────────────
// Student: own results. Teacher: results for subjects they teach.
router.get("/", async (req, res, next) => {
  try {
    const { id, role, class_id } = req.user;
    const { term, session } = req.query;
    let query, params;

    if (role === "student") {
      query = `
        SELECT r.*, s.name AS subject_name
        FROM results r
        JOIN subjects s ON s.id = r.subject_id
        WHERE r.student_id = ?
        ${term ? "AND r.term = ?" : ""}
        ${session ? "AND r.session = ?" : ""}
        ORDER BY s.name`;
      params = [id, ...(term ? [term] : []), ...(session ? [session] : [])];
    } else {
      query = `
        SELECT r.*, s.name AS subject_name,
               u.full_name AS student_name, u.email AS student_email
        FROM results r
        JOIN subjects s ON s.id = r.subject_id AND s.teacher_id = ?
        JOIN users    u ON u.id = r.student_id
        ${term ? "AND r.term = ?" : "WHERE 1=1"}
        ${session ? "AND r.session = ?" : ""}
        ORDER BY u.full_name, s.name`;
      params = [id, ...(term ? [term] : []), ...(session ? [session] : [])];
    }

    const [rows] = await db.query(query, params);
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// ── GET /api/results/student/:studentId ─────────────────────
// Admin or teacher views a single student's result sheet
router.get(
  "/student/:studentId",
  authorize("teacher", "admin"),
  async (req, res, next) => {
    try {
      const { term, session } = req.query;
      const [rows] = await db.query(
        `SELECT r.*, s.name AS subject_name,
              c.name AS class_name, c.section
       FROM results r
       JOIN subjects s ON s.id = r.subject_id
       JOIN classes  c ON c.id = s.class_id
       WHERE r.student_id = ?
         ${term ? "AND r.term = ?" : ""}
         ${session ? "AND r.session = ?" : ""}
       ORDER BY s.name`,
        [
          req.params.studentId,
          ...(term ? [term] : []),
          ...(session ? [session] : []),
        ],
      );
      res.json(rows);
    } catch (err) {
      next(err);
    }
  },
);

// ── POST /api/results ────────────────────────────────────────
// Teacher posts a single result
router.post("/", authorize("teacher", "admin"), async (req, res, next) => {
  try {
    const { student_id, subject_id, term, session, ca_score, exam_score } =
      req.body;
    if (!student_id || !subject_id || !term || !session) {
      throw createError(
        400,
        "student_id, subject_id, term, and session are required.",
      );
    }

    const total = (parseFloat(ca_score) || 0) + (parseFloat(exam_score) || 0);
    const { grade, remark } = computeGrade(total);

    await db.query(
      `INSERT INTO results
         (student_id, subject_id, term, session, ca_score, exam_score, grade, remark)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
         ca_score   = VALUES(ca_score),
         exam_score = VALUES(exam_score),
         grade      = VALUES(grade),
         remark     = VALUES(remark)`,
      [
        student_id,
        subject_id,
        term,
        session,
        ca_score || 0,
        exam_score || 0,
        grade,
        remark,
      ],
    );

    res.status(201).json({ message: "Result saved.", grade, remark, total });
  } catch (err) {
    next(err);
  }
});

// ── POST /api/results/bulk ───────────────────────────────────
// Teacher posts results for a whole class at once
// Body: { subject_id, term, session, results: [{ student_id, ca_score, exam_score }] }
router.post("/bulk", authorize("teacher", "admin"), async (req, res, next) => {
  try {
    const { subject_id, term, session, results } = req.body;
    if (
      !subject_id ||
      !term ||
      !session ||
      !Array.isArray(results) ||
      !results.length
    ) {
      throw createError(
        400,
        "subject_id, term, session, and results[] are required.",
      );
    }

    const conn = await require("../config/db").getConnection();
    try {
      await conn.beginTransaction();
      for (const r of results) {
        const ca = parseFloat(r.ca_score) || 0;
        const exam = parseFloat(r.exam_score) || 0;
        const { grade, remark } = computeGrade(ca + exam);
        await conn.query(
          `INSERT INTO results
             (student_id, subject_id, term, session, ca_score, exam_score, grade, remark)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON DUPLICATE KEY UPDATE
             ca_score = VALUES(ca_score), exam_score = VALUES(exam_score),
             grade    = VALUES(grade),    remark     = VALUES(remark)`,
          [r.student_id, subject_id, term, session, ca, exam, grade, remark],
        );
      }
      await conn.commit();
      res.json({ message: `${results.length} result(s) saved.` });
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }
  } catch (err) {
    next(err);
  }
});

// ── DELETE /api/results/:id ──────────────────────────────────
router.delete("/:id", authorize("admin"), async (req, res, next) => {
  try {
    await db.query("DELETE FROM results WHERE id = ?", [req.params.id]);
    res.json({ message: "Result deleted." });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
