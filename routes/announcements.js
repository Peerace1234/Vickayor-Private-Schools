// routes/announcements.js
const express = require("express");
const db = require("../config/db");
const { authenticate, authorize } = require("../middleware/auth");
const { createError } = require("../middleware/errorHandler");

const router = express.Router();
router.use(authenticate);

// ── GET /api/announcements ───────────────────────────────────
// Returns announcements relevant to the current user
router.get("/", async (req, res, next) => {
  try {
    const { id, role, class_id } = req.user;
    let rows;

    if (role === "student") {
      [rows] = await db.query(
        `SELECT a.*, u.full_name AS author_name,
                c.name AS class_name, c.section
         FROM announcements a
         JOIN users u ON u.id = a.author_id
         LEFT JOIN classes c ON c.id = a.class_id
         WHERE a.audience = 'all'
            OR (a.audience = 'class' AND a.class_id = ?)
         ORDER BY a.created_at DESC`,
        [class_id],
      );
    } else {
      // Teachers and admins see everything except teachers_only filtered by their role
      [rows] = await db.query(
        `SELECT a.*, u.full_name AS author_name,
                c.name AS class_name, c.section
         FROM announcements a
         JOIN users u ON u.id = a.author_id
         LEFT JOIN classes c ON c.id = a.class_id
         ORDER BY a.created_at DESC`,
      );
    }

    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// ── GET /api/announcements/:id ───────────────────────────────
router.get("/:id", async (req, res, next) => {
  try {
    const [rows] = await db.query(
      `SELECT a.*, u.full_name AS author_name,
              c.name AS class_name, c.section
       FROM announcements a
       JOIN users u ON u.id = a.author_id
       LEFT JOIN classes c ON c.id = a.class_id
       WHERE a.id = ?`,
      [req.params.id],
    );
    if (!rows.length) throw createError(404, "Announcement not found.");
    res.json(rows[0]);
  } catch (err) {
    next(err);
  }
});

// ── POST /api/announcements ──────────────────────────────────
// Teacher or admin only
router.post("/", authorize("teacher", "admin"), async (req, res, next) => {
  try {
    const { title, body, audience, class_id } = req.body;
    if (!title || !body) throw createError(400, "title and body are required.");

    const [result] = await db.query(
      `INSERT INTO announcements (author_id, class_id, title, body, audience)
       VALUES (?, ?, ?, ?, ?)`,
      [req.user.id, class_id || null, title, body, audience || "all"],
    );

    res
      .status(201)
      .json({ message: "Announcement posted.", id: result.insertId });
  } catch (err) {
    next(err);
  }
});

// ── PUT /api/announcements/:id ───────────────────────────────
router.put("/:id", authorize("teacher", "admin"), async (req, res, next) => {
  try {
    const [rows] = await db.query("SELECT * FROM announcements WHERE id = ?", [
      req.params.id,
    ]);
    if (!rows.length) throw createError(404, "Announcement not found.");

    // Only the author or admin can edit
    if (req.user.role !== "admin" && rows[0].author_id !== req.user.id) {
      throw createError(403, "Not allowed to edit this announcement.");
    }

    const { title, body, audience, class_id } = req.body;
    await db.query(
      `UPDATE announcements
       SET title = ?, body = ?, audience = ?, class_id = ?
       WHERE id = ?`,
      [
        title || rows[0].title,
        body || rows[0].body,
        audience || rows[0].audience,
        class_id !== undefined ? class_id : rows[0].class_id,
        req.params.id,
      ],
    );

    res.json({ message: "Announcement updated." });
  } catch (err) {
    next(err);
  }
});

// ── DELETE /api/announcements/:id ───────────────────────
router.delete("/:id", authorize("teacher", "admin"), async (req, res, next) => {
  try {
    const [rows] = await db.query(
      "SELECT author_id FROM announcements WHERE id = ?",
      [req.params.id],
    );
    if (!rows.length) throw createError(404, "Announcement not found.");

    if (req.user.role !== "admin" && rows[0].author_id !== req.user.id) {
      throw createError(403, "Not allowed.");
    }

    await db.query("DELETE FROM announcements WHERE id = ?", [req.params.id]);
    res.json({ message: "Announcement deleted." });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
