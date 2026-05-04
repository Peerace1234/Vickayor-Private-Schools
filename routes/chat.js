// routes/chat.js  — REST endpoints for rooms and message history
// Real-time messaging is handled by socket/chat.js via Socket.io
const express = require("express");
const db = require("../config/db");
const { authenticate, authorize } = require("../middleware/auth");
const { createError } = require("../middleware/errorHandler");

const router = express.Router();
router.use(authenticate);

// ── GET /api/chat/rooms ──────────────────────────────────────
// List all rooms the current user is a member of
router.get("/rooms", async (req, res, next) => {
  try {
    const [rows] = await db.query(
      `SELECT r.id, r.name, r.type, r.class_id,
              c.name AS class_name, c.section,
              (SELECT content FROM messages m
               WHERE m.room_id = r.id AND m.is_deleted = 0
               ORDER BY m.sent_at DESC LIMIT 1) AS last_message,
              (SELECT sent_at FROM messages m
               WHERE m.room_id = r.id AND m.is_deleted = 0
               ORDER BY m.sent_at DESC LIMIT 1) AS last_sent_at
       FROM chat_rooms r
       JOIN chat_members cm ON cm.room_id = r.id AND cm.user_id = ?
       LEFT JOIN classes c ON c.id = r.class_id
       ORDER BY last_sent_at DESC`,
      [req.user.id],
    );
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// ── POST /api/chat/rooms ─────────────────────────────────────
// Create a room (admin/teacher can create class rooms; anyone can create DMs/groups)
router.post("/rooms", async (req, res, next) => {
  try {
    const { name, type, class_id, member_ids } = req.body;
    if (!name || !type) throw createError(400, "name and type are required.");

    const [result] = await db.query(
      `INSERT INTO chat_rooms (name, type, class_id, created_by)
       VALUES (?, ?, ?, ?)`,
      [name, type, class_id || null, req.user.id],
    );
    const roomId = result.insertId;

    // Add creator as member
    const members = Array.isArray(member_ids)
      ? [...new Set([req.user.id, ...member_ids])]
      : [req.user.id];
    const memberRows = members.map((uid) => [roomId, uid]);
    await db.query(
      "INSERT IGNORE INTO chat_members (room_id, user_id) VALUES ?",
      [memberRows],
    );

    res.status(201).json({ message: "Room created.", id: roomId });
  } catch (err) {
    next(err);
  }
});

// ── GET /api/chat/rooms/:roomId/messages ─────────────────────
// Paginated message history
router.get("/rooms/:roomId/messages", async (req, res, next) => {
  try {
    // Verify membership
    const [membership] = await db.query(
      "SELECT id FROM chat_members WHERE room_id = ? AND user_id = ?",
      [req.params.roomId, req.user.id],
    );
    if (!membership.length)
      throw createError(403, "Not a member of this room.");

    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(100, parseInt(req.query.limit) || 30);
    const offset = (page - 1) * limit;

    const [rows] = await db.query(
      `SELECT m.id, m.content, m.file_url, m.sent_at, m.is_deleted,
              u.id AS sender_id, u.full_name AS sender_name, u.role AS sender_role
       FROM messages m
       JOIN users u ON u.id = m.sender_id
       WHERE m.room_id = ?
       ORDER BY m.sent_at DESC
       LIMIT ? OFFSET ?`,
      [req.params.roomId, limit, offset],
    );

    res.json(rows.reverse()); // oldest first for UI
  } catch (err) {
    next(err);
  }
});

// ── DELETE /api/chat/messages/:messageId ─────────────────────
// Soft-delete own message (or admin hard-delete)
router.delete("/messages/:messageId", async (req, res, next) => {
  try {
    const [rows] = await db.query("SELECT * FROM messages WHERE id = ?", [
      req.params.messageId,
    ]);
    if (!rows.length) throw createError(404, "Message not found.");

    if (req.user.role !== "admin" && rows[0].sender_id !== req.user.id) {
      throw createError(403, "Cannot delete someone else's message.");
    }

    await db.query(
      "UPDATE messages SET is_deleted = 1, content = NULL WHERE id = ?",
      [req.params.messageId],
    );

    res.json({ message: "Message deleted." });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
