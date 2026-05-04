// socket/chat.js  — Real-time chat via Socket.io
// Mount this in server.js:  require('./socket/chat')(io);

const jwt = require("jsonwebtoken");
const db = require("../config/db");

module.exports = function attachChatSocket(io) {
  // ── JWT auth middleware for Socket.io ────────────────────
  io.use((socket, next) => {
    const token =
      socket.handshake.auth?.token ||
      socket.handshake.headers?.authorization?.split(" ")[1];

    if (!token) return next(new Error("Authentication required."));

    try {
      socket.user = jwt.verify(token, process.env.JWT_SECRET);
      next();
    } catch {
      next(new Error("Invalid token."));
    }
  });

  // ── Connection ───────────────────────────────────────────
  io.on("connection", (socket) => {
    const { id: userId, name, role } = socket.user;
    console.log(`[Socket] Connected: ${name} (${role}) — ${socket.id}`);

    // ── join_room ────────────────────────────────────────
    // Client emits: { roomId }
    socket.on("join_room", async ({ roomId }) => {
      try {
        // Verify membership in DB
        const [rows] = await db.query(
          "SELECT id FROM chat_members WHERE room_id = ? AND user_id = ?",
          [roomId, userId],
        );
        if (!rows.length) {
          return socket.emit("error", {
            message: "Not a member of this room.",
          });
        }

        socket.join(`room:${roomId}`);
        socket.emit("joined", { roomId });
        console.log(`[Socket] ${name} joined room ${roomId}`);
      } catch (err) {
        console.error("[Socket] join_room error:", err.message);
        socket.emit("error", { message: "Failed to join room." });
      }
    });

    // ── leave_room ───────────────────────────────────────
    socket.on("leave_room", ({ roomId }) => {
      socket.leave(`room:${roomId}`);
      socket.emit("left", { roomId });
    });

    // ── send_message ─────────────────────────────────────
    // Client emits: { roomId, content, fileUrl? }
    socket.on("send_message", async ({ roomId, content, fileUrl }) => {
      try {
        if (!content && !fileUrl) return;

        // Verify sender is still a member
        const [rows] = await db.query(
          "SELECT id FROM chat_members WHERE room_id = ? AND user_id = ?",
          [roomId, userId],
        );
        if (!rows.length) {
          return socket.emit("error", {
            message: "Not a member of this room.",
          });
        }

        // Save to DB
        const [result] = await db.query(
          `INSERT INTO messages (room_id, sender_id, content, file_url)
           VALUES (?, ?, ?, ?)`,
          [roomId, userId, content || null, fileUrl || null],
        );

        const message = {
          id: result.insertId,
          room_id: roomId,
          sender_id: userId,
          sender_name: name,
          sender_role: role,
          content: content || null,
          file_url: fileUrl || null,
          sent_at: new Date().toISOString(),
          is_deleted: 0,
        };

        // Broadcast to everyone in room (including sender)
        io.to(`room:${roomId}`).emit("new_message", message);
      } catch (err) {
        console.error("[Socket] send_message error:", err.message);
        socket.emit("error", { message: "Failed to send message." });
      }
    });

    // ── typing ───────────────────────────────────────────
    // Client emits: { roomId, isTyping }
    socket.on("typing", ({ roomId, isTyping }) => {
      socket.to(`room:${roomId}`).emit("user_typing", {
        userId,
        name,
        isTyping,
      });
    });

    // ── delete_message ───────────────────────────────────
    // Client emits: { messageId, roomId }
    socket.on("delete_message", async ({ messageId, roomId }) => {
      try {
        const [rows] = await db.query(
          "SELECT sender_id FROM messages WHERE id = ?",
          [messageId],
        );
        if (!rows.length) return;
        if (rows[0].sender_id !== userId && role !== "admin") {
          return socket.emit("error", {
            message: "Cannot delete this message.",
          });
        }

        await db.query(
          "UPDATE messages SET is_deleted = 1, content = NULL WHERE id = ?",
          [messageId],
        );

        io.to(`room:${roomId}`).emit("message_deleted", { messageId });
      } catch (err) {
        console.error("[Socket] delete_message error:", err.message);
      }
    });

    // ── disconnect ───────────────────────────────────────
    socket.on("disconnect", () => {
      console.log(`[Socket] Disconnected: ${name} — ${socket.id}`);
    });
  });
};
