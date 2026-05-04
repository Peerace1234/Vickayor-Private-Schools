require("dotenv").config();
const express = require("express");
const http = require("http");
const fs = require("fs");
const path = require("path");
const cors = require("cors");

// ── Express App Setup ────────────────────────────────────────
const app = express();
const server = http.createServer(app);

// ── Socket.io Setup ──────────────────────────────────────────
const { Server } = require("socket.io");
const io = new Server(server, {
  cors: {
    origin: process.env.CLIENT_URL || "*",
    methods: ["GET", "POST"],
  },
});
require("./socket/chat")(io);

// ── Middleware ───────────────────────────────────────────────
app.use(cors({ origin: process.env.CLIENT_URL || "*" }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve uploaded files
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ── API Routes ───────────────────────────────────────────────
const authRoutes = require("./routes/auth");
const assignmentRoutes = require("./routes/assignments");
const resultRoutes = require("./routes/results");
const announcementRoutes = require("./routes/announcements");
const chatRoutes = require("./routes/chat");
const dashboardRoutes = require("./routes/dashboard");
const attendanceRoutes = require("./routes/attendance");

app.use("/api/auth", authRoutes);
app.use("/api/assignments", assignmentRoutes);
app.use("/api/results", resultRoutes);
app.use("/api/announcements", announcementRoutes);
app.use("/api/chat", chatRoutes);
app.use("/api/dashboard", dashboardRoutes);
app.use("/api/attendance", attendanceRoutes);

// Health check
app.get("/api/health", (req, res) => res.json({ status: "ok" }));

// ── ERROR HANDLER (must be LAST) ─────────────────────────────
const { errorHandler } = require("./middleware/errorHandler");
app.use(errorHandler);

// ── START SERVER ────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Vickayor backend server running on port ${PORT}`);
});
