// routes/auth.js
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const db = require("../config/db");
const { createError } = require("../middleware/errorHandler");
const { authenticate } = require("../middleware/auth");

const router = express.Router();

// ── POST /api/auth/register ──────────────────────────────────
router.post("/register", async (req, res, next) => {
  try {
    const { full_name, email, password, role, class_id } = req.body;
    if (!full_name || !email || !password) {
      throw createError(400, "full_name, email, and password are required.");
    }

    // Check if email exists
    const [existing] = await db.query("SELECT id FROM users WHERE email = ?", [
      email,
    ]);
    if (existing.length) throw createError(409, "Email already exists.");

    // Hash password
    const password_hash = await bcrypt.hash(password, 10);

    // Insert user
    const [result] = await db.query(
      `INSERT INTO users (full_name, email, password_hash, role, class_id)
       VALUES (?, ?, ?, ?, ?)`,
      [full_name, email, password_hash, role || "student", class_id || null],
    );

    res.status(201).json({ message: "User registered.", id: result.insertId });
  } catch (err) {
    next(err);
  }
});

// ── POST /api/auth/login ─────────────────────────────────────
router.post("/login", async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      throw createError(400, "email and password are required.");
    }

    // Find user
    const [rows] = await db.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);
    if (!rows.length) throw createError(401, "Invalid credentials.");

    const user = rows[0];

    // Verify password
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) throw createError(401, "Invalid credentials.");

    // Create JWT
    const token = jwt.sign(
      {
        id: user.id,
        name: user.full_name,
        email: user.email,
        role: user.role,
        class_id: user.class_id,
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" },
    );

    res.json({
      message: "Login successful.",
      token,
      user: {
        id: user.id,
        name: user.full_name,
        email: user.email,
        role: user.role,
        class_id: user.class_id,
      },
    });
  } catch (err) {
    next(err);
  }
});

// ── GET /api/auth/me ─────────────────────────────────────────
// Get current user info (requires token)
router.get("/me", authenticate, async (req, res, next) => {
  try {
    const [rows] = await db.query("SELECT * FROM users WHERE id = ?", [
      req.user.id,
    ]);
    if (!rows.length) throw createError(404, "User not found.");

    const user = rows[0];
    res.json({
      id: user.id,
      name: user.full_name,
      email: user.email,
      role: user.role,
      class_id: user.class_id,
      profile_pic: user.profile_pic,
    });
  } catch (err) {
    next(err);
  }
});

// ── PUT /api/auth/update ─────────────────────────────────────
router.put("/update", authenticate, async (req, res, next) => {
  try {
    const { full_name, password, profile_pic } = req.body;
    const userId = req.user.id;

    let updates = [];
    let values = [];

    if (full_name) {
      updates.push("full_name = ?");
      values.push(full_name);
    }
    if (profile_pic) {
      updates.push("profile_pic = ?");
      values.push(profile_pic);
    }
    if (password) {
      const password_hash = await bcrypt.hash(password, 10);
      updates.push("password_hash = ?");
      values.push(password_hash);
    }

    if (!updates.length) throw createError(400, "No fields to update.");

    values.push(userId);
    await db.query(
      `UPDATE users SET ${updates.join(", ")} WHERE id = ?`,
      values,
    );

    res.json({ message: "User updated." });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
