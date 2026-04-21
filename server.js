require("dotenv").config();
const http = require("http");
const fs = require("fs");
const path = require("path");
const url = require("url");
const querystring = require("querystring");
const crypto = require("crypto");

const contentTypes = {
  ".html": "text/html",
  ".css": "text/css",
  ".js": "application/javascript",
  ".json": "application/json",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".png": "image/png",
  ".svg": "image/svg+xml",
};

const sessions = {};
const loginAttempts = {};

// ─── RATE LIMITING ────────────────────────────────────────────────────────────
function isRateLimited(ip) {
  const now = Date.now();
  if (!loginAttempts[ip]) {
    loginAttempts[ip] = { count: 1, firstAttempt: now };
    return false;
  }
  if (now - loginAttempts[ip].firstAttempt > 15 * 60 * 1000) {
    loginAttempts[ip] = { count: 1, firstAttempt: now };
    return false;
  }
  loginAttempts[ip].count++;
  return loginAttempts[ip].count > 5;
}

// ─── STATIC FILE SERVING ─────────────────────────────────────────────────────
function serveStatic(filePath, response) {
  const ext = path.extname(filePath);
  const type = contentTypes[ext.toLowerCase()] || "application/octet-stream";
  fs.readFile(filePath, function (error, content) {
    if (error) {
      response.writeHead(404, { "Content-Type": "text/plain" });
      response.end("404 Not Found");
      return;
    }
    response.writeHead(200, { "Content-Type": type });
    response.end(content);
  });
}

// ─── BODY PARSER ─────────────────────────────────────────────────────────────
function parseBody(request, callback) {
  let body = "";
  request.on("data", (chunk) => {
    body += chunk.toString();
  });
  request.on("end", () => {
    callback(querystring.parse(body));
  });
}

// ─── COOKIES & SESSIONS ──────────────────────────────────────────────────────
function parseCookies(request) {
  const header = request.headers.cookie || "";
  return header.split(";").reduce((cookies, cookiePair) => {
    const parts = cookiePair.split("=");
    if (parts.length === 2) {
      cookies[parts[0].trim()] = decodeURIComponent(parts[1].trim());
    }
    return cookies;
  }, {});
}

function generateSessionId() {
  return crypto.randomBytes(16).toString("hex");
}

function getSession(request) {
  const cookies = parseCookies(request);
  const sessionId = cookies.sessionId;
  if (!sessionId) return null;
  const session = sessions[sessionId];
  if (!session || session.expires < Date.now()) {
    delete sessions[sessionId];
    return null;
  }
  return session;
}

// ─── PASSWORD HASHING ────────────────────────────────────────────────────────
function generateSalt() {
  return crypto.randomBytes(16).toString("hex");
}

function hashPassword(password, salt) {
  const hash = crypto
    .pbkdf2Sync(password, salt, 100000, 64, "sha512")
    .toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, storedPassword) {
  if (!storedPassword) return false;
  if (storedPassword.indexOf(":") === -1) return password === storedPassword;
  const [salt, originalHash] = storedPassword.split(":");
  const hash = crypto
    .pbkdf2Sync(password, salt, 100000, 64, "sha512")
    .toString("hex");
  try {
    return crypto.timingSafeEqual(
      Buffer.from(hash, "hex"),
      Buffer.from(originalHash, "hex"),
    );
  } catch (error) {
    return false;
  }
}

function generateRandomPassword(length = 10) {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let password = "";
  const bytes = crypto.randomBytes(length);
  for (let i = 0; i < length; i++) {
    password += chars[bytes[i] % chars.length];
  }
  return password;
}

// ─── USERS FILE ──────────────────────────────────────────────────────────────
function backupInvalidUsersFile(filePath) {
  const backupPath = path.join(
    __dirname,
    `users.json.corrupt.${Date.now()}.bak`,
  );
  try {
    fs.renameSync(filePath, backupPath);
    console.error(
      `Backed up corrupt users.json to ${backupPath}. A fresh users.json has been created.`,
    );
  } catch (backupError) {
    console.error("Failed to backup corrupt users.json:", backupError);
  }
}

function readUsersFile() {
  const filePath = path.join(__dirname, "users.json");
  if (!fs.existsSync(filePath)) return { users: [] };
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    return JSON.parse(raw || '{"users": []}');
  } catch (error) {
    console.error("Failed to read users.json:", error);
    backupInvalidUsersFile(filePath);
    try {
      fs.writeFileSync(
        filePath,
        JSON.stringify({ users: [] }, null, 2),
        "utf8",
      );
    } catch (writeError) {
      console.error("Failed to recreate users.json after backup:", writeError);
    }
    return { users: [] };
  }
}

function saveUsersFile(data) {
  const filePath = path.join(__dirname, "users.json");
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf8");
    return true;
  } catch (error) {
    console.error("Failed to save users.json:", error);
    return false;
  }
}

function findUserByEmail(email) {
  const users = readUsersFile().users || [];
  return users.find(
    (user) => user.email.toLowerCase() === (email || "").trim().toLowerCase(),
  );
}

// ─── EMAIL ───────────────────────────────────────────────────────────────────
function createEmailTransporter() {
  const smtpUser = process.env.SMTP_USER;
  const smtpPass = process.env.SMTP_PASS;
  const smtpHost = process.env.SMTP_HOST;
  const smtpPort = process.env.SMTP_PORT
    ? parseInt(process.env.SMTP_PORT, 10)
    : 587;
  const smtpService = process.env.SMTP_SERVICE;
  if (!smtpUser || !smtpPass) return null;
  let nodemailer;
  try {
    nodemailer = require("nodemailer");
  } catch (e) {
    return null;
  }
  const config = { auth: { user: smtpUser, pass: smtpPass } };
  if (smtpHost) {
    config.host = smtpHost;
    config.port = smtpPort;
    config.secure = smtpPort === 465;
  } else if (smtpService) {
    config.service = smtpService;
  }
  return nodemailer.createTransport(config);
}

// Welcome email — sent when student registers
function sendWelcomeEmail(to, name) {
  const transporter = createEmailTransporter();
  if (!transporter) {
    console.log("Email not configured. Cannot send welcome email.");
    return Promise.resolve(false);
  }
  return transporter
    .sendMail({
      from: process.env.EMAIL_FROM || process.env.SMTP_USER,
      to,
      subject: "Welcome to Vickayor Private School!",
      text: `Hello ${name},\n\nWelcome to Vickayor Private School! Your student account has been created successfully.\n\nYou can log in at any time here:\nhttp://localhost:8080/login\n\nIf you have any questions, contact us at:\nEmail: vickayorprivateschool@gmail.com\nPhone: +234 706 595 0300\n\nWarm regards,\nVickayor Private School`,
    })
    .then(() => {
      console.log("Welcome email sent to:", to);
      return true;
    })
    .catch((error) => {
      console.error("Failed to send welcome email:", error);
      return false;
    });
}

// Approval email — sent when admin approves a teacher
function sendApprovalEmail(to, name) {
  const transporter = createEmailTransporter();
  if (!transporter) {
    console.log("Email not configured. Cannot send approval email.");
    return Promise.resolve(false);
  }
  return transporter
    .sendMail({
      from: process.env.EMAIL_FROM || process.env.SMTP_USER,
      to,
      subject:
        "Your Vickayor Private School Teacher Account Has Been Approved!",
      text: `Hello ${name},\n\nGreat news! Your teacher account at Vickayor Private School has been approved by the admin.\n\nYou can now log in using your email and password at:\nhttp://localhost:8080/teacher-login\n\nWelcome to the Vickayor team! We are excited to have you on board.\n\nIf you have any questions, contact us at:\nEmail: vickayorprivateschool@gmail.com\nPhone: +234 706 595 0300\n\nWarm regards,\nVickayor Private School`,
    })
    .then(() => {
      console.log("Approval email sent to:", to);
      return true;
    })
    .catch((error) => {
      console.error("Failed to send approval email:", error);
      return false;
    });
}

// Rejection email — sent when admin rejects a teacher application
function sendRejectionEmail(to, name) {
  const transporter = createEmailTransporter();
  if (!transporter) {
    console.log("Email not configured. Cannot send rejection email.");
    return Promise.resolve(false);
  }
  return transporter
    .sendMail({
      from: process.env.EMAIL_FROM || process.env.SMTP_USER,
      to,
      subject: "Update on Your Vickayor Private School Teacher Application",
      text: `Hello ${name},\n\nThank you for applying to be a teacher at Vickayor Private School.\n\nUnfortunately, your application has not been approved at this time. Please contact the school directly for more information.\n\nEmail: vickayorprivateschool@gmail.com\nPhone: +234 706 595 0300\n\nKind regards,\nVickayor Private School`,
    })
    .then(() => {
      console.log("Rejection email sent to:", to);
      return true;
    })
    .catch((error) => {
      console.error("Failed to send rejection email:", error);
      return false;
    });
}

// Verification email — sent for email verification if enabled
function sendVerificationEmail(to, token, name) {
  const transporter = createEmailTransporter();
  const verifyUrl = `http://localhost:8080/verify?token=${token}`;
  if (!transporter) {
    console.log("Email not configured. Verification link:", verifyUrl);
    return Promise.resolve(false);
  }
  return transporter
    .sendMail({
      from: process.env.EMAIL_FROM || process.env.SMTP_USER,
      to,
      subject: "Verify your Vickayor Private School account",
      text: `Hello ${name || "User"},\n\nThank you for registering. Please verify your account by clicking the link below:\n\n${verifyUrl}\n\nIgnore this email if you did not register.\n\nVickayor Private School`,
    })
    .then(() => true)
    .catch(() => false);
}
function sendContactEmail(enquiry) {
  const transporter = createEmailTransporter();
  if (!transporter) {
    console.log("Email not configured. Contact enquiry saved locally only.");
    return Promise.resolve(false);
  }
  const schoolEmail =
    process.env.SCHOOL_EMAIL ||
    process.env.SMTP_USER ||
    "vickayorprivateschool@gmail.com";
  return transporter
    .sendMail({
      from: process.env.EMAIL_FROM || process.env.SMTP_USER,
      to: schoolEmail,
      replyTo: enquiry.email,
      subject: `New Enquiry from ${enquiry.name}: ${enquiry.subject}`,
      text: `You have a new enquiry from your school website.\n\nName: ${enquiry.name}\nEmail: ${enquiry.email}\nSubject: ${enquiry.subject}\n\nMessage:\n${enquiry.message}\n\nSent: ${enquiry.date}`,
    })
    .then(() => {
      console.log("Contact email sent to school:", schoolEmail);
      return true;
    })
    .catch((error) => {
      console.error("Failed to send contact email:", error);
      return false;
    });
}

// ─── AUTH FUNCTIONS ──────────────────────────────────────────────────────────
function authenticateLogin(data, role) {
  const email = (data.email || "").trim();
  const password = data.password || "";
  const user = findUserByEmail(email);
  if (!user) return { success: false, message: "Invalid email or password." };
  if (role && user.role !== role)
    return { success: false, message: "Invalid credentials." };
  if (!verifyPassword(password, user.password))
    return { success: false, message: "Invalid email or password." };
  if (!user.verified)
    return {
      success: false,
      message:
        "Your account is pending approval. Please wait for admin confirmation.",
    };
  return { success: true, message: "Login successful.", user };
}

function registerUser(data) {
  const name = (data.name || "").trim();
  const email = (data.email || "").trim().toLowerCase();
  const password = data.password || "";
  if (!name || !email || !password)
    return {
      success: false,
      message: "Name, email, and password are required.",
    };
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email))
    return { success: false, message: "Please enter a valid email address." };
  if (password.length < 8)
    return {
      success: false,
      message: "Password must be at least 8 characters.",
    };
  if (!/[A-Z]/.test(password))
    return {
      success: false,
      message: "Password must contain at least one uppercase letter.",
    };
  if (!/[0-9]/.test(password))
    return {
      success: false,
      message: "Password must contain at least one number.",
    };
  try {
    const usersFile = readUsersFile();
    const users = usersFile.users || [];
    if (users.some((u) => u.email === email))
      return {
        success: false,
        message: "An account already exists with this email.",
      };
    const salt = generateSalt();
    users.push({
      name,
      email,
      password: hashPassword(password, salt),
      role: "student",
      verified: true,
      status: "approved",
    });
    saveUsersFile({ users });

    // Send welcome email
    sendWelcomeEmail(email, name).catch(() => null);

    return {
      success: true,
      message:
        "Account created successfully. Welcome to Vickayor Private School!",
    };
  } catch (error) {
    return {
      success: false,
      message: "Unable to create account. Please try again.",
    };
  }
}

function registerTeacherApplication(data) {
  const name = (data.name || "").trim();
  const email = (data.email || "").trim().toLowerCase();
  const password = data.password || "";
  const subject = (data.subject || "").trim();
  const phone = (data.phone || "").trim();
  if (!name || !email || !password)
    return {
      success: false,
      message: "Name, email, and password are required.",
    };
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email))
    return { success: false, message: "Please enter a valid email address." };
  if (password.length < 8)
    return {
      success: false,
      message: "Password must be at least 8 characters.",
    };
  if (!/[A-Z]/.test(password))
    return {
      success: false,
      message: "Password must contain at least one uppercase letter.",
    };
  if (!/[0-9]/.test(password))
    return {
      success: false,
      message: "Password must contain at least one number.",
    };
  const usersFile = readUsersFile();
  const users = usersFile.users || [];
  if (users.some((u) => u.email === email))
    return {
      success: false,
      message: "An account already exists with this email.",
    };
  const salt = generateSalt();
  users.push({
    name,
    email,
    password: hashPassword(password, salt),
    role: "teacher",
    verified: false,
    status: "pending",
    subject,
    phone,
  });
  saveUsersFile({ users });
  return {
    success: true,
    message:
      "Application submitted! The admin will review and approve your account.",
  };
}

function approveTeacher(email) {
  if (!email) return { success: false, message: "Email required." };
  const usersFile = readUsersFile();
  const users = usersFile.users || [];
  const user = users.find((u) => u.email === email.trim().toLowerCase());
  if (!user) return { success: false, message: "User not found." };
  user.verified = true;
  user.status = "approved";
  user.role = "teacher";
  saveUsersFile({ users });

  // Send approval email to teacher
  sendApprovalEmail(user.email, user.name).catch(() => null);

  return {
    success: true,
    message: `${user.name} has been approved as a teacher.`,
  };
}

function rejectTeacherApplication(email) {
  if (!email) return { success: false, message: "Email required." };
  const usersFile = readUsersFile();
  const users = usersFile.users || [];
  const user = users.find((u) => u.email === email.trim().toLowerCase());

  // Send rejection email before removing
  if (user) sendRejectionEmail(user.email, user.name).catch(() => null);

  usersFile.users = (usersFile.users || []).filter(
    (u) => u.email !== email.trim().toLowerCase(),
  );
  saveUsersFile(usersFile);
  return {
    success: true,
    message: "Application rejected and applicant notified.",
  };
}

function addStudent(data) {
  const name = (data.name || "").trim();
  const email = (data.email || "").trim().toLowerCase();
  const studentId = (data.studentId || "").trim();
  if (!name || !email) {
    return {
      success: false,
      message: "Student name and email are required.",
    };
  }
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return { success: false, message: "Please enter a valid email address." };
  }
  const usersFile = readUsersFile();
  const users = usersFile.users || [];
  if (users.some((u) => u.email === email)) {
    return {
      success: false,
      message: "A student with this email already exists.",
    };
  }
  const salt = generateSalt();
  const password = generateRandomPassword(10);
  users.push({
    name,
    email,
    password: hashPassword(password, salt),
    role: "student",
    verified: true,
    status: "approved",
    studentId,
  });

  if (!saveUsersFile({ users })) {
    return {
      success: false,
      message: "Unable to save student. Please try again later.",
    };
  }

  // Send welcome email to student if possible
  sendWelcomeEmail(email, name).catch(() => null);

  return {
    success: true,
    message: "Student added successfully.",
    password,
  };
}

function removeStudent(data) {
  const email = (data.email || "").trim().toLowerCase();
  const studentId = (data.studentId || "").trim();
  if (!email && !studentId) {
    return {
      success: false,
      message: "Student email or ID is required to remove a student.",
    };
  }
  const usersFile = readUsersFile();
  const users = usersFile.users || [];
  const student = users.find(
    (u) =>
      u.role === "student" &&
      (u.email === email || (studentId && u.studentId === studentId)),
  );
  if (!student) {
    return { success: false, message: "Student not found." };
  }
  usersFile.users = users.filter((u) => u !== student);
  saveUsersFile(usersFile);
  return {
    success: true,
    message: `${student.name} has been removed from the student roster.`,
  };
}

function verifyAccountWithToken(token) {
  if (!token) return { success: false, message: "Verification token missing." };
  try {
    const usersFile = readUsersFile();
    const users = usersFile.users || [];
    const user = users.find((item) => item.verificationToken === token);
    if (!user)
      return {
        success: false,
        message: "Invalid or expired verification token.",
      };
    user.verified = true;
    user.verificationToken = null;
    saveUsersFile({ users });
    return { success: true, message: "Your account has been verified." };
  } catch (error) {
    return {
      success: false,
      message: "Unable to verify account. Please try again later.",
    };
  }
}

// ─── SERVER ───────────────────────────────────────────────────────────────────
const server = http.createServer((request, response) => {
  const parsedUrl = new URL(request.url, "http://localhost");
  let pathname = decodeURIComponent(parsedUrl.pathname || "");
  pathname = pathname.replace(/\/+$|^\s+|\s+$/g, "") || "/";

  // ── GET REQUESTS ────────────────────────────────────────────────────────────
  if (request.method === "GET") {
    // Home
    if (pathname === "/") {
      return serveStatic(path.join(__dirname, "index.html"), response);
    }

    // Logout
    if (pathname === "/logout") {
      const cookies = parseCookies(request);
      const sessionId = cookies.sessionId;
      if (sessionId) delete sessions[sessionId];
      response.writeHead(302, {
        Location: "/login",
        "Set-Cookie": "sessionId=; HttpOnly; Path=/; Max-Age=0",
      });
      response.end();
      return;
    }

    // Email verification
    if (pathname === "/verify") {
      const result = verifyAccountWithToken(
        parsedUrl.searchParams.get("token"),
      );
      response.writeHead(200, { "Content-Type": "text/html" });
      response.end(
        `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Verification</title></head><body style="font-family:Arial,sans-serif;padding:32px;"><h1>${result.success ? "✅ Verified!" : "❌ Failed"}</h1><p>${result.message}</p><a href="/login">Go to login</a></body></html>`,
      );
      return;
    }

    // Admin panel
    if (pathname === "/admin") {
      const session = getSession(request);
      if (!session || session.role !== "admin") {
        response.writeHead(302, { Location: "/login" });
        response.end();
        return;
      }
      return serveStatic(path.join(__dirname, "files/admin.html"), response);
    }

    // Admin API — pending applications
    if (pathname === "/admin/applications") {
      const session = getSession(request);
      if (!session || session.role !== "admin") {
        response.writeHead(403, { "Content-Type": "application/json" });
        response.end(JSON.stringify({ error: "Access denied." }));
        return;
      }
      const usersFile = readUsersFile();
      const applications = (usersFile.users || []).filter(
        (u) => u.status === "pending",
      );
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ applications }));
      return;
    }

    // Admin API — approved teachers
    if (pathname === "/admin/teachers") {
      const session = getSession(request);
      if (!session || session.role !== "admin") {
        response.writeHead(403, { "Content-Type": "application/json" });
        response.end(JSON.stringify({ error: "Access denied." }));
        return;
      }
      const usersFile = readUsersFile();
      const teachers = (usersFile.users || []).filter(
        (u) => u.role === "teacher" && u.verified,
      );
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ teachers }));
      return;
    }

    // Teacher dashboard
    if (pathname === "/teacher") {
      const session = getSession(request);
      if (!session || session.role !== "teacher") {
        response.writeHead(302, { Location: "/teacher-login" });
        response.end();
        return;
      }
      return serveStatic(path.join(__dirname, "files/teacher.html"), response);
    }

    // Teacher profile
    if (pathname === "/teacher-profile") {
      const session = getSession(request);
      if (!session || session.role !== "teacher") {
        response.writeHead(302, { Location: "/teacher-login" });
        response.end();
        return;
      }
      return serveStatic(
        path.join(__dirname, "files/teacher-profile.html"),
        response,
      );
    }

    // Student profile
    if (pathname === "/profile") {
      const session = getSession(request);
      if (!session) {
        response.writeHead(302, { Location: "/login" });
        response.end();
        return;
      }
      return serveStatic(path.join(__dirname, "files/profile.html"), response);
    }

    // Public pages
    const pageMap = {
      "/login": "files/login.html",
      "/register": "files/register.html",
      "/teacher-login": "files/teacher-login.html",
      "/teacher-register": "files/teacher-register.html",
      "/contact": "files/contact.html",
      "/tour": "files/tour.html",
    };

    if (pageMap[pathname]) {
      return serveStatic(path.join(__dirname, pageMap[pathname]), response);
    }

    // Static assets (CSS, images, JS)
    const safePath = path.join(__dirname, pathname);
    if (!safePath.startsWith(__dirname)) {
      response.writeHead(403, { "Content-Type": "text/plain" });
      response.end("Forbidden");
      return;
    }
    if (fs.existsSync(safePath) && fs.statSync(safePath).isFile()) {
      return serveStatic(safePath, response);
    }

    response.writeHead(404, { "Content-Type": "text/plain" });
    response.end("404 Not Found");
    return;
  }

  // ── POST REQUESTS ───────────────────────────────────────────────────────────

  // Student / Admin login
  if (request.method === "POST" && pathname === "/login") {
    const ip = request.socket.remoteAddress;
    if (isRateLimited(ip)) {
      response.writeHead(429, { "Content-Type": "application/json" });
      response.end(
        JSON.stringify({
          success: false,
          message: "Too many login attempts. Please wait 15 minutes.",
        }),
      );
      return;
    }
    parseBody(request, (data) => {
      const result = authenticateLogin(data, null);
      if (result.success) delete loginAttempts[ip];
      const headers = { "Content-Type": "application/json" };
      if (result.success) {
        const sessionId = generateSessionId();
        sessions[sessionId] = {
          email: data.email.trim().toLowerCase(),
          role: result.user.role,
          expires: Date.now() + 3600 * 1000,
        };
        headers["Set-Cookie"] =
          `sessionId=${sessionId}; HttpOnly; Path=/; Max-Age=3600`;
      }
      response.writeHead(result.success ? 200 : 401, headers);
      response.end(JSON.stringify(result));
    });
    return;
  }

  // Teacher login
  if (request.method === "POST" && pathname === "/teacher-login") {
    const ip = request.socket.remoteAddress;
    if (isRateLimited(ip)) {
      response.writeHead(429, { "Content-Type": "application/json" });
      response.end(
        JSON.stringify({
          success: false,
          message: "Too many login attempts. Please wait 15 minutes.",
        }),
      );
      return;
    }
    parseBody(request, (data) => {
      const result = authenticateLogin(data, "teacher");
      if (result.success) delete loginAttempts[ip];
      const headers = { "Content-Type": "application/json" };
      if (result.success) {
        const sessionId = generateSessionId();
        sessions[sessionId] = {
          email: data.email.trim().toLowerCase(),
          role: "teacher",
          expires: Date.now() + 3600 * 1000,
        };
        headers["Set-Cookie"] =
          `sessionId=${sessionId}; HttpOnly; Path=/; Max-Age=3600`;
      }
      response.writeHead(result.success ? 200 : 401, headers);
      response.end(JSON.stringify(result));
    });
    return;
  }

  // Student registration
  if (request.method === "POST" && pathname === "/register") {
    parseBody(request, (data) => {
      const result = registerUser(data);
      response.writeHead(result.success ? 200 : 400, {
        "Content-Type": "application/json",
      });
      response.end(JSON.stringify(result));
    });
    return;
  }

  // Teacher application
  if (request.method === "POST" && pathname === "/teacher-register") {
    parseBody(request, (data) => {
      const result = registerTeacherApplication(data);
      response.writeHead(result.success ? 200 : 400, {
        "Content-Type": "application/json",
      });
      response.end(JSON.stringify(result));
    });
    return;
  }

  // Contact form
  if (request.method === "POST" && pathname === "/contact") {
    parseBody(request, (data) => {
      const enquiry = {
        name: (data.name || "").trim(),
        email: (data.email || "").trim(),
        subject: (data.subject || "").trim(),
        message: (data.message || "").trim(),
        date: new Date().toISOString(),
      };
      const enquiriesPath = path.join(__dirname, "enquiries.json");
      let enquiries = [];
      if (fs.existsSync(enquiriesPath)) {
        try {
          enquiries = JSON.parse(
            fs.readFileSync(enquiriesPath, "utf8") || "[]",
          );
        } catch (e) {
          enquiries = [];
        }
      }
      enquiries.push(enquiry);
      fs.writeFileSync(
        enquiriesPath,
        JSON.stringify(enquiries, null, 2),
        "utf8",
      );

      // Send email to school
      sendContactEmail(enquiry).catch(() => null);

      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(
        JSON.stringify({ success: true, message: "Enquiry received." }),
      );
    });
    return;
  }

  // Admin — approve teacher
  if (request.method === "POST" && pathname === "/admin/approve") {
    const session = getSession(request);
    if (!session || session.role !== "admin") {
      response.writeHead(403, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ error: "Access denied." }));
      return;
    }
    parseBody(request, (data) => {
      const result = approveTeacher(data.email);
      response.writeHead(result.success ? 200 : 400, {
        "Content-Type": "application/json",
      });
      response.end(JSON.stringify(result));
    });
    return;
  }

  // Admin — reject teacher
  if (request.method === "POST" && pathname === "/admin/reject") {
    const session = getSession(request);
    if (!session || session.role !== "admin") {
      response.writeHead(403, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ error: "Access denied." }));
      return;
    }
    parseBody(request, (data) => {
      const result = rejectTeacherApplication(data.email);
      response.writeHead(result.success ? 200 : 400, {
        "Content-Type": "application/json",
      });
      response.end(JSON.stringify(result));
    });
    return;
  }

  // Admin — remove teacher
  if (request.method === "POST" && pathname === "/admin/remove-teacher") {
    const session = getSession(request);
    if (!session || session.role !== "admin") {
      response.writeHead(403, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ error: "Access denied." }));
      return;
    }
    parseBody(request, (data) => {
      const usersFile = readUsersFile();
      usersFile.users = (usersFile.users || []).filter(
        (u) => u.email !== (data.email || "").trim().toLowerCase(),
      );
      saveUsersFile(usersFile);
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(
        JSON.stringify({ success: true, message: "Teacher removed." }),
      );
    });
    return;
  }

  // Teacher — list student roster
  if (request.method === "GET" && pathname === "/teacher/students") {
    const session = getSession(request);
    if (!session || session.role !== "teacher") {
      response.writeHead(403, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ error: "Access denied." }));
      return;
    }
    const usersFile = readUsersFile();
    const students = (usersFile.users || [])
      .filter((u) => u.role === "student")
      .map(({ name, email, studentId, status }) => ({
        name,
        email,
        studentId: studentId || "",
        status: status || "active",
      }));
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ students }));
    return;
  }

  // teacher — add student
  if (request.method === "POST" && pathname === "/teacher/add_student") {
    const session = getSession(request);
    if (!session || session.role !== "teacher") {
      response.writeHead(403, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ error: "Access denied." }));
      return;
    }
    parseBody(request, (data) => {
      try {
        const result = addStudent(data);
        response.writeHead(result.success ? 200 : 400, {
          "Content-Type": "application/json",
        });
        response.end(JSON.stringify(result));
      } catch (error) {
        console.error("Failed to add student:", error);
        response.writeHead(500, { "Content-Type": "application/json" });
        response.end(
          JSON.stringify({
            success: false,
            message: "Server error while adding student.",
          }),
        );
      }
    });
    return;
  }

  // teacher — remove student
  if (request.method === "POST" && pathname === "/teacher/remove_student") {
    const session = getSession(request);
    if (!session || session.role !== "teacher") {
      response.writeHead(403, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ error: "Access denied" }));
      return;
    }
    parseBody(request, (data) => {
      try {
        const result = removeStudent(data);
        response.writeHead(result.success ? 200 : 400, {
          "Content-Type": "application/json",
        });
        response.end(JSON.stringify(result));
      } catch (error) {
        console.error("Failed to remove student:", error);
        response.writeHead(500, { "Content-Type": "application/json" });
        response.end(
          JSON.stringify({
            success: false,
            message: "Server error while removing student.",
          }),
        );
      }
    });
    return;
  }

  // Fallback 404
  response.writeHead(404, { "Content-Type": "text/plain" });
  response.end("404 Not Found");
});

server.listen(8080, () => {
  console.log("Server running on http://localhost:8080");
});
