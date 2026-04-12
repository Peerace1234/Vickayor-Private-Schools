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

function parseBody(request, callback) {
  let body = "";
  request.on("data", (chunk) => {
    body += chunk.toString();
  });
  request.on("end", () => {
    callback(querystring.parse(body));
  });
}

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
  if (!storedPassword) {
    return false;
  }

  if (storedPassword.indexOf(":") === -1) {
    return password === storedPassword;
  }

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

function readUsersFile() {
  const filePath = path.join(__dirname, "users.json");
  if (!fs.existsSync(filePath)) {
    return { users: [] };
  }

  const raw = fs.readFileSync(filePath, "utf8");
  return JSON.parse(raw || '{"users": []}');
}

function createEmailTransporter() {
  const smtpUser = process.env.SMTP_USER;
  const smtpPass = process.env.SMTP_PASS;
  const smtpHost = process.env.SMTP_HOST;
  const smtpPort = process.env.SMTP_PORT
    ? parseInt(process.env.SMTP_PORT, 10)
    : 587;
  const smtpService = process.env.SMTP_SERVICE;

  if (!smtpUser || !smtpPass) {
    return null;
  }

  let nodemailer;
  try {
    nodemailer = require("nodemailer");
  } catch (error) {
    console.warn(
      "Nodemailer is not installed. Email verification will be disabled.",
    );
    return null;
  }

  const transportConfig = {
    auth: { user: smtpUser, pass: smtpPass },
  };

  if (smtpHost) {
    transportConfig.host = smtpHost;
    transportConfig.port = smtpPort;
    transportConfig.secure = smtpPort === 465;
  } else if (smtpService) {
    transportConfig.service = smtpService;
  }

  return nodemailer.createTransport(transportConfig);
}

function sendVerificationEmail(to, token, name) {
  const transporter = createEmailTransporter();
  const verifyUrl = `http://localhost:8080/verify?token=${token}`;
  const mailOptions = {
    from:
      process.env.EMAIL_FROM ||
      process.env.SMTP_USER ||
      "no-reply@vickayorprivateschool.com",
    to,
    subject: "Verify your Vickayor Private School account",
    text: `Hello ${name || "User"},\n\nThank you for registering. Please verify your account by visiting the link below:\n\n${verifyUrl}\n\nIf you did not request this email, ignore it.`,
  };

  if (!transporter) {
    console.log(
      "Email verification not configured. Verification link:",
      verifyUrl,
    );
    return Promise.resolve(false);
  }

  return transporter
    .sendMail(mailOptions)
    .then((info) => {
      console.log("Verification email sent:", info.response || info.messageId);
      return true;
    })
    .catch((error) => {
      console.error("Unable to send verification email:", error);
      return false;
    });
}

function saveUsersFile(data) {
  const filePath = path.join(__dirname, "users.json");
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf8");
}

function findUserByEmail(email) {
  const users = readUsersFile().users || [];
  return users.find(
    (user) => user.email.toLowerCase() === (email || "").trim().toLowerCase(),
  );
}

function authenticateLogin(data, role) {
  const email = (data.email || "").trim();
  const password = data.password || "";
  const user = findUserByEmail(email);

  if (!user) {
    return { success: false, message: "Invalid email or password." };
  }

  if (role && user.role !== role) {
    return { success: false, message: "Invalid teacher credentials." };
  }

  if (!verifyPassword(password, user.password)) {
    return { success: false, message: "Invalid email or password." };
  }

  if (!user.verified) {
    return {
      success: false,
      message: "Please verify your email before logging in.",
    };
  }

  return { success: true, message: "Login successful.", user };
}

function registerUser(data) {
  const name = (data.name || "").trim();
  const email = (data.email || "").trim().toLowerCase();
  const password = data.password || "";

  if (!name || !email || !password) {
    return {
      success: false,
      message: "Name, email, and password are required.",
    };
  }

  try {
    const usersFile = readUsersFile();
    const users = usersFile.users || [];
    if (users.some((user) => user.email === email)) {
      return {
        success: false,
        message: "An account already exists with this email.",
      };
    }

    const salt = generateSalt();
    const passwordHash = hashPassword(password, salt);
    const verificationToken = crypto.randomBytes(20).toString("hex");

    users.push({
      name,
      email,
      password: passwordHash,
      role: "student",
      verified: false,
      verificationToken,
    });

    saveUsersFile({ users });
    sendVerificationEmail(email, verificationToken, name).catch(() => null);

    return {
      success: true,
      message:
        "Account created successfully. Please check your email to verify your account.",
    };
  } catch (error) {
    console.error("Error saving users.json", error);
    return {
      success: false,
      message: "Unable to create account. Please try again.",
    };
  }
}

function verifyAccountWithToken(token) {
  if (!token) {
    return { success: false, message: "Verification token missing." };
  }

  try {
    const usersFile = readUsersFile();
    const users = usersFile.users || [];
    const user = users.find((item) => item.verificationToken === token);

    if (!user) {
      return { success: false, message: "Invalid or expired verification token." };
    }

    user.verified = true;
    user.verificationToken = null;
    saveUsersFile({ users });

    return { success: true, message: "Your account has been verified." };
  } catch (error) {
    console.error("Error verifying account", error);
    return {
      success: false,
      message: "Unable to verify account. Please try again later.",
    };
  }
}

const server = http.createServer((request, response) => {
  const parsedUrl = url.parse(request.url, true);
  let pathname = decodeURIComponent(parsedUrl.pathname || "");
  pathname = pathname.replace(/\/+$|^\s+|\s+$/g, "") || "/";

  if (pathname === "/") {
    pathname = "/index.html";
  }

  if (request.method === "GET") {
    if (pathname === "/register") {
      pathname = "/files/register.html";
    }
    if (pathname === "/login") {
      pathname = "/files/login.html";
    }
    if (pathname === "/teacher-login") {
      pathname = "/files/teacher-login.html";
    }
    if (pathname === "/contact") {
      pathname = "/files/contact.html";
    }
    if (pathname === "/tour") {
      pathname = "/files/tour.html";
    }
    if (pathname === "/teacher") {
      pathname = "/files/teacher.html";
    }
    if (pathname === "/profile") {
      pathname = "/files/profile.html";
    }

    if (pathname === "/verify") {
      const result = verifyAccountWithToken(parsedUrl.query.token);
      response.writeHead(200, { "Content-Type": "text/html" });
      response.end(
        `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Account Verification</title></head><body style="font-family:Arial,sans-serif;padding:32px;"><h1>${result.success ? "Verified" : "Verification Failed"}</h1><p>${result.message}</p><p><a href="/login">Go to login</a></p></body></html>`,
      );
      return;
    }

    if (pathname === "/teacher") {
      const session = getSession(request);
      if (!session || session.role !== "teacher") {
        response.writeHead(403, { "Content-Type": "text/plain" });
        response.end("Access denied. Teacher login required.");
        return;
      }
    }

    if (pathname === "/profile") {
      const session = getSession(request);
      if (!session) {
        response.writeHead(403, { "Content-Type": "text/plain" });
        response.end("Access denied. Please log in first.");
        return;
      }
    }

    const safePath = path.join(__dirname, pathname);
    if (!safePath.startsWith(__dirname)) {
      response.writeHead(403, { "Content-Type": "text/plain" });
      response.end("Forbidden");
      return;
    }

    if (fs.existsSync(safePath) && fs.statSync(safePath).isFile()) {
      serveStatic(safePath, response);
      return;
    }

    response.writeHead(404, { "Content-Type": "text/plain" });
    response.end("404 Not Found");
    return;
  }

  if (request.method === "POST" && pathname === "/login") {
    parseBody(request, (data) => {
      const result = authenticateLogin(data, "student");
      const headers = { "Content-Type": "application/json" };
      if (result.success) {
        const sessionId = generateSessionId();
        sessions[sessionId] = {
          email: data.email.trim().toLowerCase(),
          role: "student",
          expires: Date.now() + 3600 * 1000,
        };
        headers["Set-Cookie"] = `sessionId=${sessionId}; HttpOnly; Path=/; Max-Age=3600`;
      }
      response.writeHead(result.success ? 200 : 401, headers);
      response.end(JSON.stringify(result));
    });
    return;
  }

  if (request.method === "POST" && pathname === "/teacher-login") {
    parseBody(request, (data) => {
      const result = authenticateLogin(data, "teacher");
      const headers = { "Content-Type": "application/json" };
      if (result.success) {
        const sessionId = generateSessionId();
        sessions[sessionId] = {
          email: data.email.trim().toLowerCase(),
          role: "teacher",
          expires: Date.now() + 3600 * 1000,
        };
        headers["Set-Cookie"] = `sessionId=${sessionId}; HttpOnly; Path=/; Max-Age=3600`;
      }
      response.writeHead(result.success ? 200 : 401, headers);
      response.end(JSON.stringify(result));
    });
    return;
  }

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
        } catch (error) {
          enquiries = [];
        }
      }
      enquiries.push(enquiry);
      fs.writeFileSync(
        enquiriesPath,
        JSON.stringify(enquiries, null, 2),
        "utf8",
      );
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(
        JSON.stringify({
          success: true,
          message:
            "Enquiry captured and ready to send to vickayorprivateschool@gmail.com.",
        }),
      );
    });
    return;
  }

  response.writeHead(404, { "Content-Type": "text/plain" });
  response.end("404 Not Found");
});

server.listen(8080, () => {
  console.log("Server running on http://localhost:8080");
});
