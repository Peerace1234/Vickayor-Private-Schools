// middleware/auth.js
const jwt = require("jsonwebtoken");

/**
 * Verifies the JWT from the Authorization header.
 * Attaches decoded user payload to req.user.
 */
function authenticate(req, res, next) {
  const header = req.headers["authorization"];
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "No token provided." });
  }

  const token = header.split(" ")[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token." });
  }
}

/**
 * Role-based access guard.
 * Usage: authorize('teacher', 'admin')
 */
function authorize(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: "Access denied." });
    }
    next();
  };
}

module.exports = { authenticate, authorize };
