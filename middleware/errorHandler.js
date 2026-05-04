// middleware/errorHandler.js

/**
 * Centralized error handler — attach as the LAST app.use() in server.js.
 * All route errors should call next(err) to reach here.
 */
function errorHandler(err, req, res, next) {
  // eslint-disable-line no-unused-vars
  const status = err.status || 500;
  const message = err.message || "Internal server error.";

  // Log full error in development
  if (process.env.NODE_ENV !== "production") {
    console.error(`[${new Date().toISOString()}] ${status} — ${message}`);
    if (err.stack) console.error(err.stack);
  }

  res.status(status).json({ error: message });
}

/**
 * Helper: create a structured error with an HTTP status code.
 * Usage: throw createError(404, 'Assignment not found.')
 */
function createError(status, message) {
  const err = new Error(message);
  err.status = status;
  return err;
}

module.exports = { errorHandler, createError };
