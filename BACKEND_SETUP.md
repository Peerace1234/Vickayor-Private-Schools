# Vickayor Backend Setup Guide

## ✅ What's Been Done

### 1. **Directory Structure Created**

- `config/` — Database configuration
- `middleware/` — Express middleware (auth, error handling)
- `routes/` — API endpoints (auth, assignments, results, announcements, chat)
- `socket/` — Real-time chat via Socket.io
- `uploads/assignments/` & `uploads/submissions/` — File storage

### 2. **Files Created**

- **config/db.js** — MySQL database connection pool
- **middleware/auth.js** — JWT authentication and role-based access
- **middleware/errorHandler.js** — Centralized error handling
- **socket/chat.js** — Real-time messaging server
- **routes/auth.js** — User registration & login
- **routes/assignments.js** — Assignment CRUD & submission handling
- **routes/results.js** — Grade management
- **routes/announcements.js** — Announcements system
- **routes/chat.js** — Chat rooms & message history
- **api-server.js** — Express API server (runs on port 5000)
- **schema.sql** — Database schema for MySQL
- **files/chat.html** — Real-time chat UI

### 3. **Dependencies Installed**

```bash
npm install bcrypt jsonwebtoken multer mysql2 socket.io express cors
```

### 4. **.env Updated**

New variables added to `.env`:

```
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=vickayor_db
JWT_SECRET=replace_with_a_long_random_string_min_32_chars_here_securely
NODE_ENV=development
PORT=5000
CLIENT_URL=http://localhost:3000
```

---

## 🚀 Next Steps

### Step 1: Set Up the Database

First, ensure MySQL is running on your system, then run:

```bash
mysql -u root -p < schema.sql
```

When prompted, enter your MySQL password.

**Default admin credentials:**

- Email: `admin@vickayor.local`
- Password: `Admin@Vickayor1`

### Step 2: Configure Environment Variables

Edit `.env` and set these values:

```env
# Update these with your actual MySQL credentials
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_mysql_password

# Create a secure JWT secret (at least 32 characters)
JWT_SECRET=your_super_secure_random_string_here_at_least_32_chars

# Frontend URL (for CORS)
CLIENT_URL=http://localhost:3000
```

### Step 3: Run Both Servers

**Option A: Run in separate terminals**

Terminal 1 (Frontend):

```bash
npm start
```

This runs the existing frontend server on port 8080.

Terminal 2 (API Backend):

```bash
npm run api
```

This runs the new Express API server on port 5000.

**Option B: Run both together** (from one terminal)

```bash
npm run dev
```

---

## 📡 API Endpoints

### **Authentication** (`/api/auth`)

- `POST /register` — Register a new user
- `POST /login` — Login and get JWT token
- `GET /me` — Get current user info (requires token)
- `PUT /update` — Update user profile

**Request:**

```json
POST /api/auth/login
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response:**

```json
{
  "message": "Login successful.",
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": 1,
    "name": "John Doe",
    "email": "user@example.com",
    "role": "student",
    "class_id": 1
  }
}
```

### **Assignments** (`/api/assignments`)

- `GET /` — Get all assignments
- `GET /:id` — Get assignment details
- `POST /` — Create assignment (teacher/admin)
- `PUT /:id` — Update assignment
- `DELETE /:id` — Delete assignment
- `POST /:id/submit` — Student submits assignment
- `GET /:id/submissions` — View all submissions (teacher)
- `PUT /:id/submissions/:studentId/grade` — Grade a submission

### **Results** (`/api/results`)

- `GET /` — Get results (students see own, teachers see their subjects)
- `GET /student/:studentId` — View student's result sheet (teacher/admin)
- `POST /` — Post a single result
- `POST /bulk` — Post multiple results at once
- `DELETE /:id` — Delete a result (admin)

### **Announcements** (`/api/announcements`)

- `GET /` — Get announcements (filtered by role)
- `GET /:id` — Get specific announcement
- `POST /` — Create announcement (teacher/admin)
- `PUT /:id` — Edit announcement
- `DELETE /:id` — Delete announcement

### **Chat** (`/api/chat`)

- `GET /rooms` — List user's chat rooms
- `POST /rooms` — Create a new room
- `GET /rooms/:roomId/messages` — Get message history (paginated)
- `DELETE /messages/:messageId` — Delete a message

**Real-time events via Socket.io:**

- `join_room` — Join a chat room
- `send_message` — Send a message
- `typing` — Broadcast typing status
- `delete_message` — Delete a message in real-time

---

## 🔐 Authentication

All API endpoints (except `/api/auth/register` and `/api/auth/login`) require a JWT token in the Authorization header:

```javascript
fetch("http://localhost:5000/api/assignments", {
  headers: {
    Authorization: "Bearer eyJhbGciOiJIUzI1NiIs...",
  },
});
```

**Token payload includes:**

- `id` — User ID
- `name` — Full name
- `email` — Email address
- `role` — User role (student/teacher/admin)
- `class_id` — Class ID (for students)

---

## 👥 User Roles & Permissions

### **Student**

- View own assignments & results
- Submit assignments
- Join chat rooms
- View announcements

### **Teacher**

- Create & manage assignments
- View student submissions & grade them
- Post results (individual or bulk)
- Create & manage announcements
- View own class chat

### **Admin**

- Full access to all endpoints
- Manage users & classes
- Delete any content
- System-wide announcements

---

## 📁 Uploading Files

When uploading assignment files or submissions:

1. Use `multipart/form-data` content type
2. Include the file in the `file` form field
3. Files are stored in `uploads/assignments/` or `uploads/submissions/`
4. Returned URL will be like: `/uploads/assignments/1234567-filename.pdf`

---

## 🛠️ Troubleshooting

### MySQL Connection Errors

- Ensure MySQL is running: `mysql -u root -p` should connect
- Check DB credentials in `.env`
- Verify database exists: `mysql -u root -p -e "USE vickayor_db;"`

### Port Already in Use

- Frontend (8080): `netstat -ano | findstr :8080`
- API (5000): `netstat -ano | findstr :5000`

### Socket.io Connection Failed

- Ensure API server is running on port 5000
- Check CORS origin in `api-server.js` matches your client URL
- Verify token is being passed in Socket.io auth

### JWT Token Expired

- Default expiry is 7 days after login
- Need to login again to get a new token

---

## 📝 File Structure Summary

```
Vickayor Project/
├── server.js              (Existing frontend server - port 8080)
├── api-server.js          (NEW Express API server - port 5000)
├── schema.sql             (Database setup script)
├── package.json           (Updated with new dependencies)
├── .env                   (Environment variables)
├── config/
│   └── db.js              (MySQL connection pool)
├── middleware/
│   ├── auth.js            (JWT & role-based access)
│   └── errorHandler.js    (Centralized error handling)
├── routes/
│   ├── auth.js            (User authentication)
│   ├── assignments.js     (Assignments & submissions)
│   ├── results.js         (Grade management)
│   ├── announcements.js   (Announcements)
│   └── chat.js            (Chat endpoints)
├── socket/
│   └── chat.js            (Real-time messaging)
├── uploads/
│   ├── assignments/       (Assignment files)
│   └── submissions/       (Student submission files)
└── files/
    ├── chat.html          (NEW Chat UI)
    ├── login.html
    ├── register.html
    └── ... (other existing files)
```

---

## 🧪 Testing the API

Use **Postman**, **Thunder Client**, or **curl** to test:

```bash
# Login
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@vickayor.local","password":"Admin@Vickayor1"}'

# Get user info
curl http://localhost:5000/api/auth/me \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"

# Health check
curl http://localhost:5000/api/health
```

---

## 📚 Next Features to Add

1. Student grades dashboard
2. Parent portal
3. Attendance tracking
4. Online exam system
5. Video lecture uploads
6. Mobile app

---

## ⚠️ Important Notes

- **Keep JWT_SECRET secure** — Use a strong, random string
- **Don't commit .env** to version control
- **Database backups** — Regularly backup `vickayor_db`
- **File uploads** — Max 10MB per file (configurable in routes/assignments.js)

---

## 📞 Support

For issues or questions, refer to:

- MySQL documentation: https://dev.mysql.com/doc/
- Express.js guide: https://expressjs.com/
- Socket.io documentation: https://socket.io/
