-- ============================================================
--  Vickayor Comprehensive College — Full Database Schema
--  Engine: MySQL 8+ / MariaDB 10.5+
-- ============================================================

CREATE DATABASE IF NOT EXISTS vickayor_db
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE vickayor_db;

-- ──────────────────────────────────────────────
--  1. CLASSES
-- ──────────────────────────────────────────────
CREATE TABLE classes (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(50)  NOT NULL,
  section     VARCHAR(10)  NOT NULL,
  teacher_id  INT UNSIGNED,
  created_at  TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_class_section (name, section)
) ENGINE=InnoDB;

-- ──────────────────────────────────────────────
--  2. USERS  (students, teachers, admins)
-- ──────────────────────────────────────────────
CREATE TABLE users (
  id             INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
  full_name      VARCHAR(120)  NOT NULL,
  email          VARCHAR(180)  NOT NULL UNIQUE,
  password_hash  VARCHAR(255)  NOT NULL,
  role           ENUM('student','teacher','admin') NOT NULL DEFAULT 'student',
  class_id       INT UNSIGNED  NULL,
  profile_pic    VARCHAR(255)  NULL,
  is_active      TINYINT(1)    NOT NULL DEFAULT 1,
  created_at     TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
  updated_at     TIMESTAMP     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_user_class FOREIGN KEY (class_id)
    REFERENCES classes(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- Now add the FK on classes back to users
ALTER TABLE classes
  ADD CONSTRAINT fk_class_teacher
    FOREIGN KEY (teacher_id) REFERENCES users(id) ON DELETE SET NULL;

-- ──────────────────────────────────────────────
--  3. SUBJECTS
-- ──────────────────────────────────────────────
CREATE TABLE subjects (
  id          INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(100)  NOT NULL,
  class_id    INT UNSIGNED  NOT NULL,
  teacher_id  INT UNSIGNED  NOT NULL,
  created_at  TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_subject_class   FOREIGN KEY (class_id)   REFERENCES classes(id)  ON DELETE CASCADE,
  CONSTRAINT fk_subject_teacher FOREIGN KEY (teacher_id) REFERENCES users(id)    ON DELETE RESTRICT
) ENGINE=InnoDB;

-- ──────────────────────────────────────────────
--  4. ASSIGNMENTS
-- ──────────────────────────────────────────────
CREATE TABLE assignments (
  id           INT UNSIGNED   AUTO_INCREMENT PRIMARY KEY,
  title        VARCHAR(200)   NOT NULL,
  description  TEXT           NOT NULL,
  subject_id   INT UNSIGNED   NOT NULL,
  teacher_id   INT UNSIGNED   NOT NULL,
  due_date     DATETIME       NOT NULL,
  max_score    DECIMAL(5,2)   NOT NULL DEFAULT 100,
  file_url     VARCHAR(255)   NULL,
  created_at   TIMESTAMP      DEFAULT CURRENT_TIMESTAMP,
  updated_at   TIMESTAMP      DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_assign_subject FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE CASCADE,
  CONSTRAINT fk_assign_teacher FOREIGN KEY (teacher_id) REFERENCES users(id)    ON DELETE RESTRICT
) ENGINE=InnoDB;

-- ──────────────────────────────────────────────
--  5. SUBMISSIONS
-- ──────────────────────────────────────────────
CREATE TABLE submissions (
  id             INT UNSIGNED   AUTO_INCREMENT PRIMARY KEY,
  assignment_id  INT UNSIGNED   NOT NULL,
  student_id     INT UNSIGNED   NOT NULL,
  content        TEXT           NULL,
  file_url       VARCHAR(255)   NULL,
  score          DECIMAL(5,2)   NULL,
  feedback       TEXT           NULL,
  status         ENUM('submitted','graded','late') DEFAULT 'submitted',
  submitted_at   DATETIME       DEFAULT CURRENT_TIMESTAMP,
  graded_at      DATETIME       NULL,
  CONSTRAINT fk_sub_assignment FOREIGN KEY (assignment_id) REFERENCES assignments(id) ON DELETE CASCADE,
  CONSTRAINT fk_sub_student    FOREIGN KEY (student_id)    REFERENCES users(id)        ON DELETE CASCADE,
  UNIQUE KEY uq_assignment_student (assignment_id, student_id)
) ENGINE=InnoDB;

-- ──────────────────────────────────────────────
--  6. RESULTS
-- ──────────────────────────────────────────────
CREATE TABLE results (
  id          INT UNSIGNED   AUTO_INCREMENT PRIMARY KEY,
  student_id  INT UNSIGNED   NOT NULL,
  subject_id  INT UNSIGNED   NOT NULL,
  term        VARCHAR(20)    NOT NULL,
  session     VARCHAR(20)    NOT NULL,
  ca_score    DECIMAL(5,2)   DEFAULT 0,
  exam_score  DECIMAL(5,2)   DEFAULT 0,
  grade       VARCHAR(2)     NOT NULL,
  remark      VARCHAR(30)    NOT NULL,
  created_at  TIMESTAMP      DEFAULT CURRENT_TIMESTAMP,
  updated_at  TIMESTAMP      DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_result_student FOREIGN KEY (student_id) REFERENCES users(id)      ON DELETE CASCADE,
  CONSTRAINT fk_result_subject FOREIGN KEY (subject_id) REFERENCES subjects(id)  ON DELETE CASCADE,
  UNIQUE KEY uq_result_unique (student_id, subject_id, term, session)
) ENGINE=InnoDB;

-- ──────────────────────────────────────────────
--  7. ANNOUNCEMENTS
-- ──────────────────────────────────────────────
CREATE TABLE announcements (
  id          INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
  author_id   INT UNSIGNED  NOT NULL,
  class_id    INT UNSIGNED  NULL,
  title       VARCHAR(200)  NOT NULL,
  body        TEXT          NOT NULL,
  audience    ENUM('all','class','teachers_only') DEFAULT 'all',
  created_at  TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
  updated_at  TIMESTAMP     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_ann_author FOREIGN KEY (author_id) REFERENCES users(id)    ON DELETE CASCADE,
  CONSTRAINT fk_ann_class  FOREIGN KEY (class_id)  REFERENCES classes(id)  ON DELETE CASCADE
) ENGINE=InnoDB;

-- ──────────────────────────────────────────────
--  8. CHAT ROOMS
-- ──────────────────────────────────────────────
CREATE TABLE chat_rooms (
  id          INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(100)  NOT NULL,
  type        ENUM('dm','group','class') NOT NULL,
  class_id    INT UNSIGNED  NULL,
  created_by  INT UNSIGNED  NOT NULL,
  created_at  TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_room_creator FOREIGN KEY (created_by) REFERENCES users(id)  ON DELETE RESTRICT,
  CONSTRAINT fk_room_class   FOREIGN KEY (class_id)   REFERENCES classes(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ──────────────────────────────────────────────
--  9. CHAT MEMBERS
-- ──────────────────────────────────────────────
CREATE TABLE chat_members (
  id          INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
  room_id     INT UNSIGNED  NOT NULL,
  user_id     INT UNSIGNED  NOT NULL,
  joined_at   TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_member_room FOREIGN KEY (room_id) REFERENCES chat_rooms(id) ON DELETE CASCADE,
  CONSTRAINT fk_member_user FOREIGN KEY (user_id) REFERENCES users(id)      ON DELETE CASCADE,
  UNIQUE KEY uq_room_user (room_id, user_id)
) ENGINE=InnoDB;

-- ──────────────────────────────────────────────
--  10. MESSAGES
-- ──────────────────────────────────────────────
CREATE TABLE messages (
  id          INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
  room_id     INT UNSIGNED  NOT NULL,
  sender_id   INT UNSIGNED  NOT NULL,
  content     TEXT          NULL,
  file_url    VARCHAR(255)  NULL,
  is_deleted  TINYINT(1)    DEFAULT 0,
  sent_at     TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_msg_room   FOREIGN KEY (room_id)   REFERENCES chat_rooms(id) ON DELETE CASCADE,
  CONSTRAINT fk_msg_sender FOREIGN KEY (sender_id) REFERENCES users(id)      ON DELETE CASCADE
) ENGINE=InnoDB;

-- ──────────────────────────────────────────────
--  11. ATTENDANCE SESSIONS
--  Teacher opens an attendance session per subject per date
-- ──────────────────────────────────────────────
CREATE TABLE attendance_sessions (
  id          INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
  subject_id  INT UNSIGNED  NOT NULL,
  teacher_id  INT UNSIGNED  NOT NULL,
  class_id    INT UNSIGNED  NOT NULL,
  date        DATE          NOT NULL,
  period      VARCHAR(50)   NULL,
  is_closed   TINYINT(1)    NOT NULL DEFAULT 0,
  created_at  TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_session (subject_id, date),
  CONSTRAINT fk_att_sess_subject  FOREIGN KEY (subject_id)  REFERENCES subjects(id)  ON DELETE CASCADE,
  CONSTRAINT fk_att_sess_teacher  FOREIGN KEY (teacher_id)  REFERENCES users(id)     ON DELETE RESTRICT,
  CONSTRAINT fk_att_sess_class    FOREIGN KEY (class_id)    REFERENCES classes(id)   ON DELETE CASCADE
) ENGINE=InnoDB;

-- ──────────────────────────────────────────────
--  12. ATTENDANCE RECORDS
--  One row per student per attendance session
-- ──────────────────────────────────────────────
CREATE TABLE attendance_records (
  id            INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
  session_id    INT UNSIGNED  NOT NULL,
  student_id    INT UNSIGNED  NOT NULL,
  status        ENUM('present','absent','late','excused') NOT NULL DEFAULT 'absent',
  note          VARCHAR(200)  NULL,
  marked_at     TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_record (session_id, student_id),
  CONSTRAINT fk_att_rec_session FOREIGN KEY (session_id)  REFERENCES attendance_sessions(id) ON DELETE CASCADE,
  CONSTRAINT fk_att_rec_student FOREIGN KEY (student_id)  REFERENCES users(id)               ON DELETE CASCADE
) ENGINE=InnoDB;

-- ──────────────────────────────────────────────
--  13. CLASS ENROLMENTS
--  Tracks when a teacher adds/removes a student
-- ──────────────────────────────────────────────
CREATE TABLE class_enrolments (
  id           INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
  student_id   INT UNSIGNED  NOT NULL,
  class_id     INT UNSIGNED  NOT NULL,
  enrolled_by  INT UNSIGNED  NOT NULL,
  enrolled_at  TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
  left_at      TIMESTAMP     NULL,
  is_active    TINYINT(1)    NOT NULL DEFAULT 1,
  UNIQUE KEY uq_enrolment (student_id, class_id),
  CONSTRAINT fk_enrol_student  FOREIGN KEY (student_id)  REFERENCES users(id)    ON DELETE CASCADE,
  CONSTRAINT fk_enrol_class    FOREIGN KEY (class_id)    REFERENCES classes(id)  ON DELETE CASCADE,
  CONSTRAINT fk_enrol_by       FOREIGN KEY (enrolled_by) REFERENCES users(id)    ON DELETE RESTRICT
) ENGINE=InnoDB;

-- ──────────────────────────────────────────────
--  INDEXES (performance)
-- ──────────────────────────────────────────────
CREATE INDEX idx_users_role          ON users(role);
CREATE INDEX idx_users_class         ON users(class_id);
CREATE INDEX idx_assignments_subject ON assignments(subject_id);
CREATE INDEX idx_submissions_student ON submissions(student_id);
CREATE INDEX idx_submissions_status  ON submissions(status);
CREATE INDEX idx_results_student     ON results(student_id);
CREATE INDEX idx_results_session     ON results(session, term);
CREATE INDEX idx_messages_room       ON messages(room_id, sent_at);
CREATE INDEX idx_ann_class           ON announcements(class_id, created_at);

-- ──────────────────────────────────────────────
--  SEED: Default admin account
--  Password: Admin@Vickayor1
--  Hash: $2b$10$8NfAOGkspJPzKQM3Bq0YWuMRVZHzVmLfJPKw.ILJUqKSPfbxQ.DUG
-- ──────────────────────────────────────────────
INSERT INTO users (full_name, email, password_hash, role)
VALUES (
  'Admin',
  'admin@vickayor.local',
  '$2b$10$8NfAOGkspJPzKQM3Bq0YWuMRVZHzVmLfJPKw.ILJUqKSPfbxQ.DUG',
  'admin'
);
