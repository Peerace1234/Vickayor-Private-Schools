-- ============================================================
--  SCHEMA EXTENSIONS FOR PROFESSIONAL WEBSITE
--  Add testimonials, achievements, staff profiles, and enquiry tracking
-- ============================================================

-- ──────────────────────────────────────────────
--  13. TESTIMONIALS (Parent & Student Reviews)
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS testimonials (
  id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  author_name     VARCHAR(150) NOT NULL,
  author_role     ENUM('parent','student','staff') NOT NULL,
  author_image    VARCHAR(255) NULL,
  title           VARCHAR(200) NOT NULL,
  content         TEXT NOT NULL,
  rating          DECIMAL(2,1) NOT NULL CHECK (rating >= 1 AND rating <= 5),
  is_featured     TINYINT(1) NOT NULL DEFAULT 0,
  is_approved     TINYINT(1) NOT NULL DEFAULT 0,
  created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ──────────────────────────────────────────────
--  14. ACHIEVEMENTS (WAEC Results, Awards)
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS achievements (
  id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  year            YEAR NOT NULL,
  category        ENUM('waec','neco','jamb','award','sports','academic') NOT NULL,
  title           VARCHAR(200) NOT NULL,
  description     TEXT NOT NULL,
  metric          VARCHAR(100) NULL COMMENT 'e.g., "8 students with As", "100% pass rate"',
  image_url       VARCHAR(255) NULL,
  is_featured     TINYINT(1) NOT NULL DEFAULT 0,
  created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ──────────────────────────────────────────────
--  15. STAFF PROFILES (Principals, Coordinators, etc.)
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS staff_profiles (
  id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id         INT UNSIGNED NULL,
  full_name       VARCHAR(150) NOT NULL,
  position        VARCHAR(100) NOT NULL,
  bio             TEXT NULL,
  qualifications  TEXT NULL,
  experience      INT NULL COMMENT 'Years of experience',
  photo_url       VARCHAR(255) NULL,
  email           VARCHAR(180) NULL,
  phone           VARCHAR(20) NULL,
  is_published    TINYINT(1) NOT NULL DEFAULT 1,
  created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_staff_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ──────────────────────────────────────────────
--  16. ENQUIRIES (Public contact submissions)
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS enquiries (
  id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name            VARCHAR(150) NOT NULL,
  email           VARCHAR(180) NOT NULL,
  phone           VARCHAR(20) NULL,
  enquiry_type    ENUM('general','admission','visit','other') DEFAULT 'general',
  subject         VARCHAR(200) NOT NULL,
  message         TEXT NOT NULL,
  status          ENUM('new','read','responded','closed') DEFAULT 'new',
  parent_name     VARCHAR(150) NULL,
  child_name      VARCHAR(150) NULL,
  child_class     VARCHAR(50) NULL,
  ip_address      VARCHAR(45) NULL,
  response        TEXT NULL,
  responded_at    DATETIME NULL,
  created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_email (email),
  INDEX idx_status (status),
  INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ──────────────────────────────────────────────
--  17. SCHOOL SETTINGS (For CMS content)
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS school_settings (
  id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  setting_key     VARCHAR(100) UNIQUE NOT NULL,
  setting_value   LONGTEXT NOT NULL,
  setting_type    ENUM('text','number','boolean','json') DEFAULT 'text',
  updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ──────────────────────────────────────────────
--  18. PROGRAMS (Academics - Streams/Tracks)
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS programs (
  id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name            VARCHAR(100) NOT NULL,
  description     TEXT NOT NULL,
  level           ENUM('nursery','primary','secondary') NOT NULL,
  duration        VARCHAR(50) NULL COMMENT 'e.g., "3 years"',
  focus_areas     TEXT NULL COMMENT 'JSON array of subjects/areas',
  icon_url        VARCHAR(255) NULL,
  is_published    TINYINT(1) NOT NULL DEFAULT 1,
  created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert sample settings for CMS
INSERT INTO school_settings (setting_key, setting_value, setting_type) VALUES
('school_name', 'Vickayor Private School', 'text'),
('school_motto', 'Utilizing your potential to the fullest', 'text'),
('school_email', 'vickayorprivateschool@gmail.com', 'text'),
('school_phone', '+234 706 595 0300', 'text'),
('school_address', '38H, Olokun Quarters, Fajuyi Road, Ile-Ife', 'text'),
('whatsapp_number', '+2347065950300', 'text'),
('founded_year', '2010', 'text'),
('mission', 'To develop confident, character-driven students with a lifelong love of learning and a commitment to academic excellence.', 'text'),
('vision', 'To be the leading institution transforming education through innovation, discipline, and holistic student development.', 'text'),
('values', '["Discipline","Excellence","Integrity","Innovation","Community"]', 'json')
ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value);
