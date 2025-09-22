require('dotenv').config();
const express = require("express");
const multer = require("multer");
const mysql = require("mysql2/promise");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const path = require("path");
const nodemailer = require("nodemailer");
const fs = require("fs");
const bcrypt = require("bcryptjs");

const app = express();
app.use(cors({ origin: 'https://pafiast-alumni-frontend.vercel.app', credentials: true }));
app.use(express.json());

// Configure multer for disk storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ storage: storage });

// Serve static files from uploads directory
app.use('/uploads', express.static('uploads', {
  setHeaders: (res, path) => {
    res.set('Access-Control-Allow-Origin', process.env.FRONTEND_URL);
  }
}));

// Database connection
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  ssl: {
    rejectUnauthorized: false  // Test; switch to CA cert later
  },
  waitForConnections: true,
  connectionLimit: 10, // Aiven free tier supports multiple connections
  queueLimit: 0
});

// Test pool connection on startup
pool.getConnection()
  .then(conn => {
    console.log('Connected to Aiven MySQL database.');
    conn.release();
  })
  .catch(err => {
    console.error('Database connection failed:', err.message);
  });

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(403).json({ message: "No token provided" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Invalid token" });
    console.log("Decoded Token Registration Number:", decoded.registration_number);
    req.user = decoded;
    next();
  });
};

// Your routes
app.get('/api/search', (req, res) => {
  const searchQuery = req.query.q;
  const sql = `SELECT id, name, profile_picture, registration_number, department 
               FROM users2 
               WHERE name LIKE ? AND is_verified = 1
               LIMIT 10`;
  db.pool(sql, [`%${searchQuery}%`], (err, results) => {
    if (err) {
      console.error("Search error:", err);
      return res.status(500).json({ message: "Database error" });
    }
    res.json(results.map(user => ({
      ...user,
      profilePicture: user.profile_picture ? `/uploads/${user.profile_picture}` : null
    })));
  });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  console.log("Login attempt for email:", email);
  const sql = "SELECT id, email, password, registration_number, is_verified FROM users2 WHERE email = ?";
  db.pool(sql, [email], async (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Database error" });
    }
    console.log("Database result:", result);
    if (result.length === 0) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }
    const user = result[0];
    if (!user.is_verified) {
      return res.status(401).json({ 
        success: false, 
        message: "Account pending verification. Please wait for admin approval." 
      });
    }
    // TEMPORARY: Direct password comparison
    // WARNING: This is not secure and should only be used during development
    if (password === user.password) {
      const token = jwt.sign(
        { id: user.id, email: user.email, registration_number: user.registration_number },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
      );
      return res.json({ success: true, message: "Login successful", token });
    } else {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }
  });
});

app.post("/signup", (req, res) => {
  const {
    name,
    email,
    password,
    registration_number,
    graduation_year,
    department,
    whatsapp_number
  } = req.body;
  const checkEmailSQL = "SELECT * FROM users2 WHERE email = ?";
  db.pool(checkEmailSQL, [email], (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ success: false, message: "Database error" });
    }
    if (result.length > 0) {
      return res.status(400).json({
        success: false,
        message: "Email already in use. Please use a different email or login to your existing account."
      });
    }
    const insertUserSQL = `
      INSERT INTO users2 (
        name, 
        email, 
        password, 
        registration_number, 
        graduation_year, 
        department, 
        whatsapp_number,
        is_verified
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;
    db.pool(
      insertUserSQL,
      [name, email, password, registration_number, graduation_year, department, whatsapp_number, false],
      (err, result) => {
        if (err) {
          console.error("Error creating user:", err);
          return res.status(500).json({
            success: false,
            message: "Failed to create user account. Please try again."
          });
        }
        res.status(201).json({
          success: true,
          message: "Account created successfully!"
        });
      }
    );
  });
});

app.get('/api/ecard/status', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const registrationNumber = req.user.registration_number;
  const sql = "SELECT status FROM e_cards WHERE user_id = ? AND registration_number = ?";
  db.pool(sql, [userId, registrationNumber], (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Database error" });
    }
    if (result.length > 0) {
      res.json({ 
        exists: true, 
        status: result[0].status 
      });
    } else {
      res.json({ 
        exists: false 
      });
    }
  });
});

app.post('/api/ecard/request', authenticateToken, upload.single('cardImage'), (req, res) => {
  const userId = req.user.id;
  const registrationNumber = req.user.registration_number;
  const expiryDate = new Date();
  expiryDate.setFullYear(expiryDate.getFullYear() + 5);
  const formattedExpiryDate = expiryDate.toISOString().split('T')[0];
  const cardImagePath = req.file ? req.file.filename : null;
  const checkSql = "SELECT * FROM e_cards WHERE user_id = ? AND registration_number = ?";
  db.pool(checkSql, [userId, registrationNumber], (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Database error" });
    }
    if (result.length > 0) {
      const updateSql = `
        UPDATE e_cards 
        SET status = 'pending', 
            request_date = CURRENT_TIMESTAMP, 
            card_image = ?, 
            approved_date = NULL, 
            rejection_reason = NULL,
            expiry_date = ?
        WHERE user_id = ? AND registration_number = ?
      `;
      db.pool(updateSql, [cardImagePath, formattedExpiryDate, userId, registrationNumber], (err, updateResult) => {
        if (err) {
          console.error("Database error:", err);
          return res.status(500).json({ message: "Database error" });
        }
        res.json({ message: "E-Card request updated successfully" });
      });
    } else {
      const insertSql = `
        INSERT INTO e_cards 
        (user_id, registration_number, card_image, expiry_date)
        VALUES (?, ?, ?, ?)
      `;
      db.pool(insertSql, [userId, registrationNumber, cardImagePath, formattedExpiryDate], (err, insertResult) => {
        if (err) {
          console.error("Database error:", err);
          return res.status(500).json({ message: "Database error" });
        }
        res.json({ message: "E-Card request submitted successfully" });
      });
    }
  });
});

app.get('/api/ecard/download', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const registrationNumber = req.user.registration_number;
  const sql = "SELECT card_image FROM e_cards WHERE user_id = ? AND registration_number = ? AND status = 'approved'";
  db.pool(sql, [userId, registrationNumber], (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Database error" });
    }
    if (result.length > 0 && result[0].card_image) {
      const imagePath = path.join(__dirname, 'uploads', result[0].card_image);
      if (fs.existsSync(imagePath)) {
        res.download(imagePath, 'PAF-IAST_Alumni_ECard.png', (err) => {
          if (err) {
            console.error("Download error:", err);
            return res.status(404).json({ message: "E-Card file not found" });
          }
        });
      } else {
        return res.status(404).json({ message: "E-Card file not found on server" });
      }
    } else {
      res.status(404).json({ message: "No approved E-Card found" });
    }
  });
});

app.get('/api/ecard/view', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const registrationNumber = req.user.registration_number;
  const sql = "SELECT card_image FROM e_cards WHERE user_id = ? AND registration_number = ? AND status = 'approved'";
  db.pool(sql, [userId, registrationNumber], (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Database error" });
    }
    if (result.length > 0 && result[0].card_image) {
      const imagePath = path.join(__dirname, 'uploads', result[0].card_image);
      if (fs.existsSync(imagePath)) {
        res.setHeader('Content-Type', 'image/png');
        fs.createReadStream(imagePath).pipe(res);
      } else {
        return res.status(404).json({ message: "E-Card file not found on server" });
      }
    } else {
      res.status(404).json({ message: "No approved E-Card found" });
    }
  });
});

app.get('/api/profile/:registrationNumber', (req, res) => {
  const registrationNumber = req.params.registrationNumber;
  const sql = `SELECT name, whatsapp_number, profile_picture, certificates, 
               is_employed, looking_for_job, graduation_year, department 
               FROM users2 
               WHERE registration_number = ?`;
  db.pool(sql, [registrationNumber], (err, result) => {
    if (err) {
      console.error("Profile fetch error:", err);
      return res.status(500).json({ message: "Database error" });
    }
    if (result.length > 0) {
      const user = result[0];
      res.json({
        name: user.name,
        whatsapp: user.whatsapp_number,
        profilePicture: user.profile_picture ? `/uploads/${user.profile_picture}` : null,
        certificates: user.certificates ? `/uploads/${user.certificates}` : null,
        isEmployed: Boolean(user.is_employed),
        lookingForJob: Boolean(user.looking_for_job),
        graduationYear: user.graduation_year,
        department: user.department
      });
    } else {
      res.status(404).json({ message: "User not found" });
    }
  });
});

app.get('/api/education/:registrationNumber', (req, res) => {
  const regNum = req.params.registrationNumber;
  const sql = "SELECT * FROM edu_info WHERE registration_number = ?";
  db.pool(sql, [regNum], (err, result) => {
    if (err) return res.status(500).json({ message: "Database error" });
    res.json(result[0] || {});
  });
});

app.get('/api/skills/:registrationNumber', (req, res) => {
  const regNum = req.params.registrationNumber;
  const sql = "SELECT skills FROM user_skills_achievements WHERE registration_number = ?";
  db.pool(sql, [regNum], (err, result) => {
    if (err) return res.status(500).json({ message: "Database error" });
    const skills = result[0]?.skills ? JSON.parse(result[0].skills) : [];
    res.json(skills);
  });
});

app.get('/api/internships/:registrationNumber', (req, res) => {
  const regNum = req.params.registrationNumber;
  const sql = "SELECT * FROM internships WHERE registration_number = ? ORDER BY start_date DESC";
  db.pool(sql, [regNum], (err, result) => {
    if (err) return res.status(500).json({ message: "Database error" });
    res.json(result);
  });
});

app.get('/api/projects/:registrationNumber', (req, res) => {
  const regNum = req.params.registrationNumber;
  const sql = "SELECT * FROM projects WHERE registration_number = ? ORDER BY completion_date DESC";
  db.pool(sql, [regNum], (err, result) => {
    if (err) return res.status(500).json({ message: "Database error" });
    res.json(result);
  });
});

app.get('/api/achievements/:registrationNumber', (req, res) => {
  const regNum = req.params.registrationNumber;
  const sql = "SELECT * FROM achievements WHERE registration_number = ? ORDER BY id DESC";
  db.pool(sql, [regNum], (err, result) => {
    if (err) return res.status(500).json({ message: "Database error" });
    res.json(result);
  });
});

app.get("/api/profile", authenticateToken, (req, res) => {
  const userId = req.user.id;
  const sql = "SELECT name, whatsapp_number, profile_picture, certificates, is_employed, looking_for_job, graduation_year, department FROM users2 WHERE id = ?";
  db.pool(sql, [userId], (err, result) => {
    if (err) return res.status(500).json({ message: "Database error" });
    if (result.length > 0) {
      const user = result[0];
      console.log("Database values:", user);
      res.json({
        name: user.name,
        whatsapp: user.whatsapp_number,
        profilePicture: user.profile_picture ? `/uploads/${user.profile_picture}` : null,
        certificates: user.certificates ? `/uploads/${user.certificates}` : null,
        isEmployed: Boolean(user.is_employed),
        lookingForJob: Boolean(user.looking_for_job),
        graduationYear: user.graduation_year,
        department: user.department,
        registrationNumber: req.user.registration_number
      });
    } else {
      res.status(404).json({ message: "User not found" });
    }
  });
});

app.post(
  "/api/profile",
  authenticateToken,
  upload.fields([
    { name: "profilePicture", maxCount: 1 },
    { name: "certificates", maxCount: 1 }
  ]),
  (req, res) => {
    const userId = req.user.id;
    const { name, whatsapp, isEmployed, lookingForJob } = req.body;
    const profilePicture = req.files?.profilePicture?.[0]?.filename;
    const certificates = req.files?.certificates?.[0]?.filename;
    let sql = `
      UPDATE users2 
      SET 
        name = ?,
        whatsapp_number = ?,
        is_employed = ?,
        looking_for_job = ?
    `;
    let values = [
      name || null,
      whatsapp || null,
      isEmployed === 'true' ? 1 : 0,
      lookingForJob === 'true' ? 1 : 0
    ];
    if (profilePicture) {
      sql += ", profile_picture = ?";
      values.push(profilePicture);
    }
    if (certificates) {
      sql += ", certificates = ?";
      values.push(certificates);
    }
    sql += " WHERE id = ?";
    values.push(userId);
    db.pool(sql, values, (err, result) => {
      if (err) {
        console.error("Error updating profile:", err);
        return res.status(500).json({ message: "Database error" });
      }
      res.json({ message: "Profile updated successfully" });
    });
  }
);

app.post("/api/education", authenticateToken, (req, res) => {
  console.log("User registration number from token:", req.user.registration_number);
  const registrationNumber = req.user.registration_number;
  const { matricInstitute, matricDegree, matricYear, matricPercentage, fscInstitute, fscDegree, fscYear, fscPercentage } = req.body;
  if (!registrationNumber) {
    console.error("Registration number missing in token");
    return res.status(400).json({ message: "Registration number is required." });
  }
  const query = `
    INSERT INTO edu_info (registration_number, matric_institute, matric_degree, matric_year, matric_percentage, fsc_institute, fsc_degree, fsc_year, fsc_percentage)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE
    matric_institute = VALUES(matric_institute), matric_degree = VALUES(matric_degree),
    matric_year = VALUES(matric_year), matric_percentage = VALUES(matric_percentage),
    fsc_institute = VALUES(fsc_institute), fsc_degree = VALUES(fsc_degree),
    fsc_year = VALUES(fsc_year), fsc_percentage = VALUES(fsc_percentage);
  `;
  db.pool(query, [registrationNumber, matricInstitute, matricDegree, matricYear, matricPercentage, fscInstitute, fscDegree, fscYear, fscPercentage], (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Database error" });
    }
    res.json({ message: "Education details saved successfully!" });
  });
});

app.get("/api/education", authenticateToken, (req, res) => {
  const registrationNumber = req.user.registration_number;
  const sql = "SELECT * FROM edu_info WHERE registration_number = ?";
  db.pool(sql, [registrationNumber], (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Database error" });
    }
    res.json(result[0] || {});
  });
});

app.get('/api/internships', authenticateToken, (req, res) => {
  const registrationNumber = req.user.registration_number;
  const sql = "SELECT * FROM internships WHERE registration_number = ?";
  db.pool(sql, [registrationNumber], (err, result) => {
    if (err) return res.status(500).json({ message: "Database error" });
    res.json(result);
  });
});

app.post('/api/internships', authenticateToken, (req, res) => {
  const registrationNumber = req.user.registration_number;
  const { title, company, duration, start_date, end_date, description, paid } = req.body;
  const sql = `
    INSERT INTO internships 
    (registration_number, title, company, duration, start_date, end_date, description, paid)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `;
  db.pool(sql, 
    [registrationNumber, title, company, duration, start_date, end_date, description, paid], 
    (err, result) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ message: "Database error" });
      }
      const newInternship = {
        id: result.insertId,
        registration_number: registrationNumber,
        ...req.body
      };
      res.json(newInternship);
    }
  );
});

app.put('/api/internships/:id', authenticateToken, (req, res) => {
  const registrationNumber = req.user.registration_number;
  const internshipId = req.params.id;
  const { title, company, duration, start_date, end_date, description, paid } = req.body;
  const checkQuery = "SELECT * FROM internships WHERE id = ? AND registration_number = ?";
  db.pool(checkQuery, [internshipId, registrationNumber], (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Database error" });
    }
    if (result.length === 0) {
      return res.status(403).json({ message: "Unauthorized access or internship not found" });
    }
    const updateQuery = `
      UPDATE internships 
      SET title = ?, company = ?, duration = ?, 
          start_date = ?, end_date = ?, description = ?, paid = ? 
      WHERE id = ? AND registration_number = ?
    `;
    db.pool(updateQuery, 
      [title, company, duration, start_date, end_date, description, paid, internshipId, registrationNumber], 
      (err, updateResult) => {
        if (err) {
          console.error("Database error:", err);
          return res.status(500).json({ message: "Database error updating internship" });
        }
        res.json({
          id: parseInt(internshipId),
          registration_number: registrationNumber,
          title,
          company,
          duration,
          start_date,
          end_date,
          description,
          paid
        });
      }
    );
  });
});

app.delete('/api/internships/:id', authenticateToken, (req, res) => {
  const sql = "DELETE FROM internships WHERE id = ?";
  db.pool(sql, [req.params.id], (err, result) => {
    if (err) return res.status(500).json({ message: "Database error" });
    res.json({ message: "Internship deleted successfully" });
  });
});

app.get('/api/projects', authenticateToken, (req, res) => {
  const registrationNumber = req.user.registration_number;
  const sql = "SELECT * FROM projects WHERE registration_number = ? ORDER BY completion_date DESC";
  db.pool(sql, [registrationNumber], (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Database error" });
    }
    res.json(result);
  });
});

app.post('/api/projects', authenticateToken, (req, res) => {
  const registrationNumber = req.user.registration_number;
  const { project_title, project_description, completion_date, months_taken } = req.body;
  const sql = `
    INSERT INTO projects 
    (registration_number, project_title, project_description, completion_date, months_taken)
    VALUES (?, ?, ?, ?, ?)
  `;
  db.pool(sql, 
    [registrationNumber, project_title, project_description, completion_date, months_taken], 
    (err, result) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ message: "Database error" });
      }
      const newProject = {
        id: result.insertId,
        registration_number: registrationNumber,
        ...req.body
      };
      res.json(newProject);
    }
  );
});

app.put('/api/projects/:id', authenticateToken, (req, res) => {
  const registrationNumber = req.user.registration_number;
  const projectId = req.params.id;
  const { project_title, project_description, completion_date, months_taken } = req.body;
  const checkQuery = "SELECT * FROM projects WHERE id = ? AND registration_number = ?";
  db.pool(checkQuery, [projectId, registrationNumber], (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Database error" });
    }
    if (result.length === 0) {
      return res.status(403).json({ message: "Unauthorized access or project not found" });
    }
    const updateQuery = `
      UPDATE projects 
      SET project_title = ?, project_description = ?, completion_date = ?, months_taken = ? 
      WHERE id = ? AND registration_number = ?
    `;
    db.pool(updateQuery, 
      [project_title, project_description, completion_date, months_taken, projectId, registrationNumber], 
      (err, updateResult) => {
        if (err) {
          console.error("Database error:", err);
          return res.status(500).json({ message: "Database error updating project" });
        }
        res.json({
          id: parseInt(projectId),
          registration_number: registrationNumber,
          project_title,
          project_description,
          completion_date,
          months_taken
        });
      }
    );
  });
});

app.delete('/api/projects/:id', authenticateToken, (req, res) => {
  const registrationNumber = req.user.registration_number;
  const projectId = req.params.id;
  const checkQuery = "SELECT * FROM projects WHERE id = ? AND registration_number = ?";
  db.pool(checkQuery, [projectId, registrationNumber], (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Database error" });
    }
    if (result.length === 0) {
      return res.status(403).json({ message: "Unauthorized access or project not found" });
    }
    const deleteQuery = "DELETE FROM projects WHERE id = ? AND registration_number = ?";
    db.pool(deleteQuery, [projectId, registrationNumber], (err, deleteResult) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ message: "Database error deleting project" });
      }
      res.json({ message: "Project deleted successfully" });
    });
  });
});

app.get('/api/jobs', authenticateToken, (req, res) => {
  const registrationNumber = req.user.registration_number;
  const sql = "SELECT * FROM jobs WHERE registration_number = ?";
  db.pool(sql, [registrationNumber], (err, result) => {
    if (err) return res.status(500).json({ message: "Database error" });
    res.json(result);
  });
});

app.post('/api/jobs', authenticateToken, (req, res) => {
  const registrationNumber = req.user.registration_number;
  const { job_title, organization, joining_date, job_description } = req.body;
  const sql = `
    INSERT INTO jobs 
    (registration_number, job_title, organization, joining_date, job_description)
    VALUES (?, ?, ?, ?, ?)
  `;
  db.pool(sql, 
    [registrationNumber, job_title, organization, joining_date, job_description], 
    (err, result) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ message: "Database error" });
      }
      const newJob = {
        id: result.insertId,
        registration_number: registrationNumber,
        ...req.body
      };
      res.json(newJob);
    }
  );
});

app.put('/api/jobs/:id', authenticateToken, (req, res) => {
  const registrationNumber = req.user.registration_number;
  const jobId = req.params.id;
  const { job_title, organization, joining_date, job_description } = req.body;
  const checkQuery = "SELECT * FROM jobs WHERE id = ? AND registration_number = ?";
  db.pool(checkQuery, [jobId, registrationNumber], (err, result) => {
    if (err) return res.status(500).json({ message: "Database error" });
    if (result.length === 0) {
      return res.status(403).json({ message: "Unauthorized access or job not found" });
    }
    const updateQuery = `
      UPDATE jobs 
      SET job_title = ?, organization = ?, joining_date = ?, job_description = ?
      WHERE id = ? AND registration_number = ?
    `;
    db.pool(updateQuery, 
      [job_title, organization, joining_date, job_description, jobId, registrationNumber], 
      (err, updateResult) => {
        if (err) return res.status(500).json({ message: "Database error updating job" });
        res.json({
          id: parseInt(jobId),
          registration_number: registrationNumber,
          ...req.body
        });
      }
    );
  });
});

app.get('/api/skills', authenticateToken, (req, res) => {
  const regNum = req.user.registration_number;
  const sql = "SELECT skills FROM user_skills_achievements WHERE registration_number = ?";
  db.pool(sql, [regNum], (err, result) => {
    if (err) return res.status(500).json({ message: "Database error" });
    let skills = [];
    if (result[0]?.skills) {
      try {
        skills = typeof result[0].skills === 'string' 
          ? JSON.parse(result[0].skills)
          : result[0].skills;
      } catch (e) {
        console.error("JSON parse error:", e);
      }
    }
    res.json({ skills });
  });
});

app.post('/api/skills', authenticateToken, (req, res) => {
  const regNum = req.user.registration_number;
  const { skills } = req.body;
  const sql = `
    INSERT INTO user_skills_achievements (registration_number, skills)
    VALUES (?, ?)
    ON DUPLICATE KEY UPDATE
    skills = VALUES(skills)
  `;
  db.pool(sql, [regNum, JSON.stringify(skills)], (err, result) => {
    if (err) return res.status(500).json({ message: "Database error" });
    res.json({ skills });
  });
});

app.delete('/api/skills/:id', authenticateToken, (req, res) => {
  const regNum = req.user.registration_number;
  const sql = "DELETE FROM user_skills_achievements WHERE id = ? AND registration_number = ? AND type = 'skill'";
  db.pool(sql, [req.params.id, regNum], (err, result) => {
    if (err) return res.status(500).json({ message: "Database error" });
    res.json({ message: "Skill deleted successfully" });
  });
});

app.get('/api/achievements', authenticateToken, (req, res) => {
  const registrationNumber = req.user.registration_number;
  const sql = "SELECT * FROM achievements WHERE registration_number = ?";
  db.pool(sql, [registrationNumber], (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Database error" });
    }
    res.json(result);
  });
});

app.post('/api/achievements', authenticateToken, upload.single('file'), (req, res) => {
  const registrationNumber = req.user.registration_number;
  const { title, details } = req.body;
  const filePath = req.file ? req.file.filename : null;
  const sql = `
    INSERT INTO achievements 
    (registration_number, title, details, file_path)
    VALUES (?, ?, ?, ?)
  `;
  db.pool(sql, 
    [registrationNumber, title, details, filePath], 
    (err, result) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ message: "Database error" });
      }
      const newAchievement = {
        id: result.insertId,
        registration_number: registrationNumber,
        title,
        details,
        file_path: filePath
      };
      res.json(newAchievement);
    }
  );
});

app.put('/api/achievements/:id', authenticateToken, upload.single('file'), (req, res) => {
  const registrationNumber = req.user.registration_number;
  const achievementId = req.params.id;
  const { title, details } = req.body;
  const checkQuery = "SELECT * FROM achievements WHERE id = ? AND registration_number = ?";
  db.pool(checkQuery, [achievementId, registrationNumber], (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Database error" });
    }
    if (result.length === 0) {
      return res.status(403).json({ message: "Unauthorized access or achievement not found" });
    }
    let updateQuery;
    let queryParams;
    if (req.file) {
      updateQuery = `
        UPDATE achievements 
        SET title = ?, details = ?, file_path = ? 
        WHERE id = ? AND registration_number = ?
      `;
      queryParams = [title, details, req.file.filename, achievementId, registrationNumber];
    } else {
      updateQuery = `
        UPDATE achievements 
        SET title = ?, details = ? 
        WHERE id = ? AND registration_number = ?
      `;
      queryParams = [title, details, achievementId, registrationNumber];
    }
    db.pool(updateQuery, queryParams, (err, updateResult) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ message: "Database error updating achievement" });
      }
      db.pool("SELECT * FROM achievements WHERE id = ?", [achievementId], (err, fetchResult) => {
        if (err || fetchResult.length === 0) {
          console.error("Error fetching updated achievement:", err);
          return res.status(500).json({ message: "Error fetching updated achievement" });
        }
        res.json(fetchResult[0]);
      });
    });
  });
});

app.delete('/api/achievements/:id', authenticateToken, (req, res) => {
  const registrationNumber = req.user.registration_number;
  const achievementId = req.params.id;
  const checkQuery = "SELECT * FROM achievements WHERE id = ? AND registration_number = ?";
  db.pool(checkQuery, [achievementId, registrationNumber], (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Database error" });
    }
    if (result.length === 0) {
      return res.status(403).json({ message: "Unauthorized access or achievement not found" });
    }
    const deleteQuery = "DELETE FROM achievements WHERE id = ? AND registration_number = ?";
    db.pool(deleteQuery, [achievementId, registrationNumber], (err, deleteResult) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ message: "Database error deleting achievement" });
      }
      res.json({ message: "Achievement deleted successfully" });
    });
  });
});

app.post("/api/send-email", upload.single('attachment'), (req, res) => {
  const {
    attestationType,
    degreeLevel,
    registrationNumber,
    studentName,
    graduationYear,
    email,
    phone,
    additionalInfo
  } = req.body;

  // Create transporter using Gmail
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });

  // Prepare email options
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: 'msaadkhan200212@gmail.com',
    subject: attestationType || 'Degree Attestation Request',
    html: `
      <h2>${attestationType || 'Degree Attestation Request'}</h2>
      ${attestationType === 'Alumni Card Application' ? `
        <p><strong>Student Name:</strong> ${studentName}</p>
        <p><strong>Registration Number:</strong> ${registrationNumber}</p>
        <p><strong>Graduation Year:</strong> ${graduationYear}</p>
        <p><strong>CNIC:</strong> ${phone}</p>
        <p><strong>Email:</strong> ${email}</p>
        ${additionalInfo ? `<p><strong>Additional Information:</strong><br>${additionalInfo}</p>` : ''}
      ` : `
        <p><strong>Attestation Type:</strong> ${attestationType}</p>
        <p><strong>Degree Level:</strong> ${degreeLevel}</p>
        <p><strong>Registration Number:</strong> ${registrationNumber}</p>
        <p><strong>Student Name:</strong> ${studentName}</p>
        <p><strong>Year of Graduation:</strong> ${graduationYear}</p>
        <p><strong>Contact Information:</strong></p>
        <ul>
          <li>Email: ${email}</li>
          <li>Phone: ${phone}</li>
        </ul>
      `}
    `
  };

  // Add attachment if file was uploaded
  if (req.file) {
    mailOptions.attachments = [{
      filename: req.file.originalname,
      path: req.file.path
    }];
    console.log('Attaching file:', req.file.path);
  }

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error("Error sending email:", error);
      return res.status(500).json({ error: 'Failed to send email' });
    }
    console.log('Email sent: ' + info.response);
    res.status(200).json({ message: 'Email sent successfully' });
  });
});

// Start server
app.listen(process.env.PORT || 5000, () => console.log("Server running on port", process.env.PORT || 5000));