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
    rejectUnauthorized: false
  },
  waitForConnections: true,
  connectionLimit: 10,
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

// Profile Routes
// GET /api/profile - Fetch authenticated user's profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  const registrationNumber = req.user.registration_number;
  const sql = `
    SELECT 
      name, 
      profile_picture AS profilePicture, 
      whatsapp_number AS whatsapp,
      is_employed AS isEmployed, 
      looking_for_job AS lookingForJob, 
      certificates,
      graduation_year AS graduationYear, 
      department, 
      registration_number AS registrationNumber
    FROM users2 
    WHERE registration_number = ? AND is_verified = 1
  `;
  try {
    const [results] = await pool.query(sql, [registrationNumber]);
    if (results.length === 0) {
      return res.status(404).json({ message: "Profile not found or not verified" });
    }
    const user = results[0];
    user.profilePicture = user.profilePicture ? `/uploads/${user.profilePicture}` : null;
    user.certificates = user.certificates ? `/uploads/${user.certificates}` : null;
    res.json(user);
  } catch (err) {
    console.error("Profile fetch error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// POST /api/profile - Update profile
const uploadProfile = upload.fields([
  { name: 'profilePicture', maxCount: 1 },
  { name: 'certificates', maxCount: 1 }
]);
app.post('/api/profile', authenticateToken, uploadProfile, async (req, res) => {
  const { name, whatsapp, isEmployed, lookingForJob } = req.body;
  const registrationNumber = req.user.registration_number;

  let profilePicturePath = null;
  let certificatesPath = null;
  if (req.files && req.files.profilePicture) {
    profilePicturePath = req.files.profilePicture[0].filename;
  }
  if (req.files && req.files.certificates) {
    certificatesPath = req.files.certificates[0].filename;
  }

  let sql = 'UPDATE users2 SET name = ?, whatsapp_number = ?, is_employed = ?, looking_for_job = ?';
  const params = [name || null, whatsapp || null, isEmployed === 'true' ? 1 : 0, lookingForJob === 'true' ? 1 : 0];

  if (profilePicturePath) {
    sql += ', profile_picture = ?';
    params.push(profilePicturePath);
  }
  if (certificatesPath) {
    sql += ', certificates = ?';
    params.push(certificatesPath);
  }

  sql += ' WHERE registration_number = ?';
  params.push(registrationNumber);

  try {
    const [result] = await pool.query(sql, params);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Profile not found" });
    }
    const [updated] = await pool.query(
      'SELECT name, profile_picture AS profilePicture, whatsapp_number AS whatsapp, is_employed AS isEmployed, looking_for_job AS lookingForJob, certificates, graduation_year AS graduationYear, department, registration_number AS registrationNumber FROM users2 WHERE registration_number = ?',
      [registrationNumber]
    );
    const user = updated[0];
    user.profilePicture = user.profilePicture ? `/uploads/${user.profilePicture}` : null;
    user.certificates = user.certificates ? `/uploads/${user.certificates}` : null;
    res.json(user);
  } catch (err) {
    console.error("Profile update error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// GET /api/profile/:registrationNumber - View another user's profile (public)
app.get('/api/profile/:registrationNumber', async (req, res) => {
  const { registrationNumber } = req.params;
  const sql = `
    SELECT 
      name, 
      profile_picture AS profilePicture, 
      whatsapp_number AS whatsapp,
      is_employed AS isEmployed, 
      looking_for_job AS lookingForJob, 
      graduation_year AS graduationYear, 
      department
    FROM users2 
    WHERE registration_number = ? AND is_verified = 1
  `;
  try {
    const [results] = await pool.query(sql, [registrationNumber]);
    if (results.length === 0) {
      return res.status(404).json({ message: "Profile not found or not verified" });
    }
    const user = results[0];
    user.profilePicture = user.profilePicture ? `/uploads/${user.profilePicture}` : null;
    res.json(user);
  } catch (err) {
    console.error("Profile view error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Education Routes
app.get('/api/education', authenticateToken, async (req, res) => {
  const registrationNumber = req.user.registration_number;
  const sql = `
    SELECT 
      matric_institute AS matricInstitute, 
      matric_degree AS matricDegree, 
      matric_year AS matricYear, 
      matric_percentage AS matricPercentage,
      fsc_institute AS fscInstitute, 
      fsc_degree AS fscDegree, 
      fsc_year AS fscYear, 
      fsc_percentage AS fscPercentage
    FROM edu_info 
    WHERE registration_number = ?
  `;
  try {
    const [results] = await pool.query(sql, [registrationNumber]);
    res.json(results[0] || {});
  } catch (err) {
    console.error("Education fetch error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

app.post('/api/education', authenticateToken, async (req, res) => {
  const registrationNumber = req.user.registration_number;
  const { matricInstitute, matricDegree, matricYear, matricPercentage, fscInstitute, fscDegree, fscYear, fscPercentage } = req.body;
  const sql = `
    INSERT INTO edu_info (registration_number, matric_institute, matric_degree, matric_year, matric_percentage, fsc_institute, fsc_degree, fsc_year, fsc_percentage)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE
      matric_institute = VALUES(matric_institute),
      matric_degree = VALUES(matric_degree),
      matric_year = VALUES(matric_year),
      matric_percentage = VALUES(matric_percentage),
      fsc_institute = VALUES(fsc_institute),
      fsc_degree = VALUES(fsc_degree),
      fsc_year = VALUES(fsc_year),
      fsc_percentage = VALUES(fsc_percentage)
  `;
  try {
    const [result] = await pool.query(sql, [registrationNumber, matricInstitute, matricDegree, matricYear, matricPercentage, fscInstitute, fscDegree, fscYear, fscPercentage]);
    res.json({ message: "Education saved successfully" });
  } catch (err) {
    console.error("Education save error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Skills Routes
app.get('/api/skills', authenticateToken, async (req, res) => {
  const registrationNumber = req.user.registration_number;
  const sql = 'SELECT skills FROM user_skills_achievements WHERE registration_number = ?';
  try {
    const [results] = await pool.query(sql, [registrationNumber]);
    let skills = [];
    if (results[0]?.skills) {
      skills = JSON.parse(results[0].skills);
    }
    res.json({ skills });
  } catch (err) {
    console.error("Skills fetch error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

app.post('/api/skills', authenticateToken, async (req, res) => {
  const registrationNumber = req.user.registration_number;
  const { skills } = req.body;
  const sql = `
    INSERT INTO user_skills_achievements (registration_number, skills)
    VALUES (?, ?)
    ON DUPLICATE KEY UPDATE skills = VALUES(skills)
  `;
  try {
    await pool.query(sql, [registrationNumber, JSON.stringify(skills)]);
    res.json({ message: "Skills saved successfully" });
  } catch (err) {
    console.error("Skills save error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Projects Routes
app.get('/api/projects', authenticateToken, async (req, res) => {
  const registrationNumber = req.user.registration_number;
  const sql = 'SELECT * FROM projects WHERE registration_number = ?';
  try {
    const [results] = await pool.query(sql, [registrationNumber]);
    res.json(results);
  } catch (err) {
    console.error("Projects fetch error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

app.post('/api/projects', authenticateToken, async (req, res) => {
  const registrationNumber = req.user.registration_number;
  const { project_title, project_description, completion_date, months_taken } = req.body;
  const sql = `
    INSERT INTO projects (registration_number, project_title, project_description, completion_date, months_taken)
    VALUES (?, ?, ?, ?, ?)
  `;
  try {
    const [result] = await pool.query(sql, [registrationNumber, project_title, project_description, completion_date, months_taken]);
    res.json({ id: result.insertId, registration_number: registrationNumber, project_title, project_description, completion_date, months_taken });
  } catch (err) {
    console.error("Project save error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

app.put('/api/projects/:id', authenticateToken, async (req, res) => {
  const registrationNumber = req.user.registration_number;
  const projectId = req.params.id;
  const { project_title, project_description, completion_date, months_taken } = req.body;
  const sql = `
    UPDATE projects 
    SET project_title = ?, project_description = ?, completion_date = ?, months_taken = ?
    WHERE id = ? AND registration_number = ?
  `;
  try {
    const [result] = await pool.query(sql, [project_title, project_description, completion_date, months_taken, projectId, registrationNumber]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Project not found or unauthorized" });
    }
    res.json({ id: projectId, registration_number: registrationNumber, project_title, project_description, completion_date, months_taken });
  } catch (err) {
    console.error("Project update error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

app.delete('/api/projects/:id', authenticateToken, async (req, res) => {
  const registrationNumber = req.user.registration_number;
  const projectId = req.params.id;
  const sql = 'DELETE FROM projects WHERE id = ? AND registration_number = ?';
  try {
    const [result] = await pool.query(sql, [projectId, registrationNumber]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Project not found or unauthorized" });
    }
    res.json({ message: "Project deleted successfully" });
  } catch (err) {
    console.error("Project delete error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Internships Routes
app.get('/api/internships', authenticateToken, async (req, res) => {
  const registrationNumber = req.user.registration_number;
  const sql = 'SELECT * FROM internships WHERE registration_number = ?';
  try {
    const [results] = await pool.query(sql, [registrationNumber]);
    res.json(results);
  } catch (err) {
    console.error("Internships fetch error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

app.post('/api/internships', authenticateToken, async (req, res) => {
  const registrationNumber = req.user.registration_number;
  const { title, company, duration, start_date, end_date, description, paid } = req.body;
  const sql = `
    INSERT INTO internships (registration_number, title, company, duration, start_date, end_date, description, paid)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `;
  try {
    const [result] = await pool.query(sql, [registrationNumber, title, company, duration, start_date, end_date, description, paid ? 1 : 0]);
    res.json({ id: result.insertId, registration_number: registrationNumber, title, company, duration, start_date, end_date, description, paid });
  } catch (err) {
    console.error("Internship save error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

app.put('/api/internships/:id', authenticateToken, async (req, res) => {
  const registrationNumber = req.user.registration_number;
  const internshipId = req.params.id;
  const { title, company, duration, start_date, end_date, description, paid } = req.body;
  const sql = `
    UPDATE internships 
    SET title = ?, company = ?, duration = ?, start_date = ?, end_date = ?, description = ?, paid = ?
    WHERE id = ? AND registration_number = ?
  `;
  try {
    const [result] = await pool.query(sql, [title, company, duration, start_date, end_date, description, paid ? 1 : 0, internshipId, registrationNumber]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Internship not found or unauthorized" });
    }
    res.json({ id: internshipId, registration_number: registrationNumber, title, company, duration, start_date, end_date, description, paid });
  } catch (err) {
    console.error("Internship update error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Jobs Routes
app.get('/api/jobs', authenticateToken, async (req, res) => {
  const registrationNumber = req.user.registration_number;
  const sql = 'SELECT * FROM jobs WHERE registration_number = ?';
  try {
    const [results] = await pool.query(sql, [registrationNumber]);
    res.json(results);
  } catch (err) {
    console.error("Jobs fetch error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

app.post('/api/jobs', authenticateToken, async (req, res) => {
  const registrationNumber = req.user.registration_number;
  const { job_title, organization, joining_date, job_description } = req.body;
  const sql = `
    INSERT INTO jobs (registration_number, job_title, organization, joining_date, job_description)
    VALUES (?, ?, ?, ?, ?)
  `;
  try {
    const [result] = await pool.query(sql, [registrationNumber, job_title, organization, joining_date, job_description]);
    res.json({ id: result.insertId, registration_number: registrationNumber, job_title, organization, joining_date, job_description });
  } catch (err) {
    console.error("Job save error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

app.put('/api/jobs/:id', authenticateToken, async (req, res) => {
  const registrationNumber = req.user.registration_number;
  const jobId = req.params.id;
  const { job_title, organization, joining_date, job_description } = req.body;
  const sql = `
    UPDATE jobs 
    SET job_title = ?, organization = ?, joining_date = ?, job_description = ?
    WHERE id = ? AND registration_number = ?
  `;
  try {
    const [result] = await pool.query(sql, [job_title, organization, joining_date, job_description, jobId, registrationNumber]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Job not found or unauthorized" });
    }
    res.json({ id: jobId, registration_number: registrationNumber, job_title, organization, joining_date, job_description });
  } catch (err) {
    console.error("Job update error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Achievements Routes
const uploadAchievement = upload.single('file');
app.get('/api/achievements', authenticateToken, async (req, res) => {
  const registrationNumber = req.user.registration_number;
  const sql = 'SELECT * FROM achievements WHERE registration_number = ?';
  try {
    const [results] = await pool.query(sql, [registrationNumber]);
    res.json(results);
  } catch (err) {
    console.error("Achievements fetch error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

app.post('/api/achievements', authenticateToken, uploadAchievement, async (req, res) => {
  const registrationNumber = req.user.registration_number;
  const { title, details } = req.body;
  const filePath = req.file ? req.file.filename : null;
  const sql = `
    INSERT INTO achievements (registration_number, title, details, file_path)
    VALUES (?, ?, ?, ?)
  `;
  try {
    const [result] = await pool.query(sql, [registrationNumber, title, details, filePath]);
    res.json({ id: result.insertId, registration_number: registrationNumber, title, details, file_path: filePath });
  } catch (err) {
    console.error("Achievement save error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

app.put('/api/achievements/:id', authenticateToken, uploadAchievement, async (req, res) => {
  const registrationNumber = req.user.registration_number;
  const achievementId = req.params.id;
  const { title, details } = req.body;
  const filePath = req.file ? req.file.filename : null;

  let sql = 'UPDATE achievements SET title = ?, details = ?';
  const params = [title, details];
  if (filePath) {
    sql += ', file_path = ?';
    params.push(filePath);
  }
  sql += ' WHERE id = ? AND registration_number = ?';
  params.push(achievementId, registrationNumber);

  try {
    const [result] = await pool.query(sql, params);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Achievement not found or unauthorized" });
    }
    const [updated] = await pool.query('SELECT * FROM achievements WHERE id = ?', [achievementId]);
    res.json(updated[0]);
  } catch (err) {
    console.error("Achievement update error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

app.delete('/api/achievements/:id', authenticateToken, async (req, res) => {
  const registrationNumber = req.user.registration_number;
  const achievementId = req.params.id;
  const checkQuery = 'SELECT * FROM achievements WHERE id = ? AND registration_number = ?';
  try {
    const [checkResult] = await pool.query(checkQuery, [achievementId, registrationNumber]);
    if (checkResult.length === 0) {
      return res.status(403).json({ message: "Unauthorized access or achievement not found" });
    }
    const deleteQuery = 'DELETE FROM achievements WHERE id = ? AND registration_number = ?';
    const [result] = await pool.query(deleteQuery, [achievementId, registrationNumber]);
    res.json({ message: "Achievement deleted successfully" });
  } catch (err) {
    console.error("Achievement delete error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Public Routes for ProfileView.js
app.get('/api/education/:registrationNumber', async (req, res) => {
  const { registrationNumber } = req.params;
  const sql = `
    SELECT 
      matric_institute AS matricInstitute, 
      matric_degree AS matricDegree, 
      matric_year AS matricYear, 
      matric_percentage AS matricPercentage,
      fsc_institute AS fscInstitute, 
      fsc_degree AS fscDegree, 
      fsc_year AS fscYear, 
      fsc_percentage AS fscPercentage
    FROM edu_info 
    WHERE registration_number = ?
  `;
  try {
    const [results] = await pool.query(sql, [registrationNumber]);
    res.json(results[0] || null);
  } catch (err) {
    console.error("Education view error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

app.get('/api/internships/:registrationNumber', async (req, res) => {
  const { registrationNumber } = req.params;
  const sql = 'SELECT * FROM internships WHERE registration_number = ?';
  try {
    const [results] = await pool.query(sql, [registrationNumber]);
    res.json(results);
  } catch (err) {
    console.error("Internships view error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

app.get('/api/projects/:registrationNumber', async (req, res) => {
  const { registrationNumber } = req.params;
  const sql = 'SELECT * FROM projects WHERE registration_number = ?';
  try {
    const [results] = await pool.query(sql, [registrationNumber]);
    res.json(results);
  } catch (err) {
    console.error("Projects view error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

app.get('/api/skills/:registrationNumber', async (req, res) => {
  const { registrationNumber } = req.params;
  const sql = 'SELECT skills FROM user_skills_achievements WHERE registration_number = ?';
  try {
    const [results] = await pool.query(sql, [registrationNumber]);
    let skills = [];
    if (results[0]?.skills) {
      skills = JSON.parse(results[0].skills);
    }
    res.json(skills);
  } catch (err) {
    console.error("Skills view error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

app.get('/api/achievements/:registrationNumber', async (req, res) => {
  const { registrationNumber } = req.params;
  const sql = 'SELECT * FROM achievements WHERE registration_number = ?';
  try {
    const [results] = await pool.query(sql, [registrationNumber]);
    res.json(results);
  } catch (err) {
    console.error("Achievements view error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Existing Routes (from your original code)
app.get('/api/search', async (req, res) => {
  const searchQuery = req.query.q;
  const sql = `
    SELECT id, name, profile_picture, registration_number, department 
    FROM users2 
    WHERE name LIKE ? AND is_verified = 1
    LIMIT 10
  `;
  try {
    const [results] = await pool.query(sql, [`%${searchQuery}%`]);
    res.json(results.map(user => ({
      ...user,
      profilePicture: user.profile_picture ? `/uploads/${user.profile_picture}` : null
    })));
  } catch (err) {
    console.error("Search error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const sql = "SELECT id, email, password, registration_number, is_verified FROM users2 WHERE email = ?";
  
  try {
    const [result] = await pool.query(sql, [email]);
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
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (isMatch) {
      const token = jwt.sign(
        { id: user.id, email: user.email, registration_number: user.registration_number },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      res.json({ success: true, token });
    } else {
      res.status(401).json({ success: false, message: "Invalid credentials" });
    }
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Database error" });
  }
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

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });

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