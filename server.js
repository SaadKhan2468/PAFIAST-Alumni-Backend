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

app.use(cors({ origin: process.env.FRONTEND_URL, credentials: true }));
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

// Database connection using a promise-based pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT
});

// Test database connection on startup
(async () => {
  try {
    await pool.getConnection();
    console.log("Connected to Aiven MySQL database.");
  } catch (err) {
    console.error("Error connecting to database:", err);
  }
})();

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error("JWT verification error:", err);
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
};

// Route to handle login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  console.log(`Login attempt for email: ${email}`);

  const sql = "SELECT id, email, password, registration_number, is_verified, role FROM users2 WHERE email = ?";
  
  try {
    const [result] = await pool.query(sql, [email]);

    if (result.length === 0) {
      console.log("User not found.");
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    const user = result[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (isMatch) {
      if (!user.is_verified) {
        console.log("Account not verified.");
        return res.status(401).json({ 
          success: false, 
          message: "Account pending verification. Please wait for admin approval." 
        });
      }
      
      const token = jwt.sign(
        { id: user.id, email: user.email, registration_number: user.registration_number, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
      );
      console.log("Login successful.");
      return res.json({ success: true, message: "Login successful", token, role: user.role });
    } else {
      console.log("Password mismatch.");
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }
  } catch (err) {
    console.error("Database error during login:", err);
    return res.status(500).json({ error: "Database error" });
  }
});

// Route to handle signup
app.post("/signup", async (req, res) => {
  const {
    name,
    email,
    password, 
    registration_number,
    graduation_year,
    department,
    whatsapp_number,
    role = 'alumni'
  } = req.body;
  
  try {
    const checkEmailSQL = "SELECT * FROM users2 WHERE email = ?";
    const [result] = await pool.query(checkEmailSQL, [email]);

    if (result.length > 0) {
      return res.status(400).json({
        success: false,
        message: "Email already in use. Please use a different email or login to your existing account."
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const insertUserSQL = `
      INSERT INTO users2 (
        name, 
        email, 
        password,
        registration_number, 
        graduation_year, 
        department, 
        whatsapp_number,
        is_verified,
        role
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    await pool.query(
      insertUserSQL,
      [name, email, hashedPassword, registration_number, graduation_year, department, whatsapp_number, false, role]
    );

    res.status(201).json({
      success: true,
      message: "Account created successfully! Please wait for admin verification."
    });

  } catch (err) {
    console.error("Signup error:", err);
    return res.status(500).json({
      success: false,
      message: "Failed to create user account. Please try again."
    });
  }
});

// Route to handle attestation form submission and email sending
app.post('/api/attestation-request', upload.single('document'), async (req, res) => {
  const {
    attestationType,
    degreeLevel,
    studentName,
    registrationNumber,
    graduationYear,
    email,
    phone,
    additionalInfo
  } = req.body;

  console.log('Received attestation request:', req.body);

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const mailOptions = {
    from: email,
    to: 'pafiast@alumni.edu.pk',
    subject: `Attestation Request: ${studentName}`,
    html: `
      <h2>Attestation Request Details</h2>
      <p><strong>Student Name:</strong> ${studentName}</p>
      <p><strong>Registration Number:</strong> ${registrationNumber}</p>
      <p><strong>Attestation Type:</strong> ${attestationType}</p>
      ${attestationType === 'Transcript' ? `
        <p><strong>Degree Level:</strong> ${degreeLevel}</p>
        <p><strong>Year of Graduation:</strong> ${graduationYear}</p>
        <p><strong>Contact Email:</strong> ${email}</p>
        <p><strong>Contact Phone:</strong> ${phone}</p>
        ${additionalInfo ? `<p><strong>Additional Information:</strong><br>${additionalInfo}</p>` : ''}
      ` : `
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

  try {
    await transporter.sendMail(mailOptions);
    console.log('Email sent successfully');
    res.status(200).json({ message: 'Email sent successfully!' });
  } catch (error) {
    console.error("Error sending email:", error);
    res.status(500).json({ error: 'Failed to send email' });
  } finally {
    if (req.file) {
      fs.unlink(req.file.path, (err) => {
        if (err) console.error('Error deleting file:', err);
      });
    }
  }
});

// Route to get a profile by registration number
app.get('/api/profile/:registrationNumber', authenticateToken, async (req, res) => {
  const { registrationNumber } = req.params;
  const sql = `
    SELECT name, profile_picture, registration_number, graduation_year, department, whatsapp_number, bio
    FROM users2
    WHERE registration_number = ?
  `;

  try {
    const [rows] = await pool.query(sql, [registrationNumber]);
    if (rows.length > 0) {
      const user = rows[0];
      user.profile_picture = user.profile_picture ? `/uploads/${user.profile_picture}` : null;
      res.json(user);
    } else {
      res.status(404).json({ message: "Profile not found" });
    }
  } catch (err) {
    console.error("Error fetching profile:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Route to get search results
app.get('/api/search', async (req, res) => {
  const searchQuery = req.query.q;
  const sql = `SELECT id, name, profile_picture, registration_number, department 
               FROM users2 
               WHERE name LIKE ? AND is_verified = 1
               LIMIT 10`;

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

// Route to get education by registration number
app.get('/api/education/:registrationNumber', async (req, res) => {
  const { registrationNumber } = req.params;
  const sql = "SELECT * FROM education WHERE registration_number = ?";
  
  try {
    const [rows] = await pool.query(sql, [registrationNumber]);
    res.json(rows);
  } catch (err) {
    console.error("Error fetching education:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Route to get skills by registration number
app.get('/api/skills/:registrationNumber', async (req, res) => {
  const { registrationNumber } = req.params;
  const sql = "SELECT * FROM skills WHERE registration_number = ?";
  
  try {
    const [rows] = await pool.query(sql, [registrationNumber]);
    res.json(rows);
  } catch (err) {
    console.error("Error fetching skills:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Route to get internships by registration number
app.get('/api/internships/:registrationNumber', async (req, res) => {
  const { registrationNumber } = req.params;
  const sql = "SELECT * FROM internships WHERE registration_number = ?";
  
  try {
    const [rows] = await pool.query(sql, [registrationNumber]);
    res.json(rows);
  } catch (err) {
    console.error("Error fetching internships:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Route to get projects by registration number
app.get('/api/projects/:registrationNumber', async (req, res) => {
  const { registrationNumber } = req.params;
  const sql = "SELECT * FROM projects WHERE registration_number = ?";
  
  try {
    const [rows] = await pool.query(sql, [registrationNumber]);
    res.json(rows);
  } catch (err) {
    console.error("Error fetching projects:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Route to get achievements by registration number
app.get('/api/achievements/:registrationNumber', async (req, res) => {
  const { registrationNumber } = req.params;
  const sql = "SELECT * FROM achievements WHERE registration_number = ?";
  
  try {
    const [rows] = await pool.query(sql, [registrationNumber]);
    res.json(rows);
  } catch (err) {
    console.error("Error fetching achievements:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Route to get jobs by registration number
app.get('/api/jobs', async (req, res) => {
  const { registrationNumber } = req.query;
  const sql = `
    SELECT 
      j.job_id,
      j.registration_number,
      j.job_title,
      j.company_name,
      j.location,
      j.job_type,
      j.description,
      j.requirements,
      j.contact_email,
      u.name AS alumni_name
    FROM jobs j
    JOIN users2 u ON j.registration_number = u.registration_number
    ORDER BY j.job_id DESC
  `;
  try {
    const [rows] = await pool.query(sql);
    res.json(rows);
  } catch (err) {
    console.error("Error fetching jobs:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Route to post a job
app.post('/api/jobs', authenticateToken, async (req, res) => {
  const { registrationNumber, jobTitle, companyName, location, jobType, description, requirements, contactEmail } = req.body;
  const sql = `INSERT INTO jobs (registration_number, job_title, company_name, location, job_type, description, requirements, contact_email) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
  try {
    await pool.query(sql, [registrationNumber, jobTitle, companyName, location, jobType, description, requirements, contactEmail]);
    res.status(201).json({ message: "Job posted successfully!" });
  } catch (err) {
    console.error("Error posting job:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Route to update a job
app.put('/api/jobs/:jobId', authenticateToken, async (req, res) => {
  const { jobId } = req.params;
  const { registrationNumber, jobTitle, companyName, location, jobType, description, requirements, contactEmail } = req.body;
  const sql = `UPDATE jobs SET job_title = ?, company_name = ?, location = ?, job_type = ?, description = ?, requirements = ?, contact_email = ? 
               WHERE job_id = ? AND registration_number = ?`;
  try {
    const [result] = await pool.query(sql, [jobTitle, companyName, location, jobType, description, requirements, contactEmail, jobId, registrationNumber]);
    if (result.affectedRows > 0) {
      res.json({ message: "Job updated successfully!" });
    } else {
      res.status(404).json({ message: "Job not found or unauthorized" });
    }
  } catch (err) {
    console.error("Error updating job:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Route to get a specific job
app.get('/api/jobs/:jobId', async (req, res) => {
  const { jobId } = req.params;
  const sql = 'SELECT * FROM jobs WHERE job_id = ?';
  try {
    const [rows] = await pool.query(sql, [jobId]);
    if (rows.length > 0) {
      res.json(rows[0]);
    } else {
      res.status(404).json({ message: "Job not found" });
    }
  } catch (err) {
    console.error("Error fetching job:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Route to post an education entry
app.post('/api/education', authenticateToken, async (req, res) => {
  const { registrationNumber, degree, university, year, cgpa } = req.body;
  const sql = "INSERT INTO education (registration_number, degree, university, year, cgpa) VALUES (?, ?, ?, ?, ?)";
  try {
    await pool.query(sql, [registrationNumber, degree, university, year, cgpa]);
    res.status(201).json({ message: "Education entry added successfully!" });
  } catch (err) {
    console.error("Error adding education:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Route to update an education entry
app.put('/api/education/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { registrationNumber, degree, university, year, cgpa } = req.body;
  const sql = "UPDATE education SET degree = ?, university = ?, year = ?, cgpa = ? WHERE id = ? AND registration_number = ?";
  try {
    const [result] = await pool.query(sql, [degree, university, year, cgpa, id, registrationNumber]);
    if (result.affectedRows > 0) {
      res.json({ message: "Education entry updated successfully!" });
    } else {
      res.status(404).json({ message: "Education entry not found or unauthorized" });
    }
  } catch (err) {
    console.error("Error updating education:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Route to add an internship
app.post('/api/internships', authenticateToken, async (req, res) => {
  const { registrationNumber, company, role, duration, description } = req.body;
  const sql = "INSERT INTO internships (registration_number, company, role, duration, description) VALUES (?, ?, ?, ?, ?)";
  try {
    await pool.query(sql, [registrationNumber, company, role, duration, description]);
    res.status(201).json({ message: "Internship added successfully!" });
  } catch (err) {
    console.error("Error adding internship:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Route to update an internship
app.put('/api/internships/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { registrationNumber, company, role, duration, description } = req.body;
  const sql = "UPDATE internships SET company = ?, role = ?, duration = ?, description = ? WHERE id = ? AND registration_number = ?";
  try {
    const [result] = await pool.query(sql, [company, role, duration, description, id, registrationNumber]);
    if (result.affectedRows > 0) {
      res.json({ message: "Internship updated successfully!" });
    } else {
      res.status(404).json({ message: "Internship not found or unauthorized" });
    }
  } catch (err) {
    console.error("Error updating internship:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Route to add a project
app.post('/api/projects', authenticateToken, async (req, res) => {
  const { registrationNumber, title, description } = req.body;
  const sql = "INSERT INTO projects (registration_number, title, description) VALUES (?, ?, ?)";
  try {
    await pool.query(sql, [registrationNumber, title, description]);
    res.status(201).json({ message: "Project added successfully!" });
  } catch (err) {
    console.error("Error adding project:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Route to update a project
app.put('/api/projects/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { registrationNumber, title, description } = req.body;
  const sql = "UPDATE projects SET title = ?, description = ? WHERE id = ? AND registration_number = ?";
  try {
    const [result] = await pool.query(sql, [title, description, id, registrationNumber]);
    if (result.affectedRows > 0) {
      res.json({ message: "Project updated successfully!" });
    } else {
      res.status(404).json({ message: "Project not found or unauthorized" });
    }
  } catch (err) {
    console.error("Error updating project:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Route to add a skill
app.post('/api/skills', authenticateToken, async (req, res) => {
  const { registrationNumber, skill_name } = req.body;
  const sql = "INSERT INTO skills (registration_number, skill_name) VALUES (?, ?)";
  try {
    await pool.query(sql, [registrationNumber, skill_name]);
    res.status(201).json({ message: "Skill added successfully!" });
  } catch (err) {
    console.error("Error adding skill:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Route to update a skill
app.put('/api/skills/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { registrationNumber, skill_name } = req.body;
  const sql = "UPDATE skills SET skill_name = ? WHERE id = ? AND registration_number = ?";
  try {
    const [result] = await pool.query(sql, [skill_name, id, registrationNumber]);
    if (result.affectedRows > 0) {
      res.json({ message: "Skill updated successfully!" });
    } else {
      res.status(404).json({ message: "Skill not found or unauthorized" });
    }
  } catch (err) {
    console.error("Error updating skill:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Route to add an achievement
app.post('/api/achievements', authenticateToken, async (req, res) => {
  const { registrationNumber, title, description, year } = req.body;
  const sql = "INSERT INTO achievements (registration_number, title, description, year) VALUES (?, ?, ?, ?)";
  try {
    await pool.query(sql, [registrationNumber, title, description, year]);
    res.status(201).json({ message: "Achievement added successfully!" });
  } catch (err) {
    console.error("Error adding achievement:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Route to update an achievement
app.put('/api/achievements/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { registrationNumber, title, description, year } = req.body;
  const sql = "UPDATE achievements SET title = ?, description = ?, year = ? WHERE id = ? AND registration_number = ?";
  try {
    const [result] = await pool.query(sql, [title, description, year, id, registrationNumber]);
    if (result.affectedRows > 0) {
      res.json({ message: "Achievement updated successfully!" });
    } else {
      res.status(404).json({ message: "Achievement not found or unauthorized" });
    }
  } catch (err) {
    console.error("Error updating achievement:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Route to update user profile
app.put('/api/profile', authenticateToken, upload.single('profile_picture'), async (req, res) => {
  const { bio, graduation_year, department, whatsapp_number } = req.body;
  const { registration_number } = req.user;
  let sql = `UPDATE users2 SET bio = ?, graduation_year = ?, department = ?, whatsapp_number = ? WHERE registration_number = ?`;
  const params = [bio, graduation_year, department, whatsapp_number, registration_number];

  if (req.file) {
    sql = `UPDATE users2 SET profile_picture = ?, bio = ?, graduation_year = ?, department = ?, whatsapp_number = ? WHERE registration_number = ?`;
    params.unshift(req.file.filename);
  }

  try {
    const [result] = await pool.query(sql, params);
    if (result.affectedRows > 0) {
      res.json({ message: "Profile updated successfully!" });
    } else {
      res.status(404).json({ message: "Profile not found" });
    }
  } catch (err) {
    console.error("Error updating profile:", err);
    res.status(500).json({ message: "Database error" });
  }
});

// Route to get all pending alumni
app.get('/api/alumni/pending', async (req, res) => {
  try {
    const sql = "SELECT * FROM users2 WHERE is_verified = 0";
    const [rows] = await pool.query(sql);
    res.json(rows);
  } catch (err) {
    console.error("Error fetching pending alumni:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// Route to verify an alumni
app.post('/api/alumni/verify', async (req, res) => {
  const { id } = req.body;
  try {
    const sql = "UPDATE users2 SET is_verified = 1 WHERE id = ?";
    const [result] = await pool.query(sql, [id]);
    if (result.affectedRows > 0) {
      res.json({ success: true, message: "Alumni verified successfully." });
    } else {
      res.status(404).json({ success: false, message: "Alumni not found." });
    }
  } catch (err) {
    console.error("Error verifying alumni:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// Route to reject an alumni
app.post('/api/alumni/reject', async (req, res) => {
  const { id } = req.body;
  try {
    const sql = "DELETE FROM users2 WHERE id = ?";
    const [result] = await pool.query(sql, [id]);
    if (result.affectedRows > 0) {
      res.json({ success: true, message: "Alumni rejected and deleted successfully." });
    } else {
      res.status(404).json({ success: false, message: "Alumni not found." });
    }
  } catch (err) {
    console.error("Error rejecting alumni:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// Route to send a contact email
app.post('/api/email_contact', async (req, res) => {
  const { name, email, message } = req.body;
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: 'pafiast@alumni.edu.pk',
    subject: `New Contact Form Submission from ${name}`,
    html: `<p><strong>Name:</strong> ${name}</p><p><strong>Email:</strong> ${email}</p><p><strong>Message:</strong><br>${message}</p>`
  };

  try {
    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'Email sent successfully!' });
  } catch (error) {
    console.error("Error sending contact email:", error);
    res.status(500).json({ error: 'Failed to send email' });
  }
});

// Route to submit feedback
app.post('/api/feedback', async (req, res) => {
  const { name, email, message } = req.body;
  const sql = `INSERT INTO feedback (name, email, message) VALUES (?, ?, ?)`;
  try {
    await pool.query(sql, [name, email, message]);
    res.status(201).json({ message: 'Feedback submitted successfully!' });
  } catch (err) {
    console.error("Error submitting feedback:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// Route to view feedback (for admin)
app.get('/api/feedback/view', async (req, res) => {
  try {
    const sql = `SELECT * FROM feedback ORDER BY created_at DESC`;
    const [rows] = await pool.query(sql);
    res.json(rows);
  } catch (err) {
    console.error("Error fetching feedback:", err);
    res.status(500).json({ error: "Database error" });
  }
});


// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
