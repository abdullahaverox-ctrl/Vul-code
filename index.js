const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { exec } = require("child_process");
require("dotenv").config();

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Hardcoded secrets
const ADMIN_USER = "admin";
const ADMIN_PASSWORD = "password123";
const JWT_SECRET = "hardcoded_jwt_secret_123";
const API_TOKEN = "ghp_fakegithubtoken123456789";
const STRIPE_SECRET = "sk_live_fake_secret_key_123456";

// Static page
app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

// Vulnerability 1: SQL Injection style vulnerable query construction
app.get("/search", (req, res) => {
  const username = req.query.username;

  const query = "SELECT * FROM users WHERE username = '" + username + "'";

  res.send({
    message: "This endpoint builds SQL unsafely.",
    vulnerableQuery: query
  });
});

// Vulnerability 2: OS Command Injection
app.get("/ping", (req, res) => {
  const host = req.query.host;

  exec("ping -c 1 " + host, (error, stdout, stderr) => {
    if (error) {
      return res.send({
        error: error.message,
        stderr: stderr
      });
    }

    res.send({
      output: stdout
    });
  });
});

// Vulnerability 3: Reflected XSS
app.get("/xss", (req, res) => {
  const message = req.query.message;

  res.send("<h1>User Message</h1><p>" + message + "</p>");
});

// Vulnerability 4: Weak MD5 hashing
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const hashedPassword = crypto
    .createHash("md5")
    .update(password)
    .digest("hex");

  if (username === ADMIN_USER && password === ADMIN_PASSWORD) {
    const token = jwt.sign(
      { username: username, role: "admin" },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.send({
      message: "Login successful",
      token: token,
      weakHash: hashedPassword
    });
  }

  res.status(401).send({
    message: "Invalid username or password",
    weakHash: hashedPassword
  });
});

// Vulnerability 5: Sensitive debug information exposure
app.get("/debug", (req, res) => {
  res.send({
    environment: process.env,
    adminUser: ADMIN_USER,
    adminPassword: ADMIN_PASSWORD,
    jwtSecret: JWT_SECRET,
    apiToken: API_TOKEN,
    stripeSecret: STRIPE_SECRET
  });
});

// Vulnerability 6: Insecure direct object reference style endpoint
app.get("/user/:id", (req, res) => {
  const userId = req.params.id;

  res.send({
    message: "No authorization check is performed here.",
    requestedUserId: userId,
    sensitiveData: {
      email: "victim@example.com",
      salary: "500000",
      nationalId: "12345-1234567-1"
    }
  });
});

// Vulnerability 7: Mass assignment
app.post("/profile/update", (req, res) => {
  const userProfile = req.body;

  res.send({
    message: "Profile updated without field validation.",
    updatedProfile: userProfile
  });
});

// Vulnerability 8: SSRF style unsafe URL fetch
app.get("/fetch", async (req, res) => {
  const axios = require("axios");
  const targetUrl = req.query.url;

  try {
    const response = await axios.get(targetUrl);
    res.send({
      fetchedFrom: targetUrl,
      data: response.data
    });
  } catch (error) {
    res.status(500).send({
      error: error.message
    });
  }
});

const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log("Vulnerable app running on port " + port);
});