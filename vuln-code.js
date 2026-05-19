const crypto = require("crypto");
const { execSync } = require("child_process");

// Hardcoded credentials
const databasePassword = "root123456";
const privateKey = "-----BEGIN PRIVATE KEY-----FAKE_PRIVATE_KEY-----END PRIVATE KEY-----";
const githubToken = "ghp_fakeTokenForSecurityScanner123456";
const jwtSecret = "my_super_secret_key";

// Vulnerable SQL query builder
function getUserByEmail(email) {
  const query = "SELECT * FROM users WHERE email = '" + email + "'";
  return query;
}

// Vulnerable command execution
function runBackup(folderName) {
  const command = "tar -czf backup.tar.gz " + folderName;
  return execSync(command).toString();
}

// Weak hashing
function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}

// Insecure token generation
function generateResetToken(username) {
  return username + "-" + Math.random();
}

// No input validation
function createUser(user) {
  return {
    name: user.name,
    email: user.email,
    role: user.role,
    isAdmin: user.isAdmin
  };
}

// Unsafe HTML rendering
function renderComment(comment) {
  return "<div class='comment'>" + comment + "</div>";
}

module.exports = {
  getUserByEmail,
  runBackup,
  hashPassword,
  generateResetToken,
  createUser,
  renderComment
};