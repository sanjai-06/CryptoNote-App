/**
 * CryptoNote Server with Working Authentication
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const winston = require('winston');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const nodemailer = require('nodemailer');

const app = express();

// Email configuration
const emailTransporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: process.env.SMTP_PORT || 587,
  secure: false, // true for 465, false for other ports
  auth: {
    user: process.env.SMTP_USER || 'your-email@gmail.com',
    pass: process.env.SMTP_PASS || 'your-app-password'
  }
});

async function sendPasswordActivityEmail(user, action, details = {}) {
  try {
    if (!user?.email) return;
    const wantsEmail = user.emailNotifications !== false;
    const wantsSecurityAlerts = user.securityAlerts !== false;
    if (!wantsEmail || !wantsSecurityAlerts) return;

    const actionText = action === 'created' ? 'added to' : 'updated in';
    const subject = action === 'created'
      ? '🔐 CryptoNote - New Vault Entry Added'
      : '🛡️ CryptoNote - Vault Entry Updated';

    const mailOptions = {
      from: process.env.SMTP_FROM || '"CryptoNote Security" <security@cryptonote.com>',
      to: user.email,
      subject,
      html: `
        <!DOCTYPE html>
        <html>
          <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #111;">
            <div style="max-width:600px;margin:0 auto;padding:24px;background:#f9fafb;border-radius:12px;">
              <h2 style="margin-top:0;color:#0f172a;">Vault entry ${action === 'created' ? 'added' : 'updated'}</h2>
              <p>Hello <strong>${user.username || 'CryptoNote user'}</strong>,</p>
              <p>A password entry was ${actionText} your CryptoNote vault.</p>
              <ul style="padding-left:20px;">
                ${details.website ? `<li><strong>Entry:</strong> ${details.website}</li>` : ''}
                <li><strong>Time:</strong> ${new Date().toLocaleString()}</li>
              </ul>
              <p>If this was you, no action is needed. If you didn’t perform this action, please sign in and review your vault immediately.</p>
              <p style="margin-top:32px;font-size:14px;color:#475569;">This notification was sent because security alerts are enabled for your account.</p>
            </div>
          </body>
        </html>
      `
    };

    const info = await emailTransporter.sendMail(mailOptions);
    logger.info('Password activity email sent', { to: user.email, action, messageId: info.messageId });
  } catch (error) {
    logger.warn('Password activity email failed', { error: error.message });
  }
}

// Admin Routes
// List users
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await User.find({}, 'username email role status lastLogin createdAt');
    res.json(users);
  } catch (error) {
    logger.error('Admin list users error:', error);
    res.status(500).json({ message: 'Failed to list users' });
  }
});

// Update user role
app.put('/api/admin/users/:id/role', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { role } = req.body;
    if (!['user', 'admin'].includes(role)) {
      return res.status(400).json({ message: 'Invalid role' });
    }
    const updated = await User.findByIdAndUpdate(
      req.params.id,
      { role },
      { new: true, select: 'username email role status lastLogin createdAt' }
    );
    if (!updated) return res.status(404).json({ message: 'User not found' });
    res.json(updated);
  } catch (error) {
    logger.error('Admin update role error:', error);
    res.status(500).json({ message: 'Failed to update role' });
  }
});

// Update user status
app.put('/api/admin/users/:id/status', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    if (!['active', 'suspended', 'banned'].includes(status)) {
      return res.status(400).json({ message: 'Invalid status' });
    }
    const updated = await User.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true, select: 'username email role status lastLogin createdAt' }
    );
    if (!updated) return res.status(404).json({ message: 'User not found' });
    res.json(updated);
  } catch (error) {
    logger.error('Admin update status error:', error);
    res.status(500).json({ message: 'Failed to update status' });
  }
});

// Delete user (and their passwords)
app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    // Validate ObjectId
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: 'Invalid user id' });
    }

    // Prevent deleting yourself
    if (id === req.user.userId) {
      return res.status(400).json({ message: 'You cannot delete your own account' });
    }

    const user = await User.findById(id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Prevent deleting other admins (policy)
    if (user.role === 'admin') {
      return res.status(403).json({ message: 'Cannot delete an admin account' });
    }

    await User.deleteOne({ _id: id });
    await Password.deleteMany({ userId: id });
    res.json({ message: 'User deleted' });
  } catch (error) {
    logger.error('Admin delete user error:', { error: error.message, userId: req.params.id });
    res.status(500).json({ message: 'Failed to delete user' });
  }
});

// System stats
app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [totalUsers, totalPasswords, activeUsers] = await Promise.all([
      User.countDocuments(),
      Password.countDocuments(),
      User.countDocuments({ status: 'active' })
    ]);
    res.json({ totalUsers, totalPasswords, activeUsers, systemHealth: 'healthy', storageUsed: 'n/a', lastBackup: 'n/a' });
  } catch (error) {
    logger.error('Admin stats error:', error);
    res.status(500).json({ message: 'Failed to fetch stats' });
  }
});

// Audit logs placeholder
app.get('/api/admin/audit-logs', authenticateToken, requireAdmin, async (req, res) => {
  // No audit storage yet; return empty list for now
  res.json([]);
});

// Middleware: Require 2FA for normal users on protected resources
async function requireTwoFactorEnabled(req, res, next) {
  try {
    if (!req.user) return res.status(401).json({ message: 'Unauthorized' });
    const user = await User.findById(req.user.userId).select('role twoFactorEnabled');
    if (!user) return res.status(401).json({ message: 'Unauthorized' });
    if (user.role === 'user' && !user.twoFactorEnabled) {
      return res.status(403).json({
        message: 'Two-factor authentication required. Please enable 2FA to continue.',
        code: 'TWO_FACTOR_REQUIRED'
      });
    }
    next();
  } catch (err) {
    return res.status(500).json({ message: 'Internal server error' });
  }
}

// Middleware: Admin-only access
function requireAdmin(req, res, next) {
  try {
    if (!req.user) return res.status(401).json({ message: 'Unauthorized' });
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Admin access required' });
    }
    next();
  } catch (err) {
    return res.status(500).json({ message: 'Internal server error' });
  }
}

// Email templates
const get2FASetupEmailTemplate = (username, qrCodeDataUrl, secret, backupCodes) => {
  return {
    subject: '🔐 CryptoNote - Two-Factor Authentication Setup',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>2FA Setup - CryptoNote</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
          .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }
          .qr-section { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; text-align: center; border: 2px solid #e9ecef; }
          .backup-codes { background: #fff3cd; border: 1px solid #ffeaa7; padding: 20px; border-radius: 8px; margin: 20px 0; }
          .code-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin: 15px 0; }
          .backup-code { background: #fff; padding: 10px; border-radius: 4px; font-family: monospace; font-weight: bold; text-align: center; border: 1px solid #ddd; }
          .warning { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 15px; border-radius: 8px; margin: 20px 0; }
          .steps { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; }
          .step { margin: 15px 0; padding: 10px; border-left: 4px solid #667eea; }
          .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
        </style>
      </head>
      <body>
        <div class="header">
          <h1>🔐 Two-Factor Authentication Setup</h1>
          <p>Secure your CryptoNote account with 2FA</p>
        </div>
        
        <div class="content">
          <p>Hello <strong>${username}</strong>,</p>
          
          <p>You've successfully enabled Two-Factor Authentication for your CryptoNote account. This adds an extra layer of security to protect your password vault.</p>
          
          <div class="qr-section">
            <h3>📱 Step 1: Scan QR Code</h3>
            <p>Use your authenticator app to scan this QR code:</p>
            <img src="${qrCodeDataUrl}" alt="2FA QR Code" style="max-width: 200px; height: auto;">
            <p><small>Recommended apps: Google Authenticator, Authy, Microsoft Authenticator</small></p>
          </div>
          
          <div class="steps">
            <h3>📋 Setup Instructions</h3>
            <div class="step">
              <strong>1.</strong> Download an authenticator app (Google Authenticator, Authy, etc.)
            </div>
            <div class="step">
              <strong>2.</strong> Open the app and scan the QR code above
            </div>
            <div class="step">
              <strong>3.</strong> If you can't scan, manually enter this secret key:<br>
              <code style="background: #f8f9fa; padding: 5px; border-radius: 3px; font-family: monospace;">${secret}</code>
            </div>
            <div class="step">
              <strong>4.</strong> Enter the 6-digit code from your app to complete setup
            </div>
          </div>
          
          <div class="backup-codes">
            <h3>🔑 Backup Recovery Codes</h3>
            <p><strong>Important:</strong> Save these backup codes in a secure location. Each code can only be used once.</p>
            <div class="code-grid">
              ${backupCodes.map(code => `<div class="backup-code">${code}</div>`).join('')}
            </div>
            <p><small>Use these codes if you lose access to your authenticator app.</small></p>
          </div>
          
          <div class="warning">
            <h4>⚠️ Security Notice</h4>
            <ul>
              <li>Keep your backup codes secure and private</li>
              <li>Each backup code can only be used once</li>
              <li>Don't share your QR code or secret key with anyone</li>
              <li>If you lose your authenticator device, use a backup code to login</li>
            </ul>
          </div>
          
          <p>If you didn't request this setup or have any concerns, please contact our support team immediately.</p>
        </div>
        
        <div class="footer">
          <p>This email was sent from CryptoNote Security System</p>
          <p>© ${new Date().getFullYear()} CryptoNote - Secure Password Manager</p>
        </div>
      </body>
      </html>
    `
  };
};

// Send 2FA setup email
async function send2FASetupEmail(userEmail, username, qrCodeDataUrl, secret, backupCodes) {
  try {
    const emailTemplate = get2FASetupEmailTemplate(username, qrCodeDataUrl, secret, backupCodes);
    
    const mailOptions = {
      from: `"CryptoNote Security" <${process.env.SMTP_USER || 'noreply@cryptonote.com'}>`,
      to: userEmail,
      subject: emailTemplate.subject,
      html: emailTemplate.html
    };

    // For development, we'll log the email instead of sending
    if (process.env.NODE_ENV === 'development') {
      logger.info('2FA Setup Email (Development Mode)', {
        to: userEmail,
        subject: emailTemplate.subject,
        qrCodeIncluded: !!qrCodeDataUrl,
        backupCodesCount: backupCodes.length
      });
      
      // Save email content to file for testing
      const fs = require('fs');
      const emailContent = `
        To: ${userEmail}
        Subject: ${emailTemplate.subject}
        
        ${emailTemplate.html}
      `;
      
      fs.writeFileSync(`2fa-email-${Date.now()}.html`, emailTemplate.html);
      logger.info('2FA email saved to file for testing');
      
      return { success: true, message: 'Email logged (development mode)' };
    }

    // Send actual email in production
    const info = await emailTransporter.sendMail(mailOptions);
    logger.info('2FA setup email sent successfully', { 
      to: userEmail, 
      messageId: info.messageId 
    });
    
    return { success: true, messageId: info.messageId };
    
  } catch (error) {
    logger.error('Failed to send 2FA setup email', { 
      error: error.message, 
      userEmail 
    });
    return { success: false, error: error.message };
  }
}

// Initialize logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.simple()
  ),
  transports: [
    new winston.transports.Console()
  ]
});

// Basic security headers
app.use(helmet());

// CORS
app.use(cors({
  origin: ['http://localhost:5173', 'http://localhost:5174'],
  credentials: true
}));

// Body parsing
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  status: { type: String, enum: ['active', 'suspended', 'banned'], default: 'active' },
  firstName: { type: String, default: '' },
  lastName: { type: String, default: '' },
  avatar: { type: String, default: '' },
  emailNotifications: { type: Boolean, default: true },
  securityAlerts: { type: Boolean, default: true },
  theme: { type: String, enum: ['dark', 'light', 'auto'], default: 'dark' },
  twoFactorSecret: { type: String },
  twoFactorEnabled: { type: Boolean, default: false },
  backupCodes: [{ type: String }],
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date }
});

const User = mongoose.model('User', userSchema);

// Password Schema
const passwordSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  website: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true }, // In real app, this would be encrypted
  category: { type: String, default: 'Personal' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const Password = mongoose.model('Password', passwordSchema);

// Category Schema
const categorySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name: { type: String, required: true },
  icon: { type: String, default: '📁' },
  color: { type: String, default: '#6B7280' },
  createdAt: { type: Date, default: Date.now }
});

const Category = mongoose.model('Category', categorySchema);

// JWT Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(
    token,
    process.env.JWT_SECRET || 'dev_jwt_secret_32chars_min',
    (err, user) => {
      if (err) {
        return res.status(403).json({ message: 'Invalid or expired token' });
      }
      req.user = user;
      next();
    }
  );
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '2.0.0',
    environment: process.env.NODE_ENV || 'development',
    features: ['authentication', 'password-management', 'categories']
  });
});

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    if (password.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });

    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const user = new User({
      username,
      email,
      password: hashedPassword
    });

    await user.save();

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'dev_jwt_secret_32chars_min',
      { expiresIn: '24h' }
    );

    logger.info('User registered successfully', { username, email });

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    logger.error('Registration error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Check if 2FA is enabled
    logger.info('Checking 2FA status', { 
      username: user.username, 
      role: user.role,
      twoFactorEnabled: user.twoFactorEnabled,
      hasSecret: !!user.twoFactorSecret 
    });

    // If policy requires 2FA for normal users and it's not enabled yet, force setup flow
    if (user.role === 'user' && !user.twoFactorEnabled) {
      const tempToken = jwt.sign(
        { userId: user._id, step: '2fa_setup_pending' },
        process.env.JWT_SECRET || 'dev_jwt_secret_32chars_min',
        { expiresIn: '15m' }
      );

      return res.json({
        message: 'Two-factor authentication setup required',
        requires2FASetup: true,
        tempToken
      });
    }

    if (user.twoFactorEnabled) {
      // Generate temporary token for 2FA verification
      const tempToken = jwt.sign(
        { userId: user._id, step: '2fa_pending' },
        process.env.JWT_SECRET || 'dev_jwt_secret_32chars_min',
        { expiresIn: '10m' }
      );

      logger.info('2FA required for user', { username: user.username });

      return res.json({
        message: '2FA verification required',
        requires2FA: true,
        tempToken
      });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'dev_jwt_secret_32chars_min',
      { expiresIn: '24h' }
    );

    logger.info('User logged in successfully', { username: user.username, email });

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        twoFactorEnabled: user.twoFactorEnabled
      }
    });

  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.json({ message: 'Logout successful' });
});

// Current user basic info
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('username email role twoFactorEnabled firstName lastName');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(user);
  } catch (error) {
    logger.error('Auth me error:', error);
    res.status(500).json({ message: 'Failed to fetch current user' });
  }
});

// User Profile Routes (no 2FA gate so users can set up 2FA from profile)
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select(
      'username email firstName lastName avatar twoFactorEnabled emailNotifications securityAlerts theme'
    );
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(user);
  } catch (error) {
    logger.error('Get profile error:', error);
    res.status(500).json({ message: 'Failed to fetch profile' });
  }
});

app.put('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const allowed = ['username', 'email', 'firstName', 'lastName', 'avatar', 'emailNotifications', 'securityAlerts', 'theme'];
    const update = {};
    for (const k of allowed) if (k in req.body) update[k] = req.body[k];

    // Basic validation
    if (update.username) update.username = String(update.username).trim();
    if (update.email) update.email = String(update.email).trim().toLowerCase();

    // Uniqueness checks
    if (update.username) {
      const exists = await User.findOne({ _id: { $ne: req.user.userId }, username: update.username });
      if (exists) return res.status(400).json({ message: 'Username already in use' });
    }
    if (update.email) {
      const exists = await User.findOne({ _id: { $ne: req.user.userId }, email: update.email });
      if (exists) return res.status(400).json({ message: 'Email already in use' });
    }

    const user = await User.findByIdAndUpdate(
      req.user.userId,
      update,
      { new: true, select: 'username email firstName lastName avatar twoFactorEnabled emailNotifications securityAlerts theme' }
    );
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(user);
  } catch (error) {
    logger.error('Update profile error:', error);
    res.status(500).json({ message: 'Failed to update profile' });
  }
});

app.get('/api/user/stats', authenticateToken, async (req, res) => {
  try {
    const [totalPasswords, categoriesUsed, user] = await Promise.all([
      Password.countDocuments({ userId: req.user.userId }),
      Category.countDocuments({ userId: req.user.userId }),
      User.findById(req.user.userId).select('createdAt lastLogin')
    ]);

    res.json({
      totalPasswords,
      categoriesUsed,
      lastLogin: user?.lastLogin || null,
      accountCreated: user?.createdAt || null,
      loginHistory: [] // Placeholder – can be backed by audit logs later
    });
  } catch (error) {
    logger.error('Get user stats error:', error);
    res.status(500).json({ message: 'Failed to fetch stats' });
  }
});

app.delete('/api/user/account', authenticateToken, async (req, res) => {
  try {
    await Password.deleteMany({ userId: req.user.userId });
    await Category.deleteMany({ userId: req.user.userId });
    await User.findByIdAndDelete(req.user.userId);
    res.json({ message: 'Account deleted' });
  } catch (error) {
    logger.error('Delete account error:', error);
    res.status(500).json({ message: 'Failed to delete account' });
  }
});

// 2FA Routes
app.post('/api/auth/generate-2fa', async (req, res) => {
  try {
    const { email, tempToken } = req.body;

    // Verify temp token if provided
    if (tempToken) {
      try {
        jwt.verify(tempToken, process.env.JWT_SECRET || 'dev_jwt_secret_32chars_min');
      } catch (err) {
        return res.status(401).json({ message: 'Invalid or expired token' });
      }
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `CryptoNote (${user.email})`,
      issuer: 'CryptoNote',
      length: 32
    });

    // Generate QR code
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

    // Store secret temporarily (in production, encrypt this)
    user.twoFactorSecret = secret.base32;
    await user.save();

    res.json({
      secret: secret.base32,
      qrCode: qrCodeUrl,
      manualEntryKey: secret.base32
    });

  } catch (error) {
    logger.error('Generate 2FA error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/auth/verify-2fa', async (req, res) => {
  try {
    const { email, code, tempToken, setup } = req.body;

    if (!email || !code) {
      return res.status(400).json({ message: 'Email and code are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (!user.twoFactorSecret) {
      return res.status(400).json({ message: '2FA not set up for this user' });
    }

    // Verify the TOTP code
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: code,
      window: 2 // Allow 2 time steps before/after current time
    });

    if (!verified) {
      return res.status(400).json({ message: 'Invalid verification code' });
    }

    if (setup) {
      // Enable 2FA and generate backup codes
      const backupCodes = [];
      for (let i = 0; i < 8; i++) {
        backupCodes.push(Math.random().toString(36).substring(2, 10));
      }

      user.twoFactorEnabled = true;
      user.backupCodes = backupCodes;
      await user.save();

      logger.info('2FA enabled for user', { username: user.username, email });

      // Send 2FA setup email with QR code and backup codes
      try {
        // Get the QR code data URL from the previous generate-2fa call
        const secret = user.twoFactorSecret;
        const qrCodeUrl = await QRCode.toDataURL(`otpauth://totp/CryptoNote%20(${user.email})?secret=${secret}&issuer=CryptoNote`);
        
        const emailResult = await send2FASetupEmail(
          user.email,
          user.username,
          qrCodeUrl,
          secret,
          backupCodes
        );

        if (emailResult.success) {
          logger.info('2FA setup email sent successfully', { username: user.username });
        } else {
          logger.warn('Failed to send 2FA setup email', { username: user.username, error: emailResult.error });
        }
      } catch (emailError) {
        logger.error('Error sending 2FA setup email', { error: emailError.message });
      }

      return res.json({
        message: '2FA enabled successfully',
        backupCodes,
        emailSent: true
      });
    }

    // Verify temp token for login
    if (tempToken) {
      try {
        const decoded = jwt.verify(tempToken, process.env.JWT_SECRET || 'dev_jwt_secret_32chars_min');
        if (decoded.userId !== user._id.toString() || decoded.step !== '2fa_pending') {
          return res.status(401).json({ message: 'Invalid token' });
        }
      } catch (err) {
        return res.status(401).json({ message: 'Invalid or expired token' });
      }
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate final JWT token
    const token = jwt.sign(
      { userId: user._id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'dev_jwt_secret_32chars_min',
      { expiresIn: '24h' }
    );

    logger.info('User logged in with 2FA', { username: user.username, email });

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        twoFactorEnabled: user.twoFactorEnabled
      }
    });

  } catch (error) {
    logger.error('Verify 2FA error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/auth/check-2fa', async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      enabled: user.twoFactorEnabled || false
    });

  } catch (error) {
    logger.error('Check 2FA error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/auth/verify-backup-code', async (req, res) => {
  try {
    const { email, backupCode, tempToken } = req.body;

    if (!email || !backupCode) {
      return res.status(400).json({ message: 'Email and backup code are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Verify temp token
    if (tempToken) {
      try {
        const decoded = jwt.verify(tempToken, process.env.JWT_SECRET || 'dev_jwt_secret_32chars_min');
        if (decoded.userId !== user._id.toString() || decoded.step !== '2fa_pending') {
          return res.status(401).json({ message: 'Invalid token' });
        }
      } catch (err) {
        return res.status(401).json({ message: 'Invalid or expired token' });
      }
    }

    // Check if backup code exists
    const codeIndex = user.backupCodes.indexOf(backupCode);
    if (codeIndex === -1) {
      return res.status(400).json({ message: 'Invalid backup code' });
    }

    // Remove used backup code
    user.backupCodes.splice(codeIndex, 1);
    user.lastLogin = new Date();
    await user.save();

    // Generate final JWT token
    const token = jwt.sign(
      { userId: user._id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'dev_jwt_secret_32chars_min',
      { expiresIn: '24h' }
    );

    logger.info('User logged in with backup code', { username: user.username, email });

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        twoFactorEnabled: user.twoFactorEnabled
      }
    });

  } catch (error) {
    logger.error('Verify backup code error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/auth/send-2fa-email', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (!user.twoFactorEnabled || !user.twoFactorSecret) {
      return res.status(400).json({ message: '2FA is not enabled for this user' });
    }

    // Generate QR code
    const qrCodeUrl = await QRCode.toDataURL(`otpauth://totp/CryptoNote%20(${user.email})?secret=${user.twoFactorSecret}&issuer=CryptoNote`);
    
    // Send email
    const emailResult = await send2FASetupEmail(
      user.email,
      user.username,
      qrCodeUrl,
      user.twoFactorSecret,
      user.backupCodes
    );

    if (emailResult.success) {
      logger.info('2FA setup email resent successfully', { username: user.username });
      res.json({ 
        message: '2FA setup email sent successfully',
        emailSent: true
      });
    } else {
      res.status(500).json({ 
        message: 'Failed to send email',
        error: emailResult.error
      });
    }

  } catch (error) {
    logger.error('Send 2FA email error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/auth/disable-2fa', authenticateToken, async (req, res) => {
  try {
    const { code } = req.body;

    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (!user.twoFactorEnabled) {
      return res.status(400).json({ message: '2FA is not enabled' });
    }

    // Verify current TOTP code
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: code,
      window: 2
    });

    if (!verified) {
      return res.status(400).json({ message: 'Invalid verification code' });
    }

    // Disable 2FA
    user.twoFactorEnabled = false;
    user.twoFactorSecret = undefined;
    user.backupCodes = [];
    await user.save();

    logger.info('2FA disabled for user', { username: user.username });

    res.json({ message: '2FA disabled successfully' });

  } catch (error) {
    logger.error('Disable 2FA error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Password Routes
app.get('/api/passwords', authenticateToken, requireTwoFactorEnabled, async (req, res) => {
  try {
    const passwords = await Password.find({ userId: req.user.userId });
    res.json(passwords);
  } catch (error) {
    logger.error('Get passwords error:', error);
    res.status(500).json({ message: 'Failed to fetch passwords' });
  }
});

app.post('/api/passwords', authenticateToken, requireTwoFactorEnabled, async (req, res) => {
  try {
    const { website, username, password, category } = req.body;

    if (!website || !username || !password) {
      return res.status(400).json({ message: 'Website, username, and password are required' });
    }

    const newPassword = new Password({
      userId: req.user.userId,
      website,
      username,
      password, // In production, encrypt this
      category: category || 'Personal'
    });

    await newPassword.save();
    try {
      const user = await User.findById(req.user.userId).select('email username emailNotifications securityAlerts');
      await sendPasswordActivityEmail(user, 'created', { website });
    } catch (emailError) {
      logger.warn('Password create email failed', { error: emailError.message });
    }
    res.status(201).json(newPassword);

  } catch (error) {
    logger.error('Create password error:', error);
    res.status(500).json({ message: 'Failed to create password' });
  }
});

app.put('/api/passwords/:id', authenticateToken, requireTwoFactorEnabled, async (req, res) => {
  try {
    const { website, username, password, category } = req.body;
    
    const updatedPassword = await Password.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.userId },
      { website, username, password, category, updatedAt: new Date() },
      { new: true }
    );

    if (!updatedPassword) {
      return res.status(404).json({ message: 'Password not found' });
    }

    try {
      const user = await User.findById(req.user.userId).select('email username emailNotifications securityAlerts');
      await sendPasswordActivityEmail(user, 'updated', { website });
    } catch (emailError) {
      logger.warn('Password update email failed', { error: emailError.message });
    }

    res.json(updatedPassword);

  } catch (error) {
    logger.error('Update password error:', error);
    res.status(500).json({ message: 'Failed to update password' });
  }
});

app.delete('/api/passwords/:id', authenticateToken, requireTwoFactorEnabled, async (req, res) => {
  try {
    const deletedPassword = await Password.findOneAndDelete({
      _id: req.params.id,
      userId: req.user.userId
    });

    if (!deletedPassword) {
      return res.status(404).json({ message: 'Password not found' });
    }

    res.json({ message: 'Password deleted successfully' });

  } catch (error) {
    logger.error('Delete password error:', error);
    res.status(500).json({ message: 'Failed to delete password' });
  }
});

// Category Routes
app.get('/api/categories', authenticateToken, requireTwoFactorEnabled, async (req, res) => {
  try {
    const categories = await Category.find({ userId: req.user.userId });
    res.json(categories);
  } catch (error) {
    logger.error('Get categories error:', error);
    res.status(500).json({ message: 'Failed to fetch categories' });
  }
});

app.post('/api/categories', authenticateToken, requireTwoFactorEnabled, async (req, res) => {
  try {
    const { name, icon, color } = req.body;

    if (!name) {
      return res.status(400).json({ message: 'Category name is required' });
    }

    const newCategory = new Category({
      userId: req.user.userId,
      name,
      icon: icon || '📁',
      color: color || '#6B7280'
    });

    await newCategory.save();
    res.status(201).json(newCategory);

  } catch (error) {
    logger.error('Create category error:', error);
    res.status(500).json({ message: 'Failed to create category' });
  }
});

// Basic API test
app.get('/api/test', (req, res) => {
  res.json({ message: 'CryptoNote API with Authentication is running!' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Route not found',
    code: 'NOT_FOUND'
  });
});

// Error handler
app.use((error, req, res, next) => {
  logger.error('Server error:', error.message);
  
  res.status(error.status || 500).json({
    error: 'Internal server error',
    code: 'SERVER_ERROR'
  });
});

// Create default admin user
async function createDefaultAdmin() {
  try {
    const adminExists = await User.findOne({ email: 'admin@cryptonote.com' });
    
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('Admin@123456', 12);
      
      // Generate 2FA secret for admin
      const secret = speakeasy.generateSecret({
        name: 'CryptoNote (admin@cryptonote.com)',
        issuer: 'CryptoNote',
        length: 32
      });

      const adminUser = new User({
        username: 'admin',
        email: 'admin@cryptonote.com',
        password: hashedPassword,
        role: 'admin',
        twoFactorSecret: secret.base32,
        twoFactorEnabled: true,
        backupCodes: ['backup123', 'backup456', 'backup789'] // Demo backup codes
      });
      
      await adminUser.save();
      logger.info('Default admin user created successfully');
      logger.info('Admin credentials: admin@cryptonote.com / Admin@123456');
    }
  } catch (error) {
    logger.error('Error creating default admin:', error);
  }
}

// Start server
async function startServer() {
  try {
    // Connect to MongoDB
    if (process.env.MONGO_URI) {
      await mongoose.connect(process.env.MONGO_URI);
      logger.info('MongoDB connected successfully');
    } else {
      logger.warn('MONGO_URI not provided, using default connection');
      await mongoose.connect('mongodb://127.0.0.1:27017/cryptonote');
      logger.info('MongoDB connected to default database');
    }

    // Create default admin user
    await createDefaultAdmin();

    const PORT = process.env.PORT || 3001;
    app.listen(PORT, () => {
      logger.info(`🔐 CryptoNote Server (Auth) running on port ${PORT}`);
      logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
      logger.info(`Health check: http://localhost:${PORT}/health`);
      logger.info(`Features: Authentication, Password Management, Categories`);
    });

  } catch (error) {
    logger.error('Server startup failed:', error);
    process.exit(1);
  }
}

startServer();
  