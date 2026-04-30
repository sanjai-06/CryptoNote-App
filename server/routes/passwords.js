const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { body, param, validationResult } = require('express-validator');
const auth = require('../middleware/auth');
const Password = require('../models/Password');
const User = require('../models/User');
const { sendPasswordChangeNotification } = require('../services/emailService');

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '';
const IV_LENGTH = 12; // AES-GCM recommended 12 bytes

function ensureKey() {
  const len = Buffer.from(ENCRYPTION_KEY).length;
  if (len !== 32) {
    throw new Error('Invalid ENCRYPTION_KEY length. Expected 32 bytes for AES-256.');
  }
}

// New format: ivHex:tagHex:cipherHex (AES-256-GCM)
function encrypt(text) {
  ensureKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY), iv);
  const enc = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('hex')}:${tag.toString('hex')}:${enc.toString('hex')}`;
}

function decrypt(text) {
  try {
    if (!text.includes(':')) {
      return text;
    }
    const parts = text.split(':');

    if (parts.length === 2) {
      // Backward compatibility: legacy AES-256-CBC format ivHex:cipherHex
      ensureKey();
      const [ivHex, cipherHex] = parts;
      const iv = Buffer.from(ivHex, 'hex');
      const encryptedTextBuffer = Buffer.from(cipherHex, 'hex');
      const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
      const dec = Buffer.concat([decipher.update(encryptedTextBuffer), decipher.final()]);
      return dec.toString('utf8');
    }

    if (parts.length === 3) {
      // AES-GCM format
      ensureKey();
      const [ivHex, tagHex, cipherHex] = parts;
      const iv = Buffer.from(ivHex, 'hex');
      const tag = Buffer.from(tagHex, 'hex');
      const encryptedTextBuffer = Buffer.from(cipherHex, 'hex');
      const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY), iv);
      decipher.setAuthTag(tag);
      const dec = Buffer.concat([decipher.update(encryptedTextBuffer), decipher.final()]);
      return dec.toString('utf8');
    }

    // Unknown format, return as-is
    return text;
  } catch (error) {
    // Do not log secrets; return masked value
    return text;
  }
}

// Validation middleware
const handleValidation = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
  }
  next();
};

// POST /api/passwords
router.post(
  '/',
  auth,
  [
    body('website').isString().trim().isLength({ min: 1, max: 200 }),
    body('username').isString().trim().isLength({ min: 1, max: 200 }),
    body('password').isString().isLength({ min: 1, max: 5000 }),
    body('category').optional().isString().trim().isLength({ min: 1, max: 100 }),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const { website, username, password, category } = req.body;
      const encryptedPassword = encrypt(password);

      const newPassword = new Password({
        userId: req.user.id,
        website,
        username,
        password: encryptedPassword,
        category: category || 'Personal'
      });

      const savedPassword = await newPassword.save();

      // Send email notification (best-effort)
      try {
        const user = await User.findById(req.user.id);
        if (user) {
          await sendPasswordChangeNotification(user.email, user.username, 'created');
        }
      } catch (_) {}

      // Return stored doc (without decrypting on server ideally)
      res.json({ ...savedPassword._doc, password: decrypt(savedPassword.password) });
    } catch (err) {
      res.status(500).json({ message: 'Server Error', error: err.message });
    }
  }
);

// GET /api/passwords
router.get('/', auth, async (req, res) => {
  try {
    const passwords = await Password.find({ userId: req.user.id });
    const decryptedPasswords = passwords.map(p => ({
      ...p._doc,
      password: decrypt(p.password)
    }));
    res.json(decryptedPasswords);
  } catch (err) {
    res.status(500).json({ message: 'Server Error', error: err.message });
  }
});

// PUT /api/passwords/:id
router.put(
  '/:id',
  auth,
  [
    param('id').isString().isLength({ min: 1 }),
    body('website').isString().trim().isLength({ min: 1, max: 200 }),
    body('username').isString().trim().isLength({ min: 1, max: 200 }),
    body('password').isString().isLength({ min: 1, max: 5000 }),
    body('category').optional().isString().trim().isLength({ min: 1, max: 100 }),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const { website, username, password, category } = req.body;
      const encryptedPassword = encrypt(password);
      const updated = await Password.findOneAndUpdate(
        { _id: req.params.id, userId: req.user.id },
        { website, username, password: encryptedPassword, category: category || 'Personal' },
        { new: true }
      );

      // Send email notification (best-effort)
      try {
        const user = await User.findById(req.user.id);
        if (user) {
          await sendPasswordChangeNotification(user.email, user.username, 'updated');
        }
      } catch (_) {}

      res.json({ ...updated._doc, password: decrypt(updated.password) });
    } catch (err) {
      res.status(500).json({ message: 'Server Error', error: err.message });
    }
  }
);

// DELETE /api/passwords/:id
router.delete(
  '/:id',
  auth,
  [param('id').isString().isLength({ min: 1 })],
  handleValidation,
  async (req, res) => {
    try {
      await Password.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
      res.json({ message: 'Deleted successfully' });
    } catch (err) {
      res.status(500).json({ message: 'Server Error', error: err.message });
    }
  }
);

module.exports = router;
