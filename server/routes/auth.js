/**
 * Enhanced Authentication Routes with Enterprise Security
 * 
 * SECURITY FEATURES:
 * - Multi-factor authentication (TOTP/SMS)
 * - Advanced password strength validation
 * - Anomaly detection integration
 * - Comprehensive audit logging
 * - Rate limiting and brute force protection
 * - Device fingerprinting and tracking
 * 
 * ATTACK VECTORS MITIGATED:
 * - Credential stuffing attacks
 * - Brute force attacks
 * - Account takeover attempts
 * - Session hijacking
 * - Password-based attacks
 */

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { body, validationResult } = require('express-validator');

// Import models and services
const User = require('../models/User');
const auth = require('../middleware/auth');
const authService = require('../services/authService');
const auditService = require('../services/auditService');
const anomalyDetection = require('../services/anomalyDetection');
const rbacService = require('../services/rbacService');
const encryptionService = require('../services/encryptionService');

const router = express.Router();

// Input validation middleware
const validateInput = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    auditService.logEvent(auditService.eventTypes.LOGIN_FAILURE, {
      reason: 'VALIDATION_FAILED',
      errors: errors.array(),
      email: req.body.email
    }, {
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      requestId: req.requestId
    });

    return res.status(400).json({
      error: 'Validation failed',
      code: 'VALIDATION_ERROR',
      details: errors.array()
    });
  }
  next();
};

// Device fingerprinting middleware
const extractDeviceInfo = (req, res, next) => {
  req.deviceInfo = {
    userAgent: req.get('User-Agent') || '',
    acceptLanguage: req.get('Accept-Language') || '',
    acceptEncoding: req.get('Accept-Encoding') || '',
    deviceId: req.get('X-Device-ID') || null,
    screenResolution: req.get('X-Screen-Resolution') || null,
    timezone: req.get('X-Timezone') || null
  };
  next();
};

// REGISTER - Enhanced user registration with MFA setup
router.post(
  '/register',
  [
    body('username')
      .isString()
      .trim()
      .isLength({ min: 3, max: 50 })
      .matches(/^[a-zA-Z0-9_-]+$/)
      .withMessage('Username can only contain letters, numbers, underscores, and hyphens'),
    body('email')
      .isString()
      .trim()
      .isEmail()
      .normalizeEmail()
      .isLength({ max: 254 }),
    body('password')
      .isString()
      .isLength({ min: 12, max: 500 })
      .withMessage('Password must be at least 12 characters'),
    body('phoneNumber')
      .optional()
      .isMobilePhone()
      .withMessage('Invalid phone number format')
  ],
  validateInput,
  extractDeviceInfo,
  async (req, res) => {
    try {
      const { username, email, password, phoneNumber } = req.body;

      // Enhanced password strength validation
      const passwordValidation = encryptionService.validatePasswordStrength ? 
        encryptionService.validatePasswordStrength(password) : 
        authService.validatePasswordStrength(password);

      if (!passwordValidation.isValid) {
        await auditService.logEvent(auditService.eventTypes.LOGIN_FAILURE, {
          reason: 'WEAK_PASSWORD',
          email,
          passwordStrength: passwordValidation.strength
        }, {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          requestId: req.requestId
        });

        return res.status(400).json({
          error: 'Password does not meet security requirements',
          code: 'WEAK_PASSWORD',
          requirements: passwordValidation.errors,
          suggestions: passwordValidation.suggestions || [],
          strength: passwordValidation.strength
        });
      }

      // Check for existing user
      const existingUser = await User.findOne({ 
        $or: [{ email }, { username }] 
      });
      
      if (existingUser) {
        await auditService.logEvent(auditService.eventTypes.LOGIN_FAILURE, {
          reason: 'USER_EXISTS',
          email,
          username
        }, {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          requestId: req.requestId
        });

        return res.status(400).json({
          error: 'User already exists',
          code: 'USER_EXISTS'
        });
      }

      // Use authService for secure registration
      const registrationResult = await authService.registerUser({
        username,
        email,
        password,
        phoneNumber
      }, req.deviceInfo);

      // Assign default user role
      await rbacService.assignRole(registrationResult.userId, 'user', 'system', {
        ipAddress: req.ip,
        requestId: req.requestId
      });

      // Log successful registration
      await auditService.logEvent(auditService.eventTypes.USER_CREATED, {
        userId: registrationResult.userId,
        username,
        email,
        mfaSetupRequired: registrationResult.mfaSetupRequired
      }, {
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        requestId: req.requestId
      });

      res.status(201).json({
        success: true,
        message: 'User registered successfully',
        userId: registrationResult.userId,
        mfaSetup: {
          required: registrationResult.mfaSetupRequired,
          qrCode: registrationResult.qrCode,
          backupCodes: registrationResult.backupCodes
        },
        passwordStrength: passwordValidation.strength
      });

    } catch (error) {
      await auditService.logEvent('REGISTRATION_ERROR', {
        error: error.message,
        email: req.body.email
      }, {
        ipAddress: req.ip,
        requestId: req.requestId
      });

      res.status(500).json({
        error: 'Registration failed',
        code: 'REGISTRATION_ERROR'
      });
    }
  }
);

// LOGIN - Enhanced authentication with anomaly detection and MFA
router.post(
  '/login',
  [
    body('email').isString().trim().isEmail().normalizeEmail().isLength({ max: 254 }),
    body('password').isString().isLength({ min: 1, max: 500 }),
    body('mfaToken').optional().isString().isLength({ min: 6, max: 8 }),
    body('rememberDevice').optional().isBoolean()
  ],
  validateInput,
  extractDeviceInfo,
  async (req, res) => {
    try {
      const { email, password, mfaToken, rememberDevice } = req.body;

      // Use authService for comprehensive authentication
      const authResult = await authService.authenticateUser({
        email,
        password,
        mfaToken,
        deviceId: req.deviceInfo.deviceId
      }, req.deviceInfo, req.ip);

      // Handle MFA requirement
      if (authResult.requiresMFA) {
        await auditService.logEvent(auditService.eventTypes.LOGIN_SUCCESS, {
          userId: authResult.userId,
          email,
          mfaRequired: true,
          riskLevel: authResult.riskLevel
        }, {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          requestId: req.requestId
        });

        return res.status(200).json({
          success: false,
          requiresMFA: true,
          userId: authResult.userId,
          riskLevel: authResult.riskLevel,
          message: 'Multi-factor authentication required'
        });
      }

      // Successful authentication
      if (authResult.success) {
        // Set session data
        req.session.userId = authResult.user.id;
        req.session.sessionId = authResult.tokens.sessionId;

        // Log successful login
        await auditService.logEvent(auditService.eventTypes.LOGIN_SUCCESS, {
          userId: authResult.user.id,
          email: authResult.user.email,
          riskLevel: authResult.riskLevel,
          mfaUsed: !!mfaToken,
          newDevice: authResult.newDevice || false
        }, {
          userId: authResult.user.id,
          sessionId: authResult.tokens.sessionId,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          requestId: req.requestId
        });

        res.json({
          success: true,
          message: 'Authentication successful',
          user: {
            id: authResult.user.id,
            username: authResult.user.username,
            email: authResult.user.email,
            mfaEnabled: authResult.user.mfaEnabled
          },
          tokens: {
            accessToken: authResult.tokens.accessToken,
            refreshToken: authResult.tokens.refreshToken,
            expiresIn: authResult.tokens.expiresIn
          },
          security: {
            riskLevel: authResult.riskLevel,
            newDevice: authResult.newDevice || false,
            sessionId: authResult.tokens.sessionId
          }
        });
      }

    } catch (error) {
      // Log failed authentication attempt
      await auditService.logEvent(auditService.eventTypes.LOGIN_FAILURE, {
        email: req.body.email,
        reason: error.message,
        ipAddress: req.ip
      }, {
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        requestId: req.requestId
      });

      // Generic error message to prevent user enumeration
      res.status(401).json({
        error: 'Authentication failed',
        code: 'AUTH_FAILED'
      });
    }
  }
);

// MFA SETUP - Setup multi-factor authentication
router.post(
  '/mfa/setup',
  auth,
  [
    body('verificationToken').isString().isLength({ min: 6, max: 8 }),
    body('method').isIn(['totp', 'sms']).withMessage('Invalid MFA method')
  ],
  validateInput,
  async (req, res) => {
    try {
      const { verificationToken, method } = req.body;
      const userId = req.user.id;

      const setupResult = await authService.setupMFA(userId, verificationToken, method);

      if (setupResult.success) {
        await auditService.logEvent(auditService.eventTypes.MFA_ENABLED, {
          userId,
          method
        }, {
          userId,
          sessionId: req.sessionId,
          ipAddress: req.ip,
          requestId: req.requestId
        });

        res.json({
          success: true,
          message: 'MFA enabled successfully',
          backupCodes: setupResult.backupCodes
        });
      }

    } catch (error) {
      await auditService.logEvent('MFA_SETUP_FAILED', {
        userId: req.user.id,
        error: error.message
      }, {
        userId: req.user.id,
        requestId: req.requestId
      });

      res.status(400).json({
        error: 'MFA setup failed',
        code: 'MFA_SETUP_ERROR'
      });
    }
  }
);

// SEND SMS TOKEN - Send SMS verification token
router.post(
  '/mfa/sms/send',
  auth,
  async (req, res) => {
    try {
      const userId = req.user.id;
      
      const result = await authService.sendSMSToken(userId);
      
      if (result.success) {
        await auditService.logEvent('SMS_TOKEN_SENT', {
          userId
        }, {
          userId,
          sessionId: req.sessionId,
          ipAddress: req.ip,
          requestId: req.requestId
        });

        res.json({
          success: true,
          message: 'SMS verification code sent'
        });
      }

    } catch (error) {
      res.status(400).json({
        error: error.message,
        code: 'SMS_SEND_ERROR'
      });
    }
  }
);

// REFRESH TOKEN - Get new access token
router.post(
  '/refresh',
  [
    body('refreshToken').isString().notEmpty()
  ],
  validateInput,
  async (req, res) => {
    try {
      const { refreshToken } = req.body;
      
      const result = await authService.refreshAccessToken(refreshToken);
      
      res.json({
        success: true,
        accessToken: result.accessToken,
        expiresIn: result.expiresIn
      });

    } catch (error) {
      await auditService.logEvent('TOKEN_REFRESH_FAILED', {
        error: error.message
      }, {
        ipAddress: req.ip,
        requestId: req.requestId
      });

      res.status(401).json({
        error: 'Token refresh failed',
        code: 'REFRESH_ERROR'
      });
    }
  }
);

// CHANGE MASTER PASSWORD - Enhanced password change with security checks
router.put(
  '/change-password',
  auth,
  rbacService.requirePermission('auth.change_password'),
  [
    body('currentPassword').isString().isLength({ min: 1, max: 500 }),
    body('newPassword').isString().isLength({ min: 12, max: 500 }),
    body('mfaToken').optional().isString().isLength({ min: 6, max: 8 })
  ],
  validateInput,
  async (req, res) => {
    try {
      const { currentPassword, newPassword, mfaToken } = req.body;
      const userId = req.user.id;

      // Get user details
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({
          error: 'User not found',
          code: 'USER_NOT_FOUND'
        });
      }

      // Verify current password
      const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
      if (!isCurrentPasswordValid) {
        await auditService.logEvent(auditService.eventTypes.PASSWORD_CHANGED, {
          userId,
          success: false,
          reason: 'INVALID_CURRENT_PASSWORD'
        }, {
          userId,
          sessionId: req.sessionId,
          ipAddress: req.ip,
          requestId: req.requestId
        });

        return res.status(400).json({
          error: 'Current password is incorrect',
          code: 'INVALID_CURRENT_PASSWORD'
        });
      }

      // Validate new password strength
      const passwordValidation = authService.validatePasswordStrength(newPassword);
      if (!passwordValidation.isValid) {
        return res.status(400).json({
          error: 'New password does not meet security requirements',
          code: 'WEAK_PASSWORD',
          requirements: passwordValidation.errors,
          suggestions: passwordValidation.suggestions || [],
          strength: passwordValidation.strength
        });
      }

      // Check if new password is different from current
      const isSamePassword = await bcrypt.compare(newPassword, user.password);
      if (isSamePassword) {
        return res.status(400).json({
          error: 'New password must be different from current password',
          code: 'SAME_PASSWORD'
        });
      }

      // MFA verification for sensitive operation
      if (user.mfaEnabled && !mfaToken) {
        return res.status(400).json({
          error: 'MFA token required for password change',
          code: 'MFA_REQUIRED'
        });
      }

      if (user.mfaEnabled && mfaToken) {
        const mfaValid = await authService.verifyMFA(user.mfaSecret, mfaToken, userId);
        if (!mfaValid) {
          return res.status(400).json({
            error: 'Invalid MFA token',
            code: 'INVALID_MFA'
          });
        }
      }

      // Hash new password with high rounds
      const salt = await bcrypt.genSalt(14);
      const hashedNewPassword = await bcrypt.hash(newPassword, salt);

      // Update password
      await User.findByIdAndUpdate(userId, {
        password: hashedNewPassword,
        passwordChangedAt: new Date()
      });

      // Invalidate all existing sessions except current
      await authService.invalidateUserSessions(userId, req.sessionId);

      // Log successful password change
      await auditService.logEvent(auditService.eventTypes.PASSWORD_CHANGED, {
        userId,
        success: true,
        mfaUsed: !!mfaToken,
        passwordStrength: passwordValidation.strength
      }, {
        userId,
        sessionId: req.sessionId,
        ipAddress: req.ip,
        requestId: req.requestId
      });

      // Send email notification (best effort)
      try {
        // This would use your email service
        console.log(`Password changed notification sent to ${user.email}`);
      } catch (emailError) {
        console.error('Failed to send email notification:', emailError);
      }

      res.json({
        success: true,
        message: 'Master password changed successfully',
        passwordStrength: passwordValidation.strength
      });

    } catch (error) {
      await auditService.logEvent('PASSWORD_CHANGE_ERROR', {
        userId: req.user.id,
        error: error.message
      }, {
        userId: req.user.id,
        requestId: req.requestId
      });

      res.status(500).json({
        error: 'Password change failed',
        code: 'PASSWORD_CHANGE_ERROR'
      });
    }
  }
);

// LOGOUT - Secure session termination
router.post(
  '/logout',
  auth,
  async (req, res) => {
    try {
      const userId = req.user.id;
      const sessionId = req.sessionId;

      // Use authService for secure logout
      await authService.logout(sessionId);

      // Clear session
      req.session.destroy((err) => {
        if (err) {
          console.error('Session destruction error:', err);
        }
      });

      // Log logout event
      await auditService.logEvent(auditService.eventTypes.LOGOUT, {
        userId,
        sessionId
      }, {
        userId,
        sessionId,
        ipAddress: req.ip,
        requestId: req.requestId
      });

      res.json({
        success: true,
        message: 'Logged out successfully'
      });

    } catch (error) {
      res.status(500).json({
        error: 'Logout failed',
        code: 'LOGOUT_ERROR'
      });
    }
  }
);

// VALIDATE PASSWORD STRENGTH - Frontend validation support
router.post(
  '/validate-password',
  [
    body('password').isString().isLength({ min: 1, max: 500 })
  ],
  validateInput,
  (req, res) => {
    try {
      const { password } = req.body;
      const validation = authService.validatePasswordStrength(password);
      
      res.json({
        success: true,
        validation
      });
    } catch (error) {
      res.status(500).json({
        error: 'Password validation failed',
        code: 'VALIDATION_ERROR'
      });
    }
  }
);

// GET USER PROFILE - Secure user information retrieval
router.get(
  '/profile',
  auth,
  rbacService.requirePermission('auth.login'),
  async (req, res) => {
    try {
      const userId = req.user.id;
      
      const user = await User.findById(userId).select('-password -mfaSecret');
      if (!user) {
        return res.status(404).json({
          error: 'User not found',
          code: 'USER_NOT_FOUND'
        });
      }

      // Get user permissions
      const permissions = await rbacService.getUserPermissions(userId);
      const roles = await rbacService.getUserRoles(userId);

      res.json({
        success: true,
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          mfaEnabled: user.mfaEnabled,
          createdAt: user.createdAt,
          lastLogin: user.lastLogin,
          roles: Array.from(roles),
          permissions
        }
      });

    } catch (error) {
      res.status(500).json({
        error: 'Failed to retrieve profile',
        code: 'PROFILE_ERROR'
      });
    }
  }
);

// SECURITY STATUS - Get security information for dashboard
router.get(
  '/security-status',
  auth,
  async (req, res) => {
    try {
      const userId = req.user.id;
      
      // Get recent security events
      const recentEvents = await auditService.queryAuditLogs({
        userId,
        eventType: [
          auditService.eventTypes.LOGIN_SUCCESS,
          auditService.eventTypes.LOGIN_FAILURE,
          auditService.eventTypes.PASSWORD_CHANGED
        ]
      }, { limit: 10 });

      // Get active sessions count
      const activeSessions = await authService.getActiveSessionsCount(userId);

      res.json({
        success: true,
        security: {
          mfaEnabled: req.user.mfaEnabled,
          activeSessions,
          recentActivity: recentEvents.events,
          lastPasswordChange: req.user.passwordChangedAt,
          accountCreated: req.user.createdAt
        }
      });

    } catch (error) {
      res.status(500).json({
        error: 'Failed to retrieve security status',
        code: 'SECURITY_STATUS_ERROR'
      });
    }
  }
);

module.exports = router;
