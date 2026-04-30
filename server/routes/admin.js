const express = require('express');
const { body, param, validationResult } = require('express-validator');
const mongoose = require('mongoose');
const auth = require('../middleware/auth');
const User = require('../models/User');
const Password = require('../models/Password');

const router = express.Router();

/**
 * Shared validation handler
 */
function handleValidation(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation failed',
      code: 'VALIDATION_ERROR',
      details: errors.array()
    });
  }
  next();
}

/**
 * Ensure requester is authenticated and has admin privileges.
 * Fallback to user role stored in DB when JWT payload lacks role info.
 */
async function requireAdmin(req, res, next) {
  try {
    const tokenPayload = req.user || {};
    const requesterId = tokenPayload.userId || tokenPayload.id;

    if (!requesterId) {
      return res.status(401).json({
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }

    const adminUser = await User.findById(requesterId).select('role');
    if (!adminUser || adminUser.role !== 'admin') {
      return res.status(403).json({
        error: 'Admin privileges required',
        code: 'ADMIN_REQUIRED'
      });
    }

    req.adminUser = adminUser;
    next();
  } catch (error) {
    console.error('Admin guard failed', error);
    res.status(500).json({
      error: 'Failed to verify admin privileges',
      code: 'ADMIN_CHECK_FAILED'
    });
  }
}

router.use(auth, requireAdmin);

/**
 * GET /api/admin/users
 * Return a lightweight list of users for the admin panel.
 */
router.get('/users', async (_req, res) => {
  try {
    const users = await User.find({}, 'username email role status lastLogin createdAt');
    res.json(users);
  } catch (error) {
    console.error('Admin list users failed', error);
    res.status(500).json({
      error: 'Failed to load users',
      code: 'ADMIN_USERS_ERROR'
    });
  }
});

/**
 * PUT /api/admin/users/:id/role
 * Update a user's role (user|admin).
 */
router.put(
  '/users/:id/role',
  [
    param('id').custom(mongoose.Types.ObjectId.isValid).withMessage('Invalid user id'),
    body('role').isIn(['user', 'admin']).withMessage('Role must be user or admin')
  ],
  handleValidation,
  async (req, res) => {
    try {
      const updatedUser = await User.findByIdAndUpdate(
        req.params.id,
        { role: req.body.role },
        { new: true, select: 'username email role status lastLogin createdAt' }
      );

      if (!updatedUser) {
        return res.status(404).json({
          error: 'User not found',
          code: 'USER_NOT_FOUND'
        });
      }

      res.json(updatedUser);
    } catch (error) {
      console.error('Admin role update failed', error);
      res.status(500).json({
        error: 'Failed to update role',
        code: 'ADMIN_ROLE_ERROR'
      });
    }
  }
);

/**
 * PUT /api/admin/users/:id/status
 * Update a user's status (active|suspended|banned).
 */
router.put(
  '/users/:id/status',
  [
    param('id').custom(mongoose.Types.ObjectId.isValid).withMessage('Invalid user id'),
    body('status').isIn(['active', 'suspended', 'banned']).withMessage('Invalid status')
  ],
  handleValidation,
  async (req, res) => {
    try {
      const updatedUser = await User.findByIdAndUpdate(
        req.params.id,
        { status: req.body.status },
        { new: true, select: 'username email role status lastLogin createdAt' }
      );

      if (!updatedUser) {
        return res.status(404).json({
          error: 'User not found',
          code: 'USER_NOT_FOUND'
        });
      }

      res.json(updatedUser);
    } catch (error) {
      console.error('Admin status update failed', error);
      res.status(500).json({
        error: 'Failed to update status',
        code: 'ADMIN_STATUS_ERROR'
      });
    }
  }
);

/**
 * DELETE /api/admin/users/:id
 * Remove a user and their stored passwords.
 */
router.delete(
  '/users/:id',
  [param('id').custom(mongoose.Types.ObjectId.isValid).withMessage('Invalid user id')],
  handleValidation,
  async (req, res) => {
    try {
      const targetUser = await User.findById(req.params.id);
      if (!targetUser) {
        return res.status(404).json({
          error: 'User not found',
          code: 'USER_NOT_FOUND'
        });
      }

      if (targetUser.role === 'admin') {
        return res.status(403).json({
          error: 'Cannot delete another admin account',
          code: 'ADMIN_DELETE_FORBIDDEN'
        });
      }

      await Password.deleteMany({ userId: targetUser._id });
      await targetUser.deleteOne();

      res.json({ success: true });
    } catch (error) {
      console.error('Admin delete user failed', error);
      res.status(500).json({
        error: 'Failed to delete user',
        code: 'ADMIN_DELETE_ERROR'
      });
    }
  }
);

/**
 * GET /api/admin/stats
 * Provide summary metrics required by the admin panel.
 */
router.get('/stats', async (_req, res) => {
  try {
    const [totalUsers, totalPasswords, activeUsers] = await Promise.all([
      User.countDocuments(),
      Password.countDocuments(),
      User.countDocuments({ status: 'active' })
    ]);

    res.json({
      totalUsers,
      totalPasswords,
      activeUsers,
      systemHealth: 'healthy'
    });
  } catch (error) {
    console.error('Admin stats failed', error);
    res.status(500).json({
      error: 'Failed to fetch stats',
      code: 'ADMIN_STATS_ERROR'
    });
  }
});

/**
 * GET /api/admin/audit-logs
 * Placeholder endpoint – return empty list until audit storage is implemented.
 */
router.get('/audit-logs', async (_req, res) => {
  res.json([]);
});

module.exports = router;

