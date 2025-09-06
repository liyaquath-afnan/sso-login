const express = require('express');
const router = express.Router();

const userService = require('../services/userService');
const { authenticateToken, authorizeRoles } = require('../middleware/auth');
const { validateRequest, userUpdateSchema } = require('../utils/validation');

/**
 * GET /api/users
 * Get all users (admin only)
 */
router.get('/', authenticateToken, authorizeRoles(['admin']), async (req, res) => {
  try {
    const users = await userService.getAllUsers();
    
    res.status(200).json({
      message: 'Users retrieved successfully',
      users,
      count: users.length
    });
    
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({
      error: 'Failed to Get Users',
      message: 'An error occurred while fetching users'
    });
  }
});

/**
 * GET /api/users/stats
 * Get user statistics (admin only)
 */
router.get('/stats', authenticateToken, authorizeRoles(['admin']), async (req, res) => {
  try {
    const stats = await userService.getUserStats();
    
    res.status(200).json({
      message: 'User statistics retrieved successfully',
      stats
    });
    
  } catch (error) {
    console.error('Get user stats error:', error);
    res.status(500).json({
      error: 'Failed to Get Statistics',
      message: 'An error occurred while fetching user statistics'
    });
  }
});

/**
 * GET /api/users/:userId
 * Get specific user by ID (admin only or own profile)
 */
router.get('/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    const requestingUser = req.user;
    
    // Check if user is admin or requesting their own profile
    if (requestingUser.role !== 'admin' && requestingUser.userId !== userId) {
      return res.status(403).json({
        error: 'Access Forbidden',
        message: 'You can only access your own profile'
      });
    }
    
    const user = await userService.findById(userId);
    
    if (!user) {
      return res.status(404).json({
        error: 'User Not Found',
        message: 'User with the specified ID not found'
      });
    }
    
    res.status(200).json({
      message: 'User retrieved successfully',
      user: userService.sanitizeUser(user)
    });
    
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      error: 'Failed to Get User',
      message: 'An error occurred while fetching user'
    });
  }
});

/**
 * PUT /api/users/:userId
 * Update user (admin only)
 */
router.put('/:userId', authenticateToken, authorizeRoles(['admin']), validateRequest(userUpdateSchema), async (req, res) => {
  try {
    const { userId } = req.params;
    const updateData = req.validatedData;
    
    // Prevent admin from deactivating themselves
    if (userId === req.user.userId && updateData.isActive === false) {
      return res.status(400).json({
        error: 'Invalid Operation',
        message: 'You cannot deactivate your own account'
      });
    }
    
    const updatedUser = await userService.updateUser(userId, updateData);
    
    res.status(200).json({
      message: 'User updated successfully',
      user: updatedUser
    });
    
  } catch (error) {
    console.error('Update user error:', error);
    
    if (error.message === 'User not found') {
      return res.status(404).json({
        error: 'User Not Found',
        message: 'User with the specified ID not found'
      });
    }
    
    res.status(500).json({
      error: 'Failed to Update User',
      message: 'An error occurred while updating user'
    });
  }
});

/**
 * DELETE /api/users/:userId
 * Delete user (admin only)
 */
router.delete('/:userId', authenticateToken, authorizeRoles(['admin']), async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Prevent admin from deleting themselves
    if (userId === req.user.userId) {
      return res.status(400).json({
        error: 'Invalid Operation',
        message: 'You cannot delete your own account'
      });
    }
    
    await userService.deleteUser(userId);
    
    res.status(200).json({
      message: 'User deleted successfully'
    });
    
  } catch (error) {
    console.error('Delete user error:', error);
    
    if (error.message === 'User not found') {
      return res.status(404).json({
        error: 'User Not Found',
        message: 'User with the specified ID not found'
      });
    }
    
    res.status(500).json({
      error: 'Failed to Delete User',
      message: 'An error occurred while deleting user'
    });
  }
});

/**
 * POST /api/users/:userId/revoke-tokens
 * Revoke all refresh tokens for a user (admin only)
 */
router.post('/:userId/revoke-tokens', authenticateToken, authorizeRoles(['admin']), async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Check if user exists
    const user = await userService.findById(userId);
    if (!user) {
      return res.status(404).json({
        error: 'User Not Found',
        message: 'User with the specified ID not found'
      });
    }
    
    // Revoke all refresh tokens
    await userService.revokeAllRefreshTokens(userId);
    
    res.status(200).json({
      message: 'All refresh tokens revoked successfully',
      user: {
        id: user.id,
        email: user.email
      }
    });
    
  } catch (error) {
    console.error('Revoke tokens error:', error);
    res.status(500).json({
      error: 'Failed to Revoke Tokens',
      message: 'An error occurred while revoking tokens'
    });
  }
});

/**
 * GET /api/users/search/:email
 * Search user by email (admin only)
 */
router.get('/search/:email', authenticateToken, authorizeRoles(['admin']), async (req, res) => {
  try {
    const { email } = req.params;
    
    const user = await userService.findByEmail(email);
    
    if (!user) {
      return res.status(404).json({
        error: 'User Not Found',
        message: 'User with the specified email not found'
      });
    }
    
    res.status(200).json({
      message: 'User found',
      user: userService.sanitizeUser(user)
    });
    
  } catch (error) {
    console.error('Search user error:', error);
    res.status(500).json({
      error: 'Search Failed',
      message: 'An error occurred while searching for user'
    });
  }
});

module.exports = router;
