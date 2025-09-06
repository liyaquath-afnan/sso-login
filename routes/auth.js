const express = require('express');
const router = express.Router();

const userService = require('../services/userService');
const jwtService = require('../utils/jwt');
const { authenticateRefreshToken } = require('../middleware/auth');
const { validateRequest, loginSchema, registerSchema, refreshTokenSchema } = require('../utils/validation');

/**
 * POST /api/auth/login
 * Authenticate user and return JWT tokens
 */
router.post('/login', validateRequest(loginSchema), async (req, res) => {
  try {
    const { email, password } = req.validatedData;
    
    // Authenticate user
    const user = await userService.authenticateUser(email, password);
    
    if (!user) {
      return res.status(401).json({
        error: 'Authentication Failed',
        message: 'Invalid email or password'
      });
    }
    
    // Generate token pair
    const tokens = jwtService.generateTokenPair(user);
    
    // Store refresh token
    const refreshDecoded = jwtService.decodeToken(tokens.refreshToken);
    await userService.storeRefreshToken(user.id, refreshDecoded.jti, tokens.refreshToken);
    
    // Update last login
    await userService.updateLastLogin(user.id);
    
    res.status(200).json({
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        permissions: user.permissions,
        lastLogin: user.lastLogin
      },
      tokens
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      error: 'Login Failed',
      message: 'An error occurred during login'
    });
  }
});

/**
 * POST /api/auth/register
 * Register new user (admin only in production)
 */
router.post('/register', validateRequest(registerSchema), async (req, res) => {
  try {
    const userData = req.validatedData;
    
    // Create new user
    const user = await userService.createUser(userData);
    
    res.status(201).json({
      message: 'User registered successfully',
      user
    });
    
  } catch (error) {
    console.error('Registration error:', error);
    
    if (error.message === 'User already exists') {
      return res.status(409).json({
        error: 'Registration Failed',
        message: 'User with this email already exists'
      });
    }
    
    res.status(500).json({
      error: 'Registration Failed',
      message: 'An error occurred during registration'
    });
  }
});

/**
 * POST /api/auth/refresh
 * Refresh access token using refresh token
 */
router.post('/refresh', validateRequest(refreshTokenSchema), authenticateRefreshToken, async (req, res) => {
  try {
    const { userId, jti } = req.user;
    
    // Validate refresh token exists in storage
    const isValidToken = await userService.validateRefreshToken(userId, jti);
    
    if (!isValidToken) {
      return res.status(401).json({
        error: 'Invalid Refresh Token',
        message: 'Refresh token not found or has been revoked'
      });
    }
    
    // Get user details
    const user = await userService.findById(userId);
    
    if (!user || !user.active) {
      return res.status(401).json({
        error: 'User Not Found',
        message: 'User account not found or inactive'
      });
    }
    
    // Generate new token pair
    const tokens = jwtService.generateTokenPair(user);
    
    // Revoke old refresh token and store new one
    await userService.revokeRefreshToken(userId, jti);
    const newRefreshDecoded = jwtService.decodeToken(tokens.refreshToken);
    await userService.storeRefreshToken(userId, newRefreshDecoded.jti, tokens.refreshToken);
    
    res.status(200).json({
      message: 'Tokens refreshed successfully',
      tokens
    });
    
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({
      error: 'Token Refresh Failed',
      message: 'An error occurred while refreshing tokens'
    });
  }
});

/**
 * POST /api/auth/logout
 * Logout user and revoke refresh token
 */
router.post('/logout', validateRequest(refreshTokenSchema), authenticateRefreshToken, async (req, res) => {
  try {
    const { userId, jti } = req.user;
    
    // Revoke the refresh token
    await userService.revokeRefreshToken(userId, jti);
    
    res.status(200).json({
      message: 'Logout successful'
    });
    
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      error: 'Logout Failed',
      message: 'An error occurred during logout'
    });
  }
});

/**
 * POST /api/auth/logout-all
 * Logout user from all devices (revoke all refresh tokens)
 */
router.post('/logout-all', validateRequest(refreshTokenSchema), authenticateRefreshToken, async (req, res) => {
  try {
    const { userId } = req.user;
    
    // Revoke all refresh tokens for the user
    await userService.revokeAllRefreshTokens(userId);
    
    res.status(200).json({
      message: 'Logged out from all devices successfully'
    });
    
  } catch (error) {
    console.error('Logout all error:', error);
    res.status(500).json({
      error: 'Logout Failed',
      message: 'An error occurred during logout'
    });
  }
});

/**
 * GET /api/auth/me
 * Get current user information (requires valid access token)
 */
router.get('/me', require('../middleware/auth').authenticateToken, async (req, res) => {
  try {
    const { userId } = req.user;
    
    const user = await userService.findById(userId);
    
    if (!user) {
      return res.status(404).json({
        error: 'User Not Found',
        message: 'User account not found'
      });
    }
    
    res.status(200).json({
      user: userService.sanitizeUser(user)
    });
    
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      error: 'Failed to Get User',
      message: 'An error occurred while fetching user information'
    });
  }
});

/**
 * GET /api/auth/validate
 * Validate access token (for other services to verify tokens)
 */
router.get('/validate', require('../middleware/auth').authenticateToken, async (req, res) => {
  try {
    const { userId, email, role, permissions, jti } = req.user;
    
    // Verify user still exists and is active
    const user = await userService.findById(userId);
    
    if (!user || !user.active) {
      return res.status(401).json({
        error: 'Invalid Token',
        message: 'User account not found or inactive'
      });
    }
    
    res.status(200).json({
      valid: true,
      user: {
        userId,
        email,
        role,
        permissions,
        jti
      }
    });
    
  } catch (error) {
    console.error('Token validation error:', error);
    res.status(500).json({
      error: 'Validation Failed',
      message: 'An error occurred while validating token'
    });
  }
});

module.exports = router;
