const jwtService = require('../utils/jwt');

/**
 * Middleware to authenticate JWT tokens
 */
const authenticateToken = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = jwtService.extractTokenFromHeader(authHeader);
    
    if (!token) {
      return res.status(401).json({
        error: 'Access Denied',
        message: 'No token provided'
      });
    }
    
    const decoded = jwtService.verifyToken(token);
    
    // Check if it's an access token
    if (decoded.type !== 'access') {
      return res.status(401).json({
        error: 'Invalid Token Type',
        message: 'Access token required'
      });
    }
    
    // Attach user info to request
    req.user = {
      userId: decoded.userId,
      email: decoded.email,
      role: decoded.role,
      permissions: decoded.permissions,
      jti: decoded.jti
    };
    
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Token Expired',
        message: 'Access token has expired'
      });
    }
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        error: 'Invalid Token',
        message: 'Invalid access token'
      });
    }
    
    return res.status(500).json({
      error: 'Authentication Error',
      message: 'Failed to authenticate token'
    });
  }
};

/**
 * Middleware to authenticate refresh tokens
 */
const authenticateRefreshToken = (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(401).json({
        error: 'Access Denied',
        message: 'Refresh token required'
      });
    }
    
    const decoded = jwtService.verifyToken(refreshToken);
    
    // Check if it's a refresh token
    if (decoded.type !== 'refresh') {
      return res.status(401).json({
        error: 'Invalid Token Type',
        message: 'Refresh token required'
      });
    }
    
    // Attach user info to request
    req.user = {
      userId: decoded.userId,
      email: decoded.email,
      jti: decoded.jti
    };
    
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Refresh Token Expired',
        message: 'Refresh token has expired, please login again'
      });
    }
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        error: 'Invalid Refresh Token',
        message: 'Invalid refresh token'
      });
    }
    
    return res.status(500).json({
      error: 'Authentication Error',
      message: 'Failed to authenticate refresh token'
    });
  }
};

/**
 * Middleware to check user roles
 * @param {Array} allowedRoles - Array of allowed roles
 */
const authorizeRoles = (allowedRoles = []) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Authentication Required',
        message: 'User not authenticated'
      });
    }
    
    if (allowedRoles.length === 0) {
      return next(); // No role restriction
    }
    
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: 'Access Forbidden',
        message: 'Insufficient permissions'
      });
    }
    
    next();
  };
};

/**
 * Middleware to check user permissions
 * @param {Array} requiredPermissions - Array of required permissions
 */
const authorizePermissions = (requiredPermissions = []) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Authentication Required',
        message: 'User not authenticated'
      });
    }
    
    if (requiredPermissions.length === 0) {
      return next(); // No permission restriction
    }
    
    const userPermissions = req.user.permissions || [];
    const hasPermission = requiredPermissions.every(permission => 
      userPermissions.includes(permission)
    );
    
    if (!hasPermission) {
      return res.status(403).json({
        error: 'Access Forbidden',
        message: 'Required permissions not found'
      });
    }
    
    next();
  };
};

/**
 * Optional authentication middleware - doesn't fail if no token
 */
const optionalAuth = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = jwtService.extractTokenFromHeader(authHeader);
    
    if (token) {
      const decoded = jwtService.verifyToken(token);
      
      if (decoded.type === 'access') {
        req.user = {
          userId: decoded.userId,
          email: decoded.email,
          role: decoded.role,
          permissions: decoded.permissions,
          jti: decoded.jti
        };
      }
    }
    
    next();
  } catch (error) {
    // Continue without authentication
    next();
  }
};

module.exports = {
  authenticateToken,
  authenticateRefreshToken,
  authorizeRoles,
  authorizePermissions,
  optionalAuth
};
