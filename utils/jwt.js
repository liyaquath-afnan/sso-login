const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

class JWTService {
  constructor() {
    this.secret = process.env.JWT_SECRET;
    this.expiresIn = process.env.JWT_EXPIRES_IN || '1h';
    this.refreshExpiresIn = process.env.JWT_REFRESH_EXPIRES_IN || '7d';
    
    if (!this.secret) {
      throw new Error('JWT_SECRET environment variable is required');
    }
  }

  /**
   * Generate access token
   * @param {Object} payload - User data to encode
   * @returns {string} JWT token
   */
  generateAccessToken(payload) {
    const tokenPayload = {
      ...payload,
      type: 'access',
      jti: uuidv4(), // JWT ID for token tracking
      iat: Math.floor(Date.now() / 1000)
    };
    
    return jwt.sign(tokenPayload, this.secret, {
      expiresIn: this.expiresIn,
      issuer: 'sso-service',
      audience: 'sso-clients'
    });
  }

  /**
   * Generate refresh token
   * @param {Object} payload - User data to encode
   * @returns {string} JWT refresh token
   */
  generateRefreshToken(payload) {
    const tokenPayload = {
      userId: payload.userId,
      email: payload.email,
      type: 'refresh',
      jti: uuidv4(),
      iat: Math.floor(Date.now() / 1000)
    };
    
    return jwt.sign(tokenPayload, this.secret, {
      expiresIn: this.refreshExpiresIn,
      issuer: 'sso-service',
      audience: 'sso-clients'
    });
  }

  /**
   * Generate both access and refresh tokens
   * @param {Object} user - User object
   * @returns {Object} Token pair
   */
  generateTokenPair(user) {
    const payload = {
      userId: user.id,
      email: user.email,
      role: user.role || 'user',
      permissions: user.permissions || []
    };

    return {
      accessToken: this.generateAccessToken(payload),
      refreshToken: this.generateRefreshToken(payload),
      expiresIn: this.expiresIn,
      tokenType: 'Bearer'
    };
  }

  /**
   * Verify and decode JWT token
   * @param {string} token - JWT token to verify
   * @returns {Object} Decoded token payload
   */
  verifyToken(token) {
    try {
      return jwt.verify(token, this.secret, {
        issuer: 'sso-service',
        audience: 'sso-clients'
      });
    } catch (error) {
      throw error;
    }
  }

  /**
   * Decode token without verification (for expired tokens)
   * @param {string} token - JWT token to decode
   * @returns {Object} Decoded token payload
   */
  decodeToken(token) {
    return jwt.decode(token);
  }

  /**
   * Check if token is expired
   * @param {string} token - JWT token to check
   * @returns {boolean} True if expired
   */
  isTokenExpired(token) {
    try {
      const decoded = this.decodeToken(token);
      if (!decoded || !decoded.exp) return true;
      
      const currentTime = Math.floor(Date.now() / 1000);
      return decoded.exp < currentTime;
    } catch (error) {
      return true;
    }
  }

  /**
   * Extract token from Authorization header
   * @param {string} authHeader - Authorization header value
   * @returns {string|null} Extracted token
   */
  extractTokenFromHeader(authHeader) {
    if (!authHeader) return null;
    
    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') return null;
    
    return parts[1];
  }
}

module.exports = new JWTService();
