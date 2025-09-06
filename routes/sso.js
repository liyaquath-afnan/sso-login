const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');

const userService = require('../services/userService');
const jwtService = require('../utils/jwt');
const { authenticateToken, optionalAuth } = require('../middleware/auth');
const { validateRequest, ssoTokenSchema } = require('../utils/validation');

// In-memory storage for SSO sessions (use Redis in production)
const ssoSessions = new Map();
const ssoClients = new Map();

// Initialize some demo SSO clients
ssoClients.set('demo-app-1', {
  id: 'demo-app-1',
  name: 'Demo Application 1',
  redirectUri: 'http://localhost:3001/auth/callback',
  secret: 'demo-secret-1',
  isActive: true
});

ssoClients.set('demo-app-2', {
  id: 'demo-app-2',
  name: 'Demo Application 2',
  redirectUri: 'http://localhost:3002/auth/callback',
  secret: 'demo-secret-2',
  isActive: true
});

/**
 * GET /api/sso/authorize
 * SSO Authorization endpoint - redirects to login if not authenticated
 */
router.get('/authorize', optionalAuth, async (req, res) => {
  try {
    const { client_id, redirect_uri, state, response_type = 'code' } = req.query;
    
    // Validate required parameters
    if (!client_id || !redirect_uri) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing required parameters: client_id, redirect_uri'
      });
    }
    
    // Validate client
    const client = ssoClients.get(client_id);
    if (!client || !client.isActive) {
      return res.status(400).json({
        error: 'invalid_client',
        error_description: 'Invalid or inactive client'
      });
    }
    
    // Validate redirect URI
    if (client.redirectUri !== redirect_uri) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Invalid redirect URI'
      });
    }
    
    // Check if user is already authenticated
    if (req.user) {
      // User is authenticated, generate authorization code
      const authCode = uuidv4();
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
      
      ssoSessions.set(authCode, {
        userId: req.user.userId,
        clientId: client_id,
        redirectUri: redirect_uri,
        expiresAt,
        used: false
      });
      
      // Redirect back to client with authorization code
      const redirectUrl = new URL(redirect_uri);
      redirectUrl.searchParams.set('code', authCode);
      if (state) redirectUrl.searchParams.set('state', state);
      
      return res.redirect(redirectUrl.toString());
    }
    
    // User not authenticated, return login URL or redirect to login page
    const loginUrl = `/api/sso/login?client_id=${client_id}&redirect_uri=${encodeURIComponent(redirect_uri)}${state ? `&state=${state}` : ''}`;
    
    res.status(200).json({
      message: 'Authentication required',
      loginUrl,
      client: {
        id: client.id,
        name: client.name
      }
    });
    
  } catch (error) {
    console.error('SSO authorize error:', error);
    res.status(500).json({
      error: 'server_error',
      error_description: 'An error occurred during authorization'
    });
  }
});

/**
 * GET /api/sso/login
 * SSO Login page endpoint
 */
router.get('/login', async (req, res) => {
  try {
    const { client_id, redirect_uri, state } = req.query;
    
    // Validate client
    const client = ssoClients.get(client_id);
    if (!client) {
      return res.status(400).json({
        error: 'invalid_client',
        error_description: 'Invalid client'
      });
    }
    
    res.status(200).json({
      message: 'SSO Login required',
      client: {
        id: client.id,
        name: client.name
      },
      loginEndpoint: '/api/sso/authenticate',
      parameters: {
        client_id,
        redirect_uri,
        state
      }
    });
    
  } catch (error) {
    console.error('SSO login error:', error);
    res.status(500).json({
      error: 'server_error',
      error_description: 'An error occurred'
    });
  }
});

/**
 * POST /api/sso/authenticate
 * SSO Authentication endpoint
 */
router.post('/authenticate', async (req, res) => {
  try {
    const { email, password, client_id, redirect_uri, state } = req.body;
    
    // Validate required fields
    if (!email || !password || !client_id || !redirect_uri) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing required parameters'
      });
    }
    
    // Validate client
    const client = ssoClients.get(client_id);
    if (!client || !client.isActive) {
      return res.status(400).json({
        error: 'invalid_client',
        error_description: 'Invalid or inactive client'
      });
    }
    
    // Authenticate user
    const user = await userService.authenticateUser(email, password);
    if (!user) {
      return res.status(401).json({
        error: 'invalid_credentials',
        error_description: 'Invalid email or password'
      });
    }
    
    // Generate authorization code
    const authCode = uuidv4();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    
    ssoSessions.set(authCode, {
      userId: user.id,
      clientId: client_id,
      redirectUri: redirect_uri,
      expiresAt,
      used: false
    });
    
    // Update last login
    await userService.updateLastLogin(user.id);
    
    // Return authorization code and redirect URL
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set('code', authCode);
    if (state) redirectUrl.searchParams.set('state', state);
    
    res.status(200).json({
      message: 'Authentication successful',
      authorizationCode: authCode,
      redirectUrl: redirectUrl.toString(),
      expiresIn: 600 // 10 minutes
    });
    
  } catch (error) {
    console.error('SSO authenticate error:', error);
    res.status(500).json({
      error: 'server_error',
      error_description: 'An error occurred during authentication'
    });
  }
});

/**
 * POST /api/sso/token
 * SSO Token exchange endpoint
 */
router.post('/token', async (req, res) => {
  try {
    const { grant_type, code, client_id, client_secret, redirect_uri } = req.body;
    
    // Validate grant type
    if (grant_type !== 'authorization_code') {
      return res.status(400).json({
        error: 'unsupported_grant_type',
        error_description: 'Only authorization_code grant type is supported'
      });
    }
    
    // Validate required parameters
    if (!code || !client_id || !client_secret || !redirect_uri) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing required parameters'
      });
    }
    
    // Validate client
    const client = ssoClients.get(client_id);
    if (!client || !client.isActive || client.secret !== client_secret) {
      return res.status(401).json({
        error: 'invalid_client',
        error_description: 'Invalid client credentials'
      });
    }
    
    // Validate authorization code
    const session = ssoSessions.get(code);
    if (!session) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid authorization code'
      });
    }
    
    // Check if code is expired
    if (new Date() > session.expiresAt) {
      ssoSessions.delete(code);
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Authorization code has expired'
      });
    }
    
    // Check if code has been used
    if (session.used) {
      ssoSessions.delete(code);
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Authorization code has already been used'
      });
    }
    
    // Validate client and redirect URI match
    if (session.clientId !== client_id || session.redirectUri !== redirect_uri) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Client or redirect URI mismatch'
      });
    }
    
    // Mark code as used
    session.used = true;
    
    // Get user details
    const user = await userService.findById(session.userId);
    if (!user || !user.isActive) {
      ssoSessions.delete(code);
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'User not found or inactive'
      });
    }
    
    // Generate tokens
    const tokens = jwtService.generateTokenPair(user);
    
    // Store refresh token
    const refreshDecoded = jwtService.decodeToken(tokens.refreshToken);
    await userService.storeRefreshToken(user.id, refreshDecoded.jti, tokens.refreshToken);
    
    // Clean up authorization code
    ssoSessions.delete(code);
    
    res.status(200).json({
      access_token: tokens.accessToken,
      token_type: tokens.tokenType,
      expires_in: 3600, // 1 hour
      refresh_token: tokens.refreshToken,
      scope: 'read write'
    });
    
  } catch (error) {
    console.error('SSO token error:', error);
    res.status(500).json({
      error: 'server_error',
      error_description: 'An error occurred during token exchange'
    });
  }
});

/**
 * GET /api/sso/userinfo
 * SSO User info endpoint (requires valid access token)
 */
router.get('/userinfo', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.user;
    
    const user = await userService.findById(userId);
    if (!user) {
      return res.status(404).json({
        error: 'user_not_found',
        error_description: 'User not found'
      });
    }
    
    res.status(200).json({
      sub: user.id,
      email: user.email,
      role: user.role,
      permissions: user.permissions,
      email_verified: true,
      updated_at: user.updatedAt || user.createdAt
    });
    
  } catch (error) {
    console.error('SSO userinfo error:', error);
    res.status(500).json({
      error: 'server_error',
      error_description: 'An error occurred while fetching user info'
    });
  }
});

/**
 * GET /api/sso/clients
 * Get registered SSO clients (admin only)
 */
router.get('/clients', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        error: 'access_denied',
        error_description: 'Admin access required'
      });
    }
    
    const clients = Array.from(ssoClients.values()).map(client => ({
      id: client.id,
      name: client.name,
      redirectUri: client.redirectUri,
      isActive: client.isActive
    }));
    
    res.status(200).json({
      message: 'SSO clients retrieved successfully',
      clients
    });
    
  } catch (error) {
    console.error('Get SSO clients error:', error);
    res.status(500).json({
      error: 'server_error',
      error_description: 'An error occurred while fetching clients'
    });
  }
});

/**
 * GET /api/sso/sessions
 * Get active SSO sessions (admin only)
 */
router.get('/sessions', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        error: 'access_denied',
        error_description: 'Admin access required'
      });
    }
    
    const sessions = Array.from(ssoSessions.entries()).map(([code, session]) => ({
      code,
      userId: session.userId,
      clientId: session.clientId,
      expiresAt: session.expiresAt,
      used: session.used
    }));
    
    res.status(200).json({
      message: 'SSO sessions retrieved successfully',
      sessions,
      count: sessions.length
    });
    
  } catch (error) {
    console.error('Get SSO sessions error:', error);
    res.status(500).json({
      error: 'server_error',
      error_description: 'An error occurred while fetching sessions'
    });
  }
});

module.exports = router;
