const bcrypt = require('bcryptjs');
const { Op } = require('sequelize');
const { User, UserProfile } = require('../models');

class UserService {
  constructor() {
    // In-memory storage for refresh tokens (consider using Redis in production)
    this.refreshTokens = new Map();
  }

  /**
   * Find user by email with profile
   * @param {string} email - User email
   * @returns {Object|null} User object or null
   */
  async findByEmail(email) {
    try {
      const user = await User.findOne({
        where: { email, active: true },
        include: [{
          model: UserProfile,
          as: 'profile',
          required: false
        }]
      });
      return user;
    } catch (error) {
      console.error('Error finding user by email:', error);
      throw error;
    }
  }

  /**
   * Find user by ID with profile
   * @param {string} userId - User ID
   * @returns {Object|null} User object or null
   */
  async findById(userId) {
    try {
      const user = await User.findOne({
        where: { id: userId },
        include: [{
          model: UserProfile,
          as: 'profile',
          required: false
        }]
      });
      return user;
    } catch (error) {
      console.error('Error finding user by ID:', error);
      throw error;
    }
  }

  /**
   * Find user by username with profile
   * @param {string} username - Username
   * @returns {Object|null} User object or null
   */
  async findByUsername(username) {
    try {
      const user = await User.findOne({
        where: { username, active: true },
        include: [{
          model: UserProfile,
          as: 'profile',
          required: false
        }]
      });
      return user;
    } catch (error) {
      console.error('Error finding user by username:', error);
      throw error;
    }
  }

  /**
   * Create new user with profile
   * @param {Object} userData - User data
   * @returns {Object} Created user
   */
  async createUser(userData) {
    const { email, password, username, role = 'user', permissions = ['read'] } = userData;
    
    try {
      // Check if user already exists
      const existingUser = await User.findOne({
        where: {
          [Op.or]: [{ email }, { username }]
        }
      });

      if (existingUser) {
        throw new Error('User with this email or username already exists');
      }

      const hashedPassword = await bcrypt.hash(password, 12);
      
      // Create user
      const newUser = await User.create({
        email,
        password: hashedPassword,
        username,
        password_create_date: new Date()
      });

      // Create user profile
      const isAdmin = role === 'admin';
      await UserProfile.create({
        username,
        is_admin: isAdmin,
        active: true
      });

      // Fetch the complete user with profile
      const userWithProfile = await this.findById(newUser.id);
      return this.sanitizeUser(userWithProfile);
    } catch (error) {
      console.error('Error creating user:', error);
      throw error;
    }
  }

  /**
   * Authenticate user credentials
   * @param {string} email - User email
   * @param {string} password - User password
   * @returns {Object|null} User object or null
   */
  async authenticateUser(email, password) {
    try {
      const user = await this.findByEmail(email);
      
      if (!user || !user.active) {
        return null;
      }

      const isValidPassword = await bcrypt.compare(password, user.password);
      
      if (!isValidPassword) {
        // Increment failed attempts
        await User.update(
          { number_of_failed_attempts: user.number_of_failed_attempts + 1 },
          { where: { id: user.id } }
        );
        return null;
      }

      // Reset failed attempts on successful login
      await User.update(
        { number_of_failed_attempts: 0 },
        { where: { id: user.id } }
      );

      return this.sanitizeUser(user);
    } catch (error) {
      console.error('Error authenticating user:', error);
      throw error;
    }
  }

  /**
   * Update user's last login time
   * @param {string} userId - User ID
   */
  async updateLastLogin(userId) {
    try {
      await User.update(
        { password_update_date: new Date() },
        { where: { id: userId } }
      );
    } catch (error) {
      console.error('Error updating last login:', error);
      throw error;
    }
  }

  /**
   * Store refresh token
   * @param {string} userId - User ID
   * @param {string} tokenId - Token JTI
   * @param {string} refreshToken - Refresh token
   */
  async storeRefreshToken(userId, tokenId, refreshToken) {
    if (!this.refreshTokens.has(userId)) {
      this.refreshTokens.set(userId, new Map());
    }
    
    this.refreshTokens.get(userId).set(tokenId, {
      token: refreshToken,
      createdAt: new Date()
    });
  }

  /**
   * Validate refresh token
   * @param {string} userId - User ID
   * @param {string} tokenId - Token JTI
   * @returns {boolean} True if valid
   */
  async validateRefreshToken(userId, tokenId) {
    const userTokens = this.refreshTokens.get(userId);
    return userTokens && userTokens.has(tokenId);
  }

  /**
   * Revoke refresh token
   * @param {string} userId - User ID
   * @param {string} tokenId - Token JTI
   */
  async revokeRefreshToken(userId, tokenId) {
    const userTokens = this.refreshTokens.get(userId);
    if (userTokens) {
      userTokens.delete(tokenId);
    }
  }

  /**
   * Revoke all refresh tokens for user
   * @param {string} userId - User ID
   */
  async revokeAllRefreshTokens(userId) {
    this.refreshTokens.delete(userId);
  }

  /**
   * Get all users (admin only)
   * @returns {Array} Array of sanitized users
   */
  async getAllUsers() {
    try {
      const users = await User.findAll({
        include: [{
          model: UserProfile,
          as: 'profile',
          required: false
        }],
        order: [['password_create_date', 'DESC']]
      });
      
      return users.map(user => this.sanitizeUser(user));
    } catch (error) {
      console.error('Error getting all users:', error);
      throw error;
    }
  }

  /**
   * Update user
   * @param {string} userId - User ID
   * @param {Object} updateData - Data to update
   * @returns {Object} Updated user
   */
  async updateUser(userId, updateData) {
    try {
      const user = await this.findById(userId);
      
      if (!user) {
        throw new Error('User not found');
      }

      // Update user profile if role or permissions are being changed
      if (updateData.role !== undefined) {
        const isAdmin = updateData.role === 'admin';
        await UserProfile.update(
          { is_admin: isAdmin },
          { where: { username: user.username } }
        );
      }

      if (updateData.isActive !== undefined) {
        await User.update(
          { active: updateData.isActive },
          { where: { id: userId } }
        );
        
        await UserProfile.update(
          { active: updateData.isActive },
          { where: { username: user.username } }
        );
      }

      // Fetch updated user
      const updatedUser = await this.findById(userId);
      return this.sanitizeUser(updatedUser);
    } catch (error) {
      console.error('Error updating user:', error);
      throw error;
    }
  }

  /**
   * Delete user
   * @param {string} userId - User ID
   */
  async deleteUser(userId) {
    try {
      const user = await this.findById(userId);
      
      if (!user) {
        throw new Error('User not found');
      }

      // Soft delete - set active to false
      await User.update(
        { active: false },
        { where: { id: userId } }
      );
      
      await UserProfile.update(
        { active: false },
        { where: { username: user.username } }
      );
      
      // Revoke all refresh tokens
      await this.revokeAllRefreshTokens(userId);
    } catch (error) {
      console.error('Error deleting user:', error);
      throw error;
    }
  }

  /**
   * Remove sensitive data from user object
   * @param {Object} user - User object
   * @returns {Object} Sanitized user object
   */
  sanitizeUser(user) {
    if (!user) return null;
    
    const userData = user.toJSON ? user.toJSON() : user;
    const { password, ...sanitizedUser } = userData;
    
    // Add role and permissions from profile
    if (sanitizedUser.profile) {
      sanitizedUser.role = sanitizedUser.profile.is_admin ? 'admin' : 'user';
      sanitizedUser.permissions = sanitizedUser.profile.is_admin 
        ? ['read', 'write', 'delete', 'admin'] 
        : ['read'];
    } else {
      sanitizedUser.role = 'user';
      sanitizedUser.permissions = ['read'];
    }
    
    return sanitizedUser;
  }

  /**
   * Get user statistics
   * @returns {Object} User statistics
   */
  async getUserStats() {
    try {
      const totalUsers = await User.count();
      const activeUsers = await User.count({ where: { active: true } });
      const inactiveUsers = totalUsers - activeUsers;
      
      const adminUsers = await User.count({
        include: [{
          model: UserProfile,
          as: 'profile',
          where: { is_admin: true },
          required: true
        }]
      });
      
      const regularUsers = activeUsers - adminUsers;
      
      return {
        totalUsers,
        activeUsers,
        inactiveUsers,
        adminUsers,
        regularUsers
      };
    } catch (error) {
      console.error('Error getting user stats:', error);
      throw error;
    }
  }

  /**
   * Create default admin user if none exists
   */
  async createDefaultAdmin() {
    try {
      const adminExists = await User.findOne({
        include: [{
          model: UserProfile,
          as: 'profile',
          where: { is_admin: true },
          required: true
        }]
      });

      if (!adminExists) {
        await this.createUser({
          email: 'admin@example.com',
          password: 'admin123',
          username: 'admin',
          role: 'admin'
        });
        console.log('✅ Default admin user created: admin@example.com / admin123');
      }
    } catch (error) {
      console.error('Error creating default admin:', error);
    }
  }
}

module.exports = new UserService();
