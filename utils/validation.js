const Joi = require('joi');

// Login validation schema
const loginSchema = Joi.object({
  email: Joi.string()
    .email()
    .required()
    .messages({
      'string.email': 'Please provide a valid email address',
      'any.required': 'Email is required'
    }),
  password: Joi.string()
    .min(6)
    .required()
    .messages({
      'string.min': 'Password must be at least 6 characters long',
      'any.required': 'Password is required'
    })
});

// User registration validation schema
const registerSchema = Joi.object({
  email: Joi.string()
    .email()
    .required()
    .messages({
      'string.email': 'Please provide a valid email address',
      'any.required': 'Email is required'
    }),
  password: Joi.string()
    .min(8)
    .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])'))
    .required()
    .messages({
      'string.min': 'Password must be at least 8 characters long',
      'string.pattern.base': 'Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character',
      'any.required': 'Password is required'
    }),
  role: Joi.string()
    .valid('user', 'admin')
    .default('user'),
  permissions: Joi.array()
    .items(Joi.string().valid('read', 'write', 'delete', 'admin'))
    .default(['read'])
});

// Refresh token validation schema
const refreshTokenSchema = Joi.object({
  refreshToken: Joi.string()
    .required()
    .messages({
      'any.required': 'Refresh token is required'
    })
});

// SSO token validation schema
const ssoTokenSchema = Joi.object({
  token: Joi.string()
    .required()
    .messages({
      'any.required': 'SSO token is required'
    }),
  clientId: Joi.string()
    .optional()
    .messages({
      'string.base': 'Client ID must be a string'
    })
});

// User update validation schema
const userUpdateSchema = Joi.object({
  role: Joi.string()
    .valid('user', 'admin')
    .optional(),
  permissions: Joi.array()
    .items(Joi.string().valid('read', 'write', 'delete', 'admin'))
    .optional(),
  isActive: Joi.boolean()
    .optional()
});

/**
 * Validate request data against schema
 * @param {Object} data - Data to validate
 * @param {Object} schema - Joi validation schema
 * @returns {Object} Validation result
 */
const validateData = (data, schema) => {
  const { error, value } = schema.validate(data, {
    abortEarly: false,
    stripUnknown: true
  });

  if (error) {
    const errors = error.details.map(detail => ({
      field: detail.path.join('.'),
      message: detail.message
    }));
    
    return {
      isValid: false,
      errors,
      data: null
    };
  }

  return {
    isValid: true,
    errors: null,
    data: value
  };
};

/**
 * Middleware to validate request body
 * @param {Object} schema - Joi validation schema
 */
const validateRequest = (schema) => {
  return (req, res, next) => {
    const validation = validateData(req.body, schema);
    
    if (!validation.isValid) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Invalid request data',
        details: validation.errors
      });
    }
    
    req.validatedData = validation.data;
    next();
  };
};

/**
 * Validate email format
 * @param {string} email - Email to validate
 * @returns {boolean} True if valid
 */
const isValidEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

/**
 * Validate password strength
 * @param {string} password - Password to validate
 * @returns {Object} Validation result with strength score
 */
const validatePasswordStrength = (password) => {
  const checks = {
    length: password.length >= 8,
    lowercase: /[a-z]/.test(password),
    uppercase: /[A-Z]/.test(password),
    number: /[0-9]/.test(password),
    special: /[!@#$%^&*(),.?":{}|<>]/.test(password)
  };
  
  const score = Object.values(checks).filter(Boolean).length;
  
  let strength = 'Very Weak';
  if (score >= 5) strength = 'Very Strong';
  else if (score >= 4) strength = 'Strong';
  else if (score >= 3) strength = 'Medium';
  else if (score >= 2) strength = 'Weak';
  
  return {
    isValid: score >= 4,
    strength,
    score,
    checks,
    suggestions: generatePasswordSuggestions(checks)
  };
};

/**
 * Generate password improvement suggestions
 * @param {Object} checks - Password validation checks
 * @returns {Array} Array of suggestions
 */
const generatePasswordSuggestions = (checks) => {
  const suggestions = [];
  
  if (!checks.length) suggestions.push('Use at least 8 characters');
  if (!checks.lowercase) suggestions.push('Include lowercase letters');
  if (!checks.uppercase) suggestions.push('Include uppercase letters');
  if (!checks.number) suggestions.push('Include numbers');
  if (!checks.special) suggestions.push('Include special characters');
  
  return suggestions;
};

/**
 * Sanitize input data
 * @param {string} input - Input to sanitize
 * @returns {string} Sanitized input
 */
const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  
  return input
    .trim()
    .replace(/[<>]/g, '') // Remove potential HTML tags
    .substring(0, 1000); // Limit length
};

module.exports = {
  // Schemas
  loginSchema,
  registerSchema,
  refreshTokenSchema,
  ssoTokenSchema,
  userUpdateSchema,
  
  // Validation functions
  validateData,
  validateRequest,
  isValidEmail,
  validatePasswordStrength,
  sanitizeInput
};
