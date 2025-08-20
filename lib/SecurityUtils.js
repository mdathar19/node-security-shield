const crypto = require('crypto');
const validator = require('validator');

class SecurityUtils {
  /**
   * Generate cryptographically secure random string
   * @param {number} length - Length of the string
   * @param {string} charset - Character set to use
   * @returns {string} Random string
   */
  static generateSecureRandom(length = 32, charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') {
    let result = '';
    const bytes = crypto.randomBytes(length);
    
    for (let i = 0; i < length; i++) {
      result += charset[bytes[i] % charset.length];
    }
    
    return result;
  }

  /**
   * Generate secure API key
   * @param {string} prefix - Optional prefix for the key
   * @returns {string} API key
   */
  static generateAPIKey(prefix = 'sk') {
    const randomPart = this.generateSecureRandom(48);
    return `${prefix}_${randomPart}`;
  }

  /**
   * Hash password with salt using bcrypt-style approach
   * @param {string} password - Password to hash
   * @param {number} saltRounds - Number of salt rounds (default: 12)
   * @returns {Promise<string>} Hashed password
   */
  static async hashPassword(password, saltRounds = 12) {
    // Note: In production, use bcrypt library
    // This is a simplified version for demonstration
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, saltRounds * 1000, 64, 'sha512').toString('hex');
    return `${saltRounds}$${salt}$${hash}`;
  }

  /**
   * Verify password against hash
   * @param {string} password - Password to verify
   * @param {string} hash - Stored hash
   * @returns {Promise<boolean>} Verification result
   */
  static async verifyPassword(password, hash) {
    try {
      const [saltRounds, salt, storedHash] = hash.split('$');
      const verifyHash = crypto.pbkdf2Sync(password, salt, parseInt(saltRounds) * 1000, 64, 'sha512').toString('hex');
      return crypto.timingSafeEqual(Buffer.from(storedHash, 'hex'), Buffer.from(verifyHash, 'hex'));
    } catch (error) {
      return false;
    }
  }

  /**
   * Generate JWT-style token (simplified)
   * @param {Object} payload - Token payload
   * @param {string} secret - Secret key
   * @param {string} expiresIn - Expiration time
   * @returns {string} Token
   */
  static generateToken(payload, secret, expiresIn = '1h') {
    const header = {
      alg: 'HS256',
      typ: 'JWT'
    };

    const now = Math.floor(Date.now() / 1000);
    const expiry = now + this.parseTimeToSeconds(expiresIn);

    const tokenPayload = {
      ...payload,
      iat: now,
      exp: expiry
    };

    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
    const encodedPayload = Buffer.from(JSON.stringify(tokenPayload)).toString('base64url');
    
    const signature = crypto
      .createHmac('sha256', secret)
      .update(`${encodedHeader}.${encodedPayload}`)
      .digest('base64url');

    return `${encodedHeader}.${encodedPayload}.${signature}`;
  }

  /**
   * Verify JWT-style token
   * @param {string} token - Token to verify
   * @param {string} secret - Secret key
   * @returns {Object|null} Decoded payload or null if invalid
   */
  static verifyToken(token, secret) {
    try {
      const [encodedHeader, encodedPayload, signature] = token.split('.');
      
      if (!encodedHeader || !encodedPayload || !signature) {
        return null;
      }

      // Verify signature
      const expectedSignature = crypto
        .createHmac('sha256', secret)
        .update(`${encodedHeader}.${encodedPayload}`)
        .digest('base64url');

      if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature))) {
        return null;
      }

      // Decode payload
      const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString());

      // Check expiration
      if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
        return null;
      }

      return payload;
    } catch (error) {
      return null;
    }
  }

  /**
   * Sanitize string input to prevent XSS
   * @param {string} input - Input to sanitize
   * @returns {string} Sanitized input
   */
  static sanitizeInput(input) {
    if (typeof input !== 'string') {
        return input;
    }

    return input
        // Remove HTML tags
        .replace(/<[^>]*>/g, '')
        // Remove javascript:, vbscript:
        .replace(/javascript:/gi, '')
        .replace(/vbscript:/gi, '')
        // Remove event handler attribute names but keep their values
        .replace(/(^|\s)on\w+\s*=\s*/gi, '$1')
        .trim();
    }



  /**
   * Validate and sanitize email
   * @param {string} email - Email to validate
   * @returns {string|null} Sanitized email or null if invalid
   */
  static validateEmail(email) {
    if (!email || typeof email !== 'string') {
      return null;
    }

    const sanitized = email.toLowerCase().trim();
    return validator.isEmail(sanitized) ? sanitized : null;
  }

  /**
   * Validate password strength
   * @param {string} password - Password to validate
   * @returns {Object} Validation result
   */
  static validatePasswordStrength(password) {
    const result = {
      isValid: false,
      score: 0,
      feedback: []
    };

    if (!password || typeof password !== 'string') {
      result.feedback.push('Password is required');
      return result;
    }

    // Length check
    if (password.length < 8) {
      result.feedback.push('Password must be at least 8 characters long');
    } else if (password.length >= 8) {
      result.score += 1;
    }

    if (password.length >= 12) {
      result.score += 1;
    }

    // Character type checks
    if (/[a-z]/.test(password)) {
      result.score += 1;
    } else {
      result.feedback.push('Password must contain lowercase letters');
    }

    if (/[A-Z]/.test(password)) {
      result.score += 1;
    } else {
      result.feedback.push('Password must contain uppercase letters');
    }

    if (/\d/.test(password)) {
      result.score += 1;
    } else {
      result.feedback.push('Password must contain numbers');
    }

    if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      result.score += 1;
    } else {
      result.feedback.push('Password must contain special characters');
    }

    // Common patterns check
    const commonPatterns = [
      /^(.)\1+$/, // All same character
      /123456/, /password/i, /qwerty/i, /admin/i,
      /^(\d{4,}|\w{1,3})$/ // Too simple
    ];

    if (commonPatterns.some(pattern => pattern.test(password))) {
      result.feedback.push('Password contains common patterns');
      result.score -= 1;
    }

    // Sequential characters
    if (/(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(password)) {
      result.feedback.push('Password contains sequential characters');
      result.score -= 1;
    }

    result.score = Math.max(0, Math.min(5, result.score));
    result.isValid = result.score >= 4 && result.feedback.length === 0;

    if (result.isValid) {
      result.feedback = ['Password strength: ' + this.getPasswordStrengthLabel(result.score)];
    }

    return result;
  }

  /**
   * Get password strength label
   */
  static getPasswordStrengthLabel(score) {
    const labels = {
      0: 'Very Weak',
      1: 'Weak', 
      2: 'Fair',
      3: 'Good',
      4: 'Strong',
      5: 'Very Strong'
    };
    return labels[score] || 'Unknown';
  }

  /**
   * Rate limiting utility
   * @param {string} key - Unique key for rate limiting
   * @param {number} maxAttempts - Maximum attempts
   * @param {number} windowMs - Time window in milliseconds
   * @returns {Object} Rate limit result
   */
  static rateLimit(key, maxAttempts = 10, windowMs = 15 * 60 * 1000) {
    if (!this.rateLimitStore) {
      this.rateLimitStore = new Map();
    }

    const now = Date.now();
    const windowStart = now - windowMs;

    if (!this.rateLimitStore.has(key)) {
      this.rateLimitStore.set(key, []);
    }

    const attempts = this.rateLimitStore.get(key);
    
    // Remove old attempts outside the window
    const validAttempts = attempts.filter(timestamp => timestamp > windowStart);
    
    // Add current attempt
    validAttempts.push(now);
    this.rateLimitStore.set(key, validAttempts);

    const isAllowed = validAttempts.length <= maxAttempts;
    const remaining = Math.max(0, maxAttempts - validAttempts.length);
    const resetTime = validAttempts.length > 0 ? validAttempts[0] + windowMs : now + windowMs;

    return {
      isAllowed,
      remaining,
      resetTime,
      retryAfter: isAllowed ? 0 : resetTime - now
    };
  }

  /**
   * Generate CSRF token
   * @returns {string} CSRF token
   */
  static generateCSRFToken() {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Verify CSRF token
   * @param {string} token - Token to verify
   * @param {string} sessionToken - Session token
   * @returns {boolean} Verification result
   */
  static verifyCSRFToken(token, sessionToken) {
    if (!token || !sessionToken) {
      return false;
    }
    
    try {
      return crypto.timingSafeEqual(
        Buffer.from(token, 'hex'),
        Buffer.from(sessionToken, 'hex')
      );
    } catch (error) {
      return false;
    }
  }

  /**
   * Mask sensitive data for logging
   * @param {Object} data - Data to mask
   * @param {Array} sensitiveFields - Fields to mask
   * @returns {Object} Masked data
   */
  static maskSensitiveData(data, sensitiveFields = ['password', 'token', 'apiKey', 'secret', 'ssn', 'creditCard']) {
    if (!data || typeof data !== 'object') {
      return data;
    }

    const masked = { ...data };
    
    const maskValue = (value) => {
        if (typeof value === 'string') {
            value = value.trim(); // prevent extra spaces/newlines from messing up mask length
            if (value.length <= 4) return '**';
            return value.substring(0, 2) + '*'.repeat(value.length - 4) + value.substring(value.length - 2);
        }
        return '**';
    };


    const maskObject = (obj, path = '') => {
      for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
          const currentPath = path ? `${path}.${key}` : key;
          const lowerKey = key.toLowerCase();
          
          if (sensitiveFields.some(field => lowerKey.includes(field.toLowerCase()))) {
            obj[key] = maskValue(obj[key]);
          } else if (typeof obj[key] === 'object' && obj[key] !== null) {
            maskObject(obj[key], currentPath);
          }
        }
      }
    };

    maskObject(masked);
    return masked;
  }

  /**
   * Parse time string to seconds
   * @param {string} timeStr - Time string (e.g., '1h', '30m', '24h')
   * @returns {number} Seconds
   */
  static parseTimeToSeconds(timeStr) {
    const match = timeStr.match(/^(\d+)([smhd])$/);
    if (!match) {
      throw new Error('Invalid time format. Use format like: 30s, 15m, 2h, 1d');
    }

    const value = parseInt(match[1]);
    const unit = match[2];

    const multipliers = {
      s: 1,
      m: 60,
      h: 3600,
      d: 86400
    };

    return value * multipliers[unit];
  }

  /**
   * Detect potential bot user agents
   * @param {string} userAgent - User agent string
   * @returns {Object} Detection result
   */
  static detectBot(userAgent) {
    // if (!userAgent || typeof userAgent !== 'string') {
    //   return { isBot: true, type: 'unknown', confidence: 1.0 };
    // }

    const ua = userAgent.toLowerCase();

    // Known legitimate bots
    const legitimateBots = [
      { pattern: /googlebot/i, type: 'search_engine', name: 'Googlebot' },
      { pattern: /bingbot/i, type: 'search_engine', name: 'Bingbot' },
      { pattern: /slackbot/i, type: 'social', name: 'Slackbot' },
      { pattern: /facebookexternalhit/i, type: 'social', name: 'Facebook' },
      { pattern: /twitterbot/i, type: 'social', name: 'Twitter' },
      { pattern: /linkedinbot/i, type: 'social', name: 'LinkedIn' }
    ];

    // Suspicious bot patterns
    const suspiciousBots = [
      { pattern: /bot/i, type: 'generic_bot', confidence: 0.7 },
      { pattern: /crawler/i, type: 'crawler', confidence: 0.8 },
      { pattern: /spider/i, type: 'spider', confidence: 0.8 },
      { pattern: /scraper/i, type: 'scraper', confidence: 0.9 },
      { pattern: /(curl|wget|python-requests|go-http-client)/i, type: 'automated_tool', confidence: 0.95 },
      { pattern: /(nikto|sqlmap|nmap|masscan|burp|owasp|zaproxy)/i, type: 'security_tool', confidence: 1.0 }
    ];

    // Check for legitimate bots first
    for (const bot of legitimateBots) {
      if (bot.pattern.test(userAgent)) {
        return {
          isBot: true,
          type: bot.type,
          name: bot.name,
          isLegitimate: true,
          confidence: 1.0
        };
      }
    }

    // Check for suspicious bots
    for (const bot of suspiciousBots) {
      if (bot.pattern.test(userAgent)) {
        return {
          isBot: true,
          type: bot.type,
          isLegitimate: false,
          confidence: bot.confidence
        };
      }
    }

    // Check for missing/unusual user agent
    if (!userAgent || userAgent.length < 10) {
      return {
        isBot: true,
        type: 'suspicious_missing_ua',
        isLegitimate: false,
        confidence: 0.8
      };
    }

    return {
      isBot: false,
      type: 'human',
      isLegitimate: true,
      confidence: 0.9
    };
  }

  /**
   * Generate security headers
   * @param {Object} options - Header options
   * @returns {Object} Security headers
   */
  static generateSecurityHeaders(options = {}) {
    return {
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': options.frameOptions || 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Referrer-Policy': options.referrerPolicy || 'strict-origin-when-cross-origin',
      'Permissions-Policy': options.permissionsPolicy || 'geolocation=(), microphone=(), camera=()',
      'Strict-Transport-Security': `max-age=${options.hstsMaxAge || 31536000}; includeSubDomains; preload`,
      'Content-Security-Policy': options.csp || "default-src 'self'",
      'X-Request-ID': options.requestId || this.generateSecureRandom(16)
    };
  }

  /**
   * Clean up rate limit store
   */
  static cleanupRateLimitStore() {
    if (!this.rateLimitStore) return;
    
    const now = Date.now();
    const oneHourAgo = now - (60 * 60 * 1000);

    for (const [key, attempts] of this.rateLimitStore.entries()) {
      const validAttempts = attempts.filter(timestamp => timestamp > oneHourAgo);
      if (validAttempts.length === 0) {
        this.rateLimitStore.delete(key);
      } else {
        this.rateLimitStore.set(key, validAttempts);
      }
    }
  }
}

// Cleanup rate limit store every hour
if (typeof setInterval !== 'undefined') {
  setInterval(() => SecurityUtils.cleanupRateLimitStore(), 60 * 60 * 1000);
}

module.exports = SecurityUtils;