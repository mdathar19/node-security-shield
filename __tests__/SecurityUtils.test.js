const SecurityUtils = require('../lib/SecurityUtils');

describe('SecurityUtils', () => {
  
  describe('generateSecureRandom', () => {
    test('should generate random string of specified length', () => {
      const result = SecurityUtils.generateSecureRandom(32);
      expect(result).toHaveLength(32);
      expect(typeof result).toBe('string');
    });

    test('should generate different strings on multiple calls', () => {
      const result1 = SecurityUtils.generateSecureRandom(16);
      const result2 = SecurityUtils.generateSecureRandom(16);
      expect(result1).not.toBe(result2);
    });

    test('should use custom charset', () => {
      const result = SecurityUtils.generateSecureRandom(10, '0123456789');
      expect(result).toMatch(/^[0-9]+$/);
      expect(result).toHaveLength(10);
    });
  });

  describe('generateAPIKey', () => {
    test('should generate API key with default prefix', () => {
      const apiKey = SecurityUtils.generateAPIKey();
      expect(apiKey).toMatch(/^sk_[a-zA-Z0-9]{48}$/);
    });

    test('should generate API key with custom prefix', () => {
      const apiKey = SecurityUtils.generateAPIKey('api');
      expect(apiKey).toMatch(/^api_[a-zA-Z0-9]{48}$/);
    });
  });

  describe('hashPassword', () => {
    test('should hash password', async () => {
      const password = 'testPassword123!';
      const hash = await SecurityUtils.hashPassword(password);
      
      expect(typeof hash).toBe('string');
      expect(hash).toMatch(/^\d+\$[a-f0-9]+\$[a-f0-9]+$/);
      expect(hash).not.toBe(password);
    });

    test('should use custom salt rounds', async () => {
      const password = 'testPassword123!';
      const hash = await SecurityUtils.hashPassword(password, 8);
      
      expect(hash.startsWith('8$')).toBe(true);
    });

    test('should generate different hashes for same password', async () => {
      const password = 'testPassword123!';
      const hash1 = await SecurityUtils.hashPassword(password);
      const hash2 = await SecurityUtils.hashPassword(password);
      
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('verifyPassword', () => {
    test('should verify correct password', async () => {
      const password = 'testPassword123!';
      const hash = await SecurityUtils.hashPassword(password);
      
      const isValid = await SecurityUtils.verifyPassword(password, hash);
      expect(isValid).toBe(true);
    });

    test('should reject incorrect password', async () => {
      const password = 'testPassword123!';
      const wrongPassword = 'wrongPassword123!';
      const hash = await SecurityUtils.hashPassword(password);
      
      const isValid = await SecurityUtils.verifyPassword(wrongPassword, hash);
      expect(isValid).toBe(false);
    });

    test('should handle invalid hash format', async () => {
      const password = 'testPassword123!';
      const invalidHash = 'invalid-hash-format';
      
      const isValid = await SecurityUtils.verifyPassword(password, invalidHash);
      expect(isValid).toBe(false);
    });
  });

  describe('generateToken', () => {
    test('should generate JWT-style token', () => {
      const payload = { userId: 123, role: 'admin' };
      const secret = 'test-secret';
      
      const token = SecurityUtils.generateToken(payload, secret);
      
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3);
    });

    test('should include expiration time', () => {
      const payload = { userId: 123 };
      const secret = 'test-secret';
      
      const token = SecurityUtils.generateToken(payload, secret, '1h');
      const decoded = SecurityUtils.verifyToken(token, secret);
      
      expect(decoded).toHaveProperty('exp');
      expect(decoded.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
    });
  });

  describe('verifyToken', () => {
    test('should verify valid token', () => {
      const payload = { userId: 123, role: 'admin' };
      const secret = 'test-secret';
      
      const token = SecurityUtils.generateToken(payload, secret);
      const decoded = SecurityUtils.verifyToken(token, secret);
      
      expect(decoded.userId).toBe(123);
      expect(decoded.role).toBe('admin');
    });

    test('should reject token with wrong secret', () => {
      const payload = { userId: 123 };
      const secret = 'test-secret';
      const wrongSecret = 'wrong-secret';
      
      const token = SecurityUtils.generateToken(payload, secret);
      const decoded = SecurityUtils.verifyToken(token, wrongSecret);
      
      expect(decoded).toBe(null);
    });

    test('should reject expired token', () => {
      const payload = { userId: 123 };
      const secret = 'test-secret';
      
      // Create token that expires immediately
      const token = SecurityUtils.generateToken(payload, secret, '0s');
      
      // Wait a bit and then verify
      setTimeout(() => {
        const decoded = SecurityUtils.verifyToken(token, secret);
        expect(decoded).toBe(null);
      }, 100);
    });

    test('should reject malformed token', () => {
      const secret = 'test-secret';
      const malformedToken = 'invalid.token.format';
      
      const decoded = SecurityUtils.verifyToken(malformedToken, secret);
      expect(decoded).toBe(null);
    });
  });

  describe('sanitizeInput', () => {
    test('should remove HTML tags', () => {
      const input = 'Hello <script>alert("xss")</script> World';
      const sanitized = SecurityUtils.sanitizeInput(input);
      
      expect(sanitized).toBe('Hello alert("xss") World');
    });

    test('should remove javascript protocols', () => {
      const input = 'javascript:alert(1)';
      const sanitized = SecurityUtils.sanitizeInput(input);
      
      expect(sanitized).toBe('alert(1)');
    });

    test('should remove event handlers', () => {
      const input = 'onclick="alert(1)" onload="badcode()"';
      const sanitized = SecurityUtils.sanitizeInput(input);
      
      expect(sanitized).toBe('"alert(1)" "badcode()"');
    });

    test('should handle non-string input', () => {
      expect(SecurityUtils.sanitizeInput(123)).toBe(123);
      expect(SecurityUtils.sanitizeInput(null)).toBe(null);
      expect(SecurityUtils.sanitizeInput(undefined)).toBe(undefined);
    });
  });

  describe('validateEmail', () => {
    test('should validate correct email addresses', () => {
      const validEmails = [
        'test@example.com',
        'user.name@domain.co.uk',
        'test+tag@gmail.com'
      ];

      validEmails.forEach(email => {
        const result = SecurityUtils.validateEmail(email);
        expect(result).toBe(email.toLowerCase());
      });
    });

    test('should reject invalid email addresses', () => {
      const invalidEmails = [
        'invalid-email',
        '@domain.com',
        'test@',
        'test..test@domain.com',
        null,
        undefined,
        123
      ];

      invalidEmails.forEach(email => {
        const result = SecurityUtils.validateEmail(email);
        expect(result).toBe(null);
      });
    });

    test('should normalize email case', () => {
      const email = 'TEST@EXAMPLE.COM';
      const result = SecurityUtils.validateEmail(email);
      expect(result).toBe('test@example.com');
    });
  });

  describe('validatePasswordStrength', () => {
    test('should validate strong password', () => {
      const strongPassword = 'StrongP@ssw0rd123';
      const result = SecurityUtils.validatePasswordStrength(strongPassword);
      
      expect(result.isValid).toBe(true);
      expect(result.score).toBeGreaterThanOrEqual(4);
    });

    test('should reject weak passwords', () => {
      const weakPasswords = [
        'short',
        'alllowercase',
        'ALLUPPERCASE',
        '12345678',
        'NoSpecialChars123'
      ];

      weakPasswords.forEach(password => {
        const result = SecurityUtils.validatePasswordStrength(password);
        expect(result.isValid).toBe(false);
        expect(result.feedback.length).toBeGreaterThan(0);
      });
    });

    test('should detect common patterns', () => {
      const commonPasswords = [
        'password123',
        'qwerty123',
        'admin123',
        '123456789'
      ];

      commonPasswords.forEach(password => {
        const result = SecurityUtils.validatePasswordStrength(password);
        expect(result.score).toBeLessThan(4);
      });
    });

    test('should provide helpful feedback', () => {
      const result = SecurityUtils.validatePasswordStrength('weak');
      
      expect(result.feedback).toEqual(
        expect.arrayContaining([
          expect.stringMatching(/at least 8 characters/i)
        ])
      );
    });
  });

  describe('rateLimit', () => {
    beforeEach(() => {
      // Clear rate limit store before each test
      SecurityUtils.rateLimitStore = new Map();
    });

    test('should allow requests within limit', () => {
      const key = 'test-key';
      
      for (let i = 0; i < 5; i++) {
        const result = SecurityUtils.rateLimit(key, 10, 60000);
        expect(result.isAllowed).toBe(true);
        expect(result.remaining).toBe(10 - (i + 1));
      }
    });

    test('should block requests exceeding limit', () => {
      const key = 'test-key';
      const maxAttempts = 3;
      
      // Make requests up to limit
      for (let i = 0; i < maxAttempts; i++) {
        SecurityUtils.rateLimit(key, maxAttempts, 60000);
      }
      
      // Next request should be blocked
      const result = SecurityUtils.rateLimit(key, maxAttempts, 60000);
      expect(result.isAllowed).toBe(false);
      expect(result.remaining).toBe(0);
      expect(result.retryAfter).toBeGreaterThan(0);
    });

    test('should reset after time window', () => {
      const key = 'test-key';
      const maxAttempts = 2;
      const windowMs = 100; // Very short window for testing
      
      // Exhaust the limit
      for (let i = 0; i < maxAttempts + 1; i++) {
        SecurityUtils.rateLimit(key, maxAttempts, windowMs);
      }
      
      // Wait for window to reset
      setTimeout(() => {
        const result = SecurityUtils.rateLimit(key, maxAttempts, windowMs);
        expect(result.isAllowed).toBe(true);
      }, windowMs + 10);
    });
  });

  describe('generateCSRFToken', () => {
    test('should generate CSRF token', () => {
      const token = SecurityUtils.generateCSRFToken();
      
      expect(typeof token).toBe('string');
      expect(token).toHaveLength(64); // 32 bytes = 64 hex characters
      expect(token).toMatch(/^[a-f0-9]+$/);
    });

    test('should generate different tokens', () => {
      const token1 = SecurityUtils.generateCSRFToken();
      const token2 = SecurityUtils.generateCSRFToken();
      
      expect(token1).not.toBe(token2);
    });
  });

  describe('verifyCSRFToken', () => {
    test('should verify matching tokens', () => {
      const token = SecurityUtils.generateCSRFToken();
      const isValid = SecurityUtils.verifyCSRFToken(token, token);
      
      expect(isValid).toBe(true);
    });

    test('should reject different tokens', () => {
      const token1 = SecurityUtils.generateCSRFToken();
      const token2 = SecurityUtils.generateCSRFToken();
      
      const isValid = SecurityUtils.verifyCSRFToken(token1, token2);
      expect(isValid).toBe(false);
    });

    test('should handle invalid inputs', () => {
      expect(SecurityUtils.verifyCSRFToken(null, 'token')).toBe(false);
      expect(SecurityUtils.verifyCSRFToken('token', null)).toBe(false);
      expect(SecurityUtils.verifyCSRFToken('', '')).toBe(false);
    });
  });

  describe('maskSensitiveData', () => {
    test('should mask password fields', () => {
      const data = {
        username: 'testuser',
        password: 'secretpassword',
        email: 'test@example.com'
      };
      
      const masked = SecurityUtils.maskSensitiveData(data);
      
      expect(masked.username).toBe('testuser');
      expect(masked.password).toBe('se**********rd');
      expect(masked.email).toBe('test@example.com');
    });

    test('should mask nested sensitive data', () => {
      const data = {
        user: {
          name: 'John',
          credentials: {
            password: 'secret123',
            apiKey: 'sk_1234567890abdef'
          }
        }
      };
      
      const masked = SecurityUtils.maskSensitiveData(data);
      
      expect(masked.user.name).toBe('John');
      expect(masked.user.credentials.password).toBe('se*****23');
      expect(masked.user.credentials.apiKey).toBe('sk**************ef');
    });

    test('should handle custom sensitive fields', () => {
      const data = { customSecret: 'topsecret' };
      const masked = SecurityUtils.maskSensitiveData(data, ['customSecret']);
      
      expect(masked.customSecret).toBe('to*****et');
    });
  });

  describe('parseTimeToSeconds', () => {
    test('should parse time strings correctly', () => {
      expect(SecurityUtils.parseTimeToSeconds('30s')).toBe(30);
      expect(SecurityUtils.parseTimeToSeconds('15m')).toBe(900);
      expect(SecurityUtils.parseTimeToSeconds('2h')).toBe(7200);
      expect(SecurityUtils.parseTimeToSeconds('1d')).toBe(86400);
    });

    test('should throw error for invalid format', () => {
      expect(() => {
        SecurityUtils.parseTimeToSeconds('invalid');
      }).toThrow('Invalid time format');
      
      expect(() => {
        SecurityUtils.parseTimeToSeconds('30x');
      }).toThrow('Invalid time format');
    });
  });

  describe('detectBot', () => {
    test('should detect legitimate bots', () => {
      const legitimateBots = [
        'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
        'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)'
      ];

      legitimateBots.forEach(userAgent => {
        const result = SecurityUtils.detectBot(userAgent);
        expect(result.isBot).toBe(true);
        expect(result.isLegitimate).toBe(true);
      });
    });

    test('should detect suspicious bots', () => {
      const suspiciousBots = [
        'sqlmap/1.6.12#stable (http://sqlmap.org)',
        'python-requests/2.25.1',
        'curl/7.68.0',
        'Nikto/2.1.6'
      ];

      suspiciousBots.forEach(userAgent => {
        const result = SecurityUtils.detectBot(userAgent);
        expect(result.isBot).toBe(true);
        expect(result.isLegitimate).toBe(false);
        expect(result.confidence).toBeGreaterThan(0.7);
      });
    });

    test('should identify human browsers', () => {
      const humanBrowsers = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
      ];

      humanBrowsers.forEach(userAgent => {
        const result = SecurityUtils.detectBot(userAgent);
        expect(result.isBot).toBe(false);
        expect(result.type).toBe('human');
      });
    });

    test('should handle missing user agent', () => {
      const result = SecurityUtils.detectBot('');
      expect(result.isBot).toBe(true);
      expect(result.type).toBe('suspicious_missing_ua');
    });
  });

  describe('generateSecurityHeaders', () => {
    test('should generate default security headers', () => {
      const headers = SecurityUtils.generateSecurityHeaders();
      
      expect(headers).toHaveProperty('X-Content-Type-Options', 'nosniff');
      expect(headers).toHaveProperty('X-Frame-Options', 'DENY');
      expect(headers).toHaveProperty('X-XSS-Protection', '1; mode=block');
      expect(headers).toHaveProperty('Referrer-Policy');
      expect(headers).toHaveProperty('Strict-Transport-Security');
      expect(headers).toHaveProperty('X-Request-ID');
    });

    test('should accept custom options', () => {
      const options = {
        frameOptions: 'SAMEORIGIN',
        referrerPolicy: 'no-referrer',
        requestId: 'custom-id-123'
      };
      
      const headers = SecurityUtils.generateSecurityHeaders(options);
      
      expect(headers['X-Frame-Options']).toBe('SAMEORIGIN');
      expect(headers['Referrer-Policy']).toBe('no-referrer');
      expect(headers['X-Request-ID']).toBe('custom-id-123');
    });
  });

  describe('cleanupRateLimitStore', () => {
    test('should remove old rate limit entries', () => {
      // Add some old entries
      const oldTimestamp = Date.now() - (2 * 60 * 60 * 1000); // 2 hours ago
      SecurityUtils.rateLimitStore = new Map();
      SecurityUtils.rateLimitStore.set('old-key', [oldTimestamp]);
      SecurityUtils.rateLimitStore.set('recent-key', [Date.now()]);
      
      SecurityUtils.cleanupRateLimitStore();
      
      expect(SecurityUtils.rateLimitStore.has('old-key')).toBe(false);
      expect(SecurityUtils.rateLimitStore.has('recent-key')).toBe(true);
    });
  });
});