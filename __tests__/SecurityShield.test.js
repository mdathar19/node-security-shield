const SecurityShield = require('../lib/SecurityShield');
const express = require('express');

describe('SecurityShield', () => {
  let app;
  
  beforeEach(() => {
    app = express();
    // Mock app.use and other express methods
    app.use = jest.fn();
    app.disable = jest.fn();
  });

  describe('createSecurityMiddleware', () => {
    test('should create security middleware with default config', () => {
      const middleware = SecurityShield.createSecurityMiddleware();
      
      expect(typeof middleware).toBe('function');
      
      // Test middleware function
      middleware(app);
      
      // Verify app.use was called multiple times for different middlewares
      expect(app.use).toHaveBeenCalled();
      expect(app.disable).toHaveBeenCalledWith('x-powered-by');
    });

    test('should create security middleware with custom config', () => {
      const config = {
        cors: {
          allowedOrigins: ['https://example.com']
        },
        bodyLimit: '5mb',
        compression: false
      };
      
      const middleware = SecurityShield.createSecurityMiddleware(config);
      
      expect(typeof middleware).toBe('function');
      
      middleware(app);
      
      expect(app.use).toHaveBeenCalled();
    });

    test('should handle request with IP validation', () => {
      const middleware = SecurityShield.createSecurityMiddleware();
      
      middleware(app);
      
      // Find the IP validation middleware call
      const middlewareCalls = app.use.mock.calls;
      const ipValidationMiddleware = middlewareCalls.find(call => {
        const fn = call[0];
        return fn && fn.toString().includes('clientIP');
      });
      
      expect(ipValidationMiddleware).toBeDefined();
    });
  });

  describe('validateIP', () => {
    test('should validate valid IPv4 addresses', () => {
      expect(SecurityShield.validateIP('192.168.1.1')).toBe(true);
      expect(SecurityShield.validateIP('127.0.0.1')).toBe(true);
      expect(SecurityShield.validateIP('10.0.0.1')).toBe(true);
    });

    test('should validate valid IPv6 addresses', () => {
      expect(SecurityShield.validateIP('::1')).toBe(true);
      expect(SecurityShield.validateIP('2001:db8::1')).toBe(true);
    });

    test('should reject invalid IP addresses', () => {
      expect(SecurityShield.validateIP('256.256.256.256')).toBe(false);
      expect(SecurityShield.validateIP('invalid-ip')).toBe(false);
      expect(SecurityShield.validateIP('')).toBe(false);
      expect(SecurityShield.validateIP(null)).toBe(false);
      expect(SecurityShield.validateIP(undefined)).toBe(false);
    });

    test('should handle malicious IP inputs', () => {
      expect(SecurityShield.validateIP('192.168.1.1<script>')).toBe(false);
      expect(SecurityShield.validateIP('192.168.1.1; DROP TABLE')).toBe(false);
    });
  });

  describe('getSanitizedIP', () => {
    test('should extract IP from various request headers', () => {
      const req1 = {
        headers: { 'cf-connecting-ip': '192.168.1.1' },
        ip: '10.0.0.1'
      };
      expect(SecurityShield.getSanitizedIP(req1)).toBe('192.168.1.1');

      const req2 = {
        headers: { 'x-forwarded-for': '192.168.1.2, 10.0.0.1' },
        ip: '10.0.0.1'
      };
      expect(SecurityShield.getSanitizedIP(req2)).toBe('192.168.1.2');

      const req3 = {
        headers: {},
        ip: '192.168.1.3'
      };
      expect(SecurityShield.getSanitizedIP(req3)).toBe('192.168.1.3');
    });

    test('should fallback to safe IP when no valid IP found', () => {
      const req = {
        headers: {},
        ip: 'invalid-ip'
      };
      expect(SecurityShield.getSanitizedIP(req)).toBe('127.0.0.1');
    });

    test('should sanitize malicious IP inputs', () => {
      const req = {
        headers: { 'x-forwarded-for': '192.168.1.1<script>alert(1)</script>' },
        ip: '10.0.0.1'
      };
      // Should clean the IP and validate it
      const result = SecurityShield.getSanitizedIP(req);
      expect(result).toBe('10.0.0.1'); // Falls back to req.ip after cleaning fails
    });
  });

  describe('Input Sanitization Middleware', () => {
    test('should sanitize XSS attempts in middleware', () => {
      const middleware = SecurityShield.createSecurityMiddleware();
      middleware(app);

      // Find the input sanitization middleware
      const middlewareCalls = app.use.mock.calls;
      const sanitizationMiddleware = middlewareCalls.find(call => {
        const fn = call[0];
        return fn && fn.toString().includes('suspiciousPatterns');
      });

      expect(sanitizationMiddleware).toBeDefined();
    });

    test('should handle content-type validation', () => {
      const middleware = SecurityShield.createSecurityMiddleware();
      middleware(app);

      // Find the content-type validation middleware
      const middlewareCalls = app.use.mock.calls;
      const contentTypeMiddleware = middlewareCalls.find(call => {
        const fn = call[0];
        return fn && fn.toString().includes('Content-Type');
      });

      expect(contentTypeMiddleware).toBeDefined();
    });
  });

  describe('Integration Tests', () => {
    test('should properly initialize all security features', () => {
      const config = {
        cors: { allowedOrigins: ['https://test.com'] },
        bodyLimit: '1mb',
        compression: { level: 9 }
      };
      
      const middleware = SecurityShield.createSecurityMiddleware(config);
      middleware(app);

      // Verify that multiple middleware functions were registered
      expect(app.use.mock.calls.length).toBeGreaterThan(5);
      expect(app.disable).toHaveBeenCalledWith('x-powered-by');
    });

    test('should handle CORS configuration correctly', () => {
      const config = {
        cors: {
          allowedOrigins: ['https://example.com', 'https://test.com'],
          credentials: true
        }
      };
      
      const middleware = SecurityShield.createSecurityMiddleware(config);
      
      expect(() => {
        middleware(app);
      }).not.toThrow();
    });
  });
});