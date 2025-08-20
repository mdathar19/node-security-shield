const SuspiciousActivityMonitor = require('../lib/SuspiciousActivityMonitor');

describe('SuspiciousActivityMonitor', () => {
  let monitor;
  let mockReq, mockRes, mockNext;

  beforeEach(() => {
    monitor = new SuspiciousActivityMonitor();
    mockReq = testUtils.createMockReq();
    mockRes = testUtils.createMockRes();
    mockNext = testUtils.createMockNext();
    
    // Clear any existing data
    monitor.requestTracker.clear();
    monitor.failedAttempts.clear();
    monitor.blockedIPs.clear();
  });

  describe('createSuspiciousActivityMiddleware', () => {
    test('should create middleware function', () => {
      const middleware = SuspiciousActivityMonitor.createSuspiciousActivityMiddleware();
      
      expect(typeof middleware).toBe('function');
    });

    test('should analyze request and call next for normal traffic', () => {
      const middleware = SuspiciousActivityMonitor.createSuspiciousActivityMiddleware();
      
      middleware(mockReq, mockRes, mockNext);
      
      expect(mockNext).toHaveBeenCalled();
      expect(mockReq.suspiciousScore).toBeDefined();
      expect(mockReq.suspiciousPatterns).toBeDefined();
      expect(mockReq.clientTracker).toBeDefined();
    });

    test('should block requests from blocked IPs', () => {
      const middleware = SuspiciousActivityMonitor.createSuspiciousActivityMiddleware();
      
      // Block the IP first
      monitor.blockedIPs.add('127.0.0.1');
      
      middleware(mockReq, mockRes, mockNext);
      
      expect(mockRes.status).toHaveBeenCalledWith(429);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'IP temporarily blocked due to suspicious activity',
          code: 'IP_BLOCKED'
        })
      );
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('detectSuspiciousPatterns', () => {
    test('should detect high request volume', () => {
      const tracker = {
        hourlyCount: 2000,
        endpoints: new Set(['/test']),
        userAgents: new Set(['Mozilla/5.0']),
        methods: new Set(['GET']),
        lastActivity: Date.now()
      };

      const patterns = monitor.detectSuspiciousPatterns(
        tracker, '127.0.0.1', 'Mozilla/5.0', '/test', 'GET', 'req123', mockReq, 
        { thresholds: { requestsPerHour: 1000 } }
      );

      expect(patterns).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: 'High Request Volume',
            severity: expect.stringMatching(/high|critical/)
          })
        ])
      );
    });

    test('should detect endpoint scanning', () => {
      const endpoints = new Set();
      for (let i = 0; i < 60; i++) {
        endpoints.add(`/endpoint${i}`);
      }

      const tracker = {
        hourlyCount: 150,
        endpoints: endpoints,
        userAgents: new Set(['Mozilla/5.0']),
        methods: new Set(['GET']),
        lastActivity: Date.now()
      };

      const patterns = monitor.detectSuspiciousPatterns(
        tracker, '127.0.0.1', 'Mozilla/5.0', '/test', 'GET', 'req123', mockReq,
        { thresholds: { uniqueEndpoints: 50 } }
      );

      expect(patterns).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: 'Endpoint Scanning',
            severity: 'high'
          })
        ])
      );
    });

    test('should detect multiple user agents', () => {
      const userAgents = new Set([
        'Mozilla/5.0 (Windows)',
        'Mozilla/5.0 (Mac)',
        'Mozilla/5.0 (Linux)',
        'Chrome/91.0',
        'Safari/14.0',
        'Firefox/89.0'
      ]);

      const tracker = {
        hourlyCount: 100,
        endpoints: new Set(['/test']),
        userAgents: userAgents,
        methods: new Set(['GET']),
        lastActivity: Date.now()
      };

      const patterns = monitor.detectSuspiciousPatterns(
        tracker, '127.0.0.1', 'Mozilla/5.0', '/test', 'GET', 'req123', mockReq,
        { thresholds: { userAgents: 5 } }
      );

      expect(patterns).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: 'Multiple User Agents',
            severity: 'medium'
          })
        ])
      );
    });

    test('should detect suspicious user agents', () => {
      const suspiciousUserAgents = [
        'sqlmap/1.6.12',
        'Nikto/2.1.6',
        'python-requests/2.25.1',
        'curl/7.68.0'
      ];

      suspiciousUserAgents.forEach(userAgent => {
        const tracker = {
          hourlyCount: 10,
          endpoints: new Set(['/test']),
          userAgents: new Set([userAgent]),
          methods: new Set(['GET']),
          lastActivity: Date.now()
        };

        const patterns = monitor.detectSuspiciousPatterns(
          tracker, '127.0.0.1', userAgent, '/test', 'GET', 'req123', mockReq, {}
        );

        expect(patterns).toEqual(
          expect.arrayContaining([
            expect.objectContaining({
              type: 'Suspicious User Agent',
              severity: 'medium'
            })
          ])
        );
      });
    });

    test('should detect SQL injection attempts', () => {
      const maliciousRequests = [
        { originalUrl: '/users?id=1\' UNION SELECT * FROM admin--' },
        { originalUrl: '/search?q=test\'; DROP TABLE users;--' },
        { body: { query: '1\' OR 1=1--' } }
      ];

      maliciousRequests.forEach(req => {
        const mockRequest = { ...mockReq, ...req };
        
        const tracker = {
          hourlyCount: 1,
          endpoints: new Set(['/test']),
          userAgents: new Set(['Mozilla/5.0']),
          methods: new Set(['GET']),
          lastActivity: Date.now()
        };

        const patterns = monitor.detectSuspiciousPatterns(
          tracker, '127.0.0.1', 'Mozilla/5.0', '/test', 'GET', 'req123', mockRequest, {}
        );

        expect(patterns).toEqual(
          expect.arrayContaining([
            expect.objectContaining({
              type: 'SQL Injection Attempt',
              severity: 'critical'
            })
          ])
        );
      });
    });

    test('should detect XSS attempts', () => {
      const xssPayloads = [
        { originalUrl: '/search?q=<script>alert(1)</script>' },
        { originalUrl: '/profile?name=javascript:alert(1)' },
        { body: { comment: '<iframe src="javascript:alert(1)"></iframe>' } }
      ];

      xssPayloads.forEach(payload => {
        const mockRequest = { ...mockReq, ...payload };
        
        const tracker = {
          hourlyCount: 1,
          endpoints: new Set(['/test']),
          userAgents: new Set(['Mozilla/5.0']),
          methods: new Set(['GET']),
          lastActivity: Date.now()
        };

        const patterns = monitor.detectSuspiciousPatterns(
          tracker, '127.0.0.1', 'Mozilla/5.0', '/test', 'GET', 'req123', mockRequest, {}
        );

        expect(patterns).toEqual(
          expect.arrayContaining([
            expect.objectContaining({
              type: 'XSS Attempt',
              severity: 'high'
            })
          ])
        );
      });
    });

    test('should detect path traversal attempts', () => {
      const pathTraversalPaths = [
        '/files/../../../etc/passwd',
        '/download/..\\..\\windows\\system32',
        '/api/..%2f..%2fetc%2fpasswd'
      ];

      pathTraversalPaths.forEach(path => {
        const tracker = {
          hourlyCount: 1,
          endpoints: new Set([path]),
          userAgents: new Set(['Mozilla/5.0']),
          methods: new Set(['GET']),
          lastActivity: Date.now()
        };

        const patterns = monitor.detectSuspiciousPatterns(
          tracker, '127.0.0.1', 'Mozilla/5.0', path, 'GET', 'req123', mockReq, {}
        );

        expect(patterns).toEqual(
          expect.arrayContaining([
            expect.objectContaining({
              type: 'Path Traversal Attempt',
              severity: 'high'
            })
          ])
        );
      });
    });

    test('should detect brute force attacks on auth endpoints', () => {
      const authEndpoints = ['/login', '/auth', '/signin', '/register'];

      authEndpoints.forEach(endpoint => {
        const tracker = {
          hourlyCount: 50,
          endpoints: new Set([endpoint]),
          userAgents: new Set(['Mozilla/5.0']),
          methods: new Set(['POST']),
          lastActivity: Date.now()
        };

        const patterns = monitor.detectSuspiciousPatterns(
          tracker, '127.0.0.1', 'Mozilla/5.0', endpoint, 'POST', 'req123', mockReq,
          { thresholds: { authAttempts: 20 } }
        );

        expect(patterns).toEqual(
          expect.arrayContaining([
            expect.objectContaining({
              type: 'Potential Brute Force Attack',
              severity: 'high'
            })
          ])
        );
      });
    });
  });

  describe('trackFailedAttempt', () => {
    test('should track failed authentication attempts', () => {
      const result = SuspiciousActivityMonitor.trackFailedAttempt(
        '127.0.0.1', '/login', 'Invalid password', 'req123', 
        { failedAttemptThreshold: 5, notifications: { enabled: false } }
      );

      expect(result).toEqual(
        expect.objectContaining({
          count: 1,
          reasons: expect.arrayContaining([
            expect.objectContaining({
              reason: 'Invalid password'
            })
          ])
        })
      );
    });

    test('should trigger notifications after threshold', async () => {
      const config = { 
        failedAttemptThreshold: 3, 
        notifications: { enabled: true, slack: { enabled: false } }
      };

      // Track multiple failed attempts
      for (let i = 0; i < 5; i++) {
        SuspiciousActivityMonitor.trackFailedAttempt(
          '127.0.0.1', '/login', 'Invalid password', `req${i}`, config
        );
      }

      // Wait for async operations
      await testUtils.wait(50);

      // The function should have triggered notifications
      // (This would be tested with mocked NotificationService)
    });
  });

  describe('IP Management', () => {
    test('should manually block and unblock IPs', () => {
      const validIP = '192.168.1.100';

      // Block IP
      monitor.blockIP(validIP, 5000); // 5 seconds
      expect(monitor.blockedIPs.has(validIP)).toBe(true);

      // Unblock IP
      const unblocked = monitor.unblockIP(validIP);
      expect(unblocked).toBe(true);
      expect(monitor.blockedIPs.has(validIP)).toBe(false);
    });

    test('should throw error for invalid IP when blocking', () => {
      expect(() => {
        monitor.blockIP('invalid-ip');
      }).toThrow('Invalid IP address format');
    });

    test('should return false when unblocking non-blocked IP', () => {
      const result = monitor.unblockIP('192.168.1.1');
      expect(result).toBe(false);
    });
  });

  describe('Statistics', () => {
    test('should return monitoring statistics', () => {
      // Add some test data
      monitor.requestTracker.set('127.0.0.1', {
        hourlyCount: 10,
        lastHour: Date.now(),
        endpoints: new Set(['/test']),
        userAgents: new Set(['Mozilla/5.0']),
        firstSeen: Date.now(),
        methods: new Set(['GET']),
        countries: new Set(),
        lastActivity: Date.now()
      });
      
      monitor.blockedIPs.add('192.168.1.1');
      monitor.failedAttempts.set('127.0.0.1:/login', { count: 3 });

      const stats = monitor.getStatistics();

      expect(stats).toEqual({
        activeIPs: 1,
        blockedIPs: 1,
        failedAttempts: 1,
        timestamp: expect.any(String)
      });
    });
  });

  describe('Cleanup', () => {
    test('should clean up old tracking data', () => {
      const oldTimestamp = Date.now() - (25 * 60 * 60 * 1000); // 25 hours ago
      
      // Add old data
      monitor.requestTracker.set('127.0.0.1', {
        firstSeen: oldTimestamp,
        lastActivity: oldTimestamp
      });
      
      monitor.failedAttempts.set('127.0.0.1:/login', {
        lastAttempt: oldTimestamp - (2 * 60 * 60 * 1000) // 2 hours ago
      });

      // Run cleanup
      monitor.cleanupTrackingData();

      // Old data should be removed
      expect(monitor.requestTracker.has('127.0.0.1')).toBe(false);
      expect(monitor.failedAttempts.has('127.0.0.1:/login')).toBe(false);
    });
  });
});