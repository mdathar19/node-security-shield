const NotificationService = require('./NotificationService');
const validator = require('validator');

class SuspiciousActivityMonitor {
  constructor() {
    this.requestTracker = new Map();
    this.failedAttempts = new Map();
    this.blockedIPs = new Set();
    
    // Start cleanup interval
    this.startCleanupInterval();
  }

  /**
   * Create suspicious activity monitoring middleware
   * @param {Object} config - Configuration options
   * @returns {Function} Express middleware
   */
  static createSuspiciousActivityMiddleware(config = {}) {
    const monitor = new SuspiciousActivityMonitor();
    
    return (req, res, next) => {
      monitor.analyzeRequest(req, res, next, config);
    };
  }

  /**
   * Analyze incoming request for suspicious patterns
   */
  analyzeRequest(req, res, next, config) {
    const clientIP = req.clientIP || req.ip;
    const userAgent = req.get('User-Agent') || 'Unknown';
    const endpoint = req.path;
    const method = req.method;
    const requestId = req.id;

    // Check if IP is blocked
    if (this.blockedIPs.has(clientIP)) {
      return res.status(429).json({
        error: 'IP temporarily blocked due to suspicious activity',
        code: 'IP_BLOCKED',
        requestId: requestId
      });
    }

    // Get current timestamp
    const now = Date.now();
    const currentHour = Math.floor(now / (1000 * 60 * 60));

    // Initialize tracking for this IP if not exists
    if (!this.requestTracker.has(clientIP)) {
      this.requestTracker.set(clientIP, {
        hourlyCount: 0,
        lastHour: currentHour,
        endpoints: new Set(),
        userAgents: new Set(),
        firstSeen: now,
        methods: new Set(),
        countries: new Set(),
        lastActivity: now
      });
    }

    const tracker = this.requestTracker.get(clientIP);
    
    // Reset hourly counter if new hour
    if (tracker.lastHour !== currentHour) {
      tracker.hourlyCount = 0;
      tracker.lastHour = currentHour;
      tracker.endpoints.clear();
    }

    // Update tracking data
    tracker.hourlyCount++;
    tracker.endpoints.add(endpoint);
    tracker.userAgents.add(userAgent);
    tracker.methods.add(method);
    tracker.lastActivity = now;

    // Suspicious activity detection patterns
    const suspiciousPatterns = this.detectSuspiciousPatterns(
      tracker, clientIP, userAgent, endpoint, method, requestId, req, config
    );

    // Handle high-severity threats immediately
    const highSeverityPatterns = suspiciousPatterns.filter(p => p.severity === 'critical');
    if (highSeverityPatterns.length > 0) {
      this.blockedIPs.add(clientIP);
      setTimeout(() => this.blockedIPs.delete(clientIP), config.blockDuration || 3600000); // 1 hour default
      
      return res.status(429).json({
        error: 'Request blocked due to suspicious activity',
        code: 'SUSPICIOUS_ACTIVITY_BLOCKED',
        requestId: requestId
      });
    }

    // Send notifications for detected patterns
    suspiciousPatterns.forEach(pattern => {
      NotificationService.sendNotification(pattern.type, pattern.details, pattern.severity, config.notifications);
    });

    // Add suspicious data to request object
    req.suspiciousScore = suspiciousPatterns.length;
    req.suspiciousPatterns = suspiciousPatterns;
    req.clientTracker = tracker;

    next();
  }

  /**
   * Detect various suspicious patterns
   */
  detectSuspiciousPatterns(tracker, clientIP, userAgent, endpoint, method, requestId, req, config) {
    const patterns = [];
    const thresholds = config.thresholds || {};

    // Pattern 1: High request volume (DDoS/Rate limit bypass)
    const requestThreshold = thresholds.requestsPerHour || 1000;
    if (tracker.hourlyCount > requestThreshold) {
      patterns.push({
        type: 'High Request Volume',
        severity: tracker.hourlyCount > requestThreshold * 3 ? 'critical' : 'high',
        details: {
          'Requests per Hour': tracker.hourlyCount,
          'Client IP': clientIP,
          'Current Endpoint': endpoint,
          'User Agent': userAgent.substring(0, 100),
          'Request ID': requestId,
          'Threshold': requestThreshold
        }
      });
    }

    // Pattern 2: Endpoint scanning/reconnaissance
    const endpointThreshold = thresholds.uniqueEndpoints || 50;
    if (tracker.endpoints.size > endpointThreshold && tracker.hourlyCount > 100) {
      patterns.push({
        type: 'Endpoint Scanning',
        severity: 'high',
        details: {
          'Unique Endpoints': tracker.endpoints.size,
          'Total Requests': tracker.hourlyCount,
          'Client IP': clientIP,
          'Sample Endpoints': Array.from(tracker.endpoints).slice(0, 10).join(', '),
          'Request ID': requestId
        }
      });
    }

    // Pattern 3: Multiple User Agents (Bot behavior)
    const userAgentThreshold = thresholds.userAgents || 5;
    if (tracker.userAgents.size > userAgentThreshold) {
      patterns.push({
        type: 'Multiple User Agents',
        severity: 'medium',
        details: {
          'User Agent Count': tracker.userAgents.size,
          'Client IP': clientIP,
          'Current User Agent': userAgent.substring(0, 100),
          'Request ID': requestId
        }
      });
    }

    // Pattern 4: Suspicious User Agent strings
    const suspiciousUAPatterns = [
      /bot/i, /crawler/i, /spider/i, /scraper/i,
      /hack/i, /exploit/i, /scan/i, /test/i,
      /python-requests/i, /curl/i, /wget/i, /postman/i,
      /nikto/i, /sqlmap/i, /nmap/i, /masscan/i,
      /burp/i, /owasp/i, /zaproxy/i
    ];

    const legitimateUserAgents = [
      'Googlebot', 'Bingbot', 'Slackbot', 'facebookexternalhit',
      'WhatsApp', 'LinkedInBot', 'axios', 'node-fetch'
    ];

    const hasSuspiciousUA = suspiciousUAPatterns.some(pattern => pattern.test(userAgent));
    const isLegitimate = legitimateUserAgents.some(legitimate => userAgent.includes(legitimate));

    if (hasSuspiciousUA && !isLegitimate) {
      patterns.push({
        type: 'Suspicious User Agent',
        severity: 'medium',
        details: {
          'User Agent': userAgent.substring(0, 200),
          'Client IP': clientIP,
          'Endpoint': endpoint,
          'Request ID': requestId
        }
      });
    }

    // Pattern 5: SQL Injection attempts
    const sqlInjectionPatterns = [
      /(\bunion\s+(all\s+)?select)|(\bselect\s+.+\bfrom\s+)/i,
      /(\bdrop\s+table)|(\bdelete\s+from)|(\binsert\s+into)/i,
      /(--|#|\/\*|\*\/)/,
      /(\bor\s+1\s*=\s*1)|(\band\s+1\s*=\s*1)/i,
      /(';\s*(drop|delete|insert|update|create))/i
    ];

    const checkSQLInjection = (str) => {
      return sqlInjectionPatterns.some(pattern => pattern.test(str));
    };

    const queryString = req.originalUrl;
    const bodyContent = JSON.stringify(req.body || {});
    
    if (checkSQLInjection(queryString) || checkSQLInjection(bodyContent)) {
      patterns.push({
        type: 'SQL Injection Attempt',
        severity: 'critical',
        details: {
          'Client IP': clientIP,
          'Endpoint': endpoint,
          'Method': method,
          'User Agent': userAgent.substring(0, 100),
          'Request ID': requestId,
          'Query String': queryString.substring(0, 200),
          'Body Sample': bodyContent.substring(0, 200)
        }
      });
    }

    // Pattern 6: XSS attempts
    const xssPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /javascript:/gi,
      /vbscript:/gi,
      /onload\s*=/gi,
      /onerror\s*=/gi,
      /<iframe/gi,
      /<object/gi,
      /<embed/gi
    ];

    const checkXSS = (str) => {
      return xssPatterns.some(pattern => pattern.test(str));
    };

    if (checkXSS(queryString) || checkXSS(bodyContent)) {
      patterns.push({
        type: 'XSS Attempt',
        severity: 'high',
        details: {
          'Client IP': clientIP,
          'Endpoint': endpoint,
          'Method': method,
          'User Agent': userAgent.substring(0, 100),
          'Request ID': requestId,
          'Detected In': checkXSS(queryString) ? 'Query String' : 'Request Body'
        }
      });
    }

    // Pattern 7: Path traversal attempts
    const pathTraversalPatterns = [
      /\.\.\//g,
      /\.\.\\/g,
      /\.\.%2f/gi,
      /\.\.%5c/gi,
      /%2e%2e%2f/gi,
      /%2e%2e%5c/gi
    ];

    const hasPathTraversal = pathTraversalPatterns.some(pattern => pattern.test(endpoint));
    
    if (hasPathTraversal) {
      patterns.push({
        type: 'Path Traversal Attempt',
        severity: 'high',
        details: {
          'Client IP': clientIP,
          'Endpoint': endpoint,
          'Method': method,
          'User Agent': userAgent.substring(0, 100),
          'Request ID': requestId
        }
      });
    }

    // Pattern 8: Brute force detection (multiple methods on auth endpoints)
    const authEndpoints = ['/login', '/auth', '/signin', '/signup', '/register', '/password', '/reset'];
    const isAuthEndpoint = authEndpoints.some(authEp => endpoint.toLowerCase().includes(authEp));
    
    if (isAuthEndpoint && tracker.hourlyCount > (thresholds.authAttempts || 20)) {
      patterns.push({
        type: 'Potential Brute Force Attack',
        severity: 'high',
        details: {
          'Client IP': clientIP,
          'Auth Endpoint': endpoint,
          'Attempts This Hour': tracker.hourlyCount,
          'Methods Used': Array.from(tracker.methods).join(', '),
          'Request ID': requestId
        }
      });
    }

    return patterns;
  }

  /**
   * Track failed authentication attempts
   */
  static trackFailedAttempt(clientIP, endpoint, reason, requestId, config = {}) {
    const monitor = new SuspiciousActivityMonitor();
    const now = Date.now();
    const key = `${clientIP}:${endpoint}`;

    if (!monitor.failedAttempts.has(key)) {
      monitor.failedAttempts.set(key, {
        count: 0,
        lastAttempt: now,
        reasons: [],
        firstAttempt: now
      });
    }

    const attempts = monitor.failedAttempts.get(key);
    attempts.count++;
    attempts.lastAttempt = now;
    attempts.reasons.push({
      reason: reason,
      timestamp: now
    });

    // Keep only last 10 reasons
    if (attempts.reasons.length > 10) {
      attempts.reasons = attempts.reasons.slice(-10);
    }

    const threshold = config.failedAttemptThreshold || 5;
    
    // Alert on multiple failed attempts
    if (attempts.count >= threshold) {
      const severity = attempts.count >= threshold * 2 ? 'critical' : 'high';
      
      NotificationService.sendNotification('Failed Authentication Attempts', {
        'Client IP': clientIP,
        'Endpoint': endpoint,
        'Failed Attempts': attempts.count,
        'Time Span': `${Math.floor((now - attempts.firstAttempt) / 60000)} minutes`,
        'Recent Reasons': attempts.reasons.slice(-3).map(r => r.reason).join(', '),
        'Request ID': requestId
      }, severity, config.notifications);

      // Temporarily block IP after too many failed attempts
      if (attempts.count >= threshold * 2) {
        monitor.blockedIPs.add(clientIP);
        setTimeout(() => monitor.blockedIPs.delete(clientIP), config.blockDuration || 3600000);
      }
    }

    return attempts;
  }

  /**
   * Start periodic cleanup of tracking data
   */
  startCleanupInterval() {
    setInterval(() => this.cleanupTrackingData(), 1000 * 60 * 60); // Run every hour
  }

  /**
   * Clean up old tracking data to prevent memory leaks
   */
  cleanupTrackingData() {
    const now = Date.now();
    const oneHourAgo = now - (1000 * 60 * 60);
    const oneDayAgo = now - (1000 * 60 * 60 * 24);

    // Clean request tracker (remove data older than 24 hours)
    for (const [ip, data] of this.requestTracker.entries()) {
      if (data.firstSeen < oneDayAgo) {
        this.requestTracker.delete(ip);
      }
    }

    // Clean failed attempts (remove data older than 1 hour)
    for (const [key, data] of this.failedAttempts.entries()) {
      if (data.lastAttempt < oneHourAgo) {
        this.failedAttempts.delete(key);
      }
    }

    console.log(`🧹 Cleaned up tracking data. Active IPs: ${this.requestTracker.size}, Failed attempts: ${this.failedAttempts.size}`);
  }

  /**
   * Get current statistics
   */
  getStatistics() {
    return {
      activeIPs: this.requestTracker.size,
      blockedIPs: this.blockedIPs.size,
      failedAttempts: this.failedAttempts.size,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Manually block an IP address
   */
  blockIP(ip, duration = 3600000) {
    if (!validator.isIP(ip)) {
      throw new Error('Invalid IP address format');
    }
    
    this.blockedIPs.add(ip);
    setTimeout(() => this.blockedIPs.delete(ip), duration);
    console.log(`🚫 Manually blocked IP: ${ip} for ${duration / 1000} seconds`);
  }

  /**
   * Unblock an IP address
   */
  unblockIP(ip) {
    if (this.blockedIPs.has(ip)) {
      this.blockedIPs.delete(ip);
      console.log(`✅ Unblocked IP: ${ip}`);
      return true;
    }
    return false;
  }
}

module.exports = SuspiciousActivityMonitor;