const SecurityShield = require('./lib/SecurityShield');
const SuspiciousActivityMonitor = require('./lib/SuspiciousActivityMonitor');
const SecurityConfig = require('./lib/SecurityConfig');
const SecurityUtils = require('./lib/SecurityUtils');

/**
 * Main entry point for Node Security Shield
 * 
 * @param {Object} options - Configuration options
 * @param {Object} options.security - Security middleware configuration
 * @param {Object} options.monitoring - Suspicious activity monitoring configuration
 * @param {Object} options.notifications - Notification configuration (Slack only)
 * @returns {Object} Security middleware functions
 */
function createSecurityShield(options = {}) {
  const config = new SecurityConfig(options);
  
  // Validate configuration
  const validation = config.validate();
  if (!validation.isValid) {
    console.warn('🚨 Security Shield Configuration Warnings:');
    validation.errors.forEach(error => console.warn(`  - ${error}`));
  }
  
  return {
    // Main security middleware
    securityMiddleware: SecurityShield.createSecurityMiddleware(config.security),
    
    // Suspicious activity monitoring
    suspiciousActivityMiddleware: SuspiciousActivityMonitor.createSuspiciousActivityMiddleware(config.monitoring),
    
    // Track failed attempts (for use in auth endpoints)
    trackFailedAttempt: (clientIP, endpoint, reason, requestId) => {
      return SuspiciousActivityMonitor.trackFailedAttempt(clientIP, endpoint, reason, requestId, config.monitoring);
    },
    
    // Utility functions
    utils: SecurityUtils,
    
    // IP validation utilities
    validateIP: SecurityShield.validateIP,
    getSanitizedIP: SecurityShield.getSanitizedIP,
    
    // Configuration helper
    config: config,
    
    // Initialize all security middlewares at once
    initializeAll: function(app) {
      // Apply security middleware first
      this.securityMiddleware(app);
      
      // Then apply suspicious activity monitoring
      app.use(this.suspiciousActivityMiddleware);
      
      console.log('🛡️  Node Security Shield initialized successfully');
      if (config.notifications.slack.enabled) {
        console.log('  ✅ Slack Notifications');
      }
    },
    
    // Get current monitoring statistics
    getStatistics: function() {
      const monitor = new SuspiciousActivityMonitor();
      return monitor.getStatistics();
    },
    
    // Manually block an IP
    blockIP: function(ip, duration) {
      const monitor = new SuspiciousActivityMonitor();
      return monitor.blockIP(ip, duration);
    },
    
    // Unblock an IP
    unblockIP: function(ip) {
      const monitor = new SuspiciousActivityMonitor();
      return monitor.unblockIP(ip);
    }
  };
}

// Export main function and individual components
module.exports = createSecurityShield;
module.exports.SecurityShield = SecurityShield;
module.exports.SuspiciousActivityMonitor = SuspiciousActivityMonitor;
module.exports.SecurityConfig = SecurityConfig;
module.exports.SecurityUtils = SecurityUtils;

// Export configuration helpers
module.exports.createFromEnvironment = SecurityConfig.createFromEnvironment;