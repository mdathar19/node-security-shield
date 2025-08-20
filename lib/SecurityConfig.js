class SecurityConfig {
  constructor(options = {}) {
    this.security = this.createSecurityConfig(options.security || {});
    this.monitoring = this.createMonitoringConfig(options.monitoring || {});
    this.notifications = this.createNotificationConfig(options.notifications || {});
  }

  /**
   * Create security middleware configuration (No rate limiting)
   */
  createSecurityConfig(config) {
    return {
      // Helmet CSP configuration
      csp: {
        defaultSrc: config.csp?.defaultSrc || ["'self'"],
        styleSrc: config.csp?.styleSrc || ["'self'", "'unsafe-inline'"],
        scriptSrc: config.csp?.scriptSrc || ["'self'"],
        imgSrc: config.csp?.imgSrc || ["'self'", "data:", "https:"],
        connectSrc: config.csp?.connectSrc || ["'self'"],
        fontSrc: config.csp?.fontSrc || ["'self'"],
        objectSrc: config.csp?.objectSrc || ["'none'"],
        mediaSrc: config.csp?.mediaSrc || ["'self'"],
        frameSrc: config.csp?.frameSrc || ["'none'"],
        ...config.csp
      },

      // HSTS configuration
      hsts: {
        maxAge: config.hsts?.maxAge || 31536000, // 1 year
        includeSubDomains: config.hsts?.includeSubDomains !== false,
        preload: config.hsts?.preload !== false,
        ...config.hsts
      },

      // CORS configuration
      cors: {
        allowedOrigins: config.cors?.allowedOrigins || 
                       process.env.ALLOWED_ORIGINS?.split(',') || 
                       ['http://localhost:3000'],
        credentials: config.cors?.credentials !== false,
        methods: config.cors?.methods || ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
        allowedHeaders: config.cors?.allowedHeaders || [
          'Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization', 'X-Request-ID'
        ],
        ...config.cors
      },

      // Body parsing limits
      bodyLimit: config.bodyLimit || '10mb',
      parameterLimit: config.parameterLimit || 1000,

      // Compression settings
      compression: config.compression === false ? false : {
        level: config.compression?.level || 6,
        threshold: config.compression?.threshold || 1024,
        ...config.compression
      },

      // Content type validation
      allowedContentTypes: config.allowedContentTypes || [
        'application/json',
        'application/x-www-form-urlencoded',
        'multipart/form-data',
        'text/plain'
      ],

      // Cross-Origin Embedder Policy
      coep: config.coep !== false,

      // IP validation settings
      ipValidation: {
        enabled: config.ipValidation?.enabled !== false,
        strictMode: config.ipValidation?.strictMode || false,
        fallbackIP: config.ipValidation?.fallbackIP || '127.0.0.1'
      }
    };
  }

  /**
   * Create monitoring configuration (No rate limiting)
   */
  createMonitoringConfig(config) {
    return {
      // Detection thresholds
      thresholds: {
        requestsPerHour: config.thresholds?.requestsPerHour || 1000,
        uniqueEndpoints: config.thresholds?.uniqueEndpoints || 50,
        userAgents: config.thresholds?.userAgents || 5,
        authAttempts: config.thresholds?.authAttempts || 20,
        failedAttemptThreshold: config.thresholds?.failedAttemptThreshold || 5,
        ...config.thresholds
      },

      // IP blocking settings
      blockDuration: config.blockDuration || 3600000, // 1 hour in milliseconds

      // Monitoring features
      enableSQLInjectionDetection: config.enableSQLInjectionDetection !== false,
      enableXSSDetection: config.enableXSSDetection !== false,
      enablePathTraversalDetection: config.enablePathTraversalDetection !== false,
      enableBruteForceDetection: config.enableBruteForceDetection !== false,

      // Cleanup settings
      cleanupInterval: config.cleanupInterval || 3600000, // 1 hour
      dataRetentionPeriod: config.dataRetentionPeriod || 86400000, // 24 hours

      ...config
    };
  }

  /**
   * Create notification configuration (Slack only)
   */
  createNotificationConfig(config) {
    return {
      enabled: config.enabled !== false,
      applicationName: config.applicationName || process.env.APP_NAME || 'Node.js Application',

      // Slack notifications only
      slack: {
        enabled: config.slack?.enabled || false,
        webhookUrl: config.slack?.webhookUrl || process.env.SLACK_WEBHOOK_URL,
        mentionUsers: config.slack?.mentionUsers || [],
        mentionChannels: config.slack?.mentionChannels || [],
        ...config.slack
      }
    };
  }

  /**
   * Get environment-specific configuration
   */
  static getEnvironmentConfig() {
    const env = process.env.NODE_ENV || 'development';
    
    const configs = {
      development: {
        security: {
          cors: {
            allowedOrigins: ['http://localhost:3000', 'http://localhost:3001', 'http://127.0.0.1:3000']
          },
          ipValidation: {
            strictMode: false
          }
        },
        monitoring: {
          thresholds: {
            requestsPerHour: 5000, // Higher threshold for development
            authAttempts: 50
          }
        },
        notifications: {
          slack: { enabled: false }
        }
      },

      production: {
        security: {
          hsts: {
            maxAge: 31536000,
            includeSubDomains: true,
            preload: true
          },
          ipValidation: {
            strictMode: true
          }
        },
        monitoring: {
          thresholds: {
            requestsPerHour: 1000,
            authAttempts: 10
          }
        },
        notifications: {
          slack: { enabled: true }
        }
      },

      test: {
        security: {
          ipValidation: {
            strictMode: false
          }
        },
        monitoring: {
          thresholds: {
            requestsPerHour: 10000
          }
        },
        notifications: {
          enabled: false // Disable all notifications in tests
        }
      }
    };

    return configs[env] || configs.development;
  }

  /**
   * Validate configuration
   */
  validate() {
    const errors = [];

    // Validate CORS origins
    if (this.security.cors && this.security.cors.allowedOrigins) {
      this.security.cors.allowedOrigins.forEach(origin => {
        if (origin !== '*' && !origin.match(/^https?:\/\/.+/) && !origin.match(/^http:\/\/localhost:\d+$/)) {
          errors.push(`Invalid CORS origin: ${origin}`);
        }
      });
    }

    // Validate monitoring thresholds
    if (this.monitoring && this.monitoring.thresholds) {
      Object.entries(this.monitoring.thresholds).forEach(([key, value]) => {
        if (typeof value !== 'number' || value <= 0) {
          errors.push(`Invalid monitoring threshold ${key}: must be a positive number`);
        }
      });
    }

    // Validate Slack notification configuration
    if (this.notifications && this.notifications.slack && this.notifications.slack.enabled && !this.notifications.slack.webhookUrl) {
      errors.push('Slack webhook URL is required when Slack notifications are enabled');
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }

  /**
   * Merge with environment-specific configuration
   */
  static createFromEnvironment(userConfig = {}) {
    const envConfig = SecurityConfig.getEnvironmentConfig();
    
    // Deep merge configurations
    const mergedConfig = this.deepMerge(envConfig, userConfig);
    
    return new SecurityConfig(mergedConfig);
  }

  /**
   * Deep merge utility function
   */
  static deepMerge(target, source) {
    const result = { ...target };
    
    for (const key in source) {
      if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
        result[key] = this.deepMerge(target[key] || {}, source[key]);
      } else {
        result[key] = source[key];
      }
    }
    
    return result;
  }
}

module.exports = SecurityConfig;