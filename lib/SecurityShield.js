const helmet = require('helmet');
const cors = require('cors');
const mongoSanitize = require('express-mongo-sanitize');
const compression = require('compression');
const crypto = require('crypto');
const validator = require('validator');

class SecurityShield {
  /**
   * Create comprehensive security middleware
   * @param {Object} config - Security configuration options
   * @returns {Function} Express middleware function
   */
  static createSecurityMiddleware(config = {}) {
    return (app) => {
      // HELMET - Security headers
      app.use(helmet({
        contentSecurityPolicy: {
          directives: {
            defaultSrc: config.csp?.defaultSrc || ["'self'"],
            styleSrc: config.csp?.styleSrc || ["'self'", "'unsafe-inline'"],
            scriptSrc: config.csp?.scriptSrc || ["'self'"],
            imgSrc: config.csp?.imgSrc || ["'self'", "data:", "https:"],
            connectSrc: config.csp?.connectSrc || ["'self'"],
            fontSrc: config.csp?.fontSrc || ["'self'"],
            objectSrc: config.csp?.objectSrc || ["'none'"],
            mediaSrc: config.csp?.mediaSrc || ["'self'"],
            frameSrc: config.csp?.frameSrc || ["'none'"],
          },
        },
        hsts: {
          maxAge: config.hsts?.maxAge || 31536000,
          includeSubDomains: config.hsts?.includeSubDomains !== false,
          preload: config.hsts?.preload !== false
        },
        crossOriginEmbedderPolicy: config.coep !== false
      }));

      // CORS configuration
      const corsOptions = {
        origin: function (origin, callback) {
          const allowedOrigins = config.cors?.allowedOrigins || 
                               process.env.ALLOWED_ORIGINS?.split(',') || 
                               ['http://localhost:3000'];
          
          // Allow requests with no origin (mobile apps, Postman) in development
          if (!origin && process.env.NODE_ENV === 'development') {
            return callback(null, true);
          }
          
          if (!origin || allowedOrigins.includes(origin) || allowedOrigins.includes('*')) {
            callback(null, true);
          } else {
            callback(new Error(`Origin ${origin} not allowed by CORS policy`));
          }
        },
        credentials: config.cors?.credentials !== false,
        optionsSuccessStatus: 200,
        methods: config.cors?.methods || ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
        allowedHeaders: config.cors?.allowedHeaders || [
          'Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization', 'X-Request-ID'
        ]
      };
      app.use(cors(corsOptions));

      // BODY PARSER with limits
      const bodyLimit = config.bodyLimit || '10mb';
      app.use(require('express').json({ 
        limit: bodyLimit,
        verify: (req, res, buf) => {
          // Store raw body for webhook signature verification
          req.rawBody = buf;
        }
      }));
      app.use(require('express').urlencoded({ 
        extended: true, 
        limit: bodyLimit,
        parameterLimit: config.parameterLimit || 1000
      }));

      // MONGO SANITIZATION
      app.use(mongoSanitize({
        replaceWith: '_',
        onSanitize: ({ req, key }) => {
          console.warn(`🚨 Potential NoSQL injection attempt detected: ${key} from IP: ${req.clientIP || req.ip}`);
        }
      }));

      // COMPRESSION
      if (config.compression !== false) {
        app.use(compression({
          level: config.compression?.level || 6,
          threshold: config.compression?.threshold || 1024,
          filter: (req, res) => {
            if (req.headers['x-no-compression']) return false;
            return compression.filter(req, res);
          }
        }));
      }

      // REMOVE FINGERPRINTING HEADERS
      app.disable('x-powered-by');
      app.use((req, res, next) => {
        res.removeHeader('Server');
        next();
      });

      // REQUEST ID & IP DETECTION with IP VALIDATION
      app.use((req, res, next) => {
        // Generate unique request ID
        req.id = crypto.randomBytes(16).toString('hex');
        res.setHeader('X-Request-ID', req.id);
        
        // Better client IP detection
        req.clientIP = req.headers['cf-connecting-ip'] || 
                      req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
                      req.headers['x-real-ip'] ||
                      req.connection.remoteAddress ||
                      req.socket.remoteAddress ||
                      req.ip;
        
        // Validate and sanitize IP format
        if (req.clientIP) {
          // Remove any potential malicious characters
          req.clientIP = req.clientIP.replace(/[^0-9a-fA-F:\.]/g, '');
          
          // Validate IP format (both IPv4 and IPv6)
          if (!validator.isIP(req.clientIP)) {
            console.warn(`🚨 Invalid IP format detected: ${req.clientIP}, falling back to req.ip`);
            req.clientIP = req.ip;
            
            // Validate fallback IP as well
            if (req.clientIP && !validator.isIP(req.clientIP)) {
              req.clientIP = '127.0.0.1'; // Safe fallback
            }
          }
        } else {
          req.clientIP = '127.0.0.1'; // Safe fallback
        }
        
        next();
      });

      // INPUT SANITIZATION MIDDLEWARE (Basic XSS protection)
      app.use((req, res, next) => {
        // Check for suspicious patterns in query parameters and body
        const suspiciousPatterns = [
          /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
          /javascript:/gi,
          /vbscript:/gi,
          /onload\s*=/gi,
          /onerror\s*=/gi,
          /eval\s*\(/gi,
          /expression\s*\(/gi
        ];

        const sanitizeString = (str) => {
          if (typeof str !== 'string') return str;
          
          // Basic XSS protection
          return str
            .replace(/[<>]/g, '') // Remove < and >
            .replace(/javascript:/gi, '') // Remove javascript: protocol
            .replace(/vbscript:/gi, '') // Remove vbscript: protocol
            .replace(/on\w+\s*=/gi, '') // Remove event handlers
            .trim();
        };

        const sanitizeObject = (obj) => {
          if (!obj || typeof obj !== 'object') return obj;
          
          for (const key in obj) {
            if (obj.hasOwnProperty(key)) {
              if (typeof obj[key] === 'string') {
                obj[key] = sanitizeString(obj[key]);
              } else if (typeof obj[key] === 'object' && obj[key] !== null) {
                sanitizeObject(obj[key]);
              }
            }
          }
        };

        // Sanitize query parameters
        if (req.query && Object.keys(req.query).length > 0) {
          sanitizeObject(req.query);
        }

        // Sanitize body
        if (req.body && Object.keys(req.body).length > 0) {
          sanitizeObject(req.body);
        }

        next();
      });

      // CONTENT-TYPE VALIDATION
      app.use((req, res, next) => {
        if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
          const contentType = req.get('Content-Type');
          const allowedTypes = config.allowedContentTypes || [
            'application/json',
            'application/x-www-form-urlencoded',
            'multipart/form-data',
            'text/plain'
          ];
          
          if (contentType && !allowedTypes.some(type => contentType.includes(type))) {
            return res.status(415).json({
              error: 'Unsupported Media Type',
              code: 'UNSUPPORTED_CONTENT_TYPE',
              requestId: req.id
            });
          }
        }
        next();
      });

      console.log('🛡️  Security middleware initialized successfully');
    };
  }

  /**
   * Additional IP validation utility
   * @param {string} ip - IP address to validate
   * @returns {boolean} - Whether IP is valid
   */
  static validateIP(ip) {
    if (!ip || typeof ip !== 'string') {
      return false;
    }
    
    // Remove any potential malicious characters
    const cleanIP = ip.replace(/[^0-9a-fA-F:\.]/g, '');
    
    // Validate using validator library
    return validator.isIP(cleanIP);
  }

  /**
   * Get sanitized IP from request
   * @param {Object} req - Express request object
   * @returns {string} - Sanitized IP address
   */
  static getSanitizedIP(req) {
    const potentialIPs = [
      req.headers['cf-connecting-ip'],
      req.headers['x-forwarded-for']?.split(',')[0]?.trim(),
      req.headers['x-real-ip'],
      req.connection?.remoteAddress,
      req.socket?.remoteAddress,
      req.ip
    ];

    for (const ip of potentialIPs) {
      if (ip && this.validateIP(ip)) {
        return ip.replace(/[^0-9a-fA-F:\.]/g, '');
      }
    }

    return '127.0.0.1'; // Safe fallback
  }
}

module.exports = SecurityShield;