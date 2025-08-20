# 🛡️ Node Security Shield

A comprehensive Node.js security middleware package with intelligent threat detection and automated security protections. Designed to protect your applications from common web vulnerabilities and suspicious activities.

## ✨ Features

- 🔒 **Security Headers** - Helmet.js integration with Content Security Policy
- 🌐 **CORS Protection** - Configurable cross-origin resource sharing
- 🛡️ **XSS Protection** - Input sanitization and script injection prevention
- 💉 **SQL Injection Protection** - Pattern detection and blocking
- 🍃 **NoSQL Injection Protection** - MongoDB query sanitization
- 📁 **Path Traversal Protection** - Directory traversal attack prevention
- 🔍 **IP Validation & Sanitization** - Robust client IP detection and validation
- 🤖 **Bot Detection** - Suspicious user agent and behavior analysis
- 🚨 **Threat Monitoring** - Real-time suspicious activity detection
- 📱 **Slack Notifications** - Instant security alerts
- 📊 **Request Compression** - Gzip compression for better performance
- 📏 **Body Parsing Limits** - Configurable request size limits

## 🚀 Installation

```bash
npm install node-security-shield
```

## 📋 Dependencies

- **helmet** - Security headers
- **cors** - Cross-origin resource sharing
- **express-mongo-sanitize** - NoSQL injection prevention
- **compression** - Response compression
- **validator** - Input validation utilities

## 🔧 Quick Start

### Basic Usage

```javascript
const express = require('express');
const createSecurityShield = require('node-security-shield');

const app = express();

// Initialize with default settings
const securityShield = createSecurityShield();

// Apply all security middlewares
securityShield.initializeAll(app);

// Your routes
app.get('/', (req, res) => {
  res.json({ 
    message: 'Protected by Security Shield!',
    requestId: req.id,
    clientIP: req.clientIP
  });
});

app.listen(3000, () => {
  console.log('🚀 Server running on port 3000');
});
```

### Advanced Configuration

```javascript
const securityShield = createSecurityShield({
  security: {
    cors: {
      allowedOrigins: [
        'https://yourdomain.com',
        'https://app.yourdomain.com'
      ],
      credentials: true
    },
    bodyLimit: '5mb',
    compression: {
      level: 6,
      threshold: 1024
    },
    csp: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      scriptSrc: ["'self'", "https://cdn.jsdelivr.net"]
    }
  },
  monitoring: {
    thresholds: {
      requestsPerHour: 1000,    // Detect if IP makes >1000 requests/hour
      uniqueEndpoints: 50,      // Detect if IP scans >50 different endpoints
      authAttempts: 10,         // Detect >10 auth attempts from same IP
      userAgents: 5            // Detect if IP uses >5 different user agents
    },
    blockDuration: 3600000,     // Block suspicious IPs for 1 hour
    enableSQLInjectionDetection: true,
    enableXSSDetection: true,
    enablePathTraversalDetection: true,
    enableBruteForceDetection: true
  },
  notifications: {
    enabled: true,
    applicationName: 'My API Server',
    slack: {
      enabled: true,
      webhookUrl: process.env.SLACK_WEBHOOK_URL,
      mentionUsers: ['U1234567890'],  // Slack user IDs to mention
      mentionChannels: ['here']       // @here, @channel for critical alerts
    }
  }
});

securityShield.initializeAll(app);
```

## 🔐 Security Features Explained

### 1. Threat Detection (NOT Rate Limiting)

The monitoring system detects **suspicious patterns** without affecting legitimate users:

```javascript
// ✅ Normal user behavior - NO blocking
// User A: 500 requests to /api/users over 1 hour = ALLOWED
// User B: 800 requests to /api/products over 1 hour = ALLOWED

// 🚨 Suspicious behavior - DETECTED & BLOCKED
// Bot: 1200 requests scanning /admin, /config, /backup = BLOCKED
// Attacker: 50 failed login attempts = BLOCKED
// Scanner: Accessing 100+ different endpoints = BLOCKED
```

**Key Difference:**
- **Rate Limiting**: Blocks everyone after X requests
- **Threat Detection**: Only blocks IPs showing attack patterns

### 2. IP Validation & Sanitization

```javascript
// Automatic IP detection and validation
app.use((req, res, next) => {
  console.log('Validated IP:', req.clientIP); // Always a valid IP
  console.log('Request ID:', req.id);         // Unique request identifier
});

// Manual IP validation
const isValidIP = securityShield.validateIP('192.168.1.1'); // true
const cleanIP = securityShield.getSanitizedIP(req);         // Clean IP from request
```

### 3. Failed Authentication Tracking

```javascript
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  const isValid = await authenticateUser(username, password);
  
  if (!isValid) {
    // Track failed attempt - triggers alerts after threshold
    securityShield.trackFailedAttempt(
      req.clientIP,
      req.path,
      'Invalid credentials',
      req.id
    );
    
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  res.json({ message: 'Login successful' });
});
```

## 📊 Monitoring & Management

### Get Security Statistics

```javascript
app.get('/admin/security-stats', (req, res) => {
  const stats = securityShield.getStatistics();
  res.json(stats);
  
  // Returns:
  // {
  //   activeIPs: 245,
  //   blockedIPs: 12,
  //   failedAttempts: 38,
  //   timestamp: "2024-01-15T10:30:00.000Z"
  // }
});
```

### Manual IP Management

```javascript
// Block an IP manually
app.post('/admin/block-ip', (req, res) => {
  const { ip, duration = 3600000 } = req.body; // 1 hour default
  
  if (!securityShield.validateIP(ip)) {
    return res.status(400).json({ error: 'Invalid IP format' });
  }
  
  securityShield.blockIP(ip, duration);
  res.json({ message: `IP ${ip} blocked for ${duration / 1000} seconds` });
});

// Unblock an IP
app.post('/admin/unblock-ip', (req, res) => {
  const { ip } = req.body;
  const unblocked = securityShield.unblockIP(ip);
  
  res.json({ 
    message: unblocked ? `IP ${ip} unblocked` : `IP ${ip} was not blocked` 
  });
});
```

## 🔔 Slack Notifications

### Setup Slack Webhook

1. Go to your Slack workspace
2. Create a new app or use existing one
3. Add "Incoming Webhooks" feature
4. Copy the webhook URL
5. Set environment variable: `SLACK_WEBHOOK_URL=your_webhook_url`

### Notification Examples

```javascript
// Critical Alert Example:
🛡️ Security Alert: SQL Injection Attempt
📊 Severity: 🚨 CRITICAL
🕒 Time: 2024-01-15T10:30:00.000Z
📋 Details:
  - Client IP: 192.168.1.100
  - Endpoint: /api/users
  - Method: POST
  - User Agent: sqlmap/1.6.12
  - Request ID: a1b2c3d4e5f6

// High Alert Example:
🛡️ Security Alert: High Request Volume
📊 Severity: 🔴 HIGH
🕒 Time: 2024-01-15T10:30:00.000Z
📋 Details:
  - Requests per Hour: 1500
  - Client IP: 10.0.0.50
  - Current Endpoint: /api/scan
  - Threshold: 1000
```

## ⚙️ Configuration Options

### Security Configuration

```javascript
{
  security: {
    // Content Security Policy
    csp: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      // ... more CSP directives
    },
    
    // CORS settings
    cors: {
      allowedOrigins: ['https://yourdomain.com'],
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE'],
      allowedHeaders: ['Content-Type', 'Authorization']
    },
    
    // HTTP Strict Transport Security
    hsts: {
      maxAge: 31536000,      // 1 year
      includeSubDomains: true,
      preload: true
    },
    
    // Body parsing limits
    bodyLimit: '10mb',
    parameterLimit: 1000,
    
    // Compression settings
    compression: {
      level: 6,              // 1-9, higher = better compression
      threshold: 1024        // Only compress responses > 1KB
    },
    
    // IP validation
    ipValidation: {
      enabled: true,
      strictMode: false,     // If true, rejects invalid IPs
      fallbackIP: '127.0.0.1'
    }
  }
}
```

### Monitoring Configuration

```javascript
{
  monitoring: {
    // Detection thresholds (NOT rate limits!)
    thresholds: {
      requestsPerHour: 1000,     // Detect suspicious volume
      uniqueEndpoints: 50,       // Detect endpoint scanning
      userAgents: 5,             // Detect bot behavior
      authAttempts: 20,          // Detect brute force
      failedAttemptThreshold: 5  // Failed auth threshold
    },
    
    // How long to block suspicious IPs
    blockDuration: 3600000,      // 1 hour in milliseconds
    
    // Feature toggles
    enableSQLInjectionDetection: true,
    enableXSSDetection: true,
    enablePathTraversalDetection: true,
    enableBruteForceDetection: true,
    
    // Cleanup settings
    cleanupInterval: 3600000,    // Clean old data every hour
    dataRetentionPeriod: 86400000 // Keep data for 24 hours
  }
}
```

### Notification Configuration

```javascript
{
  notifications: {
    enabled: true,
    applicationName: 'My API Server',
    
    slack: {
      enabled: true,
      webhookUrl: process.env.SLACK_WEBHOOK_URL,
      mentionUsers: ['U1234567890', 'U0987654321'], // Slack user IDs
      mentionChannels: ['here', 'channel']          // @here, @channel
    }
  }
}
```

## 🌍 Environment-Based Configuration

```javascript
// Automatically adjusts settings based on NODE_ENV
const securityShield = createSecurityShield.createFromEnvironment({
  // Your custom overrides here
  notifications: {
    slack: {
      enabled: true,
      webhookUrl: process.env.SLACK_WEBHOOK_URL
    }
  }
});

// Development: More lenient thresholds, no Slack alerts
// Production: Strict security, Slack alerts enabled
// Test: Notifications disabled, high thresholds
```

## 🚨 Detection Patterns

The system automatically detects these suspicious activities:

### 1. High Request Volume
- **Trigger**: IP exceeds hourly request threshold
- **Indicates**: DDoS attack, aggressive scraping
- **Action**: Block IP, send alert

### 2. Endpoint Scanning
- **Trigger**: IP accesses many unique endpoints rapidly
- **Indicates**: Reconnaissance, vulnerability scanning
- **Action**: Block IP, send alert

### 3. Multiple User Agents
- **Trigger**: Same IP uses multiple user agent strings
- **Indicates**: Bot rotation, evasion attempts
- **Action**: Flag as suspicious, send alert

### 4. Suspicious User Agents
- **Trigger**: User agent contains security tool names
- **Patterns**: `sqlmap`, `nikto`, `burp`, `nmap`, etc.
- **Action**: Flag request, send alert

### 5. SQL Injection Attempts
- **Trigger**: Request contains SQL injection patterns
- **Patterns**: `UNION SELECT`, `DROP TABLE`, `' OR 1=1`, etc.
- **Action**: Block immediately, send critical alert

### 6. XSS Attempts
- **Trigger**: Request contains script injection patterns
- **Patterns**: `<script>`, `javascript:`, `onerror=`, etc.
- **Action**: Block request, send alert

### 7. Path Traversal
- **Trigger**: Request contains directory traversal patterns
- **Patterns**: `../`, `..\\`, URL encoded variants
- **Action**: Block request, send alert

### 8. Brute Force Attacks
- **Trigger**: Multiple failed auth attempts from same IP
- **Indicates**: Password guessing, credential stuffing
- **Action**: Block IP after threshold, send alert

## 🛠️ API Reference

### Main Functions

```javascript
const securityShield = createSecurityShield(options);

// Initialize all middlewares
securityShield.initializeAll(app);

// Individual middleware access
securityShield.securityMiddleware(app);
app.use(securityShield.suspiciousActivityMiddleware);

// Utility functions
securityShield.validateIP(ip);
securityShield.getSanitizedIP(req);
securityShield.trackFailedAttempt(ip, endpoint, reason, requestId);

// Management functions
securityShield.getStatistics();
securityShield.blockIP(ip, duration);
securityShield.unblockIP(ip);
```

### Request Object Enhancements

After applying the middleware, request objects include:

```javascript
app.use((req, res, next) => {
  console.log({
    id: req.id,                    // Unique request ID
    clientIP: req.clientIP,        // Validated client IP
    suspiciousScore: req.suspiciousScore,     // 0-10 threat score
    suspiciousPatterns: req.suspiciousPatterns, // Detected threats
    clientTracker: req.clientTracker          // IP tracking data
  });
  next();
});
```

## 🔧 Troubleshooting

### Common Issues

**1. CORS Errors**
```javascript
// Solution: Add your frontend domain to allowedOrigins
cors: {
  allowedOrigins: ['https://yourfrontend.com', 'http://localhost:3000']
}
```

**2. Slack Notifications Not Working**
```bash
# Check webhook URL
echo $SLACK_WEBHOOK_URL

# Verify webhook format
https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX
```

**3. Legitimate Traffic Being Blocked**
```javascript
// Increase thresholds for your use case
thresholds: {
  requestsPerHour: 2000,  // Increase if you have high-traffic APIs
  uniqueEndpoints: 100    // Increase for SPA applications
}
```

**4. IP Validation Issues**
```javascript
// Check IP detection
app.use((req, res, next) => {
  console.log('Detected IP:', req.clientIP);
  console.log('Original IP:', req.ip);
  console.log('X-Forwarded-For:', req.headers['x-forwarded-for']);
  next();
});
```

## 📈 Performance Impact

- **Memory Usage**: ~10-50MB depending on traffic (includes cleanup)
- **CPU Overhead**: <1% for typical applications
- **Response Time**: +1-3ms per request
- **Storage**: In-memory only, automatic cleanup

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- 📧 Email: support@yourorg.com
- 🐛 Issues: [GitHub Issues](https://github.com/athar/node-security-shield/issues)
- 📖 Documentation: [GitHub Wiki](https://github.com/athar/node-security-shield/wiki)

---

**Made with ❤️ for Node.js security**