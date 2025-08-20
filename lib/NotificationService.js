class NotificationService {
  /**
   * Send security alert notification via Slack only
   * @param {string} activityType - Type of suspicious activity
   * @param {Object} details - Activity details
   * @param {string} severity - Severity level (low, medium, high, critical)
   * @param {Object} config - Notification configuration
   */
  static async sendNotification(activityType, details, severity = 'medium', config = {}) {
    if (!config || !config.enabled) {
      return;
    }

    const severityEmojis = {
      low: '🟡',
      medium: '🟠',
      high: '🔴',
      critical: '🚨'
    };

    const timestamp = new Date().toISOString();
    
    // Format details into readable text
    const detailsText = Object.entries(details)
      .map(([key, value]) => `• *${key}:* ${value}`)
      .join('\n');

    const notification = {
      activityType,
      severity: `${severityEmojis[severity]} ${severity.toUpperCase()}`,
      details: detailsText,
      timestamp,
      application: config.applicationName || 'Node.js Application'
    };

    // Send to Slack only
    try {
      if (config.slack?.enabled && config.slack?.webhookUrl) {
        await this.sendSlackNotification(notification, config.slack);
      }

      // Console logging (always enabled for debugging)
      this.logToConsole(notification);
    } catch (error) {
      console.error('🚨 Error sending security notifications:', error.message);
    }
  }

  /**
   * Send Slack notification
   */
  static async sendSlackNotification(notification, slackConfig) {
    try {
      const payload = {
        text: `🛡️ Security Alert: ${notification.activityType}`,
        blocks: [
          {
            type: 'header',
            text: {
              type: 'plain_text',
              text: `🛡️ Security Alert: ${notification.activityType}`
            }
          },
          {
            type: 'section',
            fields: [
              {
                type: 'mrkdwn',
                text: `*Severity:* ${notification.severity}`
              },
              {
                type: 'mrkdwn',
                text: `*Application:* ${notification.application}`
              },
              {
                type: 'mrkdwn',
                text: `*Time:* ${notification.timestamp}`
              }
            ]
          },
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `*Details:*\n${notification.details}`
            }
          }
        ]
      };

      // Add mentions for high/critical alerts
      const severityLevel = notification.severity.toLowerCase().split(' ')[1];
      if (['high', 'critical'].includes(severityLevel)) {
        if (slackConfig.mentionUsers && slackConfig.mentionUsers.length > 0) {
          payload.text += ` ${slackConfig.mentionUsers.map(user => `<@${user}>`).join(' ')}`;
        }
        if (slackConfig.mentionChannels && slackConfig.mentionChannels.length > 0) {
          payload.text += ` ${slackConfig.mentionChannels.map(channel => `<!${channel}>`).join(' ')}`;
        }
      }

      const response = await fetch(slackConfig.webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload)
      });

      if (response.ok) {
        console.log('✅ Slack notification sent successfully');
      } else {
        console.error('❌ Failed to send Slack notification:', response.status, response.statusText);
      }
    } catch (error) {
      console.error('🚨 Error sending Slack notification:', error.message);
    }
  }

  /**
   * Log notification to console
   */
  static logToConsole(notification) {
    const logLevel = notification.severity.toLowerCase().includes('critical') ? 'error' :
                    notification.severity.toLowerCase().includes('high') ? 'warn' : 'info';
    
    console[logLevel](`
🛡️  SECURITY ALERT: ${notification.activityType}
📊 Severity: ${notification.severity}
🕒 Time: ${notification.timestamp}
📋 Details:
${notification.details.replace(/\*/g, '').replace(/•/g, '  -')}
    `);
  }

  /**
   * Rate limit notifications to prevent spam (for internal use only)
   */
  static rateLimitedNotification = (() => {
    const notificationCache = new Map();
    const RATE_LIMIT_WINDOW = 5 * 60 * 1000; // 5 minutes
    const MAX_NOTIFICATIONS_PER_TYPE = 3;

    return async function(activityType, details, severity, config) {
      const now = Date.now();
      const key = `${activityType}_${severity}`;
      
      if (!notificationCache.has(key)) {
        notificationCache.set(key, {
          count: 0,
          firstNotification: now,
          lastNotification: now
        });
      }

      const cache = notificationCache.get(key);
      
      // Reset if window has passed
      if (now - cache.firstNotification > RATE_LIMIT_WINDOW) {
        cache.count = 0;
        cache.firstNotification = now;
      }

      cache.count++;
      cache.lastNotification = now;

      // Only send if under rate limit
      if (cache.count <= MAX_NOTIFICATIONS_PER_TYPE) {
        await this.sendNotification(activityType, details, severity, config);
      } else if (cache.count === MAX_NOTIFICATIONS_PER_TYPE + 1) {
        // Send one final notification about rate limiting
        await this.sendNotification(
          `${activityType} (Rate Limited)`,
          {
            ...details,
            'Rate Limit Info': `Further notifications for this alert type will be suppressed for ${RATE_LIMIT_WINDOW / 60000} minutes`
          },
          severity,
          config
        );
      }
    };
  })();
}

module.exports = NotificationService;