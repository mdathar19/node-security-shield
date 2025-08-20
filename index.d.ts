import { Request, Response, NextFunction, Application } from 'express';

export interface SecurityShieldOptions {
  security?: SecurityConfig;
  monitoring?: MonitoringConfig;
  notifications?: NotificationConfig;
}

export interface SecurityConfig {
  csp?: {
    defaultSrc?: string[];
    styleSrc?: string[];
    scriptSrc?: string[];
    imgSrc?: string[];
    connectSrc?: string[];
    fontSrc?: string[];
    objectSrc?: string[];
    mediaSrc?: string[];
    frameSrc?: string[];
  };
  hsts?: {
    maxAge?: number;
    includeSubDomains?: boolean;
    preload?: boolean;
  };
  cors?: {
    allowedOrigins?: string[];
    credentials?: boolean;
    methods?: string[];
    allowedHeaders?: string[];
  };
  bodyLimit?: string;
  parameterLimit?: number;
  compression?: false | {
    level?: number;
    threshold?: number;
  };
  allowedContentTypes?: string[];
  coep?: boolean;
}

export interface MonitoringConfig {
  thresholds?: {
    requestsPerHour?: number;
    uniqueEndpoints?: number;
    userAgents?: number;
    authAttempts?: number;
    failedAttemptThreshold?: number;
  };
  blockDuration?: number;
  enableSQLInjectionDetection?: boolean;
  enableXSSDetection?: boolean;
  enablePathTraversalDetection?: boolean;
  enableBruteForceDetection?: boolean;
  cleanupInterval?: number;
  dataRetentionPeriod?: number;
}

export interface NotificationConfig {
  enabled?: boolean;
  applicationName?: string;
  console?: {
    enabled?: boolean;
  };
  slack?: {
    enabled?: boolean;
    webhookUrl?: string;
    mentionUsers?: string[];
    mentionChannels?: string[];
  };
  rateLimiting?: {
    enabled?: boolean;
    windowMs?: number;
    maxNotificationsPerType?: number;
  };
}

export interface SuspiciousPattern {
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  details: Record<string, any>;
}

export interface ClientTracker {
  hourlyCount: number;
  lastHour: number;
  endpoints: Set<string>;
  userAgents: Set<string>;
  firstSeen: number;
  methods: Set<string>;
  countries: Set<string>;
  lastActivity: number;
}

export interface FailedAttempt {
  count: number;
  lastAttempt: number;
  reasons: Array<{
    reason: string;
    timestamp: number;
  }>;
  firstAttempt: number;
}

export interface ValidationResult {
  isValid: boolean;
  score: number;
  feedback: string[];
}

export interface RateLimitResult {
  isAllowed: boolean;
  remaining: number;
  resetTime: number;
  retryAfter: number;
}

export interface BotDetectionResult {
  isBot: boolean;
  type: string;
  name?: string;
  isLegitimate?: boolean;
  confidence: number;
}

export interface SecurityStatistics {
  activeIPs: number;
  blockedIPs: number;
  failedAttempts: number;
  timestamp: string;
}

export interface ConfigValidation {
  isValid: boolean;
  errors: string[];
}

// Extended Express Request interface
declare global {
  namespace Express {
    interface Request {
      id?: string;
      clientIP?: string;
      suspiciousScore?: number;
      suspiciousPatterns?: SuspiciousPattern[];
      clientTracker?: ClientTracker;
      rawBody?: Buffer;
    }
  }
}

export interface SecurityShield {
  securityMiddleware: (app: Application) => void;
  suspiciousActivityMiddleware: (req: Request, res: Response, next: NextFunction) => void;
  trackFailedAttempt: (clientIP: string, endpoint: string, reason: string, requestId: string, config?: any) => FailedAttempt;
  utils: typeof SecurityUtils;
  config: SecurityConfigClass;
  initializeAll: (app: Application) => void;
}

export interface ValidationRules {
  email: any;
  password: any;
  username: any;
  phone: any;
  url: any;
  handleValidationErrors: (req: Request, res: Response, next: NextFunction) => void;
}

export class SecurityShieldClass {
  static createSecurityMiddleware(config?: SecurityConfig): (app: Application) => void;
  static createValidationRules(): ValidationRules;
}

export class SuspiciousActivityMonitorClass {
  constructor();
  static createSuspiciousActivityMiddleware(config?: MonitoringConfig): (req: Request, res: Response, next: NextFunction) => void;
  static trackFailedAttempt(clientIP: string, endpoint: string, reason: string, requestId: string, config?: any): FailedAttempt;
  analyzeRequest(req: Request, res: Response, next: NextFunction, config: MonitoringConfig): void;
  detectSuspiciousPatterns(tracker: ClientTracker, clientIP: string, userAgent: string, endpoint: string, method: string, requestId: string, req: Request, config: MonitoringConfig): SuspiciousPattern[];
  cleanupTrackingData(): void;
  getStatistics(): SecurityStatistics;
  blockIP(ip: string, duration?: number): void;
  unblockIP(ip: string): boolean;
}

export class NotificationServiceClass {
  static sendNotification(activityType: string, details: Record<string, any>, severity?: string, config?: NotificationConfig): Promise<void>;
  static sendSlackNotification(notification: any, slackConfig: any): Promise<void>;
  static logToConsole(notification: any): void;
  static rateLimitedNotification(activityType: string, details: Record<string, any>, severity: string, config: NotificationConfig): Promise<void>;
}

export class SecurityConfigClass {
  constructor(options?: SecurityShieldOptions);
  security: SecurityConfig;
  monitoring: MonitoringConfig;
  notifications: NotificationConfig;
  
  createSecurityConfig(config: SecurityConfig): SecurityConfig;
  createMonitoringConfig(config: MonitoringConfig): MonitoringConfig;
  createNotificationConfig(config: NotificationConfig): NotificationConfig;
  static getEnvironmentConfig(): SecurityShieldOptions;
  validate(): ConfigValidation;
  static createFromEnvironment(userConfig?: SecurityShieldOptions): SecurityConfigClass;
  static deepMerge(target: any, source: any): any;
}

export class SecurityUtils {
  static generateSecureRandom(length?: number, charset?: string): string;
  static generateAPIKey(prefix?: string): string;
  static hashPassword(password: string, saltRounds?: number): Promise<string>;
  static verifyPassword(password: string, hash: string): Promise<boolean>;
  static generateToken(payload: any, secret: string, expiresIn?: string): string;
  static verifyToken(token: string, secret: string): any | null;
  static sanitizeInput(input: string): string;
  static validateEmail(email: string): string | null;
  static validatePasswordStrength(password: string): ValidationResult;
  static getPasswordStrengthLabel(score: number): string;
  static rateLimit(key: string, maxAttempts?: number, windowMs?: number): RateLimitResult;
  static generateCSRFToken(): string;
  static verifyCSRFToken(token: string, sessionToken: string): boolean;
  static maskSensitiveData(data: any, sensitiveFields?: string[]): any;
  static parseTimeToSeconds(timeStr: string): number;
  static detectBot(userAgent: string): BotDetectionResult;
  static generateSecurityHeaders(options?: any): Record<string, string>;
  static cleanupRateLimitStore(): void;
}

// Main function
declare function createSecurityShield(options?: SecurityShieldOptions): SecurityShield;

export default createSecurityShield;
