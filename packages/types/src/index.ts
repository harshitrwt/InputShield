export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS' | 'HEAD';

/**
 * Standardized Request Context
 * Wraps framework-specific requests (Express, Fastify, NestJS) into a uniform structure.
 */
export interface RequestContext {
  id: string; // Unique request identifier
  ip: string;
  method: HttpMethod;
  url: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  query: Record<string, string | string[] | undefined>;
  body: any; // Parsed body
  cookies?: Record<string, string>;
  userAgent?: string;
  timestamp: number;
}

/**
 * The final action decided by the SDK.
 */
export enum SecurityAction {
  ALLOW = 'ALLOW',
  WARN = 'WARN',
  THROTTLE = 'THROTTLE',
  CHALLENGE = 'CHALLENGE', // e.g., send CAPTCHA or JS challenge (future scope)
  BLOCK = 'BLOCK',
}

/**
 * Types of threats we detect.
 */
export enum ThreatType {
  SQL_INJECTION = 'SQL_INJECTION',
  XSS = 'XSS',
  PATH_TRAVERSAL = 'PATH_TRAVERSAL',
  COMMAND_INJECTION = 'COMMAND_INJECTION',
  NOSQL_INJECTION = 'NOSQL_INJECTION',
  SSRF = 'SSRF',
  JWT_ABUSE = 'JWT_ABUSE',
  BRUTE_FORCE = 'BRUTE_FORCE',
  BOT_TRAFFIC = 'BOT_TRAFFIC',
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  IP_REPUTATION = 'IP_REPUTATION',
  UNKNOWN = 'UNKNOWN',
}

/**
 * The result returned by a single detector.
 */
export interface DetectorResult {
  score: number; // 0 to 100
  threatType?: ThreatType;
  message?: string;
  details?: Record<string, any>; // Which field triggered it, etc.
}

/**
 * Configuration options for the SecureShield SDK.
 */
export interface ShieldConfig {
  mode: 'OBSERVE' | 'BLOCK'; // OBSERVE logs everything but doesn't block
  riskThresholds: {
    warn: number; // e.g., 50
    block: number; // e.g., 80
  };
  rateLimit?: {
    enabled: boolean;
    windowMs: number;
    maxRequests: number;
    store: 'memory' | 'redis';
    redisConfig?: {
      host: string;
      port: number;
      password?: string;
    };
  };
  detectors?: {
    sqli?: boolean;
    xss?: boolean;
    pathTraversal?: boolean;
    bot?: boolean;
  };
  logging?: {
    level: 'debug' | 'info' | 'warn' | 'error';
  };
}

/**
 * Final execution result evaluated by the core engine.
 */
export interface ExecutionResult {
  action: SecurityAction;
  totalRiskScore: number;
  results: DetectorResult[];
  contextId: string;
}
