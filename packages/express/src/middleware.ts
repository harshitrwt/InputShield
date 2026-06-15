import { Request, Response, NextFunction } from 'express';
import { ShieldConfig, RequestContext, SecurityAction, HttpMethod, ThreatType } from '@inputshield/types';
import { ShieldEngine, RateLimitDetector, MemoryRateLimitStore } from '@inputshield/core';
import { SQLInjectionDetector, XSSDetector, PathTraversalDetector } from '@inputshield/detectors';

const DEFAULT_CONFIG: ShieldConfig = {
  mode: 'BLOCK',
  riskThresholds: {
    warn: 50,
    block: 80,
  },
  rateLimit: {
    enabled: true,
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 100,
    store: 'memory',
  },
  detectors: {
    sqli: true,
    xss: true,
    pathTraversal: true,
  }
};

export function secureShield(userConfig?: Partial<ShieldConfig>) {
  const config = { ...DEFAULT_CONFIG, ...userConfig };
  
  const engine = new ShieldEngine(config);

  // Register Detectors
  if (config.detectors?.sqli) engine.registerDetector(new SQLInjectionDetector());
  if (config.detectors?.xss) engine.registerDetector(new XSSDetector());
  if (config.detectors?.pathTraversal) engine.registerDetector(new PathTraversalDetector());

  // Setup Rate Limiting
  if (config.rateLimit?.enabled && config.rateLimit.store === 'memory') {
    const memoryStore = new MemoryRateLimitStore();
    engine.registerDetector(new RateLimitDetector(config.rateLimit, memoryStore));
    
    // Simple interval to cleanup memory store
    setInterval(() => memoryStore.cleanup(), 60000).unref();
  }

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Build RequestContext
      const context: RequestContext = {
        id: req.headers['x-request-id'] as string || crypto.randomUUID(),
        ip: req.ip || req.socket.remoteAddress || 'unknown',
        method: req.method as HttpMethod,
        url: req.originalUrl,
        path: req.path,
        headers: req.headers,
        query: req.query as Record<string, string>,
        body: req.body,
        cookies: req.cookies,
        userAgent: req.headers['user-agent'],
        timestamp: Date.now(),
      };

      // Process through engine
      const result = await engine.processRequest(context);

      // Log Warnings (could be integrated with a Logger in the future)
      if (result.action === SecurityAction.WARN) {
        console.warn(`[InputShield] WARNING on ${req.method} ${req.originalUrl}: Risk Score ${result.totalRiskScore}`);
      }

      // Handle Blocks
      if (result.action === SecurityAction.BLOCK || result.action === SecurityAction.THROTTLE) {
        const isRateLimit = result.results.some(r => r.threatType === ThreatType.RATE_LIMIT_EXCEEDED);
        
        if (isRateLimit) {
          return res.status(429).json({
            error: 'Too Many Requests',
            message: 'Rate limit exceeded.'
          });
        }

        return res.status(403).json({
          error: 'Forbidden',
          message: 'Request blocked by security policies.',
          referenceId: result.contextId
        });
      }

      // Allow
      next();
    } catch (error) {
      console.error('[InputShield] Middleware Error:', error);
      next(); // Fail-open on internal error so we don't break the app, or could fail-closed based on strict config
    }
  };
}
