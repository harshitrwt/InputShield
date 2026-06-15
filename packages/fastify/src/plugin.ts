import fp from 'fastify-plugin';
import { FastifyPluginAsync, FastifyRequest, FastifyReply } from 'fastify';
import { ShieldConfig, RequestContext, SecurityAction, HttpMethod, ThreatType } from '@inputshield/types';
import { ShieldEngine, RateLimitDetector, MemoryRateLimitStore } from '@inputshield/core';
import { SQLInjectionDetector, XSSDetector, PathTraversalDetector } from '@inputshield/detectors';

const DEFAULT_CONFIG: ShieldConfig = {
  mode: 'BLOCK',
  riskThresholds: { warn: 50, block: 80 },
  rateLimit: { enabled: true, windowMs: 15 * 60 * 1000, maxRequests: 100, store: 'memory' },
  detectors: { sqli: true, xss: true, pathTraversal: true }
};

const inputShieldPlugin: FastifyPluginAsync<Partial<ShieldConfig>> = async (fastify, userConfig) => {
  const config = { ...DEFAULT_CONFIG, ...userConfig };
  const engine = new ShieldEngine(config);

  if (config.detectors?.sqli) engine.registerDetector(new SQLInjectionDetector());
  if (config.detectors?.xss) engine.registerDetector(new XSSDetector());
  if (config.detectors?.pathTraversal) engine.registerDetector(new PathTraversalDetector());

  if (config.rateLimit?.enabled && config.rateLimit.store === 'memory') {
    const memoryStore = new MemoryRateLimitStore();
    engine.registerDetector(new RateLimitDetector(config.rateLimit, memoryStore));
    const interval = setInterval(() => memoryStore.cleanup(), 60000);
    interval.unref();
    fastify.addHook('onClose', (instance, done) => {
      clearInterval(interval);
      done();
    });
  }

  fastify.addHook('preHandler', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const context: RequestContext = {
        id: (request.id as string) || crypto.randomUUID(),
        ip: request.ip,
        method: request.method as HttpMethod,
        url: request.url,
        path: request.routeOptions.url || request.url,
        headers: request.headers as Record<string, string>,
        query: request.query as Record<string, string>,
        body: request.body,
        userAgent: request.headers['user-agent'],
        timestamp: Date.now(),
      };

      const result = await engine.processRequest(context);

      if (result.action === SecurityAction.WARN) {
        request.log.warn(`[InputShield] WARNING on ${request.method} ${request.url}: Risk Score ${result.totalRiskScore}`);
      }

      if (result.action === SecurityAction.BLOCK || result.action === SecurityAction.THROTTLE) {
        const isRateLimit = result.results.some(r => r.threatType === ThreatType.RATE_LIMIT_EXCEEDED);
        
        if (isRateLimit) {
          reply.status(429).send({ error: 'Too Many Requests', message: 'Rate limit exceeded.' });
          return reply; // stop execution
        }

        reply.status(403).send({ error: 'Forbidden', message: 'Request blocked by security policies.', referenceId: result.contextId });
        return reply; // stop execution
      }
    } catch (error) {
      request.log.error(error, '[InputShield] Plugin Error');
    }
  });
};

export const secureShield = fp(inputShieldPlugin, {
  name: '@inputshield/fastify',
  fastify: '4.x'
});
