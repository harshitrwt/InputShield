import { RequestContext, DetectorResult, ThreatType, ShieldConfig } from '@inputshield/types';
import { Detector } from './Detector';
import { RateLimitStore } from '../rate-limit/RateLimitStore';

export class RateLimitDetector {
  public readonly name = 'RATE_LIMIT_DETECTOR';

  constructor(
    private config: NonNullable<ShieldConfig['rateLimit']>,
    private store: RateLimitStore
  ) {}

  public async analyze(context: RequestContext): Promise<DetectorResult> {
    if (!this.config.enabled) {
      return { score: 0 };
    }

    const key = context.ip; // Rate limit by IP
    const currentHits = await this.store.increment(key, this.config.windowMs);

    if (currentHits > this.config.maxRequests) {
      return {
        score: 100, // Instant block
        threatType: ThreatType.RATE_LIMIT_EXCEEDED,
        message: 'Rate limit exceeded',
        details: { currentHits, limit: this.config.maxRequests }
      };
    }

    return { score: 0 };
  }
}
