import { RateLimitStore } from './RateLimitStore';

export class MemoryRateLimitStore implements RateLimitStore {
  private hits: Map<string, { count: number; expiresAt: number }> = new Map();

  public async increment(key: string, windowMs: number): Promise<number> {
    const now = Date.now();
    const record = this.hits.get(key);

    if (record) {
      if (now > record.expiresAt) {
        // Window expired, reset
        this.hits.set(key, { count: 1, expiresAt: now + windowMs });
        return 1;
      } else {
        // Increment within window
        record.count += 1;
        return record.count;
      }
    } else {
      // First request
      this.hits.set(key, { count: 1, expiresAt: now + windowMs });
      return 1;
    }
  }

  /**
   * Cleanup interval for memory leak prevention.
   */
  public cleanup(): void {
    const now = Date.now();
    for (const [key, record] of this.hits.entries()) {
      if (now > record.expiresAt) {
        this.hits.delete(key);
      }
    }
  }
}
