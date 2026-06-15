export interface RateLimitStore {
  /**
   * Increments the request count for a given key and returns the current count.
   * @param key The unique identifier (e.g., IP address)
   * @param windowMs The time window in milliseconds
   */
  increment(key: string, windowMs: number): Promise<number>;
}
