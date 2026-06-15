import { RequestContext, DetectorResult, ThreatType } from '@inputshield/types';
import { Detector } from '@inputshield/core';

const SQLI_REGEX = new RegExp(
  "(?:\\b(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|EXEC|EXECUTE|DECLARE)\\b.*?\\b(?:FROM|INTO|TABLE|DATABASE|VIEW|PROCEDURE)\\b)|" +
  "(?:--|#|/\\*|\\*/)|" +
  "('|\"|`|´|’|‘)\\s*(?:OR|AND)\\s*('|\"|`|´|’|‘)?\\d+.*?=", "i"
);

export class SQLInjectionDetector implements Detector {
  public readonly name = 'SQL_INJECTION_DETECTOR';

  public async analyze(context: RequestContext): Promise<DetectorResult> {
    const payloadsToInspect = [
      ...Object.values(context.query || {}),
      ...Object.values(context.headers || {}),
      JSON.stringify(context.body || {})
    ].filter(Boolean) as string[];

    for (const payload of payloadsToInspect) {
      if (typeof payload === 'string' && SQLI_REGEX.test(payload)) {
        return {
          score: 90,
          threatType: ThreatType.SQL_INJECTION,
          message: 'Potential SQL Injection pattern detected',
          details: { matchedPayloadSegment: payload.substring(0, 100) }
        };
      }
    }

    return { score: 0 };
  }
}
