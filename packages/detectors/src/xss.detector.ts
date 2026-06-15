import { RequestContext, DetectorResult, ThreatType } from '@inputshield/types';
import { Detector } from '@inputshield/core';

const XSS_REGEX = new RegExp(
  "(?:<script.*?>.*?</script>)|" +
  "(?:javascript:)|" +
  "(?:on\\w+\\s*=)|" +
  "(?:<.*?\\s+on\\w+\\s*=.*?>)|" +
  "(?:<.*?href\\s*=\\s*['\"]javascript:.*?>)|" +
  "(?:<iframe.*?>)|" +
  "(?:<object.*?>)", "i"
);

export class XSSDetector implements Detector {
  public readonly name = 'XSS_DETECTOR';

  public async analyze(context: RequestContext): Promise<DetectorResult> {
    const payloadsToInspect = [
      ...Object.values(context.query || {}),
      ...Object.values(context.headers || {}),
      JSON.stringify(context.body || {})
    ].filter(Boolean) as string[];

    for (const payload of payloadsToInspect) {
      if (typeof payload === 'string' && XSS_REGEX.test(payload)) {
        return {
          score: 80,
          threatType: ThreatType.XSS,
          message: 'Potential Cross-Site Scripting (XSS) pattern detected',
          details: { matchedPayloadSegment: payload.substring(0, 100) }
        };
      }
    }

    return { score: 0 };
  }
}
