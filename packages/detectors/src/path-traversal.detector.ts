import { RequestContext, DetectorResult, ThreatType } from '@inputshield/types';
import { Detector } from '@inputshield/core';

const PATH_TRAVERSAL_REGEX = /(?:\.\.[\\/]+)+/i;

export class PathTraversalDetector implements Detector {
  public readonly name = 'PATH_TRAVERSAL_DETECTOR';

  public async analyze(context: RequestContext): Promise<DetectorResult> {
    const payloadsToInspect = [
      context.path,
      ...Object.values(context.query || {}),
      ...Object.values(context.headers || {}),
      JSON.stringify(context.body || {})
    ].filter(Boolean) as string[];

    for (const payload of payloadsToInspect) {
      if (typeof payload === 'string' && PATH_TRAVERSAL_REGEX.test(payload)) {
        return {
          score: 85,
          threatType: ThreatType.PATH_TRAVERSAL,
          message: 'Potential Path Traversal pattern detected',
          details: { matchedPayloadSegment: payload.substring(0, 100) }
        };
      }
    }

    return { score: 0 };
  }
}
