import { RequestContext, DetectorResult } from '@inputshield/types';

/**
 * Base interface for all security detectors.
 * Every detector (e.g., SQLiDetector, XSSDetector) must implement this.
 */
export interface Detector {
  /**
   * The name of the detector (e.g., 'SQL_INJECTION_DETECTOR')
   */
  readonly name: string;

  /**
   * Analyzes the request context and returns a result.
   */
  analyze(context: RequestContext): Promise<DetectorResult>;
}
