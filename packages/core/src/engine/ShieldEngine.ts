import { RequestContext, ShieldConfig, ExecutionResult, SecurityAction } from '@inputshield/types';
import { Detector } from '../detectors/Detector';
import { RiskAggregator } from './RiskAggregator';

/**
 * The ShieldEngine is the central coordinator for analyzing incoming requests.
 * It manages the pipeline of detectors and aggregates their results.
 */
export class ShieldEngine {
  private detectors: Detector[] = [];
  private riskAggregator: RiskAggregator;

  constructor(private config: ShieldConfig) {
    this.riskAggregator = new RiskAggregator(config);
  }

  /**
   * Register a detector into the pipeline.
   */
  public registerDetector(detector: Detector): void {
    this.detectors.push(detector);
  }

  /**
   * Execute the security pipeline against the given request context.
   */
  public async processRequest(context: RequestContext): Promise<ExecutionResult> {
    const results = await Promise.all(
      this.detectors.map((detector) => detector.analyze(context))
    );

    // Filter out results that didn't flag anything (score 0)
    const flaggedResults = results.filter((res) => res.score > 0);

    const { totalRiskScore, action } = this.riskAggregator.evaluate(flaggedResults);

    // If we are in OBSERVE mode, we never BLOCK, we only WARN/ALLOW but log the intent
    const finalAction =
      this.config.mode === 'OBSERVE' && action === SecurityAction.BLOCK
        ? SecurityAction.WARN // Downgrade block to warn in observe mode
        : action;

    return {
      contextId: context.id,
      totalRiskScore,
      action: finalAction,
      results: flaggedResults,
    };
  }
}
