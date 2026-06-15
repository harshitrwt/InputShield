import { DetectorResult, SecurityAction, ShieldConfig } from '@inputshield/types';

export class RiskAggregator {
  constructor(private config: ShieldConfig) {}

  /**
   * Calculates the total risk score and determines the action to take.
   */
  public evaluate(results: DetectorResult[]): { totalRiskScore: number; action: SecurityAction } {
    if (results.length === 0) {
      return { totalRiskScore: 0, action: SecurityAction.ALLOW };
    }

    // Simple aggregation: take the highest risk score detected
    // Advanced implementations could use weighted sum or complex rules
    const totalRiskScore = results.reduce((max, result) => Math.max(max, result.score), 0);

    let action = SecurityAction.ALLOW;

    if (totalRiskScore >= this.config.riskThresholds.block) {
      action = SecurityAction.BLOCK;
    } else if (totalRiskScore >= this.config.riskThresholds.warn) {
      action = SecurityAction.WARN;
    }

    return { totalRiskScore, action };
  }
}
