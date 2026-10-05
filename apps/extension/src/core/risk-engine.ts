import type {
  FindingType,
  Severity,
} from '@secureguard/shared';

import {
  calculateDetectionScore,
} from './sensitive-detector.js';

export interface RiskResult {
  score: number;
  severity: Severity;
  findings: FindingType[];
}

function getSeverity(
  score: number,
): Severity {
  if (score >= 80) {
    return 'CRITICAL';
  }

  if (score >= 60) {
    return 'HIGH';
  }

  if (score >= 30) {
    return 'MEDIUM';
  }

  return 'LOW';
}

export function calculateRisk(
  findings: FindingType[],
  baseScore = 0,
): RiskResult {
  const uniqueFindings = [
    ...new Set(findings),
  ];

  const detectionScore =
    calculateDetectionScore(
      uniqueFindings,
    );

  const score = Math.min(
    100,
    baseScore + detectionScore,
  );

  return {
    score,
    severity: getSeverity(score),
    findings: uniqueFindings,
  };
}

export function mergeRiskResults(
  ...results: RiskResult[]
): RiskResult {
  const findings = [
    ...new Set(
      results.flatMap(
        (result) => result.findings,
      ),
    ),
  ];

  const score = Math.min(
    100,
    results.reduce(
      (highest, result) =>
        Math.max(
          highest,
          result.score,
        ),
      0,
    ),
  );

  return {
    score,
    severity: getSeverity(score),
    findings,
  };
}