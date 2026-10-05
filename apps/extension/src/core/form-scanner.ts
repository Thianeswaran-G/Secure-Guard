import type {
  FindingType,
  Severity,
} from '@secureguard/shared';

import {
  detectSensitiveField,
} from './sensitive-detector.js';

export interface FormScanResult {
  type:
    | 'login'
    | 'payment'
    | 'registration'
    | 'general';

  sensitiveFields: Array<{
    name: string;
    type: string;
    finding: FindingType;
  }>;

  findings: FindingType[];
  score: number;
  severity: Severity;
}

function getSeverity(
  score: number,
): Severity {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 30) return 'MEDIUM';

  return 'LOW';
}

function detectType(
  form: HTMLFormElement,
): FormScanResult['type'] {
  const text =
    form.innerText.toLowerCase();

  const html =
    form.innerHTML.toLowerCase();

  if (
    text.includes('login') ||
    text.includes('sign in') ||
    html.includes('password')
  ) {
    return 'login';
  }

  if (
    text.includes('register') ||
    text.includes('sign up') ||
    text.includes('create account')
  ) {
    return 'registration';
  }

  if (
    text.includes('payment') ||
    text.includes('checkout') ||
    html.includes('cvv') ||
    html.includes('card')
  ) {
    return 'payment';
  }

  return 'general';
}

export function scanForm(
  form: HTMLFormElement,
): FormScanResult {
  const type =
    detectType(form);

  const sensitiveFields: FormScanResult['sensitiveFields'] =
    [];

  const findings: FindingType[] = [];

  let score = 0;

  const inputs =
    form.querySelectorAll<
      HTMLInputElement |
      HTMLTextAreaElement |
      HTMLSelectElement
    >(
      'input, textarea, select',
    );

  for (const input of Array.from(inputs)) {
    const finding =
      detectSensitiveField(
        input.name,
        input.value,
        input instanceof HTMLInputElement
          ? input.type
          : input.tagName.toLowerCase(),
        input.id,
      );

    if (!finding) {
      continue;
    }

    sensitiveFields.push({
      name: input.name || input.id || 'unknown',
      type:
        input instanceof HTMLInputElement
          ? input.type
          : input.tagName.toLowerCase(),
      finding,
    });

    findings.push(finding);

    /*
     * Preserve the old scanner's 15-point
     * sensitive-field contribution.
     */
    score += 15;
  }

  /*
   * Preserve old form-type weighting.
   */
  switch (type) {
    case 'login':
      score += 20;
      break;

    case 'payment':
      score += 30;
      break;

    case 'registration':
      score += 10;
      break;
  }

  return {
    type,
    sensitiveFields,
    findings: [...new Set(findings)],
    score: Math.min(100, score),
    severity: getSeverity(score),
  };
}