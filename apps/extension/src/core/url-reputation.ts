export type ReputationSeverity =
  | 'LOW'
  | 'MEDIUM'
  | 'HIGH';

export interface UrlAnalysisResult {
  score: number;
  severity: ReputationSeverity;
  findings: string[];
}

const TRUSTED_DOMAINS = [
  'google.com',
  'github.com',
  'microsoft.com',
  'apple.com',
  'amazon.com',
  'paypal.com',
  'stripe.com',
  'openai.com',
  'linkedin.com',
];

const SUSPICIOUS_TLDS = [
  '.xyz',
  '.top',
  '.click',
  '.tk',
  '.gq',
  '.ml',
  '.cf',
  '.work',
  '.buzz',
];

const PHISHING_KEYWORDS = [
  'login',
  'verify',
  'secure',
  'account',
  'signin',
  'update',
  'wallet',
  'bank',
  'payment',
  'bonus',
  'free',
];

function getSeverity(
  score: number,
): ReputationSeverity {
  if (score >= 80) {
    return 'LOW';
  }

  if (score >= 50) {
    return 'MEDIUM';
  }

  return 'HIGH';
}

function isTrusted(
  hostname: string,
): boolean {
  return TRUSTED_DOMAINS.some(
    (domain) =>
      hostname === domain ||
      hostname.endsWith(
        `.${domain}`,
      ),
  );
}

function hasSuspiciousTld(
  hostname: string,
): boolean {
  return SUSPICIOUS_TLDS.some(
    (tld) =>
      hostname.endsWith(tld),
  );
}

function isIpAddress(
  hostname: string,
): boolean {
  return /^\d+\.\d+\.\d+\.\d+$/.test(
    hostname,
  );
}

export function analyzeUrl(
  url: string,
): UrlAnalysisResult {
  let score = 100;

  const findings: string[] = [];

  try {
    const parsed =
      new URL(url);

    const hostname =
      parsed.hostname.toLowerCase();

    /*
     * Preserve the old behavior:
     * trusted domains immediately receive
     * a safe reputation score.
     */
    if (isTrusted(hostname)) {
      return {
        score: 100,
        severity: 'LOW',
        findings: [
          'Trusted Domain',
        ],
      };
    }

    if (
      parsed.protocol !==
      'https:'
    ) {
      score -= 20;

      findings.push(
        'Not using HTTPS',
      );
    }

    if (
      hasSuspiciousTld(hostname)
    ) {
      score -= 20;

      findings.push(
        'Suspicious TLD',
      );
    }

    if (
      isIpAddress(hostname)
    ) {
      score -= 25;

      findings.push(
        'Uses IP Address',
      );
    }

    if (url.length > 100) {
      score -= 10;

      findings.push(
        'Very Long URL',
      );
    }

    if (
      hostname.split('.').length >
      4
    ) {
      score -= 15;

      findings.push(
        'Too Many Subdomains',
      );
    }

    const lowerUrl =
      url.toLowerCase();

    for (
      const keyword of
      PHISHING_KEYWORDS
    ) {
      if (
        lowerUrl.includes(keyword)
      ) {
        score -= 5;

        findings.push(keyword);
      }
    }

    score = Math.max(
      0,
      score,
    );

    return {
      score,
      severity:
        getSeverity(score),
      findings,
    };
  } catch {
    return {
      score: 0,
      severity: 'HIGH',
      findings: [
        'Invalid URL',
      ],
    };
  }
}