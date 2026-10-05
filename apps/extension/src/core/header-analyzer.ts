export type HeaderSeverity = 'low' | 'medium' | 'high';

export interface HeaderFinding {
  type: string;
  severity: HeaderSeverity;
  description: string;
}

export interface HeaderAnalysisResult {
  findings: HeaderFinding[];
  score: number;
  severity: HeaderSeverity;
}

function getHeader(
  headers: Record<string, string>,
  name: string,
): string | undefined {
  const target = name.toLowerCase();

  const key = Object.keys(headers).find(
    (header) => header.toLowerCase() === target,
  );

  return key ? headers[key] : undefined;
}

function getSeverity(score: number): HeaderSeverity {
  if (score >= 60) return 'high';
  if (score >= 30) return 'medium';
  return 'low';
}

export function analyzeHeaders(
  headers: Record<string, string> = {},
): HeaderAnalysisResult {
  const findings: HeaderFinding[] = [];
  let score = 0;

  const authorization = getHeader(headers, 'authorization');

  if (authorization) {
    findings.push({
      type: 'Authorization Header',
      severity: 'high',
      description: 'Authorization token detected.',
    });

    score += 30;

    if (/^Bearer\s+/i.test(authorization)) {
      findings.push({
        type: 'Bearer Token',
        severity: 'high',
        description: 'Bearer authentication token detected.',
      });

      score += 20;
    }
  }

  if (getHeader(headers, 'cookie')) {
    findings.push({
      type: 'Cookie',
      severity: 'medium',
      description: 'Cookies are being transmitted.',
    });

    score += 20;
  }

  if (
    getHeader(headers, 'x-api-key') ||
    getHeader(headers, 'api-key')
  ) {
    findings.push({
      type: 'API Key',
      severity: 'high',
      description: 'API key detected in request headers.',
    });

    score += 30;
  }

  const cors = getHeader(
    headers,
    'access-control-allow-origin',
  );

  if (cors?.trim() === '*') {
    findings.push({
      type: 'Weak CORS',
      severity: 'medium',
      description:
        'Access-Control-Allow-Origin allows requests from any origin.',
    });

    score += 15;
  }

  if (!getHeader(headers, 'content-security-policy')) {
    findings.push({
      type: 'Missing CSP',
      severity: 'medium',
      description: 'Content Security Policy header is missing.',
    });

    score += 10;
  }

  if (!getHeader(headers, 'referrer-policy')) {
    findings.push({
      type: 'Missing Referrer Policy',
      severity: 'low',
      description: 'Referrer Policy is not configured.',
    });

    score += 5;
  }

  if (getHeader(headers, 'server')) {
    findings.push({
      type: 'Server Information',
      severity: 'low',
      description: 'Server information is exposed.',
    });

    score += 5;
  }

  if (getHeader(headers, 'x-powered-by')) {
    findings.push({
      type: 'Technology Disclosure',
      severity: 'low',
      description: 'Technology stack information is exposed.',
    });

    score += 5;
  }

  return {
    findings,
    score: Math.min(score, 100),
    severity: getSeverity(score),
  };
}