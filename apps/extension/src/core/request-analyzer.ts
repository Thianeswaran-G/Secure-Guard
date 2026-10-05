import type {
  FindingType,
  Severity,
} from '@secureguard/shared';

import {
  detectSensitiveText,
} from './sensitive-detector.js';

import {
  analyzeHeaders,
} from './header-analyzer.js';

import {
  calculateRisk,
} from './risk-engine.js';


export interface RequestDetails {
  url: string;
  method: string;
  initiator?: string;
  documentUrl?: string;
  requestHeaders?: chrome.webRequest.HttpHeader[];
  requestBody?: chrome.webRequest.OnBeforeRequestDetails['requestBody'];
}

export interface RequestAnalysisResult {
  safe: boolean;
  score: number;
  severity: Severity;
  findings: FindingType[];
  source: string;
  destination: string;
  method: string;
  body: string;
  headers: Record<string, string>;
  thirdParty: boolean;
}

export function isSecureGuardApiRequest(
  url: string,
  method: string,
): boolean {
  if (method.toUpperCase() !== 'POST') {
    return false;
  }

  let requestUrl: URL;

  try {
    requestUrl = new URL(url);
  } catch {
    return false;
  }

  const hostname = requestUrl.hostname
    .toLowerCase()
    .replace(/\.$/, '')
    .replace(/^\[|\]$/g, '');

  const isLocalhost =
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname === '127.0.0.1' ||
    hostname === '::1';

  if (
    !isLocalhost ||
    requestUrl.port !== '3000' ||
    !['http:', 'https:'].includes(requestUrl.protocol)
  ) {
    return false;
  }

  try {
    const pathname = decodeURIComponent(
      requestUrl.pathname,
    )
      .replace(/\/+$/, '')
      .toLowerCase();

    return pathname === '/api/scans';
  } catch {
    return false;
  }
}

function extractHeaders(
  details: RequestDetails,
): Record<string, string> {
  return Object.fromEntries(
    (details.requestHeaders ?? []).map(
      (header) => [
        header.name,
        header.value ?? '',
      ],
    ),
  );
}

function extractBody(
  details: RequestDetails,
): string {
  const requestBody =
    details.requestBody;

  if (!requestBody) {
    return '';
  }

  if (requestBody.formData) {
    const parts: string[] = [];

    for (
      const [key, values] of Object.entries(
        requestBody.formData,
      )
    ) {
      for (const value of values) {
        if (typeof value === 'string') {
          parts.push(
            `${key}=${value}`,
          );
        } else if (
          value instanceof File
        ) {
          parts.push(
            `${key}=${value.name}`,
          );
          parts.push(
            `${key}=FILE`,
          );
        } else {
          parts.push(
            `${key}=FILE`,
          );
        }
      }
    }

    return parts.join('&');
  }

  if (requestBody.raw) {
    try {
      const decoder =
        new TextDecoder();

      return requestBody.raw
        .filter(
          (part) =>
            part.bytes !== undefined,
        )
        .map(
          (part) =>
            decoder.decode(
              part.bytes!,
            ),
        )
        .join('');
    } catch {
      return '';
    }
  }

  return '';
}

function isThirdParty(
  source: string,
  destination: string,
): boolean {
  if (!source) {
    return false;
  }

  try {
    return (
      new URL(source).hostname !==
      new URL(destination).hostname
    );
  } catch {
    return false;
  }
}

export function analyzeRequest(
  details: RequestDetails,
): RequestAnalysisResult {
  const headers =
    extractHeaders(details);

  const body =
    extractBody(details);

  const findings: FindingType[] = [];

  let score = 0;

  const bodyResult =
    detectSensitiveText(body);

  findings.push(
    ...bodyResult.findings,
  );

  score += bodyResult.score;

  const headerResult =
    analyzeHeaders(headers);

  if (headerResult.score > 0) {
    score += headerResult.score;

    if (
      headers.authorization ||
      headers.Authorization
    ) {
      findings.push('TOKEN');
    }

    if (
      headers['x-api-key'] ||
      headers['X-API-Key'] ||
      headers['api-key']
    ) {
      findings.push('API_KEY');
    }

    if (
      headers.cookie ||
      headers.Cookie
    ) {
      findings.push('TOKEN');
    }
  }

  const source =
    details.initiator ||
    details.documentUrl ||
    '';

  const thirdParty =
    isThirdParty(
      source,
      details.url,
    );

  if (thirdParty) {
    score += 25;
  }

  const risk =
    calculateRisk(
      findings,
      score,
    );

  return {
    safe: risk.score === 0,
    score: risk.score,
    severity: risk.severity,
    findings: risk.findings,
    source,
    destination: details.url,
    method: details.method,
    body,
    headers,
    thirdParty,
  };
}

export function isSensitiveMethod(
  method: string,
): boolean {
  return [
    'POST',
    'PUT',
    'PATCH',
  ].includes(
    method.toUpperCase(),
  );
}

export function isLoginRequest(
  body: string,
): boolean {
  const text =
    body.toLowerCase();

  return (
    text.includes('password') ||
    text.includes('login') ||
    text.includes('signin') ||
    text.includes('username')
  );
}

export function isPaymentRequest(
  body: string,
): boolean {
  const text =
    body.toLowerCase();

  return (
    text.includes('card') ||
    text.includes('cvv') ||
    text.includes('expiry') ||
    text.includes('payment')
  );
}

export function isRegistrationRequest(
  body: string,
): boolean {
  const text =
    body.toLowerCase();

  return (
    text.includes('firstname') ||
    text.includes('lastname') ||
    text.includes('email') ||
    text.includes('register')
  );
}

export function isApiRequest(
  url: string,
): boolean {
  return (
    url.includes('/api/') ||
    url.includes('/graphql') ||
    url.includes('/v1/') ||
    url.includes('/v2/')
  );
}