import type {
  ScanEvent,
} from '@secureguard/shared';

import {
  scanForm,
} from './core/form-scanner.js';

import {
  scanFile,
} from './core/file-scanner.js';

import {
  submitScanFromContent,
} from './core/api-client.js';

import {
  calculateRisk,
} from './core/risk-engine.js';

function getPageContextUrl(): string {
  for (const candidate of [
    window.location.href,
    document.referrer,
  ]) {
    try {
      const url = new URL(candidate);
      if (url.protocol === 'http:' || url.protocol === 'https:') {
        return url.href;
      }
    } catch {
      // Try the embedding page when this frame has no web URL.
    }
  }

  const ancestorOrigin = window.location.ancestorOrigins?.[0];
  if (ancestorOrigin) {
    return ancestorOrigin;
  }

  return window.location.href;
}

function sendScan(
  scanType: ScanEvent['scanType'],
  score: number,
  severity: ScanEvent['severity'],
  findings: ScanEvent['findings'],
): void {
  const url = getPageContextUrl();
  const event: ScanEvent = {
    url,
    hostname: new URL(url).hostname,
    scanType,
    riskScore: Math.min(100, score),
    severity,
    findings: [
      ...new Set(findings),
    ],
    timestamp:
      new Date().toISOString(),
  };

  void submitScanFromContent(event).catch(
    (error: unknown) => {
      console.error(
        'SecureGuard could not preserve a detected scan.',
        error,
      );
    },
  );
}

function handleForm(
  form: HTMLFormElement,
): void {
  const result =
    scanForm(form);

  if (
    !result.findings.length
  ) {
    return;
  }

  const risk =
    calculateRisk(
      result.findings,
      result.score,
    );

  sendScan(
    'FORM',
    risk.score,
    risk.severity,
    risk.findings,
  );
}

function handleFileInput(
  input: HTMLInputElement,
): void {
  if (!input.files?.length) {
    return;
  }

  for (const file of Array.from(input.files)) {
    const result =
      scanFile(file);

    if (
      !result.findings.length
    ) {
      continue;
    }

    const risk =
      calculateRisk(
        result.findings,
        result.score,
      );

    sendScan(
      'FILE',
      risk.score,
      risk.severity,
      risk.findings,
    );
  }
}

function attachForm(
  form: HTMLFormElement,
): void {
  if (
    form.dataset.secureguardAttached ===
    'true'
  ) {
    return;
  }

  form.dataset.secureguardAttached =
    'true';

  form.addEventListener(
    'submit',
    () => handleForm(form),
    {
      capture: true,
    },
  );
}

function attachFileInput(
  input: HTMLInputElement,
): void {
  if (
    input.dataset.secureguardFileAttached ===
    'true'
  ) {
    return;
  }

  input.dataset.secureguardFileAttached =
    'true';

  input.addEventListener(
    'change',
    () => handleFileInput(input),
    {
      capture: true,
    },
  );
}

function attachElements(): void {
  document
    .querySelectorAll<HTMLFormElement>(
      'form',
    )
    .forEach(attachForm);

  document
    .querySelectorAll<HTMLInputElement>(
      'input[type="file"]',
    )
    .forEach(attachFileInput);
}

function initialize(): void {
  attachElements();

  if (!document.documentElement) {
    return;
  }

  const observer =
    new MutationObserver(() => {
      attachElements();
    });

  observer.observe(
    document.documentElement,
    {
      childList: true,
      subtree: true,
    },
  );
}

if (
  document.readyState ===
  'loading'
) {
  document.addEventListener(
    'DOMContentLoaded',
    initialize,
    { once: true },
  );
} else {
  initialize();
}