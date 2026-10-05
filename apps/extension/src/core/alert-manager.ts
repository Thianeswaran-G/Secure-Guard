import type {
  ScanEvent,
  Severity,
} from '@secureguard/shared';

import {
  getAlerts,
  saveAlert,
  deleteAlert,
  clearAlerts,
  getAlertsBySeverity,
  getAlertsByType,
  searchAlertsByWebsite,
  getTodayAlerts,
  incrementAlertCount,
  getSettings,
} from './storage-manager.js';

import type {
  SecureGuardAlert,
} from './storage-manager.js';

export interface CreateAlertInput {
  type?: string;
  severity?: Severity;
  title?: string;
  message?: string;
  url?: string;
  hostname?: string;
  detectedData?: string[];
  blocked?: boolean;
}

function generateId(): string {
  if (
    typeof crypto !== 'undefined' &&
    typeof crypto.randomUUID === 'function'
  ) {
    return crypto.randomUUID();
  }

  return `${Date.now()}-${Math.random()
    .toString(36)
    .slice(2)}`;
}

export async function createAlert(
  data: CreateAlertInput,
): Promise<SecureGuardAlert | null> {
  const alert: SecureGuardAlert = {
    id: generateId(),

    type:
      data.type ??
      'unknown',

    severity:
      data.severity ??
      'MEDIUM',

    title:
      data.title ??
      'Security Alert',

    message:
      data.message ??
      '',

    url:
      data.url ??
      '',

    hostname:
      data.hostname ??
      '',

    detectedData:
      data.detectedData ??
      [],

    blocked:
      data.blocked ??
      false,

    timestamp:
      new Date().toISOString(),
  };

  await saveAlert(alert);
  await incrementAlertCount();

  const settings =
    await getSettings();

  if (settings.notifications) {
    await showNotification(alert);
  }

  return alert;
}

export async function createAlertFromScan(
  scan: ScanEvent,
): Promise<SecureGuardAlert | null> {
  if (!scan.findings.length) {
    return null;
  }

  return createAlert({
    type: scan.scanType.toLowerCase(),
    severity: scan.severity,
    title: 'Sensitive information detected',
    message: `Sensitive information may be sent from ${scan.hostname}. Detected: ${scan.findings.join(', ')}`,
    url: scan.url,
    hostname: scan.hostname,
    detectedData: scan.findings,
    blocked: false,
  });
}

async function showNotification(
  alert: SecureGuardAlert,
): Promise<void> {
  if (
    typeof chrome === 'undefined' ||
    !chrome.notifications
  ) {
    return;
  }

  try {
    await chrome.notifications.create(
      `secureguard-alert-${alert.id}`,
      {
        type: 'basic',
        iconUrl: chrome.runtime.getURL('icons/icon128.png'),
        title: alert.title,
        message:
          alert.message ||
          'SecureGuard detected a security issue.',
      },
    );
  } catch (error) {
    console.warn(
      'SecureGuard notification failed:',
      error,
    );
  }
}

export async function removeAlert(
  id: string,
): Promise<void> {
  await deleteAlert(id);
  await chrome.notifications.clear(
    `secureguard-alert-${id}`,
  );
}

export async function removeAllAlerts(): Promise<void> {
  const alerts = await getAlerts();
  await clearAlerts();
  await Promise.all(
    alerts.map((alert) =>
      chrome.notifications.clear(
        `secureguard-alert-${alert.id}`,
      ),
    ),
  );
}

export async function getAllAlerts(): Promise<
  SecureGuardAlert[]
> {
  return getAlerts();
}

export async function getAlertsForSeverity(
  severity: Severity,
): Promise<SecureGuardAlert[]> {
  return getAlertsBySeverity(severity);
}

export async function getAlertsForType(
  type: string,
): Promise<SecureGuardAlert[]> {
  return getAlertsByType(type);
}

export async function searchWebsiteAlerts(
  hostname: string,
): Promise<SecureGuardAlert[]> {
  return searchAlertsByWebsite(hostname);
}

export async function getTodaysAlerts(): Promise<
  SecureGuardAlert[]
> {
  return getTodayAlerts();
}

export async function getAlertStatistics(): Promise<{
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}> {
  const alerts = await getAlerts();

  return {
    total: alerts.length,

    critical: alerts.filter(
      (alert) =>
        alert.severity === 'CRITICAL',
    ).length,

    high: alerts.filter(
      (alert) =>
        alert.severity === 'HIGH',
    ).length,

    medium: alerts.filter(
      (alert) =>
        alert.severity === 'MEDIUM',
    ).length,

    low: alerts.filter(
      (alert) =>
        alert.severity === 'LOW',
    ).length,
  };
}