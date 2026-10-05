import type {
  ExtensionSettings,
  ExtensionStats,
  ScanEvent,
  Severity,
} from '@secureguard/shared';

export interface SecureGuardAlert {
  id: string;
  type: string;
  severity: Severity;
  title: string;
  message: string;
  url: string;
  hostname: string;
  detectedData: string[];
  blocked: boolean;
  timestamp: string;
}

export interface HistoryEntry extends ScanEvent {
  scannedAt: string;
}

export interface ExportedData {
  settings: ExtensionSettings;
  alerts: SecureGuardAlert[];
  stats: ExtensionStats;
  whitelist: string[];
  history: HistoryEntry[];
}

const DEFAULT_SETTINGS: ExtensionSettings = {
  realTimeScanning: true,
  autoBlock: false,
  notifications: true,
  darkWebScanning: true,
  alertLevel: 'MEDIUM',
};

const DEFAULT_STATS: ExtensionStats = {
  sitesScanned: 0,
  alertsGenerated: 0,
  blockedRequests: 0,
};

const MAX_ALERTS = 100;
const MAX_HISTORY = 500;

async function get<T>(
  key: string,
): Promise<T | undefined> {
  const result =
    await chrome.storage.local.get(key);

  return result[key] as T | undefined;
}

async function set<T>(
  key: string,
  value: T,
): Promise<void> {
  await chrome.storage.local.set({
    [key]: value,
  });
}

export async function initializeStorage(): Promise<void> {
  await getSettings();
  await getStats();

  const alerts = await get<SecureGuardAlert[]>(
    'alerts',
  );

  if (!alerts) {
    await set('alerts', []);
  }

  const history =
    await get<HistoryEntry[]>('history');

  if (!history) {
    await set('history', []);
  }

  const whitelist =
    await get<string[]>('whitelist');

  if (!whitelist) {
    await set('whitelist', []);
  }
}

/* -------------------------------------------------------------------------- */
/* Settings                                                                   */
/* -------------------------------------------------------------------------- */

export async function getSettings(): Promise<ExtensionSettings> {
  const settings =
    await get<Partial<ExtensionSettings>>(
      'settings',
    );

  if (!settings) {
    await set(
      'settings',
      DEFAULT_SETTINGS,
    );

    return { ...DEFAULT_SETTINGS };
  }

  return {
    ...DEFAULT_SETTINGS,
    ...settings,
  };
}

export async function saveSettings(
  settings: ExtensionSettings,
): Promise<void> {
  await set('settings', {
    ...DEFAULT_SETTINGS,
    ...settings,
  });
}

/* -------------------------------------------------------------------------- */
/* Alerts                                                                     */
/* -------------------------------------------------------------------------- */

export async function getAlerts(): Promise<
  SecureGuardAlert[]
> {
  return (
    (await get<SecureGuardAlert[]>('alerts')) ?? []
  );
}

export async function saveAlert(
  alert: SecureGuardAlert,
): Promise<void> {
  const alerts = await getAlerts();

  alerts.unshift({
    ...alert,
    timestamp:
      alert.timestamp ||
      new Date().toISOString(),
  });

  await set(
    'alerts',
    alerts.slice(0, MAX_ALERTS),
  );
}

export async function deleteAlert(
  id: string,
): Promise<void> {
  const alerts = await getAlerts();

  await set(
    'alerts',
    alerts.filter(
      (alert) => alert.id !== id,
    ),
  );
}

export async function clearAlerts(): Promise<void> {
  await set('alerts', []);
}

export async function getAlertsBySeverity(
  severity: Severity,
): Promise<SecureGuardAlert[]> {
  const alerts = await getAlerts();

  return alerts.filter(
    (alert) => alert.severity === severity,
  );
}

export async function getAlertsByType(
  type: string,
): Promise<SecureGuardAlert[]> {
  const alerts = await getAlerts();

  return alerts.filter(
    (alert) => alert.type === type,
  );
}

export async function searchAlertsByWebsite(
  hostname: string,
): Promise<SecureGuardAlert[]> {
  const alerts = await getAlerts();

  const query = hostname.toLowerCase();

  return alerts.filter((alert) =>
    alert.hostname
      .toLowerCase()
      .includes(query),
  );
}

export async function getTodayAlerts(): Promise<
  SecureGuardAlert[]
> {
  const today = new Date().toDateString();
  const alerts = await getAlerts();

  return alerts.filter(
    (alert) =>
      new Date(
        alert.timestamp,
      ).toDateString() === today,
  );
}

/* -------------------------------------------------------------------------- */
/* Statistics                                                                 */
/* -------------------------------------------------------------------------- */

export async function getStats(): Promise<ExtensionStats> {
  const stats =
    await get<Partial<ExtensionStats>>(
      'stats',
    );

  if (!stats) {
    await set('stats', DEFAULT_STATS);

    return { ...DEFAULT_STATS };
  }

  return {
    ...DEFAULT_STATS,
    ...stats,
  };
}

export async function saveStats(
  stats: ExtensionStats,
): Promise<void> {
  await set('stats', stats);
}

export async function incrementSiteScan(): Promise<void> {
  const stats = await getStats();

  await saveStats({
    ...stats,
    sitesScanned:
      stats.sitesScanned + 1,
  });
}

export async function incrementAlertCount(): Promise<void> {
  const stats = await getStats();

  await saveStats({
    ...stats,
    alertsGenerated:
      stats.alertsGenerated + 1,
  });
}

export async function incrementBlockedRequests(): Promise<void> {
  const stats = await getStats();

  await saveStats({
    ...stats,
    blockedRequests:
      stats.blockedRequests + 1,
  });
}

/* -------------------------------------------------------------------------- */
/* Whitelist                                                                  */
/* -------------------------------------------------------------------------- */

export async function getWhitelist(): Promise<
  string[]
> {
  return (
    (await get<string[]>('whitelist')) ?? []
  );
}

export async function addWhitelist(
  hostname: string,
): Promise<void> {
  const whitelist = await getWhitelist();

  const normalized =
    hostname.toLowerCase().trim();

  if (!normalized) {
    return;
  }

  if (!whitelist.includes(normalized)) {
    whitelist.push(normalized);

    await set('whitelist', whitelist);
  }
}

export async function removeWhitelist(
  hostname: string,
): Promise<void> {
  const normalized =
    hostname.toLowerCase().trim();

  const whitelist = await getWhitelist();

  await set(
    'whitelist',
    whitelist.filter(
      (item) => item !== normalized,
    ),
  );
}

export async function isWhitelisted(
  hostname: string,
): Promise<boolean> {
  const normalized =
    hostname.toLowerCase().trim();

  const whitelist = await getWhitelist();

  return whitelist.some(
    (item) =>
      normalized === item ||
      normalized.endsWith(`.${item}`),
  );
}

/* -------------------------------------------------------------------------- */
/* History                                                                    */
/* -------------------------------------------------------------------------- */

export async function getHistory(): Promise<
  HistoryEntry[]
> {
  return (
    (await get<HistoryEntry[]>('history')) ?? []
  );
}

export async function addHistory(
  scan: ScanEvent,
): Promise<void> {
  const history = await getHistory();

  history.unshift({
    ...scan,
    scannedAt:
      new Date().toISOString(),
  });

  await set(
    'history',
    history.slice(0, MAX_HISTORY),
  );
}

export async function clearHistory(): Promise<void> {
  await set('history', []);
}

/* -------------------------------------------------------------------------- */
/* Import / Export                                                            */
/* -------------------------------------------------------------------------- */

export async function exportData(): Promise<
  ExportedData
> {
  return {
    settings: await getSettings(),
    alerts: await getAlerts(),
    stats: await getStats(),
    whitelist: await getWhitelist(),
    history: await getHistory(),
  };
}

export async function importData(
  data: Partial<ExportedData>,
): Promise<void> {
  if (data.settings) {
    await saveSettings(data.settings);
  }

  if (data.alerts) {
    await set(
      'alerts',
      data.alerts.slice(0, MAX_ALERTS),
    );
  }

  if (data.stats) {
    await saveStats(data.stats);
  }

  if (data.whitelist) {
    await set(
      'whitelist',
      data.whitelist,
    );
  }

  if (data.history) {
    await set(
      'history',
      data.history.slice(0, MAX_HISTORY),
    );
  }
}

/* -------------------------------------------------------------------------- */
/* Reset                                                                      */
/* -------------------------------------------------------------------------- */

export async function resetStorage(): Promise<void> {
  await chrome.storage.local.clear();

  await initializeStorage();
}