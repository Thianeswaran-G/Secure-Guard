import type { FindingType, ScanEvent, Severity } from "@secureguard/shared";
import {
  analyzeRequest,
  isSecureGuardApiRequest,
} from "./core/request-analyzer.js";
import { analyzeUrl } from "./core/url-reputation.js";
import {
  flushQueuedScans,
  submitScanMetadata,
} from "./core/api-client.js";

import {
  initializeStorage,
  getSettings,
  isWhitelisted,
  addHistory,
  exportData,
} from "./core/storage-manager.js";

import {
  createAlertFromScan,
  getAllAlerts,
  removeAlert,
  removeAllAlerts,
} from "./core/alert-manager.js";

interface PendingAlertBatch {
  event: ScanEvent;
  findings: Set<FindingType>;
  hasForm: boolean;
  deadline: number;
  keys: Set<string>;
  timer: ReturnType<typeof setTimeout>;
}

const pendingAlertBatches = new Map<string, PendingAlertBatch>();
const ALERT_BATCH_QUIET_PERIOD = 3_000;
const ALERT_BATCH_MAX_DURATION = 15_000;

function severityRank(severity: Severity): number {
  switch (severity) {
    case "CRITICAL":
      return 3;
    case "HIGH":
      return 2;
    case "MEDIUM":
      return 1;
    case "LOW":
      return 0;
  }
}

function makeEvent(
  url: string,
  scanType: ScanEvent["scanType"],
  score: number,
  severity: Severity,
  findings: ScanEvent["findings"],
): ScanEvent | null {
  try {
    const parsed = new URL(url);

    return {
      url,
      hostname: parsed.hostname,
      scanType,
      riskScore: Math.min(100, Math.max(0, score)),
      severity,
      findings: [...new Set(findings)],
      timestamp: new Date().toISOString(),
    };
  } catch {
    return null;
  }
}

function flushAlertBatch(batch: PendingAlertBatch): void {
  clearTimeout(batch.timer);
  for (const key of batch.keys) {
    if (pendingAlertBatches.get(key) === batch) {
      pendingAlertBatches.delete(key);
    }
  }

  const alertEvent: ScanEvent = {
    ...batch.event,
    findings: [...batch.findings],
  };

  void createAlertFromScan(alertEvent).catch((error: unknown) => {
    console.error(
      "SecureGuard could not create a consolidated alert:",
      error,
    );
  });
}

function scheduleAlert(
  event: ScanEvent,
  tabId: number | undefined,
  initiator?: string,
): void {
  if (!event.findings.length) {
    return;
  }

  const keys = new Set<string>();
  if (tabId !== undefined && tabId >= 0) {
    keys.add(`tab:${tabId}`);
  }

  const contextUrl = event.scanType === "REQUEST"
    ? initiator
    : event.url;
  if (contextUrl) {
    try {
      keys.add(`origin:${new URL(contextUrl).origin}`);
    } catch {
      // The tab key still correlates the event when the URL is invalid.
    }
  }

  if (!keys.size) {
    void createAlertFromScan(event).catch((error: unknown) => {
      console.error("SecureGuard could not create an alert:", error);
    });
    return;
  }

  const now = Date.now();
  let batch: PendingAlertBatch | undefined;
  for (const key of keys) {
    batch = pendingAlertBatches.get(key);
    if (batch) {
      break;
    }
  }

  if (
    batch &&
    (now >= batch.deadline ||
      (event.scanType === "FORM" && batch.hasForm))
  ) {
    flushAlertBatch(batch);
    batch = undefined;
  }

  if (!batch) {
    let newBatch: PendingAlertBatch;
    const timer = setTimeout(
      () => flushAlertBatch(newBatch),
      ALERT_BATCH_QUIET_PERIOD,
    );
    newBatch = {
      event,
      findings: new Set(event.findings),
      hasForm: event.scanType === "FORM",
      deadline: now + ALERT_BATCH_MAX_DURATION,
      keys,
      timer,
    };
    batch = newBatch;
    for (const key of keys) {
      pendingAlertBatches.set(key, batch);
    }
    return;
  }

  for (const key of keys) {
    if (!batch.keys.has(key)) {
      batch.keys.add(key);
      pendingAlertBatches.set(key, batch);
    }
  }

  for (const finding of event.findings) {
    batch.findings.add(finding);
  }

  if (event.scanType === "FORM") {
    batch.deadline = now + ALERT_BATCH_MAX_DURATION;
    batch.event = {
      ...event,
      riskScore: Math.max(batch.event.riskScore, event.riskScore),
      severity:
        severityRank(batch.event.severity) > severityRank(event.severity)
          ? batch.event.severity
          : event.severity,
    };
    batch.hasForm = true;
  } else if (severityRank(event.severity) > severityRank(batch.event.severity)) {
    batch.event = {
      ...batch.event,
      severity: event.severity,
      riskScore: Math.max(batch.event.riskScore, event.riskScore),
    };
  }

  clearTimeout(batch.timer);
  batch.timer = setTimeout(
    () => flushAlertBatch(batch!),
    Math.min(
      ALERT_BATCH_QUIET_PERIOD,
      Math.max(0, batch.deadline - Date.now()),
    ),
  );
}

async function reportScan(
  event: ScanEvent | null,
  tabId?: number,
  initiator?: string,
): Promise<void> {
  if (!event) {
    return;
  }

  scheduleAlert(event, tabId, initiator);

  await addHistory(event);

  await submitScanMetadata(event);
}

async function initialize(): Promise<void> {
  await initializeStorage();

  await chrome.alarms.clear("secureguard-sync");

  await chrome.alarms.create("secureguard-sync", {
    periodInMinutes: 5,
  });
}

function isScanEvent(value: unknown): value is ScanEvent {
  if (!value || typeof value !== "object") {
    return false;
  }

  const event = value as Partial<ScanEvent>;
  const scanTypes: ScanEvent["scanType"][] = [
    "FORM",
    "FILE",
    "URL",
    "REQUEST",
    "HEADER",
  ];
  const severities: Severity[] = [
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
  ];
  const findings: ScanEvent["findings"][number][] = [
    "PASSWORD",
    "CREDIT_CARD",
    "CVV",
    "OTP",
    "TOKEN",
    "SECRET",
    "API_KEY",
    "AADHAAR",
    "SSN",
    "SENSITIVE_FILE",
  ];

  return (
    typeof event.url === "string" &&
    typeof event.hostname === "string" &&
    scanTypes.includes(event.scanType as ScanEvent["scanType"]) &&
    Number.isInteger(event.riskScore) &&
    event.riskScore! >= 0 &&
    event.riskScore! <= 100 &&
    severities.includes(event.severity as Severity) &&
    Array.isArray(event.findings) &&
    event.findings.every((finding) => findings.includes(finding)) &&
    typeof event.timestamp === "string" &&
    !Number.isNaN(Date.parse(event.timestamp))
  );
}

function initializeSafely(): void {
  void initialize().catch((error: unknown) => {
    console.error(
      "SecureGuard service worker initialization failed:",
      error,
    );
  });
}

chrome.runtime.onInstalled.addListener(() => {
  initializeSafely();
});

chrome.runtime.onStartup.addListener(() => {
  initializeSafely();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "secureguard-sync") {
    void flushQueuedScans().catch((error: unknown) => {
      console.error(
        "SecureGuard could not flush queued scans:",
        error,
      );
    });
  }
});

/* -------------------------------------------------------------------------- */
/* Network monitoring                                                         */
/* -------------------------------------------------------------------------- */

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (
      isSecureGuardApiRequest(
        details.url,
        details.method,
      )
    ) {
      return undefined;
    }

    void (async () => {
      const settings = await getSettings();

      if (!settings.realTimeScanning) {
        return;
      }

      const method = details.method.toUpperCase();

      if (!["POST", "PUT", "PATCH"].includes(method)) {
        return;
      }

      let hostname: string;

      try {
        hostname = new URL(details.url).hostname;
      } catch {
        return;
      }

      if (await isWhitelisted(hostname)) {
        return;
      }

      const result = analyzeRequest({
        url: details.url,
        method,
        initiator: details.initiator,
        requestBody: details.requestBody,
      });

      if (!result.findings.length || result.score < 25) {
        return;
      }

      const event = makeEvent(
        details.url,
        "REQUEST",
        result.score,
        result.severity,
        result.findings,
      );

      await reportScan(event, details.tabId, details.initiator);
    })();

    return undefined;
  },
  {
    urls: ["http://*/*", "https://*/*"],
  },
  ["requestBody"],
);

/* -------------------------------------------------------------------------- */
/* URL monitoring                                                             */
/* -------------------------------------------------------------------------- */

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  void (async () => {
    if (
      changeInfo.status !== "complete" ||
      !tab.url ||
      !/^https?:\/\//i.test(tab.url)
    ) {
      return;
    }

    const settings = await getSettings();

    if (!settings.realTimeScanning) {
      return;
    }

    let hostname: string;

    try {
      hostname = new URL(tab.url).hostname;
    } catch {
      return;
    }

    if (await isWhitelisted(hostname)) {
      return;
    }

    const result = analyzeUrl(tab.url);

    /*
     * URL reputation is expressed as
     * 100 = trusted and 0 = dangerous.
     * Convert it into the common risk score.
     */
    const riskScore = Math.max(0, 100 - result.score);

    if (riskScore < 25) {
      return;
    }

    const severity: Severity =
      riskScore >= 80
        ? "CRITICAL"
        : riskScore >= 60
          ? "HIGH"
          : riskScore >= 30
            ? "MEDIUM"
            : "LOW";

    const event = makeEvent(tab.url, "URL", riskScore, severity, []);

    await reportScan(event, tabId);
  })();
});

/* -------------------------------------------------------------------------- */
/* Extension messages                                                         */
/* -------------------------------------------------------------------------- */

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "SECUREGUARD_REPORT_SCAN") {
    if (!isScanEvent(message.event)) {
      sendResponse({
        success: false,
        error: "Invalid scan event",
      });

      return false;
    }

    void reportScan(message.event, _sender.tab?.id).then(
      () => sendResponse({ success: true }),
      (error: unknown) => {
        console.error(
          "SecureGuard could not report a content scan:",
          error,
        );
        sendResponse({
          success: false,
          error: "The background service worker could not report the scan",
        });
      },
    );

    return true;
  }

  if (message?.type === "GET_ALERTS") {
    getAllAlerts().then(
      (alerts) => sendResponse({ success: true, alerts }),
      (error: unknown) => {
        console.error("SecureGuard could not load its alert log:", error);
        sendResponse({ success: false, error: "Unable to load alert log" });
      },
    );

    return true;
  }

  if (message?.type === "DELETE_ALERT") {
    if (typeof message.id !== "string" || !message.id) {
      sendResponse({ success: false, error: "Invalid alert ID" });
      return false;
    }

    removeAlert(message.id).then(
      () => sendResponse({ success: true }),
      (error: unknown) => {
        console.error("SecureGuard could not dismiss the alert:", error);
        sendResponse({ success: false, error: "Unable to dismiss alert" });
      },
    );

    return true;
  }

  if (message?.type === "CLEAR_ALERTS") {
    removeAllAlerts().then(
      () => sendResponse({ success: true }),
      (error: unknown) => {
        console.error("SecureGuard could not clear the alert log:", error);
        sendResponse({ success: false, error: "Unable to clear alert log" });
      },
    );

    return true;
  }

  if (message?.type === "EXPORT_DATA") {
    exportData().then(
      (data) => sendResponse({ success: true, data }),
      (error: unknown) => {
        console.error("SecureGuard could not export its data:", error);
        sendResponse({ success: false, error: "Unable to export extension data" });
      },
    );

    return true;
  }

  if (message?.type === "SCAN_CURRENT_PAGE") {
    const url = message.url;
    if (typeof url !== "string") {
      sendResponse({ success: false, error: "Invalid page URL" });
      return false;
    }

    void (async () => {
      const pageUrl = new URL(url);
      if (!["http:", "https:"].includes(pageUrl.protocol)) {
        throw new Error("Only HTTP and HTTPS pages can be scanned.");
      }

      const settings = await getSettings();
      if (!settings.realTimeScanning) {
        sendResponse({ success: false, error: "Real-time scanning is paused" });
        return;
      }

      if (await isWhitelisted(pageUrl.hostname)) {
        sendResponse({ success: true, skipped: "Site is whitelisted" });
        return;
      }

      const result = analyzeUrl(pageUrl.href);
      const riskScore = Math.max(0, 100 - result.score);
      if (riskScore < 25) {
        sendResponse({ success: true, skipped: "No elevated URL risk detected" });
        return;
      }

      const severity: Severity =
        riskScore >= 80 ? "CRITICAL" :
          riskScore >= 60 ? "HIGH" :
            riskScore >= 30 ? "MEDIUM" : "LOW";
      await reportScan(
        makeEvent(pageUrl.href, "URL", riskScore, severity, []),
      );
      sendResponse({ success: true });
    })().catch((error: unknown) => {
      console.error("SecureGuard could not scan the active page:", error);
      sendResponse({ success: false, error: "Unable to scan the active page" });
    });

    return true;
  }

  if (message?.type === "GET_SETTINGS") {
    getSettings()
      .then(sendResponse)
      .catch(() =>
        sendResponse({
          error: "Unable to load settings",
        }),
      );

    return true;
  }

  if (message?.type === "SAVE_SETTINGS") {
    chrome.storage.local
      .set({
        settings: message.settings,
      })
      .then(() =>
        sendResponse({
          success: true,
        }),
      )
      .catch(() =>
        sendResponse({
          success: false,
        }),
      );

    return true;
  }

  if (message?.type === "FLUSH_QUEUE") {
    flushQueuedScans()
      .then(() =>
        sendResponse({
          success: true,
        }),
      )
      .catch(() =>
        sendResponse({
          success: false,
        }),
      );

    return true;
  }

  sendResponse({
    error: "Unknown action",
  });

  return true;
});

initializeSafely();
