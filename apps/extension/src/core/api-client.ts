
import type { ScanEvent } from '@secureguard/shared';

const API_BASE = 'http://localhost:3000/api';
const QUEUE_KEY = 'pendingScanEvents';
const MAX_QUEUE_SIZE = 100;
const REQUEST_TIMEOUT = 10_000;
let flushInProgress: Promise<void> | undefined;

async function getQueue(): Promise<ScanEvent[]> {
  const result =
    await chrome.storage.local.get(QUEUE_KEY);

  return Array.isArray(result[QUEUE_KEY])
    ? result[QUEUE_KEY]
    : [];
}

async function saveQueue(
  events: ScanEvent[],
): Promise<void> {
  await chrome.storage.local.set({
    [QUEUE_KEY]: events.slice(-MAX_QUEUE_SIZE),
  });
}

function eventKey(event: ScanEvent): string {
  return [
    event.url,
    event.scanType,
    event.timestamp,
    event.riskScore,
  ].join('|');
}

async function queue(
  event: ScanEvent,
): Promise<void> {
  const events = await getQueue();

  const key = eventKey(event);

  if (
    events.some(
      (queuedEvent) =>
        eventKey(queuedEvent) === key,
    )
  ) {
    return;
  }

  await saveQueue([
    ...events,
    event,
  ]);
}

async function post(
  event: ScanEvent,
): Promise<boolean> {
  const controller =
    new AbortController();

  const timeout = setTimeout(
    () => controller.abort(),
    REQUEST_TIMEOUT,
  );

  try {
    const response = await fetch(
      `${API_BASE}/scans`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(event),
        signal: controller.signal,
      },
    );

    if (!response.ok) {
      console.debug(
        `SecureGuard scan API returned HTTP ${response.status}.`,
      );

      return false;
    }

    return true;
  } catch (error) {
    console.debug(
      'SecureGuard scan API request failed; keeping the scan queued for retry.',
      error,
    );

    return false;
  } finally {
    clearTimeout(timeout);
  }
}

export async function submitScanMetadata(
  event: ScanEvent,
): Promise<void> {
  const success = await post(event);

  if (!success) {
    await queue(event);
  }
}

export async function submitScanFromContent(
  event: ScanEvent,
): Promise<void> {
  try {
    const response = await chrome.runtime.sendMessage({
      type: 'SECUREGUARD_REPORT_SCAN',
      event,
    });

    if (response?.success === true) {
      return;
    }

    throw new Error(
      response?.error ??
      'The background service worker did not accept the scan.',
    );
  } catch (error) {
    console.debug(
      'SecureGuard could not reach the background service worker; queueing the scan locally.',
      error,
    );

    await queue(event);
  }
}

async function flushQueue(): Promise<void> {
  const events = await getQueue();

  if (!events.length) {
    return;
  }

  const successfulKeys = new Set<string>();

  /*
   * Process sequentially so an unavailable API doesn't
   * create dozens of simultaneous requests.
   */
  for (const event of events) {
    const success = await post(event);

    if (success) {
      successfulKeys.add(eventKey(event));
    }
  }

  const currentEvents = await getQueue();

  await saveQueue(
    currentEvents.filter(
      (event) => !successfulKeys.has(eventKey(event)),
    ),
  );
}

export function flushQueuedScans(): Promise<void> {
  if (!flushInProgress) {
    flushInProgress = flushQueue().finally(() => {
      flushInProgress = undefined;
    });
  }

  return flushInProgress;
}

export async function getPendingScanCount(): Promise<number> {
  const events = await getQueue();

  return events.length;
}

export async function clearPendingScans(): Promise<void> {
  await chrome.storage.local.remove(
    QUEUE_KEY,
  );
}