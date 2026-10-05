const HISTORY_KEY = 'history';
const QUEUE_KEY = 'pendingScanEvents';
const MAX_ACTIVITY_ITEMS = 100;

const statusElement = document.querySelector('#protection-status');
const siteElement = document.querySelector('#current-site');
const protectionToggle = document.querySelector('#protection-toggle');
const notificationsToggle = document.querySelector('#notifications-toggle');
const activityList = document.querySelector('#activity-list');
const activityCount = document.querySelector('#activity-count');
const alertTotal = document.querySelector('#alert-total');
const siteTotal = document.querySelector('#site-total');
const emptyState = document.querySelector('#empty-state');
const clearAlertsButton = document.querySelector('#clear-alerts-button');
const scanPageButton = document.querySelector('#scan-page-button');
const exportButton = document.querySelector('#export-button');
const queueStatus = document.querySelector('#queue-status');
const retryButton = document.querySelector('#retry-button');
const messageElement = document.querySelector('#message');

function setMessage(message, isError = false) {
  messageElement.textContent = message;
  messageElement.classList.toggle('error', isError);
}

function showError(error) {
  console.error('SecureGuard popup failed:', error);
  setMessage(error instanceof Error ? error.message : 'SecureGuard could not complete that action.', true);
}

async function sendBackgroundMessage(message) {
  const response = await chrome.runtime.sendMessage(message);
  if (response?.error === 'Unknown action') {
    throw new Error(
      'SecureGuard was updated but its background worker is outdated. Reload SecureGuard at chrome://extensions and reopen this popup.',
    );
  }
  return response;
}

function formatTime(value) {
  if (!value || Number.isNaN(Date.parse(value))) {
    return 'Time unavailable';
  }

  return new Date(value).toLocaleString([], {
    dateStyle: 'medium',
    timeStyle: 'short',
  });
}

function addDetail(container, label, value) {
  const row = document.createElement('div');
  row.className = 'detail-row';
  const term = document.createElement('dt');
  term.textContent = label;
  const description = document.createElement('dd');
  description.textContent = value || 'Not available';
  row.append(term, description);
  container.append(row);
}

function createAlertEntry(alert) {
  const item = document.createElement('li');
  item.className = 'activity-item';

  const details = document.createElement('details');
  const summary = document.createElement('summary');
  summary.className = 'alert-summary';

  const host = document.createElement('span');
  host.className = 'activity-host';
  host.textContent = alert.hostname || 'Unknown site';

  const severity = document.createElement('span');
  severity.className = `activity-severity ${(alert.severity || '').toLowerCase()}`;
  severity.textContent = alert.severity || 'UNKNOWN';

  const type = document.createElement('span');
  type.className = 'activity-type';
  type.textContent = `${(alert.type || 'alert').toUpperCase()} · ${(alert.detectedData || []).join(', ') || 'Security alert'}`;

  const time = document.createElement('span');
  time.className = 'activity-time';
  time.textContent = formatTime(alert.timestamp);
  summary.append(host, severity, type, time);

  const content = document.createElement('dl');
  content.className = 'alert-details';
  addDetail(content, 'Message', alert.message);
  addDetail(content, 'Site', alert.hostname);

  const urlRow = document.createElement('div');
  urlRow.className = 'detail-row';
  const urlTerm = document.createElement('dt');
  urlTerm.textContent = 'Page';
  const urlDescription = document.createElement('dd');
  if (alert.url) {
    const link = document.createElement('a');
    link.href = alert.url;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    link.textContent = alert.url;
    urlDescription.append(link);
  } else {
    urlDescription.textContent = 'Not available';
  }
  urlRow.append(urlTerm, urlDescription);
  content.append(urlRow);
  addDetail(content, 'Detected', (alert.detectedData || []).join(', '));
  addDetail(content, 'Severity', alert.severity);
  addDetail(content, 'Type', alert.type);
  addDetail(content, 'Time', formatTime(alert.timestamp));

  const actions = document.createElement('div');
  actions.className = 'alert-detail-actions';
  const dismiss = document.createElement('button');
  dismiss.className = 'button-danger';
  dismiss.type = 'button';
  dismiss.textContent = 'Dismiss alert';
  dismiss.addEventListener('click', async (event) => {
    event.preventDefault();
    event.stopPropagation();
    dismiss.disabled = true;
    try {
      const response = await sendBackgroundMessage({
        type: 'DELETE_ALERT',
        id: alert.id,
      });
      if (!response?.success) {
        throw new Error(response?.error || 'Unable to dismiss alert.');
      }
      setMessage('Alert dismissed.');
      await refresh();
    } catch (error) {
      dismiss.disabled = false;
      showError(error);
    }
  });
  actions.append(dismiss);
  content.append(actions);

  details.append(summary, content);
  item.append(details);
  return item;
}

function renderAlerts(alerts) {
  const entries = Array.isArray(alerts) ? alerts : [];
  const visible = entries.slice(0, MAX_ACTIVITY_ITEMS);
  activityCount.textContent = String(entries.length);
  alertTotal.textContent = String(entries.length);
  emptyState.hidden = entries.length > 0;
  clearAlertsButton.hidden = entries.length === 0;
  activityList.replaceChildren();
  visible.forEach((alert) => activityList.append(createAlertEntry(alert)));
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({
    active: true,
    currentWindow: true,
  });
  return tab;
}

async function getActiveSite() {
  const tab = await getActiveTab();
  if (!tab?.url) {
    return 'No active tab';
  }

  try {
    const url = new URL(tab.url);
    return ['http:', 'https:'].includes(url.protocol)
      ? url.hostname
      : 'Scanning unavailable on this browser page';
  } catch {
    return 'Current page unavailable';
  }
}

async function refresh() {
  const [settingsResponse, alertResponse, stored, site] = await Promise.all([
    sendBackgroundMessage({ type: 'GET_SETTINGS' }),
    sendBackgroundMessage({ type: 'GET_ALERTS' }),
    chrome.storage.local.get([HISTORY_KEY, QUEUE_KEY]),
    getActiveSite(),
  ]);

  if (!settingsResponse || settingsResponse.error) {
    throw new Error(settingsResponse?.error || 'Background service worker did not respond.');
  }
  if (!alertResponse?.success) {
    throw new Error(alertResponse?.error || 'Unable to load the alert log.');
  }

  protectionToggle.checked = settingsResponse.realTimeScanning !== false;
  notificationsToggle.checked = settingsResponse.notifications !== false;
  statusElement.textContent = protectionToggle.checked ? 'Protected' : 'Paused';
  statusElement.classList.toggle('off', !protectionToggle.checked);
  siteElement.textContent = site;
  const history = Array.isArray(stored[HISTORY_KEY]) ? stored[HISTORY_KEY] : [];
  siteTotal.textContent = String(new Set(history.map((event) => event.hostname).filter(Boolean)).size);
  renderAlerts(alertResponse.alerts);
  const queue = Array.isArray(stored[QUEUE_KEY]) ? stored[QUEUE_KEY] : [];
  queueStatus.textContent = `Scan queue: ${queue.length} pending`;
}

async function saveSetting(key, value) {
  const currentSettings = await sendBackgroundMessage({
    type: 'GET_SETTINGS',
  });
  if (!currentSettings || currentSettings.error) {
    throw new Error(currentSettings?.error || 'Unable to load current settings.');
  }

  const response = await sendBackgroundMessage({
    type: 'SAVE_SETTINGS',
    settings: { ...currentSettings, [key]: value },
  });
  if (!response?.success) {
    throw new Error('The background service worker could not save this setting.');
  }

  setMessage('Settings saved.');
  await refresh();
}

protectionToggle.addEventListener('change', () => {
  saveSetting('realTimeScanning', protectionToggle.checked).catch(showError);
});

notificationsToggle.addEventListener('change', () => {
  saveSetting('notifications', notificationsToggle.checked).catch(showError);
});

clearAlertsButton.addEventListener('click', async () => {
  if (!window.confirm('Clear all alerts from the SecureGuard log?')) {
    return;
  }

  clearAlertsButton.disabled = true;
  try {
    const response = await sendBackgroundMessage({ type: 'CLEAR_ALERTS' });
    if (!response?.success) {
      throw new Error(response?.error || 'Unable to clear the alert log.');
    }
    setMessage('Alert log cleared.');
    await refresh();
  } catch (error) {
    showError(error);
  } finally {
    clearAlertsButton.disabled = false;
  }
});

scanPageButton.addEventListener('click', async () => {
  scanPageButton.disabled = true;
  setMessage('Scanning current page…');
  try {
    const tab = await getActiveTab();
    if (!tab?.url) {
      throw new Error('The active tab has no scannable URL.');
    }
    const response = await sendBackgroundMessage({
      type: 'SCAN_CURRENT_PAGE',
      url: tab.url,
    });
    if (!response?.success) {
      throw new Error(response?.error || 'Unable to scan the active page.');
    }
    setMessage(response.skipped || 'Page scan completed.');
    await refresh();
  } catch (error) {
    showError(error);
  } finally {
    scanPageButton.disabled = false;
  }
});

exportButton.addEventListener('click', async () => {
  exportButton.disabled = true;
  try {
    const response = await sendBackgroundMessage({ type: 'EXPORT_DATA' });
    if (!response?.success) {
      throw new Error(response?.error || 'Unable to export extension data.');
    }
    const blob = new Blob([JSON.stringify(response.data, null, 2)], {
      type: 'application/json',
    });
    const downloadUrl = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = `secureguard-export-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000);
    setMessage('SecureGuard data exported.');
  } catch (error) {
    showError(error);
  } finally {
    exportButton.disabled = false;
  }
});

retryButton.addEventListener('click', async () => {
  retryButton.disabled = true;
  setMessage('Retrying queued scans…');
  try {
    const response = await sendBackgroundMessage({ type: 'FLUSH_QUEUE' });
    if (!response?.success) {
      throw new Error('The background service worker could not retry scans.');
    }
    await refresh();
    setMessage('Queued scan retry finished.');
  } catch (error) {
    showError(error);
  } finally {
    retryButton.disabled = false;
  }
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === 'local' && (changes.alerts || changes.history || changes.pendingScanEvents)) {
    refresh().catch(showError);
  }
});

refresh().catch(showError);
