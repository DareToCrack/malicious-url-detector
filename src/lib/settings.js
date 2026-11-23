// Settings, blocklist/allowlist, and stats storage.
//
// All data lives in chrome.storage.local on the device — nothing is synced or
// sent anywhere. The temporary allowlist (used by "Proceed anyway" on the
// warning page) lives in chrome.storage.session when available, so it clears
// when the browser closes; it falls back to in-memory storage otherwise.
//
// Every function degrades gracefully when chrome.storage is unavailable
// (e.g. when a UI page is opened as a plain file for screenshots): settings
// fall back to defaults and stats to zeros.

export const DEFAULT_SETTINGS = {
  sensitivity: 'balanced', // 'strict' | 'balanced' | 'lenient'
  safeBrowsingKey: '', // optional Google Safe Browsing API key
  blocklist: [], // user-added domains/URLs, one per line in Options
  allowlist: [], // user-added domains/URLs, never flagged or blocked
  enableBlocking: true, // redirect Malicious verdicts to the warning page
  enableLinkScanning: true, // content script marks suspicious links
  enableBadge: true, // toolbar badge shows the current tab's risk band
};

export const DEFAULT_STATS = {
  checked: 0,
  suspicious: 0,
  malicious: 0,
  blocked: 0,
  lastReset: null,
};

const SETTINGS_KEY = 'urlSentinelSettings';
const STATS_KEY = 'urlSentinelStats';
const TEMP_ALLOW_KEY = 'urlSentinelTempAllow';

// In-memory fallback when chrome.storage is unavailable.
const memoryStore = new Map();

function hasChromeStorage() {
  return typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local;
}

async function storageGet(key, fallback) {
  if (hasChromeStorage()) {
    try {
      const out = await chrome.storage.local.get(key);
      return out[key] !== undefined ? out[key] : fallback;
    } catch {
      return fallback;
    }
  }
  return memoryStore.has(key) ? memoryStore.get(key) : fallback;
}

async function storageSet(key, value) {
  if (hasChromeStorage()) {
    try {
      await chrome.storage.local.set({ [key]: value });
      return;
    } catch {
      // fall through to memory
    }
  }
  memoryStore.set(key, value);
}

export async function getSettings() {
  const stored = await storageGet(SETTINGS_KEY, {});
  return { ...DEFAULT_SETTINGS, ...(stored || {}) };
}

export async function saveSettings(patch) {
  const current = await getSettings();
  const next = { ...current, ...patch };
  await storageSet(SETTINGS_KEY, next);
  return next;
}

export async function getStats() {
  const stored = await storageGet(STATS_KEY, {});
  return { ...DEFAULT_STATS, ...(stored || {}) };
}

export async function bumpStat(field, by = 1) {
  const stats = await getStats();
  stats[field] = (stats[field] || 0) + by;
  await storageSet(STATS_KEY, stats);
  return stats;
}

export async function resetStats() {
  const stats = { ...DEFAULT_STATS, lastReset: new Date().toISOString() };
  await storageSet(STATS_KEY, stats);
  return stats;
}

// --- temporary allowlist (warning page "Proceed anyway") -------------------
// Entries: { [url]: expiresAtMs }. Kept in chrome.storage.session so they
// disappear when the browser closes; in-memory otherwise.

function hasSessionStorage() {
  return typeof chrome !== 'undefined' && chrome.storage && chrome.storage.session;
}

async function tempAllowGetAll() {
  if (hasSessionStorage()) {
    try {
      const out = await chrome.storage.session.get(TEMP_ALLOW_KEY);
      return out[TEMP_ALLOW_KEY] || {};
    } catch {
      return {};
    }
  }
  return memoryStore.get(TEMP_ALLOW_KEY) || {};
}

async function tempAllowSetAll(map) {
  if (hasSessionStorage()) {
    try {
      await chrome.storage.session.set({ [TEMP_ALLOW_KEY]: map });
      return;
    } catch {
      // fall through to memory
    }
  }
  memoryStore.set(TEMP_ALLOW_KEY, map);
}

export async function tempAllowUrl(url, minutes = 30) {
  const map = await tempAllowGetAll();
  map[url] = Date.now() + minutes * 60 * 1000;
  await tempAllowSetAll(map);
}

export async function isTempAllowed(url) {
  const map = await tempAllowGetAll();
  const expires = map[url];
  if (!expires) return false;
  if (expires < Date.now()) {
    delete map[url];
    await tempAllowSetAll(map);
    return false;
  }
  return true;
}

// --- list matching ----------------------------------------------------------
// A list entry matches a URL when it equals the URL's host, is a suffix of
// the host (subdomains included), or is a substring of the full URL. Entries
// are normalised (lowercase, no scheme, no trailing slash) on save; matching
// is case-insensitive.

export function normaliseListEntry(entry) {
  return String(entry || '')
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/$/, '');
}

export function parseListText(text) {
  return String(text || '')
    .split('\n')
    .map(normaliseListEntry)
    .filter(Boolean);
}

export function listMatches(list, urlString) {
  let host = '';
  try {
    host = new URL(urlString).hostname.toLowerCase();
  } catch {
    return false;
  }
  const urlLower = urlString.toLowerCase();
  return (list || []).some((rawEntry) => {
    const entry = normaliseListEntry(rawEntry);
    if (!entry) return false;
    if (host === entry || host.endsWith(`.${entry}`)) return true;
    if (urlLower.includes(entry)) return true;
    return false;
  });
}
