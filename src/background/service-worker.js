// URL Sentinel — background service worker (Manifest V3, ES module).
//
// Responsibilities:
//  - Analyse every main-frame navigation with the heuristic engine.
//  - Show a risk badge on the toolbar icon (amber/red; nothing when safe).
//  - Redirect Malicious verdicts (and user-blocklisted URLs) to the warning
//    interstitial, unless blocking is off or the URL is allowlisted.
//  - Optional Google Safe Browsing reputation lookup (only with an API key).
//  - Answer messages from the popup, content script, and warning page.
//  - Keep the stats counters in chrome.storage.local.
//
// Privacy: no data leaves the device except the optional Safe Browsing
// lookup, which sends the checked URL to Google's API (only when the user
// has entered a key in Options).

import { analyzeUrl } from '../engine/analyzer.js';
import {
  getSettings,
  saveSettings,
  getStats,
  bumpStat,
  tempAllowUrl,
  isTempAllowed,
  listMatches,
} from '../lib/settings.js';
import { checkSafeBrowsing } from '../lib/reputation.js';

const BADGE_COLORS = {
  safe: '#15803d',
  suspicious: '#b45309',
  malicious: '#b91c1c',
};

// In-memory reputation cache: url -> { result, at }. Avoids re-querying
// Safe Browsing for the same URL within an hour.
const reputationCache = new Map();
const REPUTATION_TTL_MS = 60 * 60 * 1000;

async function reputationLookup(url, apiKey) {
  const cached = reputationCache.get(url);
  if (cached && Date.now() - cached.at < REPUTATION_TTL_MS) return cached.result;
  const result = await checkSafeBrowsing(url, apiKey);
  reputationCache.set(url, { result, at: Date.now() });
  return result;
}

// Full analysis: heuristics first, then reputation (when a key is set).
// A Safe Browsing match overrides the verdict to Malicious and adds a finding.
export async function analyzeFull(url, settings) {
  const result = analyzeUrl(url, { sensitivity: settings.sensitivity });
  result.reputation = { checked: false, matched: false, threatType: null };
  if (result.error || !settings.safeBrowsingKey) return result;
  const rep = await reputationLookup(url, settings.safeBrowsingKey);
  result.reputation.checked = !rep.error;
  if (rep.matched) {
    result.reputation.matched = true;
    result.reputation.threatType = rep.threatType;
    result.findings.push({
      id: 'safeBrowsing',
      title: `Flagged by Google Safe Browsing (${rep.threatType || 'known threat'})`,
      detail: 'This URL appears in Google Safe Browsing threat lists.',
      explanation:
        'Google Safe Browsing — a continuously updated list of confirmed malicious sites — lists this address. This is the strongest signal the extension can produce.',
      points: 100,
      severity: 'high',
    });
    result.totalPoints += 100;
    result.score = 100;
    result.verdict = 'malicious';
    result.bandLabel = 'Malicious';
  }
  return result;
}

function warningUrlFor(result) {
  const params = new URLSearchParams({
    url: result.url,
    score: String(result.score),
    verdict: result.verdict,
    findings: JSON.stringify(
      result.findings.map((f) => ({ title: f.title, detail: f.detail, points: f.points })),
    ),
  });
  return chrome.runtime.getURL(`src/warning/warning.html?${params.toString()}`);
}

async function setBadge(tabId, verdict) {
  const settings = await getSettings();
  if (!settings.enableBadge) {
    await chrome.action.setBadgeText({ tabId, text: '' });
    return;
  }
  const text = verdict === 'malicious' ? '!!' : verdict === 'suspicious' ? '!' : '';
  await chrome.action.setBadgeText({ tabId, text });
  await chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS[verdict] });
}

// --- navigation handling ----------------------------------------------------
// Two listeners, two jobs, no double counting:
//  - onBeforeNavigate: blocking decision only (redirect if Malicious or
//    blocklisted). Stats for a blocked navigation are counted here, because
//    a redirected navigation never commits.
//  - onCommitted: stats + badge for navigations that actually loaded, plus a
//    safety-net re-check in case the first redirect raced the navigation.

async function blockingDecision(url) {
  const settings = await getSettings();
  if (listMatches(settings.allowlist, url) || (await isTempAllowed(url))) {
    return { action: 'allow', settings };
  }
  if (listMatches(settings.blocklist, url)) {
    return {
      action: 'block',
      settings,
      result: {
        url,
        score: 100,
        verdict: 'malicious',
        bandLabel: 'Malicious',
        findings: [
          {
            title: 'Blocked by your own blocklist',
            detail: 'This address matches an entry in your custom blocklist.',
            points: 100,
          },
        ],
      },
    };
  }
  const result = await analyzeFull(url, settings);
  if (result.error) return { action: 'allow', settings, result };
  if (result.verdict === 'malicious' && settings.enableBlocking) {
    return { action: 'block', settings, result };
  }
  return { action: 'allow', settings, result };
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // main frame only
  const url = details.url;
  if (!url.startsWith('http://') && !url.startsWith('https://')) return;
  const decision = await blockingDecision(url);
  if (decision.action !== 'block') return;
  await bumpStat('checked');
  await bumpStat('malicious');
  await bumpStat('blocked');
  await chrome.tabs.update(details.tabId, { url: warningUrlFor(decision.result) });
});

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const url = details.url;
  if (!url.startsWith('http://') && !url.startsWith('https://')) return;
  const settings = await getSettings();
  if (listMatches(settings.allowlist, url) || (await isTempAllowed(url))) {
    await setBadge(details.tabId, 'safe');
    return;
  }
  const result = await analyzeFull(url, settings);
  if (result.error) return; // unparseable — fail safe, no badge, no block
  await bumpStat('checked');
  if (result.verdict === 'suspicious') await bumpStat('suspicious');
  if (result.verdict === 'malicious') await bumpStat('malicious');
  await setBadge(details.tabId, result.verdict);
  // Safety net: if the onBeforeNavigate redirect raced and the malicious
  // page still committed, redirect now.
  if (result.verdict === 'malicious' && settings.enableBlocking) {
    try {
      const tab = await chrome.tabs.get(details.tabId);
      if (tab.url === url) {
        await bumpStat('blocked');
        await chrome.tabs.update(details.tabId, { url: warningUrlFor(result) });
      }
    } catch {
      // Tab closed already — nothing to do.
    }
  }
});

// --- messages from popup / content script / warning page --------------------

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    if (!message || typeof message.type !== 'string') return;
    if (message.type === 'analyze') {
      const settings = await getSettings();
      sendResponse(await analyzeFull(message.url, settings));
    } else if (message.type === 'analyze-batch') {
      const settings = await getSettings();
      const urls = Array.isArray(message.urls) ? message.urls.slice(0, 200) : [];
      const out = urls.map((url) => {
        const r = analyzeUrl(url, { sensitivity: settings.sensitivity });
        return {
          url,
          verdict: r.verdict,
          score: r.score,
          topFinding: r.findings.length ? r.findings[0].title : null,
          blocked: listMatches(settings.blocklist, url),
          allowed: listMatches(settings.allowlist, url),
        };
      });
      sendResponse(out);
    } else if (message.type === 'get-settings') {
      sendResponse(await getSettings());
    } else if (message.type === 'get-stats') {
      sendResponse(await getStats());
    } else if (message.type === 'temp-allow') {
      await tempAllowUrl(message.url, 30);
      sendResponse({ ok: true });
    } else if (message.type === 'add-to-list') {
      const settings = await getSettings();
      const list = message.list === 'allowlist' ? 'allowlist' : 'blocklist';
      const entry = String(message.entry || '').trim().toLowerCase();
      if (entry && !settings[list].includes(entry)) {
        settings[list] = [...settings[list], entry];
        await saveSettings({ [list]: settings[list] });
      }
      sendResponse({ ok: true });
    }
  })();
  return true; // keep the message channel open for the async response
});

// --- install -----------------------------------------------------------------

chrome.runtime.onInstalled.addListener(async () => {
  // Touch storage so defaults exist from the first run.
  await getSettings();
  await getStats();
});
