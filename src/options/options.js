// URL Sentinel options page: sensitivity, Safe Browsing key, protection
// toggles, custom lists, and statistics. All settings live in
// chrome.storage.local via src/lib/settings.js.

import { getSettings, saveSettings, getStats, resetStats, parseListText } from '../lib/settings.js';
import { checkSafeBrowsing } from '../lib/reputation.js';

// Google's own test URL for Safe Browsing — documented to return a MALWARE
// match, so it proves the key works without visiting a real malicious site.
const SAFE_BROWSING_TEST_URL = 'http://testsafebrowsing.appspot.com/s/malware.html';

const $ = (id) => document.getElementById(id);

async function load() {
  const settings = await getSettings();
  for (const radio of document.querySelectorAll('input[name="sensitivity"]')) {
    radio.checked = radio.value === settings.sensitivity;
  }
  $('sb-key').value = settings.safeBrowsingKey || '';
  $('enable-blocking').checked = settings.enableBlocking;
  $('enable-link-scanning').checked = settings.enableLinkScanning;
  $('enable-badge').checked = settings.enableBadge;
  $('blocklist').value = (settings.blocklist || []).join('\n');
  $('allowlist').value = (settings.allowlist || []).join('\n');
  await refreshStats();
}

async function refreshStats() {
  const stats = await getStats();
  $('stats-line').textContent =
    `${stats.checked} URLs checked · ${stats.suspicious} suspicious · ` +
    `${stats.malicious} malicious · ${stats.blocked} blocked` +
    (stats.lastReset ? ` · last reset ${new Date(stats.lastReset).toLocaleDateString()}` : '');
}

$('save-btn').addEventListener('click', async () => {
  const sensitivity = document.querySelector('input[name="sensitivity"]:checked')?.value || 'balanced';
  await saveSettings({
    sensitivity,
    safeBrowsingKey: $('sb-key').value.trim(),
    enableBlocking: $('enable-blocking').checked,
    enableLinkScanning: $('enable-link-scanning').checked,
    enableBadge: $('enable-badge').checked,
    blocklist: parseListText($('blocklist').value),
    allowlist: parseListText($('allowlist').value),
  });
  const msg = $('saved-msg');
  msg.textContent = 'Saved ✓';
  setTimeout(() => {
    msg.textContent = '';
  }, 2500);
});

$('test-key-btn').addEventListener('click', async () => {
  const key = $('sb-key').value.trim();
  const out = $('test-result');
  out.className = 'test-result';
  if (!key) {
    out.textContent = 'Enter an API key first.';
    return;
  }
  out.textContent = 'Testing…';
  const result = await checkSafeBrowsing(SAFE_BROWSING_TEST_URL, key);
  if (result.matched) {
    out.textContent = `Key works — Google flagged the test URL (${result.threatType}).`;
    out.classList.add('ok');
  } else if (result.error) {
    out.textContent = `Lookup failed (${result.error}). Check the key and try again.`;
    out.classList.add('bad');
  } else {
    out.textContent = 'Key accepted, but Google did not flag the test URL — unexpected. Try again later.';
    out.classList.add('bad');
  }
});

$('reset-stats-btn').addEventListener('click', async () => {
  await resetStats();
  await refreshStats();
});

load();
