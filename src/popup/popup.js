// URL Sentinel popup: verdict for the current tab's URL.
//
// Data flow: the popup asks the background worker to analyse the current
// tab (message "analyze"), so the verdict includes the optional Safe
// Browsing reputation result. Demo mode (?demo=safe|suspicious|malicious)
// analyses a fixed demo URL locally instead — used for screenshots and
// previews, and it works even when the page is opened as a plain file.

import { analyzeUrl } from '../engine/analyzer.js';

const DEMO_URLS = {
  safe: 'https://www.wikipedia.org/wiki/Phishing',
  suspicious: 'http://185.220.101.5/login',
  malicious: 'https://paypa1.com/secure/verify',
};

const ADVICE = {
  safe: 'No signs of anything malicious in this address. Stay alert as usual — heuristics cannot prove a site is safe, only that nothing suspicious was found.',
  suspicious:
    'This address has some traits seen in malicious sites. Avoid entering passwords or payment details here, and double-check the address before trusting it.',
  malicious:
    'This address strongly matches malicious patterns. Do not enter any credentials or personal details. Leave this site unless you are certain it is legitimate.',
};

const main = document.getElementById('main');
const footer = document.getElementById('stats-footer');

function escapeHtml(s) {
  return String(s)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

function render(result, { demo = false } = {}) {
  if (result.error) {
    main.innerHTML = `
      <div class="url-box"><strong>${escapeHtml(result.url || 'This page')}</strong></div>
      <div class="error-box" style="margin-top:10px">${escapeHtml(result.error)}</div>`;
    return;
  }

  const rep = result.reputation || { checked: false, matched: false };
  const repLine = rep.matched
    ? `<div class="reputation match"><strong>Google Safe Browsing:</strong> flagged as ${escapeHtml(
        rep.threatType || 'a known threat',
      )}.</div>`
    : rep.checked
      ? `<div class="reputation"><strong>Google Safe Browsing:</strong> no match — this URL is not on Google's threat lists.</div>`
      : demo
        ? `<div class="reputation"><strong>Demo:</strong> reputation lookup is not run for demo verdicts.</div>`
        : `<div class="reputation"><strong>Google Safe Browsing:</strong> not checked — add an API key in Options to enable reputation lookups.</div>`;

  const findingsHtml = result.findings.length
    ? `<div class="findings"><h2>Findings (${result.findings.length}) — points add up to the score</h2>
      ${result.findings
        .map(
          (f) => `<div class="finding">
            <div class="finding-head"><span class="finding-title">${escapeHtml(f.title)}</span><span class="points">+${f.points} pts</span></div>
            <p class="finding-detail">${escapeHtml(f.detail)}</p>
            <p class="finding-why">${escapeHtml(f.explanation)}</p>
          </div>`,
        )
        .join('')}</div>`
    : `<div class="no-findings">No suspicious traits found in this address.</div>`;

  main.innerHTML = `
    <div class="url-box"><strong>${escapeHtml(result.host || result.url)}</strong><br>${escapeHtml(result.url)}</div>
    <div class="verdict-card">
      <div class="score">${result.score}<small> / 100</small></div>
      <div class="band band-${result.verdict}">${escapeHtml(result.bandLabel)}</div>
      <p class="verdict-note">Risk score from heuristic analysis${demo ? ' (demo)' : ''} — ${escapeHtml(
        result.sensitivity || 'balanced',
      )} sensitivity.</p>
    </div>
    ${repLine}
    ${findingsHtml}
    <div class="advice advice-${result.verdict}">${ADVICE[result.verdict]}</div>
    <div class="actions">
      <button class="btn" id="allow-btn">Allow this site</button>
      <button class="btn" id="block-btn">Block this site</button>
    </div>`;

  const allowBtn = document.getElementById('allow-btn');
  const blockBtn = document.getElementById('block-btn');
  const hasRuntime = typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage;
  if (!hasRuntime || demo) {
    allowBtn.disabled = true;
    blockBtn.disabled = true;
    allowBtn.title = demo ? 'Disabled in demo mode' : 'Available in the installed extension';
    blockBtn.title = allowBtn.title;
    return;
  }
  allowBtn.addEventListener('click', async () => {
    allowBtn.disabled = true;
    allowBtn.textContent = 'Allowed ✓';
    await chrome.runtime.sendMessage({ type: 'add-to-list', list: 'allowlist', entry: result.host });
  });
  blockBtn.addEventListener('click', async () => {
    blockBtn.disabled = true;
    blockBtn.textContent = 'Blocked ✓';
    await chrome.runtime.sendMessage({ type: 'add-to-list', list: 'blocklist', entry: result.host });
  });
}

async function loadStats() {
  if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.sendMessage) {
    footer.textContent = 'URL Sentinel — heuristic analysis runs offline on your device.';
    return;
  }
  try {
    const stats = await chrome.runtime.sendMessage({ type: 'get-stats' });
    footer.textContent = `${stats.checked} checked · ${stats.suspicious} suspicious · ${stats.malicious} malicious · ${stats.blocked} blocked`;
  } catch {
    footer.textContent = 'URL Sentinel — heuristic analysis runs offline on your device.';
  }
}

async function init() {
  const params = new URLSearchParams(location.search);
  const demo = params.get('demo');
  if (demo && DEMO_URLS[demo]) {
    render(analyzeUrl(DEMO_URLS[demo]), { demo: true });
    await loadStats();
    return;
  }
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) {
      render({ url: '', error: 'Could not read the current tab address.' });
      return;
    }
    const result = await chrome.runtime.sendMessage({ type: 'analyze', url: tab.url });
    render(result);
  } catch (err) {
    render({ url: '', error: `Analysis failed: ${err.message}` });
  }
  await loadStats();
}

init();
