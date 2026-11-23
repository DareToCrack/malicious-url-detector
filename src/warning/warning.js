// URL Sentinel warning interstitial.
//
// The background worker redirects here with the blocked URL, score, verdict
// and findings in the query string. "Go back" returns to the previous page;
// "Proceed anyway" asks the background worker to temporarily allow this exact
// URL (30 minutes) and then navigates to it.

const params = new URLSearchParams(location.search);
const url = params.get('url') || '';
const score = params.get('score') || '?';
const verdict = params.get('verdict') || 'malicious';
let findings = [];
try {
  findings = JSON.parse(params.get('findings') || '[]');
} catch {
  findings = [];
}

function escapeHtml(s) {
  return String(s)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

let host = url;
try {
  host = new URL(url).hostname;
} catch {
  // keep the raw string
}

document.getElementById('url-box').innerHTML = `<strong>${escapeHtml(host)}</strong><br>${escapeHtml(url)}`;
document.getElementById('score').innerHTML = `${escapeHtml(score)}<small> / 100</small>`;
const band = document.getElementById('band');
band.textContent = verdict === 'malicious' ? 'Malicious' : verdict;

document.getElementById('findings').innerHTML = findings.length
  ? findings
      .map(
        (f) => `<div class="finding">
          <div class="finding-head"><span class="finding-title">${escapeHtml(f.title)}</span><span class="points">+${f.points} pts</span></div>
          <p class="finding-detail">${escapeHtml(f.detail || '')}</p>
        </div>`,
      )
      .join('')
  : '<p class="finding-detail">No details were passed with this warning.</p>';

document.getElementById('back-btn').addEventListener('click', () => {
  if (history.length > 1) history.back();
  else window.close();
});

document.getElementById('proceed-btn').addEventListener('click', async () => {
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
    try {
      await chrome.runtime.sendMessage({ type: 'temp-allow', url });
    } catch {
      // If messaging fails, still navigate — the user explicitly chose to.
    }
  }
  location.href = url;
});
