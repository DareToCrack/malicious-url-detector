// URL Sentinel content script — scans links on the page and marks the
// risky ones.
//
// This is a classic (non-module) content script, so it cannot import the
// engine directly. Instead it sends each page's links to the background
// worker in one batch message ("analyze-batch") and marks the results:
//  - Suspicious links get a small amber warning marker and a tooltip.
//  - Malicious links get a red marker and a click warning: following one
//    shows a confirm dialog first.
// Links are only ever marked, never removed or rewritten. Scanning respects
// the "Scan links on pages" toggle in Options.

(() => {
  const PROCESSED = new WeakSet();
  const MARKER_CLASS = 'url-sentinel-marker';
  let enabled = true;
  let scanTimer = null;

  // Ask the background worker whether link scanning is enabled.
  chrome.runtime.sendMessage({ type: 'get-settings' }, (settings) => {
    if (chrome.runtime.lastError) return;
    enabled = settings ? settings.enableLinkScanning !== false : true;
    if (enabled) scanLinks();
  });

  function collectLinks() {
    const out = [];
    for (const a of document.querySelectorAll('a[href]')) {
      if (PROCESSED.has(a)) continue;
      let href = a.getAttribute('href');
      if (!href) continue;
      href = href.trim();
      if (
        href.startsWith('#') ||
        href.startsWith('javascript:') ||
        href.startsWith('mailto:') ||
        href.startsWith('tel:')
      ) {
        PROCESSED.add(a);
        continue;
      }
      try {
        const absolute = new URL(href, location.href).href;
        if (!absolute.startsWith('http://') && !absolute.startsWith('https://')) {
          PROCESSED.add(a);
          continue;
        }
        out.push({ element: a, url: absolute });
      } catch {
        PROCESSED.add(a);
      }
    }
    return out;
  }

  function markLink(element, verdict, topFinding) {
    if (PROCESSED.has(element)) return; // idempotent: overlapping scans must not double-mark
    PROCESSED.add(element);
    if (verdict === 'safe') return;
    element.classList.add(
      verdict === 'malicious' ? 'url-sentinel-malicious' : 'url-sentinel-suspicious',
    );
    const marker = document.createElement('span');
    marker.className = `${MARKER_CLASS} ${MARKER_CLASS}-${verdict}`;
    marker.textContent = '⚠';
    marker.setAttribute('aria-hidden', 'true');
    element.insertAdjacentElement('afterend', marker);
    const label =
      verdict === 'malicious'
        ? `URL Sentinel: this link looks malicious${topFinding ? ` — ${topFinding}` : ''}. Clicking it will ask first.`
        : `URL Sentinel: this link looks suspicious${topFinding ? ` — ${topFinding}` : ''}.`;
    element.setAttribute('title', label);
    marker.setAttribute('title', label);
    if (verdict === 'malicious') {
      element.addEventListener('click', (event) => {
        const ok = window.confirm(
          'URL Sentinel: this link looks malicious.\n\n' +
            `${topFinding || 'It matches malicious URL patterns.'}\n\n` +
            'Are you sure you want to follow it?',
        );
        if (!ok) event.preventDefault();
      });
    }
  }

  function scanLinks() {
    if (!enabled) return;
    const links = collectLinks();
    if (!links.length) return;
    const urls = [...new Set(links.map((l) => l.url))];
    chrome.runtime.sendMessage({ type: 'analyze-batch', urls }, (results) => {
      if (chrome.runtime.lastError || !Array.isArray(results)) return;
      const byUrl = new Map(results.map((r) => [r.url, r]));
      for (const { element, url } of links) {
        const r = byUrl.get(url);
        if (!r) {
          PROCESSED.add(element);
          continue;
        }
        // User-blocklisted links are treated as malicious; allowlisted as safe.
        const verdict = r.blocked ? 'malicious' : r.allowed ? 'safe' : r.verdict;
        markLink(element, verdict, r.blocked ? 'Blocked by your own blocklist' : r.topFinding);
      }
    });
  }

  // Re-scan when the page changes (single-page apps, lazy content), debounced.
  const observer = new MutationObserver(() => {
    if (scanTimer) clearTimeout(scanTimer);
    scanTimer = setTimeout(scanLinks, 500);
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });

  // First scan as soon as the DOM is ready.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', scanLinks);
  } else {
    scanLinks();
  }
})();
