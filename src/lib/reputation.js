// Optional Google Safe Browsing (v4) reputation lookup.
//
// Privacy: this is the ONLY network call the extension ever makes, and it
// only happens when the user has entered an API key in Options. When a lookup
// runs, the checked URL is sent to Google's Safe Browsing API — that is
// stated in the README and on the Options page. Without a key, the extension
// is heuristic-only and nothing leaves the device.
//
// If the lookup fails for any reason (no key, network error, bad key, API
// error), the caller falls back silently to the heuristic verdict.

const API_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';

// Build the threatMatches request body for one URL. Pure function, tested.
export function buildThreatMatchesRequest(url) {
  return {
    client: { clientId: 'url-sentinel', clientVersion: '1.0.0' },
    threatInfo: {
      threatTypes: [
        'MALWARE',
        'SOCIAL_ENGINEERING',
        'UNWANTED_SOFTWARE',
        'POTENTIALLY_HARMFUL_APPLICATION',
      ],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url }],
    },
  };
}

// Returns { matched: true, threatType } when Safe Browsing flags the URL,
// { matched: false } when it does not, or { matched: false, error } when the
// lookup could not be completed (caller treats all of these as "no signal").
export async function checkSafeBrowsing(url, apiKey, fetchFn = fetch) {
  if (!apiKey) return { matched: false, error: 'no-key' };
  try {
    const response = await fetchFn(`${API_URL}?key=${encodeURIComponent(apiKey)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildThreatMatchesRequest(url)),
    });
    if (!response.ok) return { matched: false, error: `http-${response.status}` };
    const data = await response.json();
    const matches = data && Array.isArray(data.matches) ? data.matches : [];
    if (!matches.length) return { matched: false };
    return { matched: true, threatType: matches[0].threatType || 'UNKNOWN' };
  } catch (err) {
    return { matched: false, error: String(err && err.message ? err.message : err) };
  }
}
