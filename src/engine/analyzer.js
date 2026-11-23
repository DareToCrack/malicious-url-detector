// URL Sentinel — heuristic URL analyzer.
//
// Pure JavaScript: no chrome.* imports, no network access. The same module
// runs in the extension (background worker, popup) and in node:test.
//
// Design principles:
//  - Explainable: every finding carries plain-language text and a point value;
//    the score is the sum of finding points, capped at 100.
//  - Fail-safe: unknown or ambiguous input resolves toward NOT flagging.
//    A single finding can never produce a Malicious verdict — the highest
//    single finding is 30 points and the lowest Malicious threshold is 45
//    (strict sensitivity), so corroboration is always required.
//  - No blocklist of "bad" domains: reputation comes from the optional
//    Google Safe Browsing lookup (src/lib/reputation.js), not from here.

import {
  SHORTENERS,
  SUSPICIOUS_TLDS,
  POPULAR_DOMAINS,
  BRANDS,
  BRAND_OWNED_DOMAINS,
  SUSPICIOUS_KEYWORDS,
  REDIRECT_PARAMS,
} from './data.js';
import { levenshtein } from './levenshtein.js';
import {
  isIpHost,
  isPrivateHost,
  hostLabels,
  registrableDomain,
  topLevelDomain,
  subdomainCount,
  tokens,
} from './domains.js';

// Score thresholds per sensitivity setting. Sensitivity scales the
// thresholds, not the points — the same URL scores the same everywhere,
// but strict mode calls it Suspicious/Malicious sooner.
export const THRESHOLDS = {
  strict: { suspicious: 15, malicious: 45 },
  balanced: { suspicious: 25, malicious: 60 },
  lenient: { suspicious: 35, malicious: 70 },
};

export const BAND_LABELS = {
  safe: 'Safe',
  suspicious: 'Suspicious',
  malicious: 'Malicious',
};

// Finding point values. Highest single finding is 30 — by construction no
// single signal can reach even the strict Malicious threshold (45).
const POINTS = {
  ipHost: 25,
  atSymbol: 15,
  subdomains: 10,
  punycode: 15,
  shortener: 12,
  suspiciousTld: 10,
  longUrl: 5,
  percentEncoding: 8,
  nonStandardPort: 10,
  typosquat: 30,
  brandImpersonation: 25,
  hyphenDigitHeavy: 8,
  suspiciousKeywords: 5,
  openRedirect: 12,
  dataUrl: 30,
};

function finding(id, title, detail, explanation, severity) {
  return { id, title, detail, explanation, points: POINTS[id], severity };
}

// --- individual checks (each returns a finding or null) -------------------

function checkIpHost(host) {
  if (!isIpHost(host) || isPrivateHost(host)) return null;
  return finding(
    'ipHost',
    'IP address instead of a domain name',
    `The address is ${host}, a raw IP address.`,
    'Legitimate websites use domain names. Attackers often use bare IP addresses to avoid registering a domain that can be traced or blocked.',
    'high',
  );
}

function checkAtSymbol(parsed) {
  if (!parsed.username) return null;
  return finding(
    'atSymbol',
    'Contains an "@" before the real address',
    `The URL contains "${parsed.username}@…" — everything before the last "@" is ignored by the browser.`,
    'Attackers put a trusted-looking name before "@" (e.g. paypal.com@evil.com) so the link looks legitimate. The real site is always the part after the last "@".',
    'medium',
  );
}

function checkSubdomains(host) {
  const count = subdomainCount(host);
  if (count < 4) return null;
  return finding(
    'subdomains',
    `Unusually many subdomains (${count})`,
    `The address has ${count} subdomain levels.`,
    'Deep subdomain chains are often used to bury the real domain (e.g. paypal.com.login.verify.evil.com) or to hide behind a long, confusing address.',
    'medium',
  );
}

function checkPunycode(host) {
  if (!host.toLowerCase().includes('xn--')) return null;
  return finding(
    'punycode',
    'Internationalised domain (punycode)',
    'The address contains "xn--", an encoded non-English domain name.',
    'Attackers register domains with look-alike characters from other alphabets (for example a Cyrillic "а" that looks like a Latin "a") to impersonate trusted sites.',
    'medium',
  );
}

function checkShortener(host) {
  const reg = registrableDomain(host);
  if (!SHORTENERS.has(reg)) return null;
  return finding(
    'shortener',
    'URL shortener hides the destination',
    `The link goes through ${reg}, a URL-shortening service.`,
    'Shortened links hide where they really lead, so you cannot judge the destination before clicking. Shorteners are also used legitimately, so this alone is only a weak signal.',
    'medium',
  );
}

function checkSuspiciousTld(host) {
  const tld = topLevelDomain(host);
  if (!SUSPICIOUS_TLDS.has(tld)) return null;
  return finding(
    'suspiciousTld',
    `Uncommon top-level domain (.${tld})`,
    `The address ends in .${tld}.`,
    'Some top-level domains are cheap or free to register and appear far more often in phishing and malware reports than others. Many legitimate sites use them too, so this is only a weak signal.',
    'medium',
  );
}

function checkLongUrl(raw, host) {
  const parts = [];
  if (raw.length > 200) parts.push(`the full URL is ${raw.length} characters`);
  if (host.length > 50) parts.push(`the host name is ${host.length} characters`);
  if (!parts.length) return null;
  return finding(
    'longUrl',
    'Unusually long address',
    `The address is very long: ${parts.join(' and ')}.`,
    'Very long URLs are sometimes used to push the suspicious part off the edge of the address bar, or to smuggle extra data in the link.',
    'low',
  );
}

function checkPercentEncoding(raw) {
  const matches = raw.match(/%[0-9a-fA-F]{2}/g) || [];
  const encodedChars = matches.length * 3;
  if (matches.length < 10 && encodedChars / raw.length <= 0.2) return null;
  return finding(
    'percentEncoding',
    'Heavy percent-encoding',
    `The URL contains ${matches.length} percent-encoded sequences.`,
    'Encoding normal characters as %XX can hide what a link really contains from a quick glance — a common obfuscation trick.',
    'low',
  );
}

function checkPort(parsed) {
  if (!parsed.port || parsed.port === '80' || parsed.port === '443') return null;
  return finding(
    'nonStandardPort',
    `Non-standard port (:${parsed.port})`,
    `The address uses port ${parsed.port} instead of the usual 80 or 443.`,
    'Websites normally run on ports 80 (http) or 443 (https). An unusual port can mean the site is hosted on a compromised machine or a hastily set-up server.',
    'medium',
  );
}

function checkTyposquat(host) {
  if (isIpHost(host)) return null;
  const reg = registrableDomain(host);
  if (POPULAR_DOMAINS.includes(reg)) return null; // it IS the popular domain
  // A subdomain of a popular domain (mail.google.com) is legitimate.
  if (POPULAR_DOMAINS.some((p) => host.toLowerCase().endsWith(`.${p}`))) return null;
  let best = null;
  for (const popular of POPULAR_DOMAINS) {
    // Very short domains are excluded: edit distance is meaningless at that
    // length (e.g. a.com is distance 1 from x.com).
    if (Math.min(reg.length, popular.length) < 8) continue;
    const distance = levenshtein(reg, popular);
    if (distance === 0 || distance > 2) continue;
    // Same TLD, or a one-character difference (catches paypal.co vs paypal.com).
    const sameTld = topLevelDomain(reg) === topLevelDomain(popular);
    if (!sameTld && distance > 1) continue;
    if (!best || distance < best.distance) best = { popular, distance };
  }
  if (!best) return null;
  return finding(
    'typosquat',
    `Looks like a misspelling of ${best.popular}`,
    `"${reg}" is ${best.distance} character${best.distance === 1 ? '' : 's'} away from ${best.popular}.`,
    'Attackers register domains that are one or two keystrokes away from popular sites to catch typos and to look legitimate at a glance.',
    'high',
  );
}

function checkBrandImpersonation(host, parsed) {
  const reg = registrableDomain(host);
  const lowerHost = host.toLowerCase();
  // Brand-owned domains (and their subdomains) are legitimate by definition.
  for (const owned of BRAND_OWNED_DOMAINS) {
    if (reg === owned || lowerHost.endsWith(`.${owned}`)) return null;
  }
  // Where to look for brand tokens: subdomain labels, the registrable
  // domain's own first label, and path segments.
  //
  // Matching rules (fail-safe by design):
  //  - Exact token match anywhere (subdomain, domain label, path).
  //  - Fuzzy match (Levenshtein distance 1, brand at least 5 letters) ONLY
  //    in the registrable domain's first label — that is where typosquatters
  //    operate (paypa1-login.com). Fuzzy matching in subdomains or paths
  //    would false-positive on ordinary words ("apply" is distance 1 from
  //    "apple", and apply.example.com / example.com/apply are legitimate).
  const labels = hostLabels(host);
  const regLabels = reg.split('.');
  let match = null; // { brand, token, where, fuzzy }
  const scanExact = (list, where) => {
    for (const label of list) {
      for (const token of tokens(label)) {
        if (BRANDS.includes(token)) {
          match = { brand: token, token, where, fuzzy: false };
          return true;
        }
      }
    }
    return false;
  };
  const scanFuzzy = (label, where) => {
    for (const token of tokens(label)) {
      for (const brand of BRANDS) {
        if (brand.length < 5) continue;
        if (token !== brand && levenshtein(token, brand) === 1) {
          match = { brand, token, where, fuzzy: true };
          return true;
        }
      }
    }
    return false;
  };
  if (!scanExact(labels.slice(0, labels.length - regLabels.length), 'subdomain')) {
    if (!scanExact([regLabels[0]], 'domain name')) {
      if (!scanFuzzy(regLabels[0], 'domain name')) {
        scanExact(parsed.pathname.split('/').filter(Boolean), 'page address');
      }
    }
  }
  if (!match) return null;
  const { brand, token, where, fuzzy } = match;
  const detail = fuzzy
    ? `The word "${token}" in the ${where} looks like "${brand}", but this site is not owned by ${brand}.`
    : `The word "${brand}" appears in the ${where}, but this site is not owned by ${brand}.`;
  return finding(
    'brandImpersonation',
    fuzzy ? `Uses a look-alike of "${brand}"` : `Uses the name "${brand}" but is not ${brand}`,
    detail,
    'Phishing sites often put a trusted brand name — or a near-misspelling of one — in the address to look official while the real domain belongs to someone else.',
    'high',
  );
}

function checkHyphenDigitHeavy(host) {
  if (isIpHost(host)) return null; // IP literals are digits by nature
  const reg = registrableDomain(host);
  // Punycode labels start with "xn--" by definition — those two hyphens are
  // part of the encoding, not suspicious, so strip the prefix before counting.
  const countable = reg.replace(/(^|\.)xn--/g, '$1');
  const hyphens = (countable.match(/-/g) || []).length;
  const digits = (host.match(/\d/g) || []).length;
  const reasons = [];
  if (hyphens >= 3) reasons.push(`${hyphens} hyphens in the domain name`);
  if (digits >= 4) reasons.push(`${digits} digits in the address`);
  if (!reasons.length) return null;
  return finding(
    'hyphenDigitHeavy',
    'Hyphen- or digit-heavy address',
    `The address has ${reasons.join(' and ')}.`,
    'Legitimate domains are usually short and readable. Strings of hyphens and numbers are typical of quickly registered phishing domains.',
    'low',
  );
}

function checkKeywords(parsed, otherFindings) {
  // Keywords only count with corroboration: a lone "/login" is normal.
  if (otherFindings === 0) return null;
  const haystack = `${parsed.pathname}${parsed.search}`.toLowerCase();
  const matched = SUSPICIOUS_KEYWORDS.filter((kw) => haystack.includes(kw));
  if (!matched.length) return null;
  return finding(
    'suspiciousKeywords',
    'Phishing-style words in the address',
    `The address contains: ${matched.slice(0, 4).join(', ')}${matched.length > 4 ? ', …' : ''}.`,
    'Words like "verify", "secure" or "account" in a link are common in phishing pages that imitate login or security screens. On their own they prove nothing — they only add weight here because other signals are already present.',
    'low',
  );
}

function checkOpenRedirect(parsed, host) {
  for (const param of REDIRECT_PARAMS) {
    const value = parsed.searchParams.get(param);
    if (!value) continue;
    let target;
    try {
      target = new URL(value, parsed); // resolves relative + protocol-relative
    } catch {
      continue;
    }
    if (!['http:', 'https:'].includes(target.protocol)) continue;
    if (target.hostname.toLowerCase() === host.toLowerCase()) continue;
    return finding(
      'openRedirect',
      `Redirects to another site (${target.hostname})`,
      `The "?${param}=" parameter sends visitors to ${target.hostname}, a different site.`,
      'Open redirects let an attacker hide a malicious destination behind a link that starts with a trusted domain. The trusted part is only the wrapper — the real destination is elsewhere.',
      'medium',
    );
  }
  return null;
}

// --- main entry point -------------------------------------------------------

export function analyzeUrl(rawUrl, options = {}) {
  const sensitivity = THRESHOLDS[options.sensitivity] ? options.sensitivity : 'balanced';
  const { suspicious, malicious } = THRESHOLDS[sensitivity];

  const base = {
    url: String(rawUrl || ''),
    scheme: '',
    host: '',
    port: '',
    score: 0,
    verdict: 'safe',
    bandLabel: BAND_LABELS.safe,
    findings: [],
    totalPoints: 0,
    sensitivity,
    error: null,
  };

  let parsed;
  try {
    parsed = new URL(String(rawUrl));
  } catch {
    return { ...base, error: 'This address could not be read as a URL, so it was not flagged.' };
  }

  base.scheme = parsed.protocol.replace(':', '');
  base.host = parsed.hostname.toLowerCase();
  base.port = parsed.port;

  if (parsed.protocol === 'data:') {
    const f = finding(
      'dataUrl',
      'Data URL, not a real web address',
      'The link is a data: URL — its content is embedded in the link itself.',
      'Data URLs can carry a whole fake login page inside the link, with no website behind it to take down or trace. They are almost never used for legitimate navigation.',
      'high',
    );
    return scoreAndBand({ ...base, findings: [f] }, suspicious, malicious);
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { ...base, error: 'Only web addresses (http/https) can be analysed.' };
  }

  const host = base.host;
  const checks = [
    checkIpHost(host),
    checkAtSymbol(parsed),
    checkSubdomains(host),
    checkPunycode(host),
    checkShortener(host),
    checkSuspiciousTld(host),
    checkLongUrl(base.url, host),
    checkPercentEncoding(base.url),
    checkPort(parsed),
    checkTyposquat(host),
    checkBrandImpersonation(host, parsed),
    checkHyphenDigitHeavy(host),
  ];
  const findings = checks.filter(Boolean);
  // Keywords and open redirects are evaluated after the other signals so the
  // keyword check can require corroboration.
  const keywordFinding = checkKeywords(parsed, findings.length);
  if (keywordFinding) findings.push(keywordFinding);
  const redirectFinding = checkOpenRedirect(parsed, host);
  if (redirectFinding) findings.push(redirectFinding);

  return scoreAndBand({ ...base, findings }, suspicious, malicious);
}

function scoreAndBand(result, suspiciousThreshold, maliciousThreshold) {
  const total = result.findings.reduce((sum, f) => sum + f.points, 0);
  const score = Math.min(100, total);
  const verdict =
    score >= maliciousThreshold ? 'malicious' : score >= suspiciousThreshold ? 'suspicious' : 'safe';
  return {
    ...result,
    totalPoints: total,
    score,
    verdict,
    bandLabel: BAND_LABELS[verdict],
  };
}
