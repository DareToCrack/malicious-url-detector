// Tests for the heuristic URL analyzer — every check, scoring math, band
// boundaries, typosquat near-misses, brand impersonation, sensitivity
// scaling, and URL edge cases.
import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeUrl, THRESHOLDS } from '../src/engine/analyzer.js';

const ids = (r) => r.findings.map((f) => f.id);
const has = (r, id) => ids(r).includes(id);

// --- safe basics ------------------------------------------------------------

test('well-known legitimate sites are Safe with score 0', () => {
  for (const url of [
    'https://www.google.com/',
    'https://github.com/DareToCrack/phishsim',
    'https://en.wikipedia.org/wiki/Phishing',
    'https://www.bbc.com/news',
  ]) {
    const r = analyzeUrl(url);
    assert.equal(r.verdict, 'safe', url);
    assert.equal(r.score, 0, url);
    assert.deepEqual(r.findings, []);
  }
});

test('a plain login page with no other signals is Safe', () => {
  const r = analyzeUrl('https://example.com/login');
  assert.equal(r.verdict, 'safe');
  assert.equal(has(r, 'suspiciousKeywords'), false);
});

// --- individual checks ------------------------------------------------------

test('public IP host is flagged; private IPs and localhost are not', () => {
  const bad = analyzeUrl('http://185.220.101.5/login');
  assert.equal(has(bad, 'ipHost'), true);
  assert.equal(bad.verdict, 'suspicious');

  for (const url of ['http://192.168.1.1/admin', 'http://10.0.0.5/', 'http://localhost:3000/', 'http://127.0.0.1:8080/']) {
    const r = analyzeUrl(url);
    assert.equal(has(r, 'ipHost'), false, url);
  }
});

test('"@" userinfo trick is flagged', () => {
  const r = analyzeUrl('http://google.com@evil-example.com/');
  assert.equal(has(r, 'atSymbol'), true);
  // '@' in the path (e.g. a profile URL) is NOT flagged
  const ok = analyzeUrl('https://example.com/@someone');
  assert.equal(has(ok, 'atSymbol'), false);
});

test('4+ subdomains flagged; a normal www host is not', () => {
  assert.equal(has(analyzeUrl('https://a.b.c.d.example.com/'), 'subdomains'), true);
  assert.equal(has(analyzeUrl('https://www.example.com/'), 'subdomains'), false);
  assert.equal(has(analyzeUrl('https://a.b.c.example.com/'), 'subdomains'), false); // only 3
});

test('punycode host is flagged', () => {
  assert.equal(has(analyzeUrl('https://xn--pple-43d.com/'), 'punycode'), true);
  assert.equal(has(analyzeUrl('https://apple.com/'), 'punycode'), false);
});

test('known shorteners are flagged but never Malicious alone', () => {
  for (const url of ['https://bit.ly/3abc123', 'https://tinyurl.com/xyz', 'https://t.co/abcdef']) {
    const r = analyzeUrl(url);
    assert.equal(has(r, 'shortener'), true, url);
    assert.notEqual(r.verdict, 'malicious', url);
  }
});

test('commonly abused TLDs are flagged; ordinary TLDs are not', () => {
  assert.equal(has(analyzeUrl('https://example.tk/'), 'suspiciousTld'), true);
  assert.equal(has(analyzeUrl('https://example.xyz/'), 'suspiciousTld'), true);
  assert.equal(has(analyzeUrl('https://example.com/'), 'suspiciousTld'), false);
  assert.equal(has(analyzeUrl('https://example.org/'), 'suspiciousTld'), false);
});

test('very long URLs are flagged', () => {
  const long = `https://example.com/${'a'.repeat(220)}`;
  assert.equal(has(analyzeUrl(long), 'longUrl'), true);
  assert.equal(has(analyzeUrl('https://example.com/short'), 'longUrl'), false);
});

test('heavy percent-encoding is flagged', () => {
  const encoded = `https://example.com/${'%41%42%43%44%45%46%47%48%49%4a%4b%4c'}`;
  assert.equal(has(analyzeUrl(encoded), 'percentEncoding'), true);
  assert.equal(has(analyzeUrl('https://example.com/hello%20world'), 'percentEncoding'), false);
});

test('non-standard ports are flagged; 80/443 are not', () => {
  assert.equal(has(analyzeUrl('https://example.com:8080/'), 'nonStandardPort'), true);
  assert.equal(has(analyzeUrl('https://example.com:8443/'), 'nonStandardPort'), true);
  assert.equal(has(analyzeUrl('https://example.com:443/'), 'nonStandardPort'), false);
  assert.equal(has(analyzeUrl('http://example.com:80/'), 'nonStandardPort'), false);
});

test('typosquatting: near-misses of popular domains are flagged', () => {
  const cases = [
    ['https://gogle.com/', 'google.com'],
    ['https://facebok.com/', 'facebook.com'],
    ['https://paypa1.com/', 'paypal.com'],
    ['https://arnazon.com/', 'amazon.com'],
    ['https://rnicrosoft.com/', 'microsoft.com'],
  ];
  for (const [url, popular] of cases) {
    const r = analyzeUrl(url);
    assert.equal(has(r, 'typosquat'), true, url);
    assert.ok(r.findings.find((f) => f.id === 'typosquat').detail.includes(popular), url);
  }
});

test('typosquatting: the real domain and its subdomains are NOT flagged', () => {
  for (const url of [
    'https://google.com/',
    'https://mail.google.com/',
    'https://www.paypal.com/',
    'https://en.wikipedia.org/',
  ]) {
    assert.equal(has(analyzeUrl(url), 'typosquat'), false, url);
  }
});

test('typosquatting: near-misses that must NOT flag', () => {
  // Different TLD at distance 3 — too far.
  assert.equal(has(analyzeUrl('https://google.org/'), 'typosquat'), false);
  // Short domains are excluded: edit distance is meaningless at that length.
  assert.equal(has(analyzeUrl('https://abc.com/'), 'typosquat'), false);
  assert.equal(has(analyzeUrl('https://a.com/'), 'typosquat'), false);
  // Unrelated domains.
  assert.equal(has(analyzeUrl('https://example.com/'), 'typosquat'), false);
  assert.equal(has(analyzeUrl('https://myblog.net/'), 'typosquat'), false);
});

test('brand impersonation: brand in subdomain, domain, or path of a stranger domain', () => {
  assert.equal(has(analyzeUrl('https://paypal.secure-login.com/'), 'brandImpersonation'), true);
  assert.equal(has(analyzeUrl('https://example.com/paypal/login'), 'brandImpersonation'), true);
  assert.equal(has(analyzeUrl('https://paypal-login.com/'), 'brandImpersonation'), true);
  assert.equal(has(analyzeUrl('https://apple-support-helpdesk.net/verify'), 'brandImpersonation'), true);
});

test('brand impersonation: brand-owned domains and look-alike words are NOT flagged', () => {
  for (const url of [
    'https://paypal.com/',
    'https://www.amazon.com/',
    'https://amazonaws.com/',
    'https://console.cloud.google.com/',
    'https://pineapple.com/', // "apple" inside a longer word
    'https://myapplepierecipes.com/',
  ]) {
    assert.equal(has(analyzeUrl(url), 'brandImpersonation'), false, url);
  }
});

test('brand impersonation: misspelled brands in the domain are caught, but ordinary words are not', () => {
  // Fuzzy match (distance 1) in the registrable domain's first label.
  assert.equal(has(analyzeUrl('https://paypa1-login.com/'), 'brandImpersonation'), true);
  assert.equal(has(analyzeUrl('https://applle.com/'), 'brandImpersonation'), true);
  // But fuzzy matching does NOT apply to subdomains or paths, where ordinary
  // words like "apply" (distance 1 from "apple") are legitimate.
  assert.equal(has(analyzeUrl('https://apply.example.com/'), 'brandImpersonation'), false);
  assert.equal(has(analyzeUrl('https://example.com/apply'), 'brandImpersonation'), false);
  // Short brands need an exact match even in the domain.
  assert.equal(has(analyzeUrl('https://viva.com/'), 'brandImpersonation'), false);
});

test('hyphen- or digit-heavy domains are flagged', () => {
  assert.equal(has(analyzeUrl('https://secure-login-verify-account.com/'), 'hyphenDigitHeavy'), true);
  assert.equal(has(analyzeUrl('https://example12345.com/'), 'hyphenDigitHeavy'), true);
  assert.equal(has(analyzeUrl('https://my-site.com/'), 'hyphenDigitHeavy'), false);
});

test('suspicious keywords only count with corroboration', () => {
  // Keywords alone: no finding.
  assert.equal(has(analyzeUrl('https://example.com/account/verify'), 'suspiciousKeywords'), false);
  // Keywords + another signal: finding appears.
  const r = analyzeUrl('https://example.tk/account/verify');
  assert.equal(has(r, 'suspiciousKeywords'), true);
  assert.equal(has(r, 'suspiciousTld'), true);
});

test('open-redirect parameters pointing off-domain are flagged', () => {
  const r = analyzeUrl('https://trusted-example.com/redirect?url=https://evil-example.com/phish');
  assert.equal(has(r, 'openRedirect'), true);
  // Same-host redirect target is fine.
  const ok = analyzeUrl('https://trusted-example.com/redirect?next=/dashboard');
  assert.equal(has(ok, 'openRedirect'), false);
  // Relative target resolves to the same host — fine.
  const ok2 = analyzeUrl('https://trusted-example.com/login?next=/home');
  assert.equal(has(ok2, 'openRedirect'), false);
});

test('data: URLs are flagged as Suspicious', () => {
  const r = analyzeUrl('data:text/html;base64,PGh0bWw+');
  assert.equal(has(r, 'dataUrl'), true);
  assert.equal(r.verdict, 'suspicious');
});

// --- scoring, bands, sensitivity --------------------------------------------

test('score is the sum of finding points, capped at 100', () => {
  const r = analyzeUrl('https://gogle.com/');
  const sum = r.findings.reduce((s, f) => s + f.points, 0);
  assert.equal(r.totalPoints, sum);
  assert.equal(r.score, Math.min(100, sum));
  // Kitchen-sink URL: score never exceeds 100.
  const kitchen = analyzeUrl(
    'http://user@a.b.c.d.paypa1-login-verify-account.tk:8080/secure/login?url=https://evil.com&x=' +
      '%41'.repeat(15) + 'a'.repeat(150),
  );
  assert.ok(kitchen.score <= 100);
  assert.equal(kitchen.verdict, 'malicious');
});

test('band thresholds follow the sensitivity setting', () => {
  // IP host alone scores exactly 25.
  const url = 'http://185.220.101.5/';
  assert.equal(analyzeUrl(url).score, 25);
  assert.equal(analyzeUrl(url, { sensitivity: 'balanced' }).verdict, 'suspicious');
  assert.equal(analyzeUrl(url, { sensitivity: 'strict' }).verdict, 'suspicious');
  assert.equal(analyzeUrl(url, { sensitivity: 'lenient' }).verdict, 'safe');
  // Pure typosquat alone scores 30 (wikipedia has no brand entry, so no
  // brand finding stacks on top).
  assert.equal(analyzeUrl('https://wikipedai.org/').score, 30);
  assert.equal(analyzeUrl('https://wikipedai.org/', { sensitivity: 'lenient' }).verdict, 'safe');
  assert.equal(analyzeUrl('https://wikipedai.org/', { sensitivity: 'balanced' }).verdict, 'suspicious');
});

test('a realistic phishing URL is Malicious at balanced, Suspicious at lenient', () => {
  // typosquat 30 + brand impersonation 25 + keywords 5 = 60.
  const url = 'https://paypa1.com/secure/verify';
  const balanced = analyzeUrl(url, { sensitivity: 'balanced' });
  assert.equal(balanced.score, 60);
  assert.equal(balanced.verdict, 'malicious');
  assert.ok(balanced.score >= THRESHOLDS.balanced.malicious);
  assert.equal(analyzeUrl(url, { sensitivity: 'lenient' }).verdict, 'suspicious');
  assert.equal(analyzeUrl(url, { sensitivity: 'strict' }).verdict, 'malicious');
});

test('no single finding can produce a Malicious verdict at any sensitivity', () => {
  const singleSignalUrls = [
    'http://185.220.101.5/', // ipHost 25
    'http://user@evil-example.com/', // atSymbol 15
    'https://a.b.c.d.example.com/', // subdomains 10
    'https://xn--mnchen-3ya.de/', // punycode 15 (a legitimate German IDN)
    'https://bit.ly/abc', // shortener 12
    'https://example.tk/', // suspiciousTld 10
    'https://example.com:8080/', // port 10
    'https://wikipedai.org/', // typosquat 30 (no brand entry to stack)
    'https://paypal-login.com/', // brand 25
    'data:text/html,hello', // dataUrl 30
  ];
  for (const url of singleSignalUrls) {
    for (const sensitivity of ['strict', 'balanced', 'lenient']) {
      const r = analyzeUrl(url, { sensitivity });
      assert.notEqual(r.verdict, 'malicious', `${url} @ ${sensitivity}`);
    }
  }
});

test('unknown sensitivity falls back to balanced', () => {
  const r = analyzeUrl('http://185.220.101.5/', { sensitivity: 'bogus' });
  assert.equal(r.sensitivity, 'balanced');
  assert.equal(r.verdict, 'suspicious');
});

// --- edge cases ---------------------------------------------------------------

test('malformed URLs return an error and a Safe verdict (fail-safe)', () => {
  for (const bad of ['not a url', 'ht!tp://broken', '', '://missing-scheme']) {
    const r = analyzeUrl(bad);
    assert.ok(r.error, bad);
    assert.equal(r.verdict, 'safe', bad);
    assert.equal(r.score, 0, bad);
  }
});

test('non-web schemes are not analysed', () => {
  for (const url of ['chrome://extensions/', 'about:blank', 'ftp://example.com/file', 'file:///etc/passwd']) {
    const r = analyzeUrl(url);
    assert.ok(r.error, url);
    assert.equal(r.verdict, 'safe', url);
  }
});

test('every finding carries an explanation and a positive point value', () => {
  const r = analyzeUrl('https://paypa1-login.tk/secure/verify?url=https://evil.com');
  assert.ok(r.findings.length >= 3);
  for (const f of r.findings) {
    assert.ok(f.title && f.title.length > 0);
    assert.ok(f.explanation && f.explanation.length > 20);
    assert.ok(f.points > 0);
    assert.ok(['low', 'medium', 'high'].includes(f.severity));
  }
});
