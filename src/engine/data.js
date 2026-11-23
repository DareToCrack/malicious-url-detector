// Curated data lists for the URL Sentinel heuristic engine.
//
// These lists are deliberately small, generic, and stable:
//  - URL shorteners and abused TLDs change slowly, so a curated list stays useful.
//  - Popular domains and brand names are used only for similarity checks,
//    never as a blocklist.
// We do NOT bundle a list of "known bad" domains: such lists go stale fast and
// can wrongly accuse a domain. Reputation comes from the optional Google Safe
// Browsing lookup instead (see src/lib/reputation.js).

// Well-known URL shorteners. A shortener hides the real destination, which is
// a common phishing technique — but shorteners are also used legitimately, so
// this is only a medium signal, never enough alone for a Malicious verdict.
export const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
  'cutt.ly', 'rb.gy', 'shorturl.at', 'tiny.cc', 'rebrand.ly', 'bl.ink',
  'qr.ae', 'v.gd', 's.id', 'short.io', 'lnkd.in', 'fb.me', 'su.pr',
  'shorte.st', 'adf.ly', 'bc.vc', 'soo.gd', 'clk.im', 'yourls.org',
  'bit.do', 'mcaf.ee', 't2m.io', 'plu.sh', 'u.to', 'j.mp', 'dlvr.it',
]);

// TLDs that appear disproportionately often in phishing/malware reports
// (cheap or free registration, weak abuse handling). A TLD alone proves
// nothing — this is a weak corroborating signal only.
export const SUSPICIOUS_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', // free Freenom TLDs, heavily abused
  'xyz', 'top', 'club', 'online', 'site', 'fun', 'icu', 'buzz', 'live',
  'world', 'work', 'click', 'link', 'pw', 'cc', 'ws', 'men', 'party',
  'review', 'trade', 'bid', 'loan', 'win', 'racing', 'science', 'stream',
  'download', 'zip', 'mov', 'quest', 'lol', 'mom', 'country', 'kim',
  'cricket', 'date', 'faith', 'pro', 'rest', 'bar', 'kim', 'gdn',
]);

// ~50 popular domains used for typosquatting detection (Levenshtein distance).
// A domain within edit distance 2 of one of these — that is not the domain
// itself and not one of its subdomains — is likely a look-alike.
export const POPULAR_DOMAINS = [
  'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'yahoo.com',
  'wikipedia.org', 'twitter.com', 'x.com', 'instagram.com', 'linkedin.com',
  'netflix.com', 'reddit.com', 'microsoft.com', 'apple.com', 'office.com',
  'paypal.com', 'ebay.com', 'whatsapp.com', 'telegram.org', 'tiktok.com',
  'pinterest.com', 'github.com', 'stackoverflow.com', 'bing.com',
  'yandex.ru', 'baidu.com', 'twitch.tv', 'spotify.com', 'adobe.com',
  'zoom.us', 'dropbox.com', 'salesforce.com', 'oracle.com', 'intel.com',
  'ibm.com', 'samsung.com', 'steam.com', 'wordpress.com', 'tumblr.com',
  'quora.com', 'medium.com', 'slack.com', 'discord.com', 'canva.com',
  'shopify.com', 'alibaba.com', 'booking.com', 'airbnb.com', 'uber.com',
  'bbc.com', 'nytimes.com', 'cnn.com', 'chase.com', 'wellsfargo.com',
  'bankofamerica.com', 'hsbc.com', 'americanexpress.com', 'visa.com',
  'mastercard.com',
];

// ~25 well-known brands used for impersonation detection. A brand name
// appearing as a token in a subdomain label or path segment of an unrelated
// domain (e.g. paypal.secure-login.com, example.com/apple/verify) suggests
// the site is pretending to be that brand.
export const BRANDS = [
  'paypal', 'google', 'microsoft', 'apple', 'amazon', 'netflix', 'facebook',
  'instagram', 'twitter', 'linkedin', 'ebay', 'adobe', 'spotify',
  'whatsapp', 'telegram', 'steam', 'github', 'dropbox', 'zoom', 'chase',
  'wellsfargo', 'bankofamerica', 'hsbc', 'americanexpress', 'visa',
  'mastercard', 'netflix', 'disney', 'samsung', 'oracle',
];

// Domains owned by the brands above (or their close affiliates). A brand token
// inside one of these is legitimate, not impersonation — e.g. "amazon" inside
// amazonaws.com, or "google" inside googleapis.com. Subdomains of these are
// also treated as owned.
export const BRAND_OWNED_DOMAINS = new Set([
  'google.com', 'googleapis.com', 'gstatic.com', 'youtube.com', 'gmail.com',
  'google.co.uk', 'google.co.in', 'google.com.au', 'google.ca',
  'amazon.com', 'amazonaws.com', 'amazon.co.uk', 'amazon.co.in',
  'amazon.ca', 'amazon.com.au', 'cloudfront.net',
  'apple.com', 'icloud.com', 'apple.co.uk',
  'microsoft.com', 'office.com', 'live.com', 'outlook.com', 'azure.com',
  'windows.com', 'microsoftonline.com', 'sharepoint.com', 'xbox.com',
  'facebook.com', 'fb.com', 'instagram.com', 'whatsapp.com', 'meta.com',
  'netflix.com', 'paypal.com', 'ebay.com', 'adobe.com', 'spotify.com',
  'telegram.org', 'steam.com', 'steampowered.com', 'github.com',
  'dropbox.com', 'zoom.us', 'zoom.com', 'chase.com', 'wellsfargo.com',
  'bankofamerica.com', 'hsbc.com', 'americanexpress.com', 'visa.com',
  'mastercard.com', 'disney.com', 'samsung.com', 'oracle.com',
  'linkedin.com', 'twitter.com', 'x.com', 'pinterest.com', 'tiktok.com',
]);

// Words commonly used in phishing paths and query strings. These only count
// when at least one other signal is present — a lone "/login" is normal.
export const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'sign-in', 'verify', 'verification', 'secure',
  'security', 'update', 'account', 'confirm', 'unlock', 'free', 'prize',
  'winner', 'urgent', 'suspended', 'limited', 'support', 'wallet',
  'password', 'bank', 'billing', 'refund', 'claim', 'gift',
];

// Query parameters commonly abused for open redirects.
export const REDIRECT_PARAMS = [
  'url', 'redirect', 'redirect_to', 'redirectto', 'next', 'return',
  'returnurl', 'return_url', 'target', 'dest', 'destination', 'continue',
  'goto', 'out', 'link', 'u', 'r', 'redir',
];

// Common two-part public suffixes, so "example.co.uk" is treated as one
// registrable domain instead of "co.uk". This is a small pragmatic subset,
// not the full public suffix list — see domains.js for the limitation note.
export const TWO_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au',
  'co.in', 'com.br', 'com.cn', 'co.jp', 'co.kr', 'com.mx', 'com.ar',
  'co.nz', 'com.sg', 'co.za', 'com.tr', 'com.pl', 'com.ru', 'co.id',
]);
