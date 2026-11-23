// Host and domain helpers for the heuristic engine. Pure JS, no chrome.*
// imports, so node:test can exercise them directly.
//
// Limitation: registrable-domain extraction uses a small list of common
// two-part suffixes (see data.js TWO_PART_SUFFIXES) rather than the full
// public suffix list. Unlisted multi-part suffixes (e.g. github.io, co.nz
// subdomains) may be split one label too far, which can only make the
// typosquat check more conservative — it fails toward NOT flagging.

import { TWO_PART_SUFFIXES } from './data.js';

const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^\[[0-9a-fA-F:]+\]$|^[0-9a-fA-F]*:[0-9a-fA-F:]+$/;

// Is this host an IP literal (v4 or v6)? Note: URL.host strips the brackets
// from IPv6 literals, so we check both forms.
export function isIpHost(host) {
  if (!host) return false;
  if (IPV4_RE.test(host)) {
    return host.split('.').every((part) => {
      const n = Number(part);
      return Number.isInteger(n) && n >= 0 && n <= 255;
    });
  }
  return IPV6_RE.test(host) && host.includes(':');
}

// Is this a loopback / private / link-local address, or localhost? Such hosts
// are local development or LAN devices — the IP-host finding is skipped for
// them (fail-safe: never flag someone's own network).
export function isPrivateHost(host) {
  if (!host) return false;
  const h = host.toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost') || h === '[::1]' || h === '::1') return true;
  if (!IPV4_RE.test(h)) return false;
  const [a, b] = h.split('.').map(Number);
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local
  return false;
}

// Split a host into labels, lowercased, without a trailing dot.
export function hostLabels(host) {
  if (!host) return [];
  return host.toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
}

// The registrable domain: the label just left of the public suffix, plus the
// suffix. e.g. "mail.google.com" -> "google.com", "shop.example.co.uk" ->
// "example.co.uk". Returns the host itself for IPs and single-label hosts.
export function registrableDomain(host) {
  const labels = hostLabels(host);
  if (labels.length <= 2 || isIpHost(host)) return host.toLowerCase().replace(/\.$/, '');
  const lastTwo = labels.slice(-2).join('.');
  if (TWO_PART_SUFFIXES.has(lastTwo)) {
    return labels.length >= 3 ? labels.slice(-3).join('.') : labels.join('.');
  }
  return lastTwo;
}

// The top-level domain (last label), e.g. "tk" for "example.tk".
export function topLevelDomain(host) {
  const labels = hostLabels(host);
  return labels.length ? labels[labels.length - 1] : '';
}

// Number of subdomain labels (labels left of the registrable domain).
export function subdomainCount(host) {
  const labels = hostLabels(host);
  if (isIpHost(host) || labels.length <= 2) return 0;
  const reg = registrableDomain(host);
  return labels.length - reg.split('.').length;
}

// Split a host label or path segment into word tokens on common separators,
// so "paypal-secure" yields ["paypal", "secure"] but "pineapple" stays
// ["pineapple"] (no false brand match inside a longer word).
export function tokens(text) {
  return String(text || '')
    .toLowerCase()
    .split(/[-_.+]+/)
    .filter(Boolean);
}
