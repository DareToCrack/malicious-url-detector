// Tests for the Safe Browsing reputation lookup (request building and
// response handling, with a mocked fetch — no real network calls).
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildThreatMatchesRequest, checkSafeBrowsing } from '../src/lib/reputation.js';

test('threatMatches request has the right shape', () => {
  const body = buildThreatMatchesRequest('https://evil-example.com/phish');
  assert.equal(body.client.clientId, 'url-sentinel');
  assert.ok(body.threatInfo.threatTypes.includes('MALWARE'));
  assert.ok(body.threatInfo.threatTypes.includes('SOCIAL_ENGINEERING'));
  assert.deepEqual(body.threatInfo.threatEntries, [{ url: 'https://evil-example.com/phish' }]);
  assert.deepEqual(body.threatInfo.threatEntryTypes, ['URL']);
});

test('a Safe Browsing match is reported with its threat type', async () => {
  const mockFetch = async () => ({
    ok: true,
    json: async () => ({ matches: [{ threatType: 'SOCIAL_ENGINEERING' }] }),
  });
  const r = await checkSafeBrowsing('https://evil-example.com/', 'fake-key', mockFetch);
  assert.equal(r.matched, true);
  assert.equal(r.threatType, 'SOCIAL_ENGINEERING');
});

test('no matches means no reputation signal', async () => {
  const mockFetch = async () => ({ ok: true, json: async () => ({}) });
  const r = await checkSafeBrowsing('https://example.com/', 'fake-key', mockFetch);
  assert.equal(r.matched, false);
  assert.equal(r.error, undefined);
});

test('no API key means no lookup is attempted', async () => {
  let called = false;
  const mockFetch = async () => {
    called = true;
    throw new Error('should not be called');
  };
  const r = await checkSafeBrowsing('https://example.com/', '', mockFetch);
  assert.equal(r.matched, false);
  assert.equal(r.error, 'no-key');
  assert.equal(called, false);
});

test('HTTP errors and network failures fail closed to "no signal"', async () => {
  const httpError = async () => ({ ok: false, status: 403, json: async () => ({}) });
  const r1 = await checkSafeBrowsing('https://example.com/', 'bad-key', httpError);
  assert.equal(r1.matched, false);
  assert.equal(r1.error, 'http-403');

  const throwing = async () => {
    throw new Error('network down');
  };
  const r2 = await checkSafeBrowsing('https://example.com/', 'key', throwing);
  assert.equal(r2.matched, false);
  assert.ok(r2.error.includes('network down'));
});
