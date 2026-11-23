// Tests for host/domain helpers.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isIpHost,
  isPrivateHost,
  hostLabels,
  registrableDomain,
  topLevelDomain,
  subdomainCount,
  tokens,
} from '../src/engine/domains.js';

test('isIpHost detects IPv4 literals', () => {
  assert.equal(isIpHost('185.220.101.5'), true);
  assert.equal(isIpHost('127.0.0.1'), true);
  assert.equal(isIpHost('example.com'), false);
  assert.equal(isIpHost('999.1.1.1'), false); // octets out of range
  assert.equal(isIpHost('1.2.3'), false);
});

test('isIpHost detects IPv6 literals', () => {
  assert.equal(isIpHost('::1'), true);
  assert.equal(isIpHost('[2001:db8::1]'), true);
  assert.equal(isIpHost('2001:db8::1'), true);
});

test('isPrivateHost covers localhost and private ranges', () => {
  assert.equal(isPrivateHost('localhost'), true);
  assert.equal(isPrivateHost('127.0.0.1'), true);
  assert.equal(isPrivateHost('10.0.0.5'), true);
  assert.equal(isPrivateHost('192.168.1.1'), true);
  assert.equal(isPrivateHost('172.16.0.1'), true);
  assert.equal(isPrivateHost('172.31.255.255'), true);
  assert.equal(isPrivateHost('169.254.1.1'), true);
  assert.equal(isPrivateHost('8.8.8.8'), false);
  assert.equal(isPrivateHost('172.32.0.1'), false); // just outside 172.16/12
  assert.equal(isPrivateHost('example.com'), false);
});

test('hostLabels lowercases and drops a trailing dot', () => {
  assert.deepEqual(hostLabels('Mail.Google.COM.'), ['mail', 'google', 'com']);
  assert.deepEqual(hostLabels(''), []);
});

test('registrableDomain strips subdomains', () => {
  assert.equal(registrableDomain('mail.google.com'), 'google.com');
  assert.equal(registrableDomain('google.com'), 'google.com');
  assert.equal(registrableDomain('shop.example.co.uk'), 'example.co.uk');
  assert.equal(registrableDomain('example.co.uk'), 'example.co.uk');
  assert.equal(registrableDomain('185.220.101.5'), '185.220.101.5');
});

test('topLevelDomain returns the last label', () => {
  assert.equal(topLevelDomain('example.tk'), 'tk');
  assert.equal(topLevelDomain('a.b.example.co.uk'), 'uk');
});

test('subdomainCount counts labels left of the registrable domain', () => {
  assert.equal(subdomainCount('example.com'), 0);
  assert.equal(subdomainCount('www.example.com'), 1);
  assert.equal(subdomainCount('a.b.c.d.example.com'), 4);
  assert.equal(subdomainCount('shop.example.co.uk'), 1);
  assert.equal(subdomainCount('185.220.101.5'), 0);
});

test('tokens splits on separators but keeps whole words intact', () => {
  assert.deepEqual(tokens('paypal-secure'), ['paypal', 'secure']);
  assert.deepEqual(tokens('pineapple'), ['pineapple']);
  assert.deepEqual(tokens('secure_login.verify'), ['secure', 'login', 'verify']);
  assert.deepEqual(tokens(''), []);
});
