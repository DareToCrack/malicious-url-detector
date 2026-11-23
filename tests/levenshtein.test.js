// Tests for the Levenshtein distance helper.
import test from 'node:test';
import assert from 'node:assert/strict';
import { levenshtein } from '../src/engine/levenshtein.js';

test('identical strings have distance 0', () => {
  assert.equal(levenshtein('google.com', 'google.com'), 0);
});

test('empty string distances', () => {
  assert.equal(levenshtein('', ''), 0);
  assert.equal(levenshtein('', 'abc'), 3);
  assert.equal(levenshtein('abc', ''), 3);
});

test('single insertion, deletion, substitution', () => {
  assert.equal(levenshtein('google.com', 'gogle.com'), 1); // deletion
  assert.equal(levenshtein('gogle.com', 'google.com'), 1); // insertion
  assert.equal(levenshtein('google.com', 'goggle.com'), 1); // substitution
});

test('classic example: kitten -> sitting is 3', () => {
  assert.equal(levenshtein('kitten', 'sitting'), 3);
});

test('distance is symmetric', () => {
  assert.equal(levenshtein('paypal.com', 'paypa1.com'), levenshtein('paypa1.com', 'paypal.com'));
  assert.equal(levenshtein('paypal.com', 'paypa1.com'), 1);
});

test('case matters (callers lowercase first)', () => {
  assert.equal(levenshtein('Google', 'google'), 1);
});
