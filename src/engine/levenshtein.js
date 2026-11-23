// Levenshtein (edit) distance — the number of single-character insertions,
// deletions, or substitutions needed to turn one string into another.
// Used for typosquatting detection: a domain within distance 2 of a popular
// domain is likely a deliberate look-alike.
//
// Pure JS, no dependencies. Iterative two-row implementation, O(m*n) time and
// O(min(m, n)) space.

export function levenshtein(a, b) {
  if (a === b) return 0;
  let m = a.length;
  let n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  // Work on the shorter string as the columns to save memory.
  if (n > m) {
    [a, b] = [b, a];
    [m, n] = [n, m];
  }
  let prev = new Array(n + 1);
  let cur = new Array(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    cur[0] = i;
    const aChar = a.charCodeAt(i - 1);
    for (let j = 1; j <= n; j++) {
      const cost = aChar === b.charCodeAt(j - 1) ? 0 : 1;
      cur[j] = Math.min(
        prev[j] + 1, // deletion
        cur[j - 1] + 1, // insertion
        prev[j - 1] + cost, // substitution
      );
    }
    [prev, cur] = [cur, prev];
  }
  return prev[n];
}
