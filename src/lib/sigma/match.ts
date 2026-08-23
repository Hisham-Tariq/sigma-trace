import type { FieldCheck, SigmaEvent } from './types.ts';

/**
 * Modifiers this version implements. Anything outside this set is reported as
 * unsupported rather than silently treated as a mismatch — a wrong "no match"
 * is worse than an honest "cannot tell".
 */
export const SUPPORTED = new Set([
  'contains', 'startswith', 'endswith', 'all', 're', 'i', 'cased',
  'fieldref', 'exists', 'lt', 'lte', 'gt', 'gte', 'windash',
]);

/** Modifiers we know exist in the spec but have not implemented yet. */
export const KNOWN_UNSUPPORTED = new Set([
  'base64', 'base64offset', 'utf16', 'utf16le', 'utf16be', 'wide', 'cidr', 'expand',
]);

/**
 * Sigma values may contain `*` (any run of characters) and `?` (one character).
 * A backslash escapes the next character. Everything else is literal.
 */
export function wildcardToRegex(pattern: string): RegExp {
  let out = '';
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === '\\') {
      const next = pattern[i + 1];
      // A backslash only escapes *, ? and itself. Otherwise it is a literal
      // backslash — which is the common case in Windows paths like '\cmd.exe'.
      if (next === '*' || next === '?' || next === '\\') {
        out += escapeRe(next);
        i++;
      } else {
        out += '\\\\';
      }
    } else if (c === '*') {
      out += '[\\s\\S]*';
    } else if (c === '?') {
      out += '[\\s\\S]';
    } else {
      out += escapeRe(c);
    }
  }
  return new RegExp('^' + out + '$');
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function hasWildcard(v: string): boolean {
  for (let i = 0; i < v.length; i++) {
    if (v[i] === '\\') { i++; continue; }
    if (v[i] === '*' || v[i] === '?') return true;
  }
  return false;
}

/** `-flag` also matches `/flag` and the three unicode dashes Windows accepts. */
function windashVariants(v: string): string[] {
  const leads = ['-', '/', '–', '—', '―'];
  if (!leads.some((l) => v.startsWith(l))) return [v];
  const rest = v.slice(1);
  return leads.map((l) => l + rest);
}

function asString(v: unknown): string {
  if (v === null || v === undefined) return '';
  return String(v);
}

/** Split "Image|endswith|all" into ["Image", ["endswith","all"]]. */
export function splitKey(key: string): { field: string; modifiers: string[] } {
  const parts = key.split('|');
  return { field: parts[0], modifiers: parts.slice(1) };
}

/**
 * Field lookup. Exact name first, then a case-insensitive fallback, because
 * log sources disagree about capitalisation more often than rules do.
 */
export function lookup(event: SigmaEvent, field: string): { found: boolean; value: unknown; usedKey?: string } {
  if (Object.prototype.hasOwnProperty.call(event, field)) {
    return { found: true, value: event[field], usedKey: field };
  }
  const lower = field.toLowerCase();
  for (const k of Object.keys(event)) {
    if (k.toLowerCase() === lower) return { found: true, value: event[k], usedKey: k };
  }
  return { found: false, value: undefined };
}

/** Does one expected value match the actual value, under these modifiers? */
function matchOne(actual: unknown, expected: unknown, mods: string[]): boolean {
  const cased = mods.includes('cased');
  const actualStr = asString(actual);

  if (mods.includes('re')) {
    const flags = mods.includes('i') ? 'i' : '';
    try {
      return new RegExp(String(expected), flags).test(actualStr);
    } catch {
      return false;
    }
  }

  if (mods.includes('lt') || mods.includes('lte') || mods.includes('gt') || mods.includes('gte')) {
    const a = Number(actual);
    const b = Number(expected);
    if (Number.isNaN(a) || Number.isNaN(b)) return false;
    if (mods.includes('lt')) return a < b;
    if (mods.includes('lte')) return a <= b;
    if (mods.includes('gt')) return a > b;
    return a >= b;
  }

  // null means "field is absent or null"; '' means "field is empty".
  if (expected === null) return actual === null || actual === undefined;

  let pattern = asString(expected);
  if (mods.includes('contains')) pattern = '*' + pattern + '*';
  else if (mods.includes('startswith')) pattern = pattern + '*';
  else if (mods.includes('endswith')) pattern = '*' + pattern;

  const candidates = mods.includes('windash') ? windashVariants(pattern) : [pattern];

  return candidates.some((p) => {
    if (!hasWildcard(p)) {
      // Plain equality, but backslash escapes still have to be unwrapped.
      const literal = p.replace(/\\([*?\\])/g, '$1');
      return cased ? actualStr === literal : actualStr.toLowerCase() === literal.toLowerCase();
    }
    const re = wildcardToRegex(p);
    return cased ? re.test(actualStr) : new RegExp(re.source, 'i').test(actualStr);
  });
}

/** Evaluate one `Field|mods: value` entry against the event. */
export function checkField(event: SigmaEvent, key: string, expected: unknown): FieldCheck {
  const { field, modifiers } = splitKey(key);
  const bad = modifiers.find((m) => !SUPPORTED.has(m));

  const { found, value: actual } = lookup(event, field);

  const base: FieldCheck = {
    field, modifiers, expected, actual: found ? actual : undefined,
    matched: false, reason: '',
  };

  if (bad) {
    base.unsupported = bad;
    base.reason = KNOWN_UNSUPPORTED.has(bad)
      ? `modifier "${bad}" is part of Sigma but not implemented here yet — this line was skipped`
      : `unknown modifier "${bad}" — this line was skipped`;
    return base;
  }

  if (modifiers.includes('exists')) {
    const want = expected === true || expected === 'true';
    base.matched = found === want;
    base.reason = base.matched
      ? `field is ${found ? 'present' : 'absent'}, as required`
      : `field is ${found ? 'present' : 'absent'}, but the rule wants it ${want ? 'present' : 'absent'}`;
    return base;
  }

  if (modifiers.includes('fieldref')) {
    const other = lookup(event, asString(expected));
    base.actual = found ? actual : undefined;
    base.matched = found && other.found && asString(actual) === asString(other.value);
    base.reason = base.matched
      ? `matches the value of field "${expected}" (${asString(other.value)})`
      : `does not match field "${expected}" (${other.found ? asString(other.value) : 'field absent'})`;
    return base;
  }

  if (!found) {
    // A rule asking for null on a missing field is satisfied.
    if (expected === null) {
      base.matched = true;
      base.reason = 'field is absent, and the rule expects null';
      return base;
    }
    base.matched = false;
    base.reason = 'field is not present in the event';
    return base;
  }

  const list = Array.isArray(expected) ? expected : [expected];
  const wantAll = modifiers.includes('all');
  const results = list.map((e) => ({ e, ok: matchOne(actual, e, modifiers) }));

  base.matched = wantAll ? results.every((r) => r.ok) : results.some((r) => r.ok);
  const hit = results.find((r) => r.ok);
  if (hit) base.matchedValue = hit.e;

  const how = modifiers.filter((m) => m !== 'all').join('|') || 'equals';
  if (base.matched) {
    base.reason = Array.isArray(expected)
      ? (wantAll ? `every value in the list matched (${how})` : `matched "${asString(hit?.e)}" (${how})`)
      : `matched (${how})`;
  } else {
    base.reason = Array.isArray(expected)
      ? (wantAll ? `not every value in the list matched (${how})` : `none of the ${list.length} values matched (${how})`)
      : `"${asString(actual)}" does not match "${asString(expected)}" (${how})`;
  }
  return base;
}
