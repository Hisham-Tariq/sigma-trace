import yaml from 'js-yaml';
import { checkField } from './match.ts';
import { ConditionError, evaluateCondition, parseCondition, referencedBlocks } from './condition.ts';
import type { BlockResult, ConditionNode, FieldCheck, SigmaEvent, Trace } from './types.ts';

export * from './types.ts';
export { parseCondition, nameMatches } from './condition.ts';
export { wildcardToRegex, checkField } from './match.ts';

/**
 * Parse a log event pasted as text. Two shapes are accepted:
 *  - JSON object
 *  - `Field: value` lines, which is how Sysmon events are usually pasted around
 *
 * Windows event text often puts several fields on one line separated by two
 * spaces, so that is handled too.
 */
export function parseEvent(text: string): { event: SigmaEvent; error?: string } {
  const trimmed = text.trim();
  if (!trimmed) return { event: {} };

  if (trimmed.startsWith('{')) {
    try {
      const obj = JSON.parse(trimmed);
      // evtx-sigma-checker wraps the real fields; unwrap the common shapes.
      const inner = obj?.Event?.EventData ?? obj?.EventData ?? obj;
      if (typeof inner !== 'object' || inner === null) return { event: {}, error: 'JSON is not an object' };
      return { event: flatten(inner) };
    } catch (e) {
      return { event: {}, error: `not valid JSON: ${(e as Error).message}` };
    }
  }

  const event: SigmaEvent = {};
  for (const rawLine of trimmed.split(/\r?\n/)) {
    // Split on two-or-more spaces first: "A: 1  B: 2" is one physical line.
    for (const part of rawLine.split(/ {2,}/)) {
      const m = part.match(/^\s*([A-Za-z0-9_.\-#@]+)\s*:\s*(.*)$/);
      if (!m) continue;
      const [, k, v] = m;
      if (k in event && !v) continue;
      event[k] = v;
    }
  }
  return { event };
}

/** Nested JSON is flattened to leaf names, which is how rules address fields. */
function flatten(obj: Record<string, unknown>, out: SigmaEvent = {}): SigmaEvent {
  for (const [k, v] of Object.entries(obj)) {
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
      flatten(v as Record<string, unknown>, out);
    } else if (!(k in out)) {
      out[k] = v;
    }
  }
  return out;
}

function evaluateBlock(name: string, spec: unknown, event: SigmaEvent): BlockResult {
  const groups: BlockResult['groups'] = [];
  let kind: BlockResult['kind'] = 'map';

  const runMap = (m: Record<string, unknown>) => {
    const checks: FieldCheck[] = Object.entries(m).map(([k, v]) => checkField(event, k, v));
    // An unsupported modifier must not be allowed to decide the outcome.
    const usable = checks.filter((c) => !c.unsupported);
    return { matched: usable.length > 0 && usable.every((c) => c.matched), checks };
  };

  if (Array.isArray(spec)) {
    const allMaps = spec.every((x) => x !== null && typeof x === 'object' && !Array.isArray(x));
    if (allMaps) {
      kind = 'list-of-maps';
      for (const m of spec) groups.push(runMap(m as Record<string, unknown>));
    } else {
      // A bare list of strings is a keyword search across every field value.
      kind = 'keywords';
      const haystack = Object.values(event).map((v) => String(v ?? '')).join('\n').toLowerCase();
      for (const kw of spec) {
        const needle = String(kw).toLowerCase();
        const ok = haystack.includes(needle);
        groups.push({
          matched: ok,
          checks: [{
            field: '(any field)', modifiers: ['keyword'], expected: kw,
            actual: undefined, matched: ok,
            reason: ok ? 'this text appears somewhere in the event' : 'this text does not appear in the event',
          }],
        });
      }
    }
  } else if (spec !== null && typeof spec === 'object') {
    groups.push(runMap(spec as Record<string, unknown>));
  } else {
    groups.push({
      matched: false,
      checks: [{
        field: name, modifiers: [], expected: spec, actual: undefined, matched: false,
        reason: 'this block is not a map or a list, so it cannot be evaluated',
        unsupported: 'shape',
      }],
    });
  }

  return {
    name,
    kind,
    groups,
    // A map ANDs its fields; a list of maps ORs the maps; keywords OR too.
    matched: kind === 'map' ? groups[0]?.matched === true : groups.some((g) => g.matched),
    hasUnsupported: groups.some((g) => g.checks.some((c) => c.unsupported)),
  };
}

/** Run one Sigma rule against one event and return everything needed to draw the trace. */
export function evaluate(ruleYaml: string, eventText: string): Trace {
  const errors: string[] = [];
  const warnings: string[] = [];

  const trace: Trace = {
    blocks: [], condition: '', ast: null, alert: false,
    unreferenced: [], errors, warnings,
  };

  let rule: Record<string, unknown>;
  try {
    const loaded = yaml.load(ruleYaml);
    if (loaded === null || typeof loaded !== 'object') {
      errors.push('the rule is empty or is not a YAML mapping');
      return trace;
    }
    rule = loaded as Record<string, unknown>;
  } catch (e) {
    errors.push(`YAML error: ${(e as Error).message}`);
    return trace;
  }

  trace.title = rule.title as string | undefined;
  trace.id = rule.id as string | undefined;
  trace.level = rule.level as string | undefined;
  trace.logsource = rule.logsource as Record<string, unknown> | undefined;

  const detection = rule.detection as Record<string, unknown> | undefined;
  if (!detection || typeof detection !== 'object') {
    errors.push('the rule has no detection: section');
    return trace;
  }

  const conditionRaw = detection.condition;
  if (conditionRaw === undefined) {
    errors.push('detection: has no condition: line');
    return trace;
  }
  if (Array.isArray(conditionRaw)) {
    errors.push('a list of conditions is not supported in this version');
    return trace;
  }
  trace.condition = String(conditionRaw);

  const { event, error: evErr } = parseEvent(eventText);
  if (evErr) errors.push(evErr);
  if (Object.keys(event).length === 0) warnings.push('no fields were read from the event');

  for (const [name, spec] of Object.entries(detection)) {
    if (name === 'condition' || name === 'timeframe') continue;
    trace.blocks.push(evaluateBlock(name, spec, event));
  }
  if (trace.blocks.length === 0) errors.push('detection: defines no search identifiers');

  for (const b of trace.blocks) {
    if (b.hasUnsupported) {
      warnings.push(`block "${b.name}" uses a modifier this version does not implement — its result is not reliable`);
    }
  }

  let ast: ConditionNode;
  try {
    ast = parseCondition(trace.condition);
  } catch (e) {
    errors.push(e instanceof ConditionError ? e.message : `could not parse the condition: ${(e as Error).message}`);
    return trace;
  }
  trace.ast = ast;

  const blockMap = new Map(trace.blocks.map((b) => [b.name, b.matched]));
  trace.alert = evaluateCondition(ast, blockMap, errors);

  const referenced = referencedBlocks(ast, [...blockMap.keys()]);
  trace.unreferenced = trace.blocks.map((b) => b.name).filter((n) => !referenced.has(n));

  return trace;
}
