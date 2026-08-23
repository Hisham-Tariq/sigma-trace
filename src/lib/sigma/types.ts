/** A log event: flat field -> value. Values arrive as strings from most log sources. */
export type SigmaEvent = Record<string, unknown>;

/** One `Field|mod: value` check inside a search identifier. */
export interface FieldCheck {
  /** Field name as written in the rule, e.g. "Image". */
  field: string;
  /** Modifiers in order, e.g. ["endswith"]. */
  modifiers: string[];
  /** The value(s) the rule expects. */
  expected: unknown;
  /** The value found in the event, or undefined when the field is absent. */
  actual: unknown;
  matched: boolean;
  /** Human sentence explaining the outcome. Shown in the UI. */
  reason: string;
  /** Set when a modifier is not implemented; the result is then not trustworthy. */
  unsupported?: string;
  /** Which of a list of expected values matched, when one did. */
  matchedValue?: unknown;
}

/**
 * A search identifier is either a map (fields ANDed) or a list of maps (ORed),
 * or a bare list of keywords. Each entry in `groups` is one map.
 */
export interface BlockResult {
  name: string;
  matched: boolean;
  kind: 'map' | 'list-of-maps' | 'keywords';
  groups: { matched: boolean; checks: FieldCheck[] }[];
  /** True when any check inside used an unimplemented modifier. */
  hasUnsupported: boolean;
}

export type ConditionNode =
  | { type: 'id'; name: string; value?: boolean; missing?: boolean }
  | { type: 'and' | 'or'; left: ConditionNode; right: ConditionNode; value?: boolean }
  | { type: 'not'; node: ConditionNode; value?: boolean }
  | {
      type: 'quant';
      /** "1", "all", "any", or a number as written. */
      count: string;
      /** A block-name pattern like "filter_optional_*", or "them". */
      pattern: string;
      /** Blocks the pattern resolved to. */
      resolved?: string[];
      value?: boolean;
    };

export interface Trace {
  title?: string;
  id?: string;
  level?: string;
  logsource?: Record<string, unknown>;
  blocks: BlockResult[];
  condition: string;
  ast: ConditionNode | null;
  /** Final verdict: does this rule alert on this event? */
  alert: boolean;
  /** Blocks defined in `detection:` that the condition never references. */
  unreferenced: string[];
  /** Fatal problems that stop evaluation. */
  errors: string[];
  /** Non-fatal problems: unsupported modifiers, unknown fields, etc. */
  warnings: string[];
}
