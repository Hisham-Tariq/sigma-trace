import type { ConditionNode } from './types.ts';

/**
 * The Sigma condition grammar, in the order operators bind:
 *
 *   expr    := orExpr
 *   orExpr  := andExpr ('or' andExpr)*
 *   andExpr := notExpr ('and' notExpr)*
 *   notExpr := 'not' notExpr | primary
 *   primary := '(' expr ')' | quantifier | identifier
 *   quantifier := ('1' | 'all' | 'any' | N) 'of' (pattern | 'them')
 *
 * Aggregations (`| count() > 5`) are not part of this version and are rejected
 * loudly rather than silently ignored.
 */

export function tokenize(src: string): string[] {
  return src.match(/[()]|[^\s()]+/g) ?? [];
}

export class ConditionError extends Error {}

export function parseCondition(src: string): ConditionNode {
  if (src.includes('|')) {
    throw new ConditionError(
      'aggregation conditions (the "|" part) are not supported in this version',
    );
  }
  const tokens = tokenize(src);
  let i = 0;

  const peek = () => tokens[i];
  const eat = () => tokens[i++];
  const isKeyword = (t: string | undefined, kw: string) => t !== undefined && t.toLowerCase() === kw;

  function parseExpr(): ConditionNode {
    return parseOr();
  }

  function parseOr(): ConditionNode {
    let left = parseAnd();
    while (isKeyword(peek(), 'or')) {
      eat();
      left = { type: 'or', left, right: parseAnd() };
    }
    return left;
  }

  function parseAnd(): ConditionNode {
    let left = parseNot();
    while (isKeyword(peek(), 'and')) {
      eat();
      left = { type: 'and', left, right: parseNot() };
    }
    return left;
  }

  function parseNot(): ConditionNode {
    if (isKeyword(peek(), 'not')) {
      eat();
      return { type: 'not', node: parseNot() };
    }
    return parsePrimary();
  }

  function parsePrimary(): ConditionNode {
    const t = peek();
    if (t === undefined) throw new ConditionError('condition ended unexpectedly');

    if (t === '(') {
      eat();
      const inner = parseExpr();
      if (peek() !== ')') throw new ConditionError('missing closing ")"');
      eat();
      return inner;
    }
    if (t === ')') throw new ConditionError('unexpected ")"');

    // quantifier: "1 of x*", "all of them", "2 of selection*"
    const lower = t.toLowerCase();
    if ((lower === 'all' || lower === 'any' || /^\d+$/.test(lower)) && isKeyword(tokens[i + 1], 'of')) {
      eat(); eat();
      const pattern = eat();
      if (pattern === undefined) throw new ConditionError(`"${t} of" needs something after it`);
      return { type: 'quant', count: lower, pattern };
    }

    eat();
    return { type: 'id', name: t };
  }

  const ast = parseExpr();
  if (i < tokens.length) {
    throw new ConditionError(`unexpected "${tokens[i]}" after the end of the condition`);
  }
  return ast;
}

/** Does a block name match a condition pattern like `filter_optional_*`? */
export function nameMatches(pattern: string, name: string): boolean {
  if (pattern === name) return true;
  if (!pattern.includes('*')) return false;
  const re = new RegExp('^' + pattern.split('*').map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$');
  return re.test(name);
}

/**
 * Evaluate the tree. `blocks` maps block name -> whether that block matched.
 * The tree is mutated in place so every node carries its own truth value —
 * that is what the UI draws.
 */
export function evaluateCondition(
  ast: ConditionNode,
  blocks: Map<string, boolean>,
  errors: string[],
): boolean {
  const allNames = [...blocks.keys()];

  function walk(n: ConditionNode): boolean {
    switch (n.type) {
      case 'id': {
        if (!blocks.has(n.name)) {
          n.missing = true;
          errors.push(`the condition refers to "${n.name}", which is not defined under detection:`);
          n.value = false;
          return false;
        }
        n.value = blocks.get(n.name)!;
        return n.value;
      }
      case 'and': {
        // Both sides are always walked, never short-circuited, so the trace
        // shows a truth value for every block the reader can see.
        walk(n.left); walk(n.right);
        n.value = n.left.value === true && n.right.value === true;
        return n.value;
      }
      case 'or': {
        walk(n.left); walk(n.right);
        n.value = n.left.value === true || n.right.value === true;
        return n.value;
      }
      case 'not': {
        walk(n.node);
        n.value = n.node.value !== true;
        return n.value;
      }
      case 'quant': {
        const resolved = n.pattern.toLowerCase() === 'them'
          ? allNames
          : allNames.filter((name) => nameMatches(n.pattern, name));
        n.resolved = resolved;
        if (resolved.length === 0) {
          errors.push(`"${n.count} of ${n.pattern}" matches no block defined under detection:`);
        }
        const hits = resolved.filter((name) => blocks.get(name) === true).length;
        const need = n.count === 'all' ? resolved.length : n.count === 'any' ? 1 : Number(n.count);
        n.value = resolved.length > 0 && hits >= need;
        return n.value;
      }
    }
  }
  return walk(ast);
}

/** Every block name the condition mentions, directly or through a pattern. */
export function referencedBlocks(ast: ConditionNode, allNames: string[]): Set<string> {
  const out = new Set<string>();
  (function walk(n: ConditionNode) {
    switch (n.type) {
      case 'id': out.add(n.name); break;
      case 'and': case 'or': walk(n.left); walk(n.right); break;
      case 'not': walk(n.node); break;
      case 'quant': {
        if (n.pattern.toLowerCase() === 'them') allNames.forEach((x) => out.add(x));
        else allNames.filter((x) => nameMatches(n.pattern, x)).forEach((x) => out.add(x));
        break;
      }
    }
  })(ast);
  return out;
}
