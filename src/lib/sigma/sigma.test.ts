import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluate, parseEvent, parseCondition, nameMatches, wildcardToRegex, checkField } from './index.ts';

/* ------------------------------------------------------------------ *
 * Ground truth
 *
 * The rule and the three events below are real. They come from SigmaHQ
 * rule 36480ae1-a1cb-4eaa-a0d6-29801d7e9142 and from the output of
 * Nextron's evtx-sigma-checker run against the public Windows baselines
 * on 21 Aug 2026. The verdicts asserted here are the verdicts that
 * checker produced, not verdicts this code was allowed to invent.
 * ------------------------------------------------------------------ */

const RULE_ORIGINAL = `
title: Potential Defense Evasion Via Binary Rename
id: 36480ae1-a1cb-4eaa-a0d6-29801d7e9142
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName:
            - 'Cmd.Exe'
            - 'CONHOST.EXE'
            - '7z.exe'
            - 'WinRAR.exe'
            - 'net.exe'
            - 'netsh.exe'
            - 'InstallUtil.exe'
    filter:
        Image|endswith:
            - '\\cmd.exe'
            - '\\conhost.exe'
            - '\\7z.exe'
            - '\\WinRAR.exe'
            - '\\net.exe'
            - '\\netsh.exe'
            - '\\InstallUtil.exe'
    condition: selection and not filter
level: medium
`;

/** The fix that was written this week: filter added AND condition updated. */
const RULE_FIXED = RULE_ORIGINAL.replace(
  '    condition: selection and not filter',
  `    filter_optional_ninite:
        OriginalFileName: 'WinRAR.exe'
        Image|endswith: '\\target.exe'
        ParentImage|endswith: '\\Ninite.exe'
    condition: selection and not filter and not 1 of filter_optional_*`,
);

/** The classic mistake: block added, condition left alone. */
const RULE_DEAD_BLOCK = RULE_ORIGINAL.replace(
  '    condition: selection and not filter',
  `    filter_optional_ninite:
        OriginalFileName: 'WinRAR.exe'
        Image|endswith: '\\target.exe'
        ParentImage|endswith: '\\Ninite.exe'
    condition: selection and not filter`,
);

/** Real Sysmon event from the win10-client baseline. Ninite installing WinRAR. */
const EVENT_NINITE = `RuleName: -  UtcTime: 2022-02-08 11:46:04.808  ProcessId: 6068  Image: C:\\Users\\user\\AppData\\Local\\Temp\\46F399~1\\target.exe  FileVersion: 6.10.0  Description: WinRAR archiver  Product: WinRAR  Company: Alexander Roshal  OriginalFileName: WinRAR.exe  CommandLine: "C:\\Users\\user\\AppData\\Local\\Temp\\46F399~1\\target.exe" /S  User: DESKTOP-A8CALR3\\user  IntegrityLevel: High  ParentImage: C:\\Users\\user\\AppData\\Local\\Temp\\0cb1bbbb-88d4-11ec-89b1-080027dfe1cd\\Ninite.exe  ParentUser: DESKTOP-A8CALR3\\user  EventID: 1`;

/** The rule's own regression sample: a genuinely renamed netsh. */
const EVENT_RENAMED_NETSH = `Image: C:\\Users\\Administrator\\Downloads\\testdata\\renamed-netsh.exe
OriginalFileName: netsh.exe
ParentImage: C:\\Windows\\System32\\cmd.exe
CommandLine: renamed-netsh.exe
Product: Microsoft(R) Windows(R) Operating System
Company: Microsoft Corporation`;

/** A plain, legitimate cmd.exe. Should never alert. */
const EVENT_NORMAL_CMD = `Image: C:\\Windows\\System32\\cmd.exe
OriginalFileName: Cmd.Exe
ParentImage: C:\\Windows\\explorer.exe`;

/* ------------------------------------------------------------------ *
 * The verdicts that matter
 * ------------------------------------------------------------------ */

test('ground truth: unfixed rule alerts on the Ninite/WinRAR event', () => {
  const t = evaluate(RULE_ORIGINAL, EVENT_NINITE);
  assert.deepEqual(t.errors, []);
  assert.equal(t.alert, true, 'harness reported 1 match on win10/win11/win11-2023');
});

test('ground truth: the fix silences it', () => {
  const t = evaluate(RULE_FIXED, EVENT_NINITE);
  assert.deepEqual(t.errors, []);
  assert.equal(t.alert, false, 'harness reported 0 after the filter was added');
});

test('ground truth: the fix does NOT silence the real renamed binary', () => {
  const t = evaluate(RULE_FIXED, EVENT_RENAMED_NETSH);
  assert.equal(t.alert, true, 'regression sample must still match exactly once');
});

test('ground truth: a normal cmd.exe never alerts', () => {
  assert.equal(evaluate(RULE_ORIGINAL, EVENT_NORMAL_CMD).alert, false);
  assert.equal(evaluate(RULE_FIXED, EVENT_NORMAL_CMD).alert, false);
});

test('breaking the filter brings the alert back (the break-test)', () => {
  const broken = RULE_FIXED.replace('\\Ninite.exe', '\\NiniteZZZ.exe');
  assert.notEqual(broken, RULE_FIXED, 'the break-edit must actually change the rule');
  assert.equal(evaluate(broken, EVENT_NINITE).alert, true);
});

/* ------------------------------------------------------------------ *
 * The feature this tool exists for
 * ------------------------------------------------------------------ */

test('a block the condition never references is reported, and does nothing', () => {
  const t = evaluate(RULE_DEAD_BLOCK, EVENT_NINITE);
  assert.deepEqual(t.unreferenced, ['filter_optional_ninite']);
  const block = t.blocks.find((b) => b.name === 'filter_optional_ninite')!;
  assert.equal(block.matched, true, 'the block itself matches the event');
  assert.equal(t.alert, true, 'yet the rule still alerts, because the condition ignores it');
});

test('a correctly wired rule reports nothing unreferenced', () => {
  assert.deepEqual(evaluate(RULE_FIXED, EVENT_NINITE).unreferenced, []);
});

test('a condition naming a block that does not exist is an error', () => {
  const t = evaluate(RULE_ORIGINAL.replace('not filter', 'not filter_typo'), EVENT_NINITE);
  assert.ok(t.errors.some((e) => e.includes('filter_typo')), t.errors.join(' | '));
});

/* ------------------------------------------------------------------ *
 * Field matching
 * ------------------------------------------------------------------ */

test('matching is case-insensitive by default, and |cased is not', () => {
  const ev = { Image: 'C:\\Windows\\System32\\CMD.EXE' };
  assert.equal(checkField(ev, 'Image|endswith', '\\cmd.exe').matched, true);
  assert.equal(checkField(ev, 'Image|endswith|cased', '\\cmd.exe').matched, false);
});

test('endswith needs the leading backslash to avoid matching notcmd.exe', () => {
  const ev = { Image: 'C:\\tools\\notcmd.exe' };
  assert.equal(checkField(ev, 'Image|endswith', '\\cmd.exe').matched, false);
  assert.equal(checkField(ev, 'Image|endswith', 'cmd.exe').matched, true);
});

test('backslash and wildcard rules, pinned to the real corpus', () => {
  // Sigma text  \\Users\\*\\Temp  -> the '\\' pairs consume first, so the
  // lone '*' is a wildcard. This is how SigmaHQ writes "any user folder"
  // (proc_creation_win_rundll32_udl_exec.yml: '\\Users\\*\\Downloads\\').
  assert.equal(wildcardToRegex('\\\\Users\\\\*\\\\Temp').test('\\Users\\bob\\Temp'), true);

  // Sigma text  a\*c  -> '\*' is an ESCAPED asterisk, not a wildcard.
  assert.equal(wildcardToRegex('a\\*c').test('abc'), false);
  assert.equal(wildcardToRegex('a\\*c').test('a*c'), true);

  assert.equal(wildcardToRegex('a?c').test('abc'), true);
  assert.equal(wildcardToRegex('a?c').test('ac'), false);

  // Ground truth. SigmaHQ zeek_smb_converted_win_lm_namedpipe.yml writes
  //     path: '\\\\\\\\\\*\\\\IPC$'
  // and its own comment states the intended string is  \\*\IPC$ .
  // Pinning it here means these escape rules can never drift back into a guess.
  assert.equal(wildcardToRegex('\\\\\\\\\\*\\\\IPC$').test('\\\\*\\IPC$'), true);
  assert.equal(wildcardToRegex('\\\\\\\\\\*\\\\IPC$').test('\\\\anything\\IPC$'), false);
});

test('a list of values is OR, and |all makes it AND', () => {
  const ev = { CommandLine: 'powershell -enc AAA -nop' };
  assert.equal(checkField(ev, 'CommandLine|contains', ['-enc', '-zzz']).matched, true);
  assert.equal(checkField(ev, 'CommandLine|contains|all', ['-enc', '-zzz']).matched, false);
  assert.equal(checkField(ev, 'CommandLine|contains|all', ['-enc', '-nop']).matched, true);
});

test('a missing field does not match, but null expects it to be missing', () => {
  const ev = { Image: 'x.exe' };
  assert.equal(checkField(ev, 'ParentImage', 'y.exe').matched, false);
  assert.equal(checkField(ev, 'ParentImage', null).matched, true);
  assert.equal(checkField(ev, 'Image', null).matched, false);
});

test('|re, |windash, |fieldref and |exists behave', () => {
  assert.equal(checkField({ Image: 'a1b' }, 'Image|re', 'a\\db').matched, true);
  assert.equal(checkField({ CommandLine: '/S' }, 'CommandLine|windash', '-S').matched, true);
  assert.equal(checkField({ a: 'x', b: 'x' }, 'a|fieldref', 'b').matched, true);
  assert.equal(checkField({ a: 'x', b: 'y' }, 'a|fieldref', 'b').matched, false);
  assert.equal(checkField({ a: 'x' }, 'a|exists', true).matched, true);
  assert.equal(checkField({ a: 'x' }, 'b|exists', false).matched, true);
});

test('an unimplemented modifier is flagged, never silently counted as a mismatch', () => {
  const c = checkField({ CommandLine: 'whatever' }, 'CommandLine|base64offset|contains', 'x');
  assert.equal(c.unsupported, 'base64offset');
  const t = evaluate(
    `title: t\ndetection:\n  sel:\n    CommandLine|base64offset|contains: 'x'\n  condition: sel\n`,
    'CommandLine: whatever',
  );
  assert.ok(t.warnings.some((w) => w.includes('not implement')), t.warnings.join(' | '));
});

/* ------------------------------------------------------------------ *
 * Condition grammar
 * ------------------------------------------------------------------ */

test('condition parsing: precedence, parentheses, quantifiers', () => {
  assert.equal(parseCondition('a and b or c').type, 'or', 'and binds tighter than or');
  assert.equal(parseCondition('a and (b or c)').type, 'and');
  assert.equal(parseCondition('not a').type, 'not');
  const q = parseCondition('1 of filter_main_*');
  assert.equal(q.type, 'quant');
  assert.throws(() => parseCondition('a and'), /unexpectedly/);
  assert.throws(() => parseCondition('a and (b'), /closing/);
  assert.throws(() => parseCondition('sel | count() > 5'), /aggregation/);
});

test('block-name patterns resolve the way Sigma expects', () => {
  assert.equal(nameMatches('filter_optional_*', 'filter_optional_ninite'), true);
  assert.equal(nameMatches('filter_optional_*', 'filter_main_svchost'), false);
  assert.equal(nameMatches('selection', 'selection'), true);
  assert.equal(nameMatches('sel*', 'selection_2'), true);
});

test('"all of them" and "N of x*" count correctly', () => {
  const rule = (cond: string) => `title: t
detection:
  sel_a:
    A: '1'
  sel_b:
    B: '2'
  sel_c:
    C: '9'
  condition: ${cond}
`;
  const ev = 'A: 1\nB: 2\nC: 3';
  assert.equal(evaluate(rule('all of them'), ev).alert, false, 'sel_c does not match');
  assert.equal(evaluate(rule('1 of sel_*'), ev).alert, true);
  assert.equal(evaluate(rule('2 of sel_*'), ev).alert, true);
  assert.equal(evaluate(rule('3 of sel_*'), ev).alert, false);
  assert.equal(evaluate(rule('all of sel_a*'), ev).alert, true);
});

test('a list of maps under one block is OR, a map is AND', () => {
  const orRule = `title: t
detection:
  sel:
    - A: '1'
    - B: 'nope'
  condition: sel
`;
  const andRule = `title: t
detection:
  sel:
    A: '1'
    B: 'nope'
  condition: sel
`;
  assert.equal(evaluate(orRule, 'A: 1\nB: 2').alert, true);
  assert.equal(evaluate(andRule, 'A: 1\nB: 2').alert, false);
});

/* ------------------------------------------------------------------ *
 * Event parsing
 * ------------------------------------------------------------------ */

test('event parsing: Sysmon one-liner, multi-line, and JSON', () => {
  const flat = parseEvent(EVENT_NINITE).event;
  assert.equal(flat.OriginalFileName, 'WinRAR.exe');
  assert.equal(flat.Image, 'C:\\Users\\user\\AppData\\Local\\Temp\\46F399~1\\target.exe');
  assert.equal(flat.CommandLine, '"C:\\Users\\user\\AppData\\Local\\Temp\\46F399~1\\target.exe" /S');

  const multi = parseEvent(EVENT_RENAMED_NETSH).event;
  assert.equal(multi.OriginalFileName, 'netsh.exe');

  const json = parseEvent('{"Event":{"EventData":{"Image":"a.exe","OriginalFileName":"b.exe"}}}').event;
  assert.equal(json.Image, 'a.exe');
  assert.equal(json.OriginalFileName, 'b.exe');

  assert.ok(parseEvent('{not json').error);
});

test('a value containing a colon survives parsing', () => {
  const ev = parseEvent('Image: C:\\Windows\\cmd.exe').event;
  assert.equal(ev.Image, 'C:\\Windows\\cmd.exe');
});

/* ------------------------------------------------------------------ *
 * Bad input must produce a message, never a crash or a false verdict
 * ------------------------------------------------------------------ */

test('malformed input is reported, not thrown', () => {
  for (const [rule, ev] of [
    ['', ''],
    ['title: t', ''],
    ['title: t\ndetection:\n  sel:\n    A: 1\n', ''],
    ['::::not yaml::::', 'A: 1'],
    ['title: t\ndetection:\n  condition: sel\n', 'A: 1'],
  ] as [string, string][]) {
    const t = evaluate(rule, ev);
    assert.equal(typeof t.alert, 'boolean');
    assert.ok(t.errors.length > 0 || t.warnings.length > 0, `expected a message for: ${JSON.stringify(rule)}`);
  }
});

test('an empty event never produces an alert by accident', () => {
  assert.equal(evaluate(RULE_ORIGINAL, '').alert, false);
});
