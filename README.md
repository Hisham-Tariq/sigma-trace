# Sigma Trace

Paste a Sigma rule. Paste a log event. See exactly why it matched — field by field,
block by block, condition and all.

**Everything runs in your browser. No log ever leaves your machine.** There is no
server, no upload, and no account. Share links carry their state in the URL fragment,
which browsers never send anywhere.

Unofficial. Not affiliated with SigmaHQ.

## What it shows

- which field matched which value, highlighted on both sides
- each block's truth value, and every field check inside it
- the `condition:` line as a tree, with a value on every node
- **blocks the condition never references** — valid YAML that silently does nothing
- modifiers this version does not implement, named rather than guessed

## Run it

```sh
npm install
npm test        # the evaluator suite — no framework, Node runs the TypeScript directly
npm run dev     # http://localhost:4321
npm run build   # static output in dist/
```

Node 24+ (the tests rely on native type stripping).

## How it is checked

The test suite does not assert what this code thinks is reasonable. It asserts the
verdicts that Nextron's `evtx-sigma-checker` produced against the public Windows
baselines on 21 Aug 2026, for SigmaHQ rule
`36480ae1-a1cb-4eaa-a0d6-29801d7e9142`:

| Rule state | Real harness | This evaluator |
|---|---|---|
| unfixed, Ninite/WinRAR event | 1 match | ALERT |
| with the filter added and wired | 0 | NO ALERT |
| filter deliberately broken | 1 | ALERT |
| the rule's own regression sample | 1 | ALERT |

Backslash and wildcard semantics are pinned to two real corpus rules rather than to
anyone's memory of the specification.

## Not implemented yet

`base64` · `base64offset` · `utf16` · `cidr` · `expand` · correlation rules ·
aggregations (`| count() > N`).

These are **reported on screen**, never silently treated as a mismatch.

## Licence

MIT.
