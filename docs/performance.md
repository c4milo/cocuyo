# Performance work in cocuyo

The method every performance change follows is pepegrillo's
[docs/performance.md](https://github.com/c4milo/pepegrillo/blob/main/docs/performance.md), at the
commit `build.zig.zon` pins; read it first. This appendix is what that method leaves to the project:
cocuyo's instruments, its admission rule, its baselines and the pitfalls it has paid for.

## The instruments

- The judge is `zig build bench`, the microbenchmarks of design §15 step 7, built ReleaseSafe
  whatever `-Drelease` says, on the machine written down beside the numbers; `zig build test`
  compiles the bench and runs the harness's own tests.
- `zig build bench-cares` runs the same two operations against the installed c-ares, the
  comparison the design measures against.
- A laptop run is a filter: it orders candidates and never lands in a document. A number recalled
  rather than measured says so where it appears (CLAUDE.md).
- The units of work are a query, a message decoded or encoded, and a cache operation.

## The admission rule

The shared rule: a change stays when it wins past the noise in `zig build bench`'s numbers and no
operation loses past the noise; the losses come first in the report, with the message's size beside
every speed.

## The baselines

c-ares, through `zig build bench-cares`, is a number and an oracle, never a design: cocuyo is written
from the RFCs, and a baseline's source is not read.

## Pitfalls this tree has paid for

None recorded yet. The first performance change that pays one adds it here, as symptom, cause and
rule.

## Commands

```bash
zig build bench
zig build bench-cares
```
