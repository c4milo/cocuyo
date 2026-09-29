# Performance work in cocuyo

The method every performance change follows is pepegrillo's `docs/performance.md`: `zig build
guide` installs it, at the commit `build.zig.zon` pins, to `zig-out/docs/performance-method.md`;
read it first. This appendix is what that method leaves to the project: cocuyo's instruments, its
admission rule in numbers, the unit that waits on I/O, its baselines, its costs and the pitfalls it
has paid for. Where the method asks for a number cocuyo has not measured, this says so.

## The instruments

- The judge is `zig build bench`, the microbenchmarks of design §15 step 7, built ReleaseSafe
  whatever `-Drelease` says, on the machine written down beside the numbers; `zig build test`
  compiles the bench and runs the harness's own tests. A run takes 21 samples of each case after
  one untimed warm-up, and reports the fastest, the median and the ninetieth percentile.
- Design §11's numbers are the judge's, from an Apple M1 Pro under macOS 26.6.2. The laptop was
  in ordinary use: those numbers predate the method's rule that time counts only on a machine
  running nothing else.
- cocuyo has no Linux judge. On Linux every `memset` in a Zig executable stores one byte at a
  time (the method, "Copies and fills"), and the lookup and the cache fill kilobytes through it in
  ReleaseSafe (c4milo/cocuyo#34). A number from macOS says nothing of those paths on Linux.
- `zig build bench-cares` runs the same two operations against the installed c-ares, the
  comparison the design measures against.
- The filter is a run of a case or two on the developer's machine: it orders candidates in a
  minute, and its numbers never land in a document. A number recalled rather than measured says
  so where it appears (CLAUDE.md).
- The units of work are a query, a message decoded or encoded, a cache operation, and a lookup
  through the engine, which waits on I/O.

## The admission rule

The method's rule, in cocuyo's numbers:

- A number is the median of five runs of the judge, with its spread: the slowest run less the
  fastest, over the median.
- The floor is 2%, the run-to-run band design §11 measured on the judge and calls the harness's
  precision. An input's noise is the larger of its spread and the floor.
- A change stays when a case wins past the noise in every one of at least two paired jobs, each
  measuring the base and the change in one run, and no case loses past the noise in any job. The
  losses come first in the report, with the message's size beside every speed.
- The layout noise on the judge is a fifth of a row: design §11 measured the parse of one A record
  at 42.8, 45.0 and 52.7 ns in three binaries with the same code on its path. A win smaller than a
  fifth must hold on a second CPU model too.
- cocuyo has no ruled exception: runtime safety stays on everywhere, and there is no assembly.

## The lookup through the engine

The end-to-end comparison of design §11 (`bench/end_to_end/`) offers its load as a count of
lookups in flight, 1, 16 and 128, from a driver that starts a lookup when one ends, and reports the
median and the 99th percentile. The method asks for two things it does not do yet:

- A generator that sends on a schedule. A driver that waits for each lookup to end sends nothing
  while the engine stalls, so its percentiles leave the stall out.
- The 99.9th percentile and the maximum, beside the median and the 99th.

## The baselines

c-ares, through `zig build bench-cares`, is a number and an oracle, never a design: cocuyo is written
from the RFCs, and a baseline's source is not read.

## The costs

The table the method asks for is not measured yet. Design §11 has one row of the kind: the slot
restore, a copy of 3,048 bytes, at a median of 43.0 ns on the judge. It gives a memory access on
that machine as on the order of a hundred nanoseconds, a figure recalled and not measured.

## Pitfalls this tree has paid for

None recorded yet. The first performance change that pays one adds it here, as symptom, cause and
rule.

## Commands

```bash
zig build guide
zig build bench
zig build bench-cares
```
