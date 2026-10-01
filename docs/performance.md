# Performance work in cocuyo

The method every performance change follows is pepegrillo's `docs/performance/`: `zig build guide`
installs it, at the commit `build.zig.zon` pins, to `zig-out/docs/performance/`; read its
`performance.md` first. This appendix is what that method leaves to the project: cocuyo's
instruments, its admission rule in numbers, the unit that waits on I/O, its baselines, its costs and
the pitfalls it has paid for. Where the method asks for a number cocuyo has not measured, this says
so.

## The instruments

- The judge is `zig build bench`, the microbenchmarks of design §15 step 7, built ReleaseSafe
  whatever `-Drelease` says, on the machine written down beside the numbers; `zig build test`
  compiles the bench and runs the harness's own tests. A run takes 21 samples of each case after
  one untimed warm-up, and reports the fastest, the median and the ninetieth percentile.
- Design §11's numbers are the judge's, from an Apple M1 Pro under macOS 26.6.2. The laptop was
  in ordinary use: those numbers predate the method's rule that time counts only on a machine
  running nothing else.
- cocuyo has no Linux judge. On Linux every `memset` a Zig 0.16 program calls is compiler_rt's,
  which stores one byte at a time, so `bench` and `bench-cares` export one of their own there
  (`bench/memset.zig`), as the method's `performance_zig.md` prescribes in "Copies and fills".
  c-ares keeps glibc's: the program's `memset` takes the hidden visibility of compiler_rt's, which
  it replaces, and stays out of the dynamic symbol table. `bench/count.zig` exports none, so its
  counts include a fill at the cost a consumer's Zig 0.16 program pays for it. A number from macOS
  says nothing of Linux.
- `zig build bench-cares` runs the same two operations against the installed c-ares, the
  comparison the design measures against.
- The check on every commit is a count, not a time. `zig build instructions` holds each case of
  `bench/count.zig`, the benchmark's own cases, to the instructions one operation takes, in
  `bench/instructions.zon`, through pepegrillo's `instructions` tool under cachegrind on CI's Linux
  runner. A count moves only when the code does, so a move past 2% fails the commit, and a move that
  is meant writes the counts anew and says why. A count sees neither a cache miss nor a mispredict,
  so the judge still decides a speed.
- The filter is a run of a case or two on the developer's machine: it orders candidates in a
  minute, and its numbers never land in a document. A number recalled rather than measured says
  so where it appears (CLAUDE.md).
- The units of work are a query, a message decoded or encoded, a cache operation, a lookup
  through the engine, which waits on I/O, and a lookup the engine's cache answers, which does not.

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

The end-to-end comparison of design §11 (`bench/end_to_end/`) offers its loads on a schedule:
10,000, 40,000, 80,000 and 160,000 lookups a second, each sent when it is due whether or not the
stack has answered, with at most 128 out. Its constants say why those rates. A lookup's latency
runs from when it was due to its result. A row reports:

- the median, the 99th and the 99.9th percentile, and the slowest lookup, from 20,000 a row, which
  put the 99.9th percentile at the twentieth slowest;
- how late the 99th percentile of lookups went out: the driver's part of the latency, from the
  timer that woke it or a wait for room;
- the most out at once, and the failures;
- the system calls and context switches of the stack's process per lookup, which the responder's
  own process keeps out of. macOS counts both. Linux counts system calls only for a tracer, which
  stops the process at every call, so a row there gives the switches alone. macOS counts every
  switch as involuntary, so a wakeup is not told apart from a preemption.

A last row asks 64 names in turn, each asked and answered once before it, so that both stacks'
caches answer every lookup, and it counts the hits. A hit waits on no I/O, so the row is timed as
the microbenchmarks are: one lookup at a time, back to back, from its start to its result, in
microseconds to the nanosecond.

Its numbers wait for a quiet machine (c4milo/cocuyo#5).

## The baselines

c-ares, through `zig build bench-cares`, is a number and an oracle, never a design: cocuyo is written
from the RFCs, and a baseline's source is not read.

## The costs

The table the method asks for is not measured yet. Design §11 has one row of the kind: the slot
restore, a copy of 3,048 bytes, at a median of 43.0 ns on the judge. It gives a memory access on
that machine as on the order of a hundred nanoseconds, a figure recalled and not measured.

## Costs held at zero

Some costs on the hot paths are none today, and a change that makes one of them some is a step,
which an exact check catches where no timing can (c4milo/cocuyo#35):

- A cache hit makes no system call and never blocks. The comparison's tests run n hits and 2n hits
  through the engine over rotor and require the kernel's counts not to grow: system calls on macOS,
  the switches of a thread that blocked on Linux.
- The hot paths' ReleaseSafe code, the library's and the engine's over rotor, calls `memset` or
  `bzero` only where `tools/fill_check/fill_check.zig` knows it does. `zig build fill-check`, in
  the gate, reads the code for x86-64 Linux and arm64 macOS. What it knows are two fills made on
  purpose, the zeros of the EDNS padding and `Lookup.init`, which builds a whole lookup to hand
  back by value, and two of rotor's that no lookup pays: on Linux its choice of backend, once a
  process, and on macOS the early flush of a full changelist. The fills c4milo/cocuyo#34 found, of
  the answers' storage, are gone (design §16, decision 34), and so are the engine's 66,168 bytes
  at every opening and shut of a TCP connection (design §19 step 13, the stream's rule 10). It
  reads the benchmark programs' own `memset` too, which calls none: in a program that exports it,
  a loop the compiler turned into a call to `memset` would call itself forever.
- Nothing allocates: the heap lint (CLAUDE.md, non-negotiable 2).

## Pitfalls this tree has paid for

None recorded yet. The first performance change that pays one adds it here, as symptom, cause and
rule.

## Commands

```bash
zig build guide
zig build bench
zig build bench-cares
zig build fill-check
zig build instructions
```
