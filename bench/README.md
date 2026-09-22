# bench

The microbenchmarks of [docs/design.md](../docs/design.md) §15 step 7: what one query build,
one response parse and one datagram match cost, in nanoseconds per operation.

```bash
zig build bench
```

The numbers, the machine they were measured on and the method are in §11 of the design document,
which is the only place a number is recorded: a table here would be a second copy to keep true.
The rule the numbers live under is the one every document in this tree follows — a number that
was recalled rather than measured says so where it appears, and a number measured here says what
produced it.

Every case is built ReleaseSafe whatever `-Drelease` says, because that is the mode cocuyo ships
in. `zig build test` compiles the bench and runs the harness's own tests, so a bench that stopped
compiling, or a case that stopped doing what its name says, fails the gate.

## Against c-ares

```bash
zig build bench-cares
```

The same two operations — a query build and a response parse — against the c-ares installed on
the machine, found under `-Dcares=<prefix>` and Homebrew's by default. The datagram match has no
counterpart: c-ares decides whose datagram it is inside its own event loop, which is the thing
cocuyo was split to avoid. This step links a library the gate must not require, so nothing of it
runs under `zig build test`; its own tests, which show c-ares writes the same query bytes cocuyo
does, run first under the step and alone under `zig build test-cares`.
