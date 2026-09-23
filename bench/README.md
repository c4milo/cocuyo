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

The same step then runs the comparison end to end (`bench/end_to_end/`): one responder thread on
the loopback answers every query with one A record, and each stack resolves 20,000 distinct
names against it with 1, 16 and 128 lookups in flight. cocuyo's side is the engine of design §19
step 13 over rotor, built privately for the bench; c-ares's is the installed build with its
event thread. The rows are lookups per second, and the median and 99th-percentile latency. The
numbers live in §11 of the design document, with the machine and the day.

## A real DNS log

```bash
zig build bench-log -- <dataset.csv>
```

The cache, its policy models and the optimal replayed over a real resolver's log, as design §18
describes. The log is not in this tree: at 8.25 GB it is too big for it, and its source keeps it.
It is "DNS Exfiltration Dataset" by Kristijan Ziza, Pavle Vuletić and Predrag Tadić, version 3,
on Mendeley Data (doi:10.17632/c4n7fckkz3.3), licensed CC BY 4.0. The replay reads its
`dataset.csv` and nothing else. Fetch it, then check it is the file the numbers in §18 came from:

```bash
curl -L -o dataset.csv https://data.mendeley.com/public-files/datasets/c4n7fckkz3/files/e0677d33-6dd8-4bf7-b419-568a8973b754/file_downloaded
```

```bash
shasum -a 256 dataset.csv
```

The digest must be `f1bacba18d109f9f7017f08b7e14a8cf591c9d57b8c4ba79f50f3c657403cdec`, and the
size 8,252,974,842 octets. The replay reads the first five columns of each row alone.

A copy trimmed to those five columns, every row kept and compressed with zstd, is the asset of this
repository's `bench-data-1` release, in case the source moves. It is shared under the same
CC BY 4.0 license. The asset is 293,497,189 octets with SHA-256
`ffaf3b2a638628e7f1abb924749128d6dbd2ddc6601454e4bddfe06080df4420`:

```bash
gh release download bench-data-1 --repo c4milo/cocuyo
```

```bash
zstd -d dns-exfiltration-dataset-v3-5col.csv.zst -o dataset.csv
```
