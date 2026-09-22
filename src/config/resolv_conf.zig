//! config: the `resolv.conf` parser. It takes bytes rather than a path, because the caller reads
//! the file, and it produces a `core.Config` — a `core` type, so the state machine depends on the
//! values and never on the file format (docs/design.md §10).
//!
//! Step 5 of §15 fills this module.
const core = @import("core");

test {
    _ = core;
}
