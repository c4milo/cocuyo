//! resolver: the state machine. `Lookup` drives one lookup and `Resolver` holds a bounded table of
//! them plus the code that decides which lookup an inbound datagram belongs to (docs/design.md §5
//! and §7).
//!
//! It reads `core` and `wire` and nothing else. It cannot reach the config parser: the state
//! machine takes a server list and a search list, whoever produced them, and
//! `zig build graph-check` is what shows the compiler enforces that.
//!
//! Steps 3 and 4 of §15 fill this module.
const core = @import("core");
const wire = @import("wire");

test {
    _ = core;
    _ = wire;
}
