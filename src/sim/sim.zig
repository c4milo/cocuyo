//! sim: the deterministic harness. A scripted server and a virtual clock, driven by one seed, so
//! every state and every transition of docs/design.md §5 can be reached without a network.
//!
//! It is test-only. Nothing a consumer imports reaches it (docs/design.md §2).
//!
//! Step 3 of §15 fills this module.
const core = @import("core");
const wire = @import("wire");
const resolver = @import("resolver");

test {
    _ = core;
    _ = wire;
    _ = resolver;
}
