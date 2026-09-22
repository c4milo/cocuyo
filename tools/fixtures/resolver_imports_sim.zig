//! Check fixture for tools/graph_check.zig. Compiled as the root of a module carrying exactly the
//! import set build/modules.zig gives `resolver`; the compile MUST fail, because the harness reads
//! the state machine and is never read back (docs/design.md §2).
//!
//! The import sits in a `comptime` block on purpose. Zig analyses lazily, so an unreferenced
//! `const x = @import("sim");` compiles clean and the check would pass while proving nothing.
comptime {
    _ = @import("sim");
}
