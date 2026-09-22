//! Check fixture for tools/graph_check.zig. Compiled as the root of a module carrying exactly the
//! import set build/modules.zig gives `resolver`; the compile MUST fail, because docs/design.md §2
//! keeps the config parser out of that set.
//!
//! The import sits in a `comptime` block on purpose. Zig analyses lazily, so an unreferenced
//! `const x = @import("config");` compiles clean and the check would pass while proving nothing.
comptime {
    _ = @import("config");
}
