//! The `stdx.crypto.Context` that the tests of `io/` take (docs/design.md §16 decision 48, as
//! amended on 2026-11-26). Since stdx v0.4.0, `stdx.crypto.init` alone makes one, and colibri
//! names the type but not the call. So the tests of `io/` import this module, and this module
//! imports stdx.
//!
//! It is a module of its own, rooted outside `io/`, so `zig build graph-check` can tell it from the
//! library: a walk from a test's root module reads no import of it, and a module that a consumer
//! imports must not reach it (`build/graph_check_packages.zig`). `build/crypto_context.zig` gives
//! it to the tests' root modules alone.
const std = @import("std");
const stdx = @import("stdx");

/// The context that colibri's TLS takes.
pub const Context = stdx.crypto.Context;
/// The CPU's features, which the context holds.
pub const CpuFeatures = stdx.platform.CpuFeatures;

/// The context of `features` that draws from `random`, as a program makes it once.
pub fn init(features: CpuFeatures, random: std.Random) Context {
    return stdx.crypto.init(features, random);
}
