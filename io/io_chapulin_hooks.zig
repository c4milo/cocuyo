//! chapulin's hook: the one function a chapulin object leaves to the image that links it,
//! `ch_assert_fail`. The owner ruled on 2026-09-24 that an image defines it once, for every chapulin
//! object and every user of chapulin it links, and that it is safe to call from several threads at
//! once (docs/design.md §21, §24; chapulin's docs/porting.md).
//!
//! So it lives here, in a module of its own that the image binds, rather than in cocuyo's sessions.
//! An image that binds its own module with this surface in place of this one gets no second
//! definition.
//!
//! chapulin's other hook, `ch_rand_bytes`, went with colibri#71: colibri's objects are built
//! `RAND=session`, and each session draws from the source its caller hands colibri's `start`. The
//! owner ruled on 2026-09-27 that this module drops it, with the `enter` and `leave` that pointed
//! it at a stream.
const std = @import("std");

/// A chapulin assertion that failed: a programmer's error in chapulin or in its caller, which stops
/// the program as cocuyo's own assertions do (CLAUDE.md non-negotiable 3).
export fn ch_assert_fail(condition: [*:0]const u8, file: [*:0]const u8, line: c_int) noreturn {
    std.debug.panic("chapulin: {s} at {s}:{d}", .{ condition, file, line });
}
