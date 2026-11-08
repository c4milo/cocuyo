//! The sizes an engine's options give its arrays. Split from `io.zig` by the file-length rule.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const Options = @import("io.zig").Options;
const constants = @import("constants.zig");

/// `count` with a QUIC transport, and none without one: that engine holds no QUIC connection.
pub fn with_quic(comptime options: Options, comptime count: usize) usize {
    return if (options.quic.enabled) count else 0;
}

/// A request slot holds a DoQ message at its longest, prefix and all (request rule 3).
pub fn check_transports(comptime options: Options) void {
    assert(!options.quic.enabled or options.quic.request_bytes_max >= cocuyo.limits.query_bytes_max);
}

/// `count`, for an engine with a request transport or a channel type, and none without: such an
/// engine holds no request slot and no answer buffer.
pub fn with_requests(comptime options: Options, comptime count: usize) usize {
    return if (options.quic.enabled or options.doh.enabled) count else 0;
}

/// `count`, for an engine with a channel type, and none without.
pub fn with_doh(comptime options: Options, comptime count: usize) usize {
    return if (options.doh.enabled) count else 0;
}

/// The longest request a slot holds: what the QUIC transport asks, and a DNS message over a
/// channel, whose GET the channel builds (rule 21).
pub fn request_bytes_of(comptime options: Options) usize {
    const channel_bytes = if (options.doh.enabled) cocuyo.limits.query_bytes_max else 0;
    return @max(options.quic.request_bytes_max, channel_bytes);
}

/// The request slots of the pool: the caller's, or 2 × `lookups`, and never fewer than `lookups`,
/// so each lookup's current request has a slot (docs/design.md §24, request rule 3).
pub fn request_slots(comptime options: Options) usize {
    const slots: usize = options.requests orelse constants.requests_per_lookup_default * @as(usize, options.lookups);
    if (slots < options.lookups) @compileError("an engine needs a request slot for each lookup");
    return slots;
}
