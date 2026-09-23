//! What a consumer does to a whole engine (docs/design.md §19 step 13): ending every lookup at
//! once, which is `ares_cancel`, and taking a new configuration, which is `ares_reinit`. Free
//! functions over the engine, split out of `io.zig` so each is scored on its own.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const drive_module = @import("io_drive.zig");
const tcp = @import("io_tcp.zig");
const send_module = @import("io_send.zig");

/// Settles every lookup as cancelled, which is `ares_cancel`. Each failure comes through
/// `take` like any other, so the caller learns of all of them.
pub fn cancel_all(self: anytype, now_ns: u64) void {
    for (self.slots[0..], 0..) |*slot, index| {
        if (!slot.occupied) continue;
        if (self.resolver.lookup_of(self.handles[index]).is_settled()) continue;
        self.resolver.cancel(self.handles[index]);
    }
    drive_module.drive(self, now_ns);
}

/// A new configuration, which is `ares_reinit`: the cache is emptied because its answers
/// came from servers that may be gone, the streams are closed, and the sockets are opened
/// again on the new servers.
///
/// The engine must be idle: a lookup in flight was started against servers that are
/// going away, and its handle would name a slot the new table has never heard of. A
/// caller with lookups in flight calls `cancel_all` and takes their failures first, which
/// is what tells it what it lost.
pub fn reinit(self: anytype, config: *const cocuyo.Config, seed: u64, now_ns: u64) @TypeOf(self.*).InitErrorType!void {
    config.assert_valid();
    assert(self.resolver.in_flight() == 0);
    _ = now_ns;
    tcp.cancel_all(self);
    tcp.close_all(self);
    self.tcp_connection = @splat(null);
    self.sockets.cancel(self.loop);
    self.sockets.close();
    self.config = config;
    self.resolver = cocuyo.Resolver.init(&self.slots, &self.keys, config, seed);
    self.cache = cocuyo.Cache.init(&self.cache_slots, &self.cache_keys, seed, cocuyo.cache.constants.ttl_seconds_max_default);
    // A send the old table made keeps its buffer until its final event, which then speaks for
    // nobody (the stream's rules 6 and 7).
    send_module.forget_all(self);
    self.reported = @splat(false);
    self.results = .{};
    self.last_taken = null;
    try self.sockets.open(self.loop, config, seed, @TypeOf(self.*).tag);
}
