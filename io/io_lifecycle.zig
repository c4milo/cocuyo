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
    cancel_every(self);
    drive_module.drive(self, now_ns);
}

/// Cancels every lookup in the table. One that has ended keeps its end (`Resolver.cancel`).
pub fn cancel_every(self: anytype) void {
    for (self.slots[0..], 0..) |*slot, index| {
        if (slot.occupied) self.resolver.cancel(self.handles[index]);
    }
}

/// A new table over the engine's slots, and a new cache under it, which is what `init` starts
/// with and what `reinit` starts again with. The cache is put under the table here, so no path
/// builds one without the other (docs/design.md §20). A send the old table made keeps its buffer
/// until its final event, which then speaks for nobody (the stream's rules 6 and 7).
pub fn reset_tables(self: anytype, config: *const cocuyo.Config, seed: u64) void {
    self.resolver = cocuyo.Resolver.init(&self.slots, &self.keys, config, seed);
    self.cache = cocuyo.Cache.init(&self.cache_slots, &self.cache_keys, seed, cocuyo.cache.constants.ttl_seconds_max_default);
    self.resolver.remember_with(cocuyo.remembered_by(&self.cache));
    send_module.forget_all(self);
    self.reported = @splat(false);
    self.results = .{};
    self.last_taken = null;
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
    // No TLS yet (docs/design.md §21 step 5): see `Engine.init`.
    assert(!config.uses_tls());
    assert(self.resolver.in_flight() == 0);
    _ = now_ns;
    tcp.cancel_all(self);
    tcp.close_all(self);
    self.tcp_connection = @splat(null);
    self.sockets.cancel(self.loop);
    self.sockets.close();
    self.config = config;
    reset_tables(self, config, seed);
    try self.sockets.open(self.loop, config, seed, @TypeOf(self.*).tag);
}
