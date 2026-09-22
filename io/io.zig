//! The driver of docs/design.md §19 step 13: the state machine, the cache, and the sockets and
//! timers under them, driven by a completion loop with rotor's surface. `zig build test-io`
//! compiles it against the deterministic twin of `src/sim/`, which is where its tests run and
//! how the gate drives every path of the library from a seed. It is not exported, and nothing
//! binds it to rotor itself: the owner held that back on 2026-09-22 until a consumer asks for
//! it, and the build's `rotor` import is the one place that would change.
//!
//! The engine is a struct sized at compile time by its `Options`: the lookups it holds, the
//! cache's slots, the buffers of its datagram group. Nothing here allocates; the caller declares
//! one and calls `init` on it in place, because `Resolver` and the loop hold pointers into it.
//!
//! What the caller does with it: `start` a question, hand every event of its `tick` to `apply`,
//! and `take` the results. `now_ns` is the caller's clock on every call, as it is on every call
//! into cocuyo (CLAUDE.md non-negotiable 4).
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
pub const constants = @import("constants.zig");
const udp = @import("io_udp.zig");
const results_module = @import("io_results.zig");
const drive_module = @import("io_drive.zig");
const events_module = @import("io_events.zig");

pub const Options = struct {
    lookups: u16 = constants.lookups_default,
    cache_slots: u16 = constants.cache_slots_default,
    tag: u16 = constants.tag_default,
    group_buffers: u16 = constants.group_buffers_default,
};

pub const InitError = error{ SocketFailed, ReceiveFailed };

/// What one of the engine's `user_data` values says.
pub const Kind = enum(u8) { udp_send, udp_receive, timer };

pub fn Engine(comptime options: Options) type {
    return struct {
        const Self = @This();

        pub const Result = results_module.Result;
        pub const Started = union(enum) {
            /// A lookup is on its way; its result comes through `take`.
            lookup: cocuyo.Handle,
            /// The cache had it, answered or negative. Valid until the next call on the engine.
            hit: cocuyo.Hit,
        };

        loop: *rotor.Loop,
        config: *const cocuyo.Config,
        resolver: cocuyo.Resolver,
        slots: [options.lookups]cocuyo.Slot,
        keys: [keys_for(options.lookups, cocuyo.resolver.constants.keys_per_slot_min)]cocuyo.MatchKey,
        cache: cocuyo.Cache,
        cache_slots: [options.cache_slots]cocuyo.cache.Slot,
        cache_keys: [keys_for(options.cache_slots, cocuyo.cache.constants.keys_per_slot_min)]cocuyo.cache.Key,
        /// One handle per slot, kept so an event's index finds its lookup.
        handles: [options.lookups]cocuyo.Handle,
        /// Whether a send is queued for the slot and not yet completed: the lookup is polled but
        /// not sent again meanwhile (rotor decision 5, rule 3).
        send_in_flight: [options.lookups]bool,
        /// Whether the slot's end was handed to `results` already.
        reported: [options.lookups]bool,
        send_buffers: [options.lookups][cocuyo.constants.query_bytes_max]u8,
        outbounds: [options.lookups]rotor.datagram.Outbound,
        sockets: udp.Sockets,
        group: udp.Group(options.group_buffers),
        results: results_module.Queue(options.lookups),
        /// The result handed out last, whose slot is freed at the next `take`.
        last_taken: ?cocuyo.Handle,
        timer_handle: ?rotor.Handle,
        timer_due_ns: ?u64,
        /// Which timer is the current one: the index of its `user_data`, raised each time one is
        /// armed, so the canceled end of a timer the deadline moved away from is told from the
        /// current timer's fire (rotor decision 5, rule 2: a cancel answers through the
        /// target's own final event, which arrives after the new timer is armed).
        timer_generation: u32,
        scratch: [cocuyo.constants.query_bytes_max]u8,
        closing: bool,

        /// The key table a slot table needs: the load factor its owner asks, at a power of two.
        fn keys_for(count: usize, per_slot: usize) usize {
            return std.math.ceilPowerOfTwoAssert(usize, count * per_slot);
        }

        /// The high bits of every `user_data` this engine submits.
        pub const tag = options.tag;

        /// The operations and entries a loop needs for this engine: what `Loop.Options` takes.
        pub const loop_operations = @as(u32, options.lookups) + cocuyo.constants.servers_max + constants.loop_operations_slack;

        pub fn init(self: *Self, loop: *rotor.Loop, config: *const cocuyo.Config, seed: u64, now_ns: u64) InitError!void {
            config.assert_valid();
            self.loop = loop;
            self.config = config;
            self.resolver = cocuyo.Resolver.init(&self.slots, &self.keys, config, seed);
            self.cache = cocuyo.Cache.init(&self.cache_slots, &self.cache_keys, seed, cocuyo.cache.constants.ttl_seconds_max_default);
            self.send_in_flight = @splat(false);
            self.reported = @splat(false);
            self.results = .{};
            self.last_taken = null;
            self.timer_handle = null;
            self.timer_due_ns = null;
            self.timer_generation = 0;
            self.closing = false;
            try self.group.provide(loop);
            try self.sockets.open(loop, config, seed, options.tag);
            _ = now_ns;
        }

        /// Ends every receive and the timer. The caller drains the loop, then calls `close`.
        pub fn deinit(self: *Self) void {
            self.closing = true;
            self.resolver_cancel_all();
            if (self.timer_handle) |handle| self.loop.cancel(handle);
            self.timer_handle = null;
            self.sockets.cancel(self.loop);
        }

        /// Closes the sockets, once the loop has drained (rotor decision 5, rule 4).
        pub fn close(self: *Self) void {
            assert(self.closing);
            self.sockets.close();
        }

        fn resolver_cancel_all(self: *Self) void {
            for (self.slots[0..], 0..) |*slot, index| {
                if (!slot.occupied) continue;
                self.resolver.cancel(self.handles[index]);
            }
        }

        /// Asks the cache, then the table. A hit is answered here; a lookup's result comes
        /// through `take`.
        pub fn start(self: *Self, question: cocuyo.Question, now_ns: u64) error{Full}!Started {
            assert(!self.closing);
            if (self.cache.get(&question, now_ns)) |hit| return .{ .hit = hit };
            const handle = self.resolver.start(question) catch return error.Full;
            self.handles[handle.index] = handle;
            self.send_in_flight[handle.index] = false;
            self.reported[handle.index] = false;
            drive_module.drive(self, now_ns);
            return .{ .lookup = handle };
        }

        /// Settles the lookup as cancelled; its failure comes through `take` like any other.
        pub fn cancel(self: *Self, handle: cocuyo.Handle, now_ns: u64) void {
            self.resolver.cancel(handle);
            drive_module.drive(self, now_ns);
        }

        pub fn active(self: *const Self) usize {
            return self.resolver.in_flight();
        }

        /// One completion event. True when it was the engine's, in which case the engine has
        /// acted on it; false hands it back to the caller untouched.
        pub fn apply(self: *Self, event: rotor.Event, now_ns: u64) bool {
            return events_module.apply(self, event, now_ns);
        }

        /// Polls the table for what every lookup wants and does it: a send queued, an end handed
        /// to `results`, and the timer moved to the soonest deadline.
        pub fn drive(self: *Self, now_ns: u64) void {
            drive_module.drive(self, now_ns);
        }

        /// The result ready first, or null. The slot of the result taken before is freed here,
        /// so a result's slices are valid until the next `take`.
        pub fn take(self: *Self, now_ns: u64) ?Result {
            _ = now_ns;
            if (self.last_taken) |handle| {
                self.resolver.release(handle);
                self.last_taken = null;
            }
            const result = self.results.pop() orelse return null;
            self.last_taken = result.handle;
            return result;
        }

        pub fn user_data(kind: Kind, index: usize) u64 {
            assert(index <= constants.index_mask);
            return (@as(u64, options.tag) << constants.tag_shift) |
                (@as(u64, @intFromEnum(kind)) << constants.kind_shift) | index;
        }
    };
}

test {
    _ = udp;
    _ = results_module;
    _ = drive_module;
    _ = events_module;
    // The tests drive the engine on the twin, which is the only `rotor` that has scripts.
    if (comptime @hasDecl(rotor, "server")) _ = @import("io_sim_test.zig");
}
