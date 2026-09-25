//! The driver of docs/design.md §19 step 13: the state machine, the cache, and the sockets and
//! timers under them, driven by a completion loop with rotor's surface. `zig build test-io`
//! compiles it against the deterministic twin of `src/sim/`, which is where its tests run and
//! how the gate drives every path of the library from a seed. It is exported as `cocuyo_rotor`,
//! whose `rotor` import the consumer binds, so it runs on the consumer's loop (docs/design.md
//! §24).
//!
//! The engine is a struct sized at compile time by its `Options`: the lookups it holds, the
//! cache's slots, the buffers of its datagram group. Nothing here allocates; the caller declares
//! one and calls `init` on it in place, because the table, `cocuyo.Resolver`, and the loop hold
//! pointers into it.
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
const tcp = @import("io_tcp.zig");
const results_module = @import("io_results.zig");
const drive_module = @import("io_drive.zig");
const events_module = @import("io_events.zig");
const lifecycle = @import("io_lifecycle.zig");
const send_module = @import("io_send.zig");
const tcp_queue = @import("io_tcp_queue.zig");
pub const tls = @import("io_tls.zig");
/// The request transport's default and the engine's requests (docs/design.md §24).
pub const quic = @import("io_request.zig");
const request_connection = @import("io_request_connection.zig");
const request_events = @import("io_request_events.zig");

pub const Options = struct {
    lookups: u16 = constants.lookups_default,
    cache_slots: u16 = constants.cache_slots_default,
    tag: u16 = constants.tag_default,
    group_buffers: u16 = constants.group_buffers_default,
    /// The TCP connections held at once, and the chunk buffers they read into. None suits an
    /// engine that speaks DoQ alone, which asks for no stream (docs/design.md §24).
    tcp_connections: u16 = constants.tcp_connections_default,
    tcp_group_buffers: u16 = constants.tcp_group_buffers_default,
    /// The longest message one connection can assemble (RFC 7766 §8).
    tcp_message_bytes: u32 = constants.tcp_message_bytes_max,
    /// The TLS session type of docs/design.md §21, the session interface: chapulin's when the
    /// build links it, the twin's in its tests, and `tls.None`, which refuses a TLS configuration.
    tls: type = tls.None,
    /// The QUIC connection type of docs/design.md §24, the request interface: colibri's over
    /// chapulin's QUIC object when the build links them, the twin's in its tests, and
    /// `quic.None`, which refuses a DoQ configuration. A DoQ answer is read into one buffer of
    /// `tcp_message_bytes`, since a DoQ stream holds what a TCP connection holds (RFC 9250 §4.2).
    quic: type = quic.None,
};

pub const InitError = error{ SocketFailed, ReceiveFailed };

/// What one of the engine's `user_data` values says.
pub const Kind = enum(u8) { udp_send, udp_receive, timer, tcp_connect, tcp_send, tcp_receive, tls_send, quic_send, quic_receive };

/// `count`, for an engine with a request transport, and none without: such an engine holds no
/// QUIC connection, no request slot and no answer buffer.
fn with_quic(comptime options: Options, comptime count: usize) usize {
    return if (options.quic.enabled) count else 0;
}

pub fn Resolver(comptime options: Options) type {
    const quic_servers = with_quic(options, cocuyo.constants.servers_max);
    const quic_lookups = with_quic(options, options.lookups);
    const answer_bytes = with_quic(options, options.tcp_message_bytes);
    return struct {
        const Self = @This();

        pub const Result = results_module.Result;
        pub const InitErrorType = InitError;

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
        /// Whether the slot's send buffer is lent to the loop: from a send's submission to its
        /// final event, whoever the slot holds meanwhile (rotor decision 5, rule 3).
        send_in_flight: [options.lookups]bool,
        /// The attempt the send in flight speaks for, or null for none the engine still answers
        /// to (`io_send.zig`).
        send_owner: [options.lookups]?send_module.Owner,
        /// A send asked for while the buffer was lent, and its octets, until the buffer is back.
        held: [options.lookups]?send_module.Held,
        held_buffers: [options.lookups][cocuyo.constants.query_bytes_max]u8,
        /// The socket each slot's last datagram left from, which a draining socket stays open
        /// for while the answer is owed (the datagram's rule 4). It outlives the lookup, since a
        /// send in flight from a freed slot still needs its socket.
        sent_from: [options.lookups]?udp.SentFrom,
        /// Whether the slot's end was handed to `results` already.
        reported: [options.lookups]bool,
        send_buffers: [options.lookups][cocuyo.constants.query_bytes_max]u8,
        /// How long the query in each slot's buffer is, for a stream's send that went short.
        send_lengths: [options.lookups]u16,
        outbounds: [options.lookups]rotor.datagram.Outbound,
        sockets: udp.Sockets,
        group: udp.Group(options.group_buffers),
        /// The streams of RFC 7766, and which one each lookup is on (`io_tcp.zig`).
        connections: [options.tcp_connections]tcp.Connection(options.tcp_message_bytes, options.lookups, options.tls),
        tcp_connection: [options.lookups]?u8,
        tcp_group: tcp.Group(options.tcp_group_buffers),
        /// The newest ticket each server's sessions were given, kept for its next connection,
        /// and what every session starts from (docs/design.md §21, TLS rule 8).
        tls_tickets: [cocuyo.constants.servers_max]?tls.Kept(options.tls),
        tls_context: options.tls.Context,
        tcp_idle_ns: u64,
        /// A QUIC connection slot for each server, what the loop borrows from each, and a request
        /// slot for each lookup (docs/design.md §24, request rules 1, 3 and 8).
        quic_connections: [quic_servers]request_connection.Connection(options.quic, options.lookups),
        quic_sends: [quic_servers]request_connection.Send(options.quic),
        requests: [quic_lookups]quic.Request(options.quic),
        /// The newest ticket each server's QUIC connections were given (request rule 10).
        quic_tickets: [quic_servers]?tls.Kept(options.quic),
        quic_context: options.quic.Context,
        quic_idle_ns: u64,
        /// Where a stream's answer is read to, whole, and handed over at once (request rule 5).
        answer: [answer_bytes]u8,
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

        /// The TLS session type, which `io_tls.zig` reads through the engine.
        pub const Tls = options.tls;

        /// Whether the engine keeps any TCP connection. One built for DoQ alone needs none, and
        /// the TCP path then returns at compile time, so nothing indexes an array of none
        /// (c4milo/cocuyo#14). A lookup that asks for a stream is told it failed.
        pub const keeps_tcp = options.tcp_connections != 0;

        /// The QUIC connection type, which `io_request.zig` reads through the engine.
        pub const Quic = options.quic;

        /// What `Loop.Options.operations` needs for this engine: a send per lookup, a receive
        /// per server, a connect and a receive per connection, a receive and a send per QUIC
        /// connection, one timer, and slack.
        pub const loop_operations = @as(u32, options.lookups) + cocuyo.constants.servers_max +
            constants.loop_operations_per_connection * @as(u32, options.tcp_connections) +
            constants.loop_operations_per_quic_connection * @as(u32, quic_servers) +
            constants.loop_operations_slack;

        pub fn init(self: *Self, loop: *rotor.Loop, config: *const cocuyo.Config, seed: u64, now_ns: u64) InitError!void {
            config.assert_valid();
            assert_tls(config);
            self.loop = loop;
            self.config = config;
            self.send_in_flight = @splat(false);
            self.sent_from = @splat(null);
            lifecycle.reset_tables(self, config, seed);
            self.timer_handle = null;
            self.timer_due_ns = null;
            self.timer_generation = 0;
            self.closing = false;
            self.connections = @splat(.{});
            self.tcp_connection = @splat(null);
            self.tcp_idle_ns = constants.tcp_idle_ns_default;
            self.tls_tickets = @splat(null);
            self.tls_context = .{};
            self.quic_connections = @splat(.{});
            self.quic_sends = @splat(.{});
            self.requests = @splat(.{});
            self.quic_tickets = @splat(null);
            self.quic_context = .{};
            self.quic_idle_ns = constants.quic_idle_ns_default;
            self.sockets.reset_generation();
            try self.group.provide(loop);
            try self.tcp_group.provide(loop);
            try self.sockets.open(loop, config, seed, options.tag);
            _ = now_ns;
        }

        /// Ends every receive and the timer. The caller drains the loop, then calls `close`.
        pub fn deinit(self: *Self) void {
            self.closing = true;
            lifecycle.cancel_every(self);
            if (self.timer_handle) |handle| self.loop.cancel(handle);
            self.timer_handle = null;
            self.sockets.cancel(self.loop);
            tcp.cancel_all(self);
            request_connection.cancel_all(self);
        }

        /// Closes the sockets, once the loop has drained (rotor decision 5, rule 4).
        pub fn close(self: *Self) void {
            assert(self.closing);
            self.sockets.close();
            tcp.close_all(self);
            request_connection.close_all(self);
        }

        /// Starts a lookup. Its result comes through `take`, and one the cache already holds is
        /// there by the time this returns: the table asks the cache at the lookup's first poll,
        /// which the drive below makes (docs/design.md §20).
        pub fn start(self: *Self, question: cocuyo.Question, now_ns: u64) error{Full}!cocuyo.Handle {
            assert(!self.closing);
            const handle = self.resolver.start(question) catch return error.Full;
            self.handles[handle.index] = handle;
            // The buffer may still be lent to a send of the lookup the slot held before: it stays
            // lent until that send's final event (the stream's rule 6).
            self.held[handle.index] = null;
            self.reported[handle.index] = false;
            self.tcp_connection[handle.index] = null;
            drive_module.drive(self, now_ns);
            return handle;
        }

        /// A TLS configuration needs an engine that speaks TLS: one without it would carry
        /// cleartext on port 853 (RFC 7858 §3.1). And it needs a connection slot for each of its
        /// servers, since a TLS connection is never closed to make room (§21, TLS rule 6). A DoQ
        /// configuration needs an engine with a request transport (§24).
        pub fn assert_tls(config: *const cocuyo.Config) void {
            // DoH's HTTP/3 is §24 step 5.
            assert(!config.uses_https());
            if (config.uses_quic()) assert(options.quic.enabled);
            if (!config.uses_tls()) return;
            assert(options.tls.enabled);
            assert(config.servers.len <= options.tcp_connections);
        }

        /// What every TLS session starts from (docs/design.md §21): for chapulin, the anchors,
        /// the wall clock and the seed's stream. The twin's needs nothing.
        pub fn use_tls(self: *Self, context: options.tls.Context) void {
            self.tls_context = context;
        }

        /// What every QUIC connection starts from (docs/design.md §24), as `use_tls` says for
        /// TLS. The twin's needs nothing.
        pub fn use_quic(self: *Self, context: options.quic.Context) void {
            self.quic_context = context;
        }

        /// Settles every lookup as cancelled, which is `ares_cancel`. Each failure comes through
        /// `take` like any other, so the caller learns of all of them.
        pub fn cancel_all(self: *Self, now_ns: u64) void {
            lifecycle.cancel_all(self, now_ns);
        }

        /// A new configuration, which is `ares_reinit`. The engine must be idle; `io_lifecycle.zig`
        /// says why and what a caller does first.
        pub fn reinit(self: *Self, config: *const cocuyo.Config, seed: u64, now_ns: u64) InitError!void {
            try lifecycle.reinit(self, config, seed, now_ns);
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

        comptime {
            // A connection's slot shares its `user_data` with its incarnation (`io_tcp.zig`).
            assert(options.tcp_connections <= constants.tcp_slot_mask + 1);
            // A request slot holds a DoQ message at its longest, prefix and all (request rule 3).
            assert(!options.quic.enabled or options.quic.request_bytes_max >= cocuyo.constants.query_bytes_max);
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
    _ = tcp;
    _ = results_module;
    _ = drive_module;
    _ = events_module;
    _ = lifecycle;
    _ = send_module;
    _ = tcp_queue;
    _ = @import("io_tcp_group.zig");
    _ = tls;
    _ = quic;
    _ = request_connection;
    _ = request_events;
    _ = @import("io_tcp_queue_ring.zig");
    // The tests drive the engine on the twin, which is the only `rotor` that has scripts.
    if (comptime @hasDecl(rotor, "server")) {
        _ = @import("io_sim_test.zig");
        _ = @import("io_tcp_test.zig");
        _ = @import("io_lifecycle_test.zig");
        _ = @import("io_tls_test.zig");
        _ = @import("io_request_test.zig");
        _ = @import("io_request_failure_test.zig");
        _ = @import("io_quic_test.zig");
    }
}
