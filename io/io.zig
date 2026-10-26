//! The driver of docs/design.md §19 step 13: the state machine, the cache, and the sockets and
//! timers under them, driven by a completion loop with rotor's surface. `zig build test-io`
//! compiles it against the deterministic twin of `src/sim/`, which is where its tests run and
//! how the gate drives every path of the library from a seed. It is exported as `cocuyo_rotor`,
//! whose `rotor` import the consumer binds, so it runs on the consumer's loop (docs/design.md
//! §24).
//!
//! The engine is a struct sized at compile time by its `Options`: the lookups it holds and the
//! buffers of its datagram group. Nothing here allocates; the caller declares one and calls
//! `init` on it in place, because the table, `cocuyo.Resolver`, and the loop hold pointers into
//! it. The cache's memory is the caller's too, and a second value: `init` and `reinit` are handed
//! its slots and its key index, sized at compile time or at run time, or none for an engine with
//! no cache (docs/design.md §19 step 13, the cache's memory).
//!
//! What the caller does with it: `start` a question, hand every event of its `tick` to `apply`,
//! and `take` the results. `now_ns` is the caller's clock on every call, as it is on every call
//! into cocuyo (CLAUDE.md non-negotiable 4).
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
pub const constants = @import("constants.zig");
pub const limits = @import("limits.zig");
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
/// The channel type's default and the engine's DoH over a channel (docs/design.md §24, DoH over
/// colibri's client).
pub const channel = @import("io_channel.zig");
const channel_link = @import("io_channel_link.zig");
const context_module = @import("io_context.zig");
const request_connection = @import("io_request_connection.zig");
const request_tend = @import("io_request_connection_tend.zig");
const request_events = @import("io_request_events.zig");

pub const Options = struct {
    lookups: u16 = constants.lookups_default,
    tag: u16 = constants.tag_default,
    group_buffers: u16 = constants.group_buffers_default,
    /// The TCP connections held at once, and the chunk buffers they read into. None suits an
    /// engine that speaks DoQ alone, which asks for no stream (docs/design.md §24).
    tcp_connections: u16 = constants.tcp_connections_default,
    tcp_group_buffers: u16 = constants.tcp_group_buffers_default,
    /// The longest message one connection can assemble (RFC 7766 §8).
    tcp_message_bytes: u32 = limits.tcp_message_bytes_max,
    /// The TLS session type of docs/design.md §21, the session interface: chapulin's when the
    /// build links it, the twin's in its tests, and `tls.None`, which refuses a TLS configuration.
    tls: type = tls.None,
    /// The QUIC connection type of docs/design.md §24, the request interface: colibri's over
    /// chapulin's QUIC object when the build links them, the twin's in its tests, and
    /// `quic.None`, which refuses a DoQ configuration. A DoQ answer is read into one buffer of
    /// `tcp_message_bytes` and a prefix, since a DoQ stream holds what a TCP connection holds
    /// (RFC 9250 §4.2).
    quic: type = quic.None,
    /// The channel type of docs/design.md §24, DoH over colibri's client: colibri's
    /// `client.Channel` under `cocuyo_doh` when the build links it, the twin's in its tests, and
    /// `channel.None`, which refuses a DoH configuration (decision 33).
    doh: type = channel.None,
};

/// What `init` and `reinit` return. `UdpPayloadTooLarge` refuses a `Config.udp_payload_bytes` above
/// `limits.udp_payload_bytes_max`. The call then changes nothing (docs/design.md §19 step 13,
/// the datagram's rule 7; §24, What `init` and `reinit` return).
pub const InitError = error{ SocketFailed, ReceiveFailed, UdpPayloadTooLarge };

/// What one of the engine's `user_data` values says.
pub const Kind = enum(u8) { udp_send, udp_receive, timer, tcp_connect, tcp_send, tcp_receive, tls_send, quic_send, quic_receive, doh_connect, doh_send, doh_receive };

/// `count` with a QUIC transport, and none without one: that engine holds no QUIC connection.
fn with_quic(comptime options: Options, comptime count: usize) usize {
    return if (options.quic.enabled) count else 0;
}

/// The table holds 1 to `lookup_slots_max` lookups, which `Resolver.init` asserts. An engine of any
/// other count does not compile, and the error names the bound (docs/design.md §19 step 13, §17
/// question 43).
fn check_lookups(comptime options: Options) void {
    if (options.lookups > 0 and options.lookups <= cocuyo.limits.lookup_slots_max) return;
    @compileError(std.fmt.comptimePrint(
        "an engine holds 1 to {d} lookups, lookup_slots_max, and these Options name {d}",
        .{ cocuyo.limits.lookup_slots_max, options.lookups },
    ));
}

/// A request slot holds a DoQ message at its longest, prefix and all (request rule 3).
fn check_transports(comptime options: Options) void {
    assert(!options.quic.enabled or options.quic.request_bytes_max >= cocuyo.limits.query_bytes_max);
}

/// `count`, for an engine with a request transport or a channel type, and none without: such an
/// engine holds no request slot and no answer buffer.
fn with_requests(comptime options: Options, comptime count: usize) usize {
    return if (options.quic.enabled or options.doh.enabled) count else 0;
}

/// `count`, for an engine with a channel type, and none without.
fn with_doh(comptime options: Options, comptime count: usize) usize {
    return if (options.doh.enabled) count else 0;
}

/// The longest request a slot holds: what the QUIC transport asks, and a DNS message over a
/// channel, whose GET the channel builds (rule 21).
fn request_bytes_of(comptime options: Options) usize {
    const channel_bytes = if (options.doh.enabled) cocuyo.limits.query_bytes_max else 0;
    return @max(options.quic.request_bytes_max, channel_bytes);
}

pub fn Resolver(comptime options: Options) type {
    comptime check_lookups(options);
    const quic_servers = with_quic(options, cocuyo.limits.servers_max);
    const doh_servers = with_doh(options, cocuyo.limits.servers_max);
    const request_lookups = with_requests(options, options.lookups);
    const request_bytes_max = request_bytes_of(options);
    // The stream of a DoQ answer holds the message and its prefix (RFC 9250 §4.2).
    const answer_bytes = with_requests(options, cocuyo.constants.tcp_prefix_bytes + options.tcp_message_bytes);
    comptime check_transports(options);
    return struct {
        const Self = @This();

        pub const Result = results_module.Result;
        pub const InitErrorType = InitError;

        loop: *rotor.Loop,
        config: *const cocuyo.Config,
        resolver: cocuyo.Resolver,
        slots: [options.lookups]cocuyo.Slot,
        keys: [table_keys_for(options.lookups)]cocuyo.MatchKey,
        /// The cache under the table, built over the memory `init` or the last `reinit` was
        /// handed, or null when that was none. The slots and the key index are the caller's.
        cache: ?cocuyo.Cache,
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
        held_buffers: [options.lookups][cocuyo.limits.query_bytes_max]u8,
        /// The socket each slot's last datagram left from, which a draining socket stays open
        /// for while the answer is owed (the datagram's rule 4). It outlives the lookup, since a
        /// send in flight from a freed slot still needs its socket.
        sent_from: [options.lookups]?udp.SentFrom,
        /// Whether the slot's end was handed to `results` already.
        reported: [options.lookups]bool,
        send_buffers: [options.lookups][cocuyo.limits.query_bytes_max]u8,
        /// How long the query in each slot's buffer is, for a stream's send that went short.
        send_lengths: [options.lookups]u16,
        outbounds: [options.lookups]rotor.datagram.Outbound,
        sockets: udp.Sockets,
        group: udp.Group(options.group_buffers),
        /// The streams of RFC 7766, and which one each lookup is on (`io_tcp.zig`).
        connections: [options.tcp_connections]tcp.Connection(options.tcp_message_bytes, options.lookups, options.tls),
        tcp_connection: [options.lookups]?u8,
        /// Whether each lookup waits for a connection slot, on no connection, and how many do
        /// (docs/design.md §19 step 13, the stream's rule 12).
        tcp_waiting: [options.lookups]bool,
        tcp_waiters: u16,
        tcp_group: tcp.Group(options.tcp_group_buffers),
        /// The newest ticket each server's sessions were given, kept for its next connection
        /// (docs/design.md §21, TLS rule 8).
        tls_tickets: [cocuyo.limits.servers_max]?tls.Kept(options.tls),
        /// What every TLS session starts from, or null until `use_tls` names it: the engine has
        /// no context of its own (§16 decision 39). `io_context.zig` is what reads it.
        tls_context: ?options.tls.Context,
        tcp_idle_ns: u64,
        /// The QUIC connections, a slot for each server, and a request slot for each lookup
        /// (docs/design.md §24, request rules 1, 3 and 8).
        quic: request_connection.Set(options.quic, quic_servers, options.lookups),
        /// The channels DoH goes over, a slot for each server (§24, rules 18 to 25).
        doh: channel.Set(options.doh, doh_servers, options.lookups),
        requests: [request_lookups]quic.Request(request_bytes_max),
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
        scratch: [cocuyo.limits.query_bytes_max]u8,
        closing: bool,

        /// The key table the lookups' slots need: the load factor the table asks, at a power of
        /// two. The cache's key index is sized by its caller, with `cocuyo.cache.keys_for`.
        fn table_keys_for(lookups: usize) usize {
            return std.math.ceilPowerOfTwoAssert(usize, lookups * cocuyo.resolver.limits.keys_per_slot_min);
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

        /// The channel type, which `io_channel.zig` reads through the engine.
        pub const Doh = options.doh;

        /// What `Loop.Options.operations` needs for this engine: a send per lookup, a receive
        /// per server, a connect and a receive per connection, a receive and a send per QUIC
        /// connection, one timer, and slack. Its type is written, so the `usize` limits in the
        /// sum do not change it from `u32` (docs/design.md §16 decision 40).
        pub const loop_operations: u32 = @as(u32, options.lookups) + cocuyo.limits.servers_max +
            limits.loop_operations_per_connection * @as(u32, options.tcp_connections) +
            limits.loop_operations_per_quic_connection * @as(u32, quic_servers) +
            limits.loop_operations_per_channel * @as(u32, doh_servers) +
            limits.loop_operations_slack;

        /// Starts the engine on the caller's loop. `cache_memory` is the memory of its cache,
        /// the slots and the key index as `cocuyo.Cache.init` takes them, or null for an engine
        /// with no cache, whose every lookup goes to its servers. The engine builds the cache
        /// over it, keyed by `seed` and capped at `config.cache_ttl_seconds_max`. The memory is
        /// the caller's and this engine's alone, and must stay valid and unmoved until `close`
        /// returns, or until a `reinit` that is handed other memory or none returns
        /// (docs/design.md §19 step 13, the cache's memory). Slices `Cache.init` would refuse
        /// are a programmer error: `cocuyo.cache.slot_count_valid` and `keys_for` say what it
        /// takes. The engine starts with no context for DoT, DoQ or DoH, whatever its memory
        /// held: a consumer that speaks one calls `use_tls`, `use_quic` or `use_doh` next, before
        /// its first lookup (§24, the context a session starts from, rule 4). A
        /// `config.udp_payload_bytes` above `limits.udp_payload_bytes_max` is refused before
        /// anything is written (§19 step 13, the datagram's rule 7).
        pub fn init(
            self: *Self,
            loop: *rotor.Loop,
            config: *const cocuyo.Config,
            cache_memory: ?cocuyo.cache.Slices,
            seed: u64,
            now_ns: u64,
        ) InitError!void {
            config.assert_valid();
            assert_tls(config);
            lifecycle.assert_cache_memory(cache_memory);
            try lifecycle.check_payload(config);
            self.loop = loop;
            self.config = config;
            self.send_in_flight = @splat(false);
            self.sent_from = @splat(null);
            lifecycle.reset_tables(self, config, cache_memory, seed);
            self.timer_handle = null;
            self.timer_due_ns = null;
            self.timer_generation = 0;
            self.closing = false;
            self.connections = @splat(.{});
            self.tcp_connection = @splat(null);
            self.tcp_waiting = @splat(false);
            self.tcp_waiters = 0;
            self.tcp_idle_ns = constants.tcp_idle_ns_default;
            self.tls_tickets = @splat(null);
            // No context, whatever the memory held: the consumer names each after `init`, and a
            // set of connections or of channels starts with none (§16 decision 39).
            self.tls_context = null;
            self.quic = .{};
            self.doh = .{};
            self.requests = @splat(.{});
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
            request_tend.cancel_all(self);
            channel_link.cancel_all(self);
        }

        /// Closes the sockets, once the loop has drained (rotor decision 5, rule 4).
        pub fn close(self: *Self) void {
            assert(self.closing);
            self.sockets.close();
            tcp.close_all(self);
            request_tend.close_all(self);
            channel_link.close_all(self);
        }

        /// Starts a lookup. Its result comes through `take`, and one the cache already holds is
        /// there by the time this returns: the table asks the cache at the lookup's first poll,
        /// which the drive below makes (docs/design.md §20). The transport the configuration's
        /// servers speak must have its context by now: `has_context` says whether it has.
        pub fn start(self: *Self, question: cocuyo.Question, now_ns: u64) error{Full}!cocuyo.Handle {
            assert(!self.closing);
            // A lookup is the first call that can reach a server, and a session never starts from
            // a context nobody named: forgetting `use_tls`, `use_quic` or `use_doh` is a
            // programmer error (docs/design.md §24, the context a session starts from, rule 3).
            assert(self.has_context());
            const handle = self.resolver.start(question) catch return error.Full;
            self.handles[handle.index] = handle;
            // The buffer may still be lent to a send of the lookup the slot held before: it stays
            // lent until that send's final event (the stream's rule 6).
            self.held[handle.index] = null;
            self.reported[handle.index] = false;
            self.tcp_connection[handle.index] = null;
            // The lookup before in the slot left any wait for a connection slot at its end (the
            // stream's rule 12).
            assert(!self.tcp_waiting[handle.index]);
            drive_module.drive(self, now_ns);
            return handle;
        }

        /// A TLS configuration needs an engine that speaks TLS: one without it would carry
        /// cleartext on port 853 (RFC 7858 §3.1). And it needs a connection slot for each of its
        /// servers, since a TLS connection is never closed to make room (§21, TLS rule 6). A DoQ
        /// configuration needs an engine with a request transport, and a DoH one an engine with a
        /// channel type (§24).
        pub fn assert_tls(config: *const cocuyo.Config) void {
            if (config.transport() == .quic) assert(options.quic.enabled);
            if (config.uses_https()) assert(options.doh.enabled);
            if (!config.uses_tls()) return;
            assert(options.tls.enabled);
            assert(config.servers.len <= options.tcp_connections);
        }

        /// Whether the transport the configuration's servers speak has its context: DoT's from
        /// `use_tls`, DoQ's from `use_quic`, DoH's from `use_doh`. Plain DNS needs none, so a
        /// configuration of plain DNS always has what it needs. `start` asserts this, and a
        /// consumer may ask it first (docs/design.md §24, the context a session starts from).
        pub fn has_context(self: *const Self) bool {
            return context_module.held(self);
        }

        /// Names what every TLS session starts from (docs/design.md §21, and §24, the context a
        /// session starts from): for chapulin's session the anchors, the wall clock, and a stream
        /// keyed by 32 octets of the caller's CSPRNG. The call is required, after `init` and before
        /// any lookup reaches a TLS server. The engine has no context of its own, and a `start`
        /// against a TLS configuration whose context was never set stops the program at an
        /// assertion (§16 decision 39). The engine checks that a context was set, and cannot check
        /// the seed or the clock in it. `reinit` keeps the context, and `init` forgets it. A
        /// context handed again, after an `init` or to pin the clock again, is built from a new
        /// draw of 32 octets: built from the octets of one before, it starts its stream where that
        /// one started. The twin's context holds nothing, and a test names it all the same.
        pub fn use_tls(self: *Self, context: options.tls.Context) void {
            self.tls_context = context;
        }

        /// Names what every QUIC connection starts from (docs/design.md §24): the session's
        /// context, and the stream the connection IDs are drawn from, each keyed by a draw of its
        /// own. The call is required, after `init` and before any lookup reaches a DoQ server:
        /// without it a `start` against a DoQ configuration stops the program at an assertion,
        /// as `use_tls` says for TLS, and a context handed again takes new draws.
        pub fn use_quic(self: *Self, context: options.quic.Context) void {
            self.quic.context = context;
        }

        /// Names what every channel starts from (docs/design.md §24, DoH over colibri's client):
        /// the anchors, the wall clock and the stream. The call is required, after `init` and
        /// before any lookup reaches a DoH server: without it a `start` against a DoH
        /// configuration stops the program at an assertion, as `use_tls` says for TLS, and a
        /// context handed again takes a new draw.
        pub fn use_doh(self: *Self, context: options.doh.Context) void {
            self.doh.context = context;
        }

        /// Settles every lookup as cancelled, which is `ares_cancel`. Each failure comes through
        /// `take` like any other, so the caller learns of all of them.
        pub fn cancel_all(self: *Self, now_ns: u64) void {
            lifecycle.cancel_all(self, now_ns);
        }

        /// A new configuration, which is `ares_reinit`. The engine must be idle, and `seed` a new
        /// draw from a CSPRNG; `io_lifecycle.zig` says why and what a caller does first. Every
        /// server's latency samples start over (docs/design.md §5), and a server marked as one
        /// that lowercases the name is asked with DNS-0x20 again (§7). The cache is built again
        /// over `cache_memory`, empty: the memory the engine holds, other memory of any size
        /// `Cache.init` takes, or null for no cache from here on. Memory the engine held before
        /// and is not handed again is the caller's to free once this returns, whatever it
        /// returns but `UdpPayloadTooLarge`, which changes nothing. A `reinit` that fails at its
        /// sockets has still taken the memory it was handed. That memory is the engine's until a
        /// later `reinit` or `close` returns: never free it on that error. The contexts of DoT,
        /// DoQ and DoH stay as they are: one set before still counts, and one never set is still
        /// missing (§24, the context a session starts from, rule 5).
        pub fn reinit(
            self: *Self,
            config: *const cocuyo.Config,
            cache_memory: ?cocuyo.cache.Slices,
            seed: u64,
            now_ns: u64,
        ) InitError!void {
            try lifecycle.reinit(self, config, cache_memory, seed, now_ns);
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
    _ = channel;
    _ = channel_link;
    _ = context_module;
    _ = @import("io_request_template.zig");
    _ = @import("io_tcp_queue_ring.zig");
    _ = @import("io_reset.zig");
    // The tests drive the engine on the twin, which is the only `rotor` that has scripts.
    if (comptime @hasDecl(rotor, "server")) {
        _ = @import("io_sim_test.zig");
        _ = @import("io_sim_servers_test.zig");
        _ = @import("io_sim_datagram_test.zig");
        _ = @import("io_tcp_test.zig");
        _ = @import("io_tcp_cause_test.zig");
        _ = @import("io_tcp_wait_test.zig");
        _ = @import("io_tcp_frame_test.zig");
        _ = @import("io_lifecycle_test.zig");
        _ = @import("io_lifecycle_cache_test.zig");
        _ = @import("io_tls_test.zig");
        _ = @import("io_tls_failing_test.zig");
        _ = @import("io_tls_cause_test.zig");
        _ = @import("io_request_test.zig");
        _ = @import("io_request_failure_test.zig");
        _ = @import("io_channel_test.zig");
        _ = @import("io_channel_link_test.zig");
        _ = @import("io_context_test.zig");
        _ = @import("io_quic_test.zig");
        _ = @import("io_threads_test.zig");
    }
}
