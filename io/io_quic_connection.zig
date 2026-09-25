//! What one of `cocuyo_quic`'s connections does (docs/design.md §24, colibri under the request
//! interface): free functions over the connection, split out of `io_quic.zig` so each is scored on
//! its own. colibri's state is read after each call, since it reports little as events, and its
//! next deadline with it.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const constants = @import("io_quic_constants.zig");
const h3_module = @import("io_quic_h3.zig");

/// Where a connection is: not started, handshaking, up, failed and not yet told, or told.
pub const Stage = enum { idle, handshaking, up, failed, done };

/// Begins a connection: its IDs, drawn from the context's stream, its transport parameters, and
/// the session's first flight owed.
pub fn start(self: anytype, context: anytype) error{Failed}!void {
    const Self = @TypeOf(self.*);
    assert(self.stage == .idle);
    // A DoH server needs HTTP/3, which a connection without it cannot speak.
    if (context.https != null and !Self.http3) return error.Failed;
    self.* = .{ .stage = .handshaking, .https = context.https != null };
    context.context.stream.fill(&self.destination);
    context.context.stream.fill(&self.source);
    if (comptime Self.http3) {
        if (context.https) |https| try h3_module.start(self, https, &context.context.stream);
    }
    try self.session.start(context);
    self.connection.init(.{
        .role = .client,
        .local_parameters = parameters(Self.receive_bytes, self.https),
        .now_ns = context.now_ns,
        .identity = .{ .local_initial_source = &self.source, .original_destination = &self.destination },
        .receive = self.pool.storage(),
    });
    self.send_scratch = .{};
    var body: [constants.params_bytes_max]u8 = undefined;
    var writer = quic.core.Writer.init(&body);
    quic.transport_parameters.write(&writer, &self.connection.local_parameters, .client) catch return fail(self);
    self.session.provider().set_transport_params(writer.written()) catch return fail(self);
    const suite = self.session.suite();
    // RFC 9001 §5.2: the Initial keys derive from the client's Destination Connection ID.
    suite.vtable.install_initial_keys(suite.context, .client, &self.destination) catch return fail(self);
    read_deadline(self);
}

/// What this end tells the server it will take (RFC 9000 §18.2): a whole answer on each of our
/// streams, and an idle timeout (RFC 9250 §4.4). Over DoQ no stream of the server's own (RFC 9250
/// §4.2 has it open none). Over HTTP/3 its control and QPACK streams, with the credit RFC 9114 §6.2
/// asks for.
fn parameters(receive_bytes: usize, https: bool) quic.transport_parameters.Parameters {
    var local = quic.transport_parameters.Parameters.initial();
    local.max_idle_timeout_ms = constants.idle_timeout_ms;
    local.max_udp_payload_size = constants.datagram_receive_bytes;
    local.initial_max_data = receive_bytes;
    local.initial_max_stream_data_bidi_local = @min(constants.answer_bytes_max, receive_bytes);
    if (https) {
        local.initial_max_streams_uni = constants.h3_peer_uni_streams;
        local.initial_max_stream_data_uni = constants.h3_peer_uni_stream_bytes;
    }
    return local;
}

/// One datagram, read in place in a copy the connection owns. One colibri refuses closes the
/// connection, and `next` says so.
pub fn receive(self: anytype, bytes: []const u8, now_ns: u64) void {
    if (self.stage != .handshaking and self.stage != .up) return;
    if (bytes.len > self.inbound.len) return;
    @memcpy(self.inbound[0..bytes.len], bytes);
    _ = quic.connection_datagram.receive(
        &self.connection,
        self.session.suite(),
        self.session.provider(),
        .{ .octets = self.inbound[0..bytes.len], .now_ns = now_ns, .ecn = .not_ect },
        &self.scratch,
    ) catch |err| {
        quic.connection_close.owe(&self.connection, quic.connection_close.transport(
            quic.connection_datagram.connection_error_code(&self.connection, err),
            null,
        ));
        self.stage = .failed;
        return;
    };
    read_deadline(self);
}

/// What the datagrams and the timer did, one thing at a time (docs/design.md §24).
pub fn next(self: anytype, out: []u8) ?@TypeOf(self.*).Next {
    switch (self.stage) {
        .idle, .done => return null,
        .failed => {
            self.stage = .done;
            return if (self.connection.handshake_complete) .closed else .refused;
        },
        .handshaking, .up => {},
    }
    if (ended(self)) {
        self.stage = .done;
        return .closed;
    }
    if (self.stage == .handshaking and self.connection.handshake_complete) return up(self);
    return said(self, out) orelse ticket(self);
}

/// The handshake ended, on the protocol the provider says. A connection that speaks HTTP/3
/// starts `h3` then, and one `h3` refuses to start closes.
fn up(self: anytype) @TypeOf(self.*).Next {
    self.stage = .up;
    if (comptime @TypeOf(self.*).http3) {
        if (self.https) h3_module.up(self) catch {
            self.stage = .done;
            return .closed;
        };
    }
    return .{ .up = self.session.provider().negotiated_alpn() orelse "" };
}

/// What a stream said: over DoQ read off colibri's streams, over HTTP/3 from `h3`'s events.
fn said(self: anytype, out: []u8) ?@TypeOf(self.*).Next {
    if (comptime @TypeOf(self.*).http3) {
        if (self.https) return h3_module.next(self, out);
    }
    const told = self.streams.next(&self.connection, out) orelse return null;
    return switch (told) {
        .answered => |answered| .{ .answered = .{ .stream = answered.stream, .len = answered.len } },
        .reset => |stream| .{ .reset = stream },
    };
}

/// A ticket the session was given, which the engine keeps (request rule 10).
fn ticket(self: anytype) ?@TypeOf(self.*).Next {
    const given = self.session.take_ticket() orelse return null;
    return .{ .ticket = given };
}

/// Whether the connection ended on its own or by the server: the server closed it, or it sat
/// idle past its timeout (RFC 9000 §10). A close of this end's own is the engine's, which has the
/// socket closed once the CONNECTION_CLOSE has gone, and reopens it for what waits (request rule 9).
fn ended(self: anytype) bool {
    const termination = &self.connection.termination;
    if (termination.state == .active) return false;
    return termination.reason != .closed_locally;
}

/// Opens a stream for `bytes`, then FIN (RFC 9250 §4.2), or null when there is no room for one
/// yet.
pub fn request(self: anytype, bytes: []const u8) error{Failed}!?u64 {
    assert(self.stage == .up);
    if (comptime @TypeOf(self.*).http3) {
        if (self.https) {
            const opened = h3_module.request(self, bytes) catch return fail(self);
            read_deadline(self);
            return opened;
        }
    }
    const opened = self.streams.open(&self.connection, bytes) catch return fail(self);
    read_deadline(self);
    return opened;
}

/// STOP_SENDING and a reset of this end's side, with DOQ_REQUEST_CANCELLED (RFC 9250 §4.3.1).
pub fn cancel(self: anytype, stream: u64) void {
    if (comptime @TypeOf(self.*).http3) {
        if (self.https) {
            h3_module.cancel(self, stream);
            return read_deadline(self);
        }
    }
    self.streams.cancel(&self.connection, stream);
    read_deadline(self);
}

/// The next datagram the connection owes, or nothing. A send colibri refuses closes the
/// connection, and `next` says so.
pub fn datagram(self: anytype, out: []u8, now_ns: u64) usize {
    if (self.stage == .idle or self.stage == .done) return 0;
    const sent = quic.connection_send.send(
        &self.connection,
        self.session.suite(),
        self.session.provider(),
        provider_of(self),
        &self.send_scratch,
        out,
        now_ns,
    ) catch |err| {
        const code = quic.connection_send.connection_error_code(err) orelse quic.error_code.internal_error;
        quic.connection_close.owe(&self.connection, quic.connection_close.transport(code, null));
        self.stage = .failed;
        return 0;
    };
    read_deadline(self);
    return if (sent) |made| made.len else 0;
}

/// Where colibri reads the streams' octets: every request's from its slot, and over HTTP/3 the
/// control and QPACK streams' from `h3`, which wraps the slots' provider.
fn provider_of(self: anytype) quic.stream.stream_provider.StreamProvider {
    if (comptime @TypeOf(self.*).http3) {
        if (self.https) return self.h3.connection.provider(self.streams.provider());
    }
    return self.streams.provider();
}

/// The instant came: colibri resends what was lost, or closes an idle connection.
pub fn expire(self: anytype, now_ns: u64) void {
    if (self.stage == .idle or self.stage == .done) return;
    _ = quic.connection_timer.on_instant(&self.connection, self.session.suite(), &self.scratch.recovery, now_ns) catch {
        self.stage = .failed;
    };
    read_deadline(self);
}

/// How long before the idle timeout the connection negotiated closes it (RFC 9250 §4.4).
pub fn idle_left_ns(self: anytype, now_ns: u64) u64 {
    const probe_ns = self.connection.recovery.rtt.probe_timeout_ns(true);
    const due = self.connection.termination.idle_deadline_ns(probe_ns) orelse return std.math.maxInt(u64);
    return due -| now_ns;
}

/// The CONNECTION_CLOSE of an idle close, with DOQ_NO_ERROR (RFC 9250 §4.4), or HTTP/3's own.
pub fn close(self: anytype) void {
    if (comptime @TypeOf(self.*).http3) {
        if (self.https) {
            h3_module.close(self);
            return read_deadline(self);
        }
    }
    quic.connection_close.owe(&self.connection, .{
        .layer = .application,
        .error_code = constants.doq_no_error,
        .frame_type = null,
        .reason = "",
    });
    read_deadline(self);
}

pub fn wipe(self: anytype) void {
    if (self.stage != .idle) self.session.wipe();
    self.stage = .idle;
    self.due_ns = null;
}

/// colibri's next deadline, which the engine's one timer is armed for (request rule 11).
fn read_deadline(self: anytype) void {
    const due = quic.connection_timer.next(&self.connection) orelse {
        self.due_ns = null;
        return;
    };
    self.due_ns = due.at_ns;
}

fn fail(self: anytype) error{Failed} {
    self.stage = .failed;
    return error.Failed;
}
