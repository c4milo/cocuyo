//! A DoQ server over colibri and `plain`, for tests (docs/design.md §24, colibri over the twin). A
//! test puts one behind the twin's responder, so the engine runs colibri's client against colibri's
//! server: real packets, streams and flow control on the twin's clock. It takes the client's first
//! Initial, reads each stream's query once all of it has arrived, and answers it on the same
//! stream, then FIN (RFC 9250 §4.2), with what an `Answerer` makes of it.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const quic = @import("quic");
const constants = @import("io_quic_constants.zig");
const plain = @import("io_quic_plain.zig");

pub const StreamId = quic.stream.StreamId;
const connection_id_bytes_max = quic.crypto.constants.connection_id_len_max;

/// What answers a query: the message, written into `out`, and its octets, or null to reset the
/// stream instead.
pub const Answerer = struct {
    context: *anyopaque,
    answer: *const fn (context: *anyopaque, query: []const u8, out: []u8) ?usize,
};

/// One of the client's streams: its query as it arrives, and the answer the server keeps while
/// colibri may read it.
const Request = struct {
    live: bool = false,
    id: StreamId = .{ .value = 0 },
    query: [cocuyo.constants.query_bytes_max]u8 = undefined,
    query_len: usize = 0,
    answer: [constants.server_answer_bytes_max]u8 = undefined,
    answer_len: usize = 0,
    answered: bool = false,
};

pub fn Server(comptime streams: u16) type {
    return struct {
        const Self = @This();

        connection: quic.Connection = undefined,
        session: plain.Session = undefined,
        pool: quic.stream.stream_incoming.Pool(constants.server_receive_bytes) = undefined,
        send_scratch: quic.connection_send.DefaultScratch = undefined,
        scratch: quic.connection_datagram.Scratch = undefined,
        inbound: [constants.datagram_receive_bytes]u8 = undefined,
        source: [constants.connection_id_bytes]u8 = @splat(constants.server_id_octet),
        original: [connection_id_bytes_max]u8 = undefined,
        original_len: usize = 0,
        client: [connection_id_bytes_max]u8 = undefined,
        client_len: usize = 0,
        started: bool = false,
        /// Selects a protocol other than the one offered, for a test.
        other_protocol: bool = false,
        /// Reads each query and leaves it unanswered, neither answer nor reset, for a test.
        hold: bool = false,
        next_index: u64 = 0,
        requests: [streams]Request = @splat(.{}),
        answered: usize = 0,

        /// One datagram from the client. The first, an Initial, starts the connection (RFC 9000
        /// §7.2). A datagram colibri refuses closes the connection.
        pub fn receive(self: *Self, bytes: []const u8, now_ns: u64, answerer: Answerer) void {
            receive_datagram(self, bytes, now_ns, answerer);
        }

        /// The next datagram the server owes, or nothing.
        pub fn send(self: *Self, out: []u8, now_ns: u64) usize {
            return send_datagram(self, out, now_ns);
        }

        pub fn deadline(self: *Self) ?u64 {
            return next_deadline(self);
        }

        pub fn expire(self: *Self, now_ns: u64) void {
            expire_due(self, now_ns);
        }

        const stream_vtable: quic.stream.stream_provider.VTable = .{ .read = read_answer };

        fn read_answer(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
            const self: *Self = @ptrCast(@alignCast(context));
            return provide(&self.requests, stream_id, offset, output);
        }
    };
}

fn receive_datagram(self: anytype, bytes: []const u8, now_ns: u64, answerer: Answerer) void {
    if (bytes.len > self.inbound.len) return;
    @memcpy(self.inbound[0..bytes.len], bytes);
    // A client names a connection by its Destination Connection ID: the one its first
    // Initial chose, and the server's own after the server's first Initial (RFC 9000
    // §7.2). An Initial that names neither is a new connection, from a socket that reuses
    // a closed one's descriptor.
    if (self.started and is_new(self, bytes)) self.* = .{ .other_protocol = self.other_protocol, .hold = self.hold };
    if (!self.started and !start(self, bytes, now_ns)) return;
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
        return;
    };
    step(self, answerer);
}

/// Starts the connection from the client's first Initial: its Destination Connection ID
/// derives the Initial keys (RFC 9001 §5.2), and its Source Connection ID is the server's
/// destination (RFC 9000 §7.2).
fn start(self: anytype, bytes: []const u8, now_ns: u64) bool {
    const parsed = quic.packet.header.read(bytes, constants.connection_id_bytes) catch return false;
    const long = switch (parsed) {
        .long => |held| held,
        else => return false,
    };
    if (long.type != .initial) return false;
    @memcpy(self.original[0..long.dcid.len], long.dcid);
    self.original_len = long.dcid.len;
    @memcpy(self.client[0..long.scid.len], long.scid);
    self.client_len = long.scid.len;
    self.session = plain.Session.init(.server, "", self.other_protocol);
    self.connection.init(.{
        .role = .server,
        .local_parameters = parameters(@intCast(self.requests.len)),
        .now_ns = now_ns,
        .identity = .{
            .local_initial_source = &self.source,
            .original_destination = self.original[0..self.original_len],
            .peer_initial_source = self.client[0..self.client_len],
        },
        .receive = self.pool.storage(),
    });
    self.send_scratch = .{};
    var body: [constants.params_bytes_max]u8 = undefined;
    var writer = quic.core.Writer.init(&body);
    quic.transport_parameters.write(&writer, &self.connection.local_parameters, .server) catch return false;
    self.session.provider().set_transport_params(writer.written()) catch return false;
    const suite = self.session.suite();
    suite.vtable.install_initial_keys(suite.context, .server, self.original[0..self.original_len]) catch return false;
    self.started = true;
    return true;
}

fn is_new(self: anytype, bytes: []const u8) bool {
    const parsed = quic.packet.header.read(bytes, constants.connection_id_bytes) catch return false;
    const long = switch (parsed) {
        .long => |held| held,
        else => return false,
    };
    if (long.type != .initial) return false;
    return !std.mem.eql(u8, long.dcid, self.original[0..self.original_len]) and !std.mem.eql(u8, long.dcid, &self.source);
}

/// A stream for each of the client's queries at once, each query whole, and an idle
/// timeout (RFC 9000 §18.2).
fn parameters(streams: u16) quic.transport_parameters.Parameters {
    var local = quic.transport_parameters.Parameters.initial();
    local.max_idle_timeout_ms = constants.idle_timeout_ms;
    local.max_udp_payload_size = constants.datagram_receive_bytes;
    local.initial_max_data = constants.server_receive_bytes;
    local.initial_max_stream_data_bidi_remote = cocuyo.constants.query_bytes_max;
    local.initial_max_streams_bidi = streams;
    return local;
}

/// What a datagram may have changed: streams the client opened, queries that arrived
/// whole, answers the client has whole.
fn step(self: anytype, answerer: Answerer) void {
    take_opened(self);
    for (&self.requests) |*request| {
        if (!request.live) continue;
        if (request.answered) {
            release_if_done(self, request);
        } else {
            read_query(self, request, answerer);
        }
    }
}

fn take_opened(self: anytype) void {
    for (0..self.requests.len) |_| {
        const id = StreamId.of(.client, .bidirectional, self.next_index);
        switch (self.connection.streams.lookup(id)) {
            .unopened => return,
            .closed => {},
            .live => {
                const slot = for (&self.requests) |*request| {
                    if (!request.live) break request;
                } else return;
                slot.* = .{ .live = true, .id = id };
            },
        }
        self.next_index += 1;
    }
}

/// Reads what has arrived of the query, and answers once the client's side ended. A query
/// the answerer declines, or one the client reset, has its stream reset.
fn read_query(self: anytype, request: *Request, answerer: Answerer) void {
    const room = request.query[request.query_len..];
    if (room.len == 0) return refuse(self, request);
    const got = quic.connection_stream_read.read(&self.connection, request.id, room) catch {
        request.* = .{};
        return;
    };
    request.query_len += got.len;
    if (!got.fin or self.hold) return;
    const prefix = cocuyo.constants.tcp_prefix_bytes;
    const query = request.query[0..request.query_len];
    if (query.len < prefix) return refuse(self, request);
    const out = request.answer[prefix..];
    const len = answerer.answer(answerer.context, query[prefix..], out) orelse return refuse(self, request);
    std.mem.writeInt(u16, request.answer[0..prefix], @intCast(len), .big);
    request.answer_len = prefix + len;
    request.answered = true;
    self.answered += 1;
    quic.connection_stream_send.supply(&self.connection, request.id, request.answer_len, true) catch refuse(self, request);
}

fn refuse(self: anytype, request: *Request) void {
    request.answered = true;
    quic.connection_stream_send.reset(&self.connection, request.id, constants.doq_request_cancelled) catch {};
}

fn release_if_done(self: anytype, request: *Request) void {
    switch (self.connection.streams.lookup(request.id)) {
        .live => |stream| switch (stream.sending.state) {
            .data_recvd, .reset_sent, .reset_recvd => request.live = false,
            else => {},
        },
        .closed, .unopened => request.live = false,
    }
}

fn send_datagram(self: anytype, out: []u8, now_ns: u64) usize {
    if (!self.started) return 0;
    const provider: quic.stream.stream_provider.StreamProvider = .{ .context = self, .vtable = &@TypeOf(self.*).stream_vtable };
    const sent = quic.connection_send.send(
        &self.connection,
        self.session.suite(),
        self.session.provider(),
        provider,
        &self.send_scratch,
        out,
        now_ns,
    ) catch return 0;
    return if (sent) |made| made.len else 0;
}

/// The octets of stream `stream_id`'s answer from `offset`, as many as fit.
fn provide(requests: []Request, stream_id: u64, offset: u64, output: []u8) usize {
    for (requests) |*request| {
        if (!request.live or request.id.value != stream_id) continue;
        if (offset >= request.answer_len) return 0;
        const left = request.answer[@intCast(offset)..request.answer_len];
        const written = @min(left.len, output.len);
        @memcpy(output[0..written], left[0..written]);
        return written;
    }
    return 0;
}

fn next_deadline(self: anytype) ?u64 {
    if (!self.started) return null;
    const due = quic.connection_timer.next(&self.connection) orelse return null;
    return due.at_ns;
}

fn expire_due(self: anytype, now_ns: u64) void {
    if (!self.started) return;
    _ = quic.connection_timer.on_instant(&self.connection, self.session.suite(), &self.scratch.recovery, now_ns) catch {};
}
