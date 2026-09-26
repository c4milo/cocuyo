//! The HTTP/3 of one of `cocuyo_quic`'s connections, which DoH goes over (docs/design.md §24, DoH
//! over HTTP/3): colibri's `h3` connection, a buffer for each response in flight, and the GET each
//! request is. Free functions over the connection, as `io_quic_connection.zig`'s are.
//!
//! `h3` hands a response's content over as it arrives, a piece at a time, with the pieces of
//! different streams in turn, and takes them out of colibri's pool as it does. So an answer waits
//! in a buffer of its own until it is whole, and a request opens its stream only when a buffer is
//! free.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const quic = @import("quic");
const h3 = @import("h3");
const constants = @import("io_quic_constants.zig");
const template = @import("io_quic_template.zig");
const response = @import("io_quic_response.zig");

const FieldSection = h3.http.FieldSection;
const Indexing = h3.qpack.encoder.Indexing;
const Writer = h3.core.Writer;

/// One response in flight: the stream it answers, what its header section said, and its content
/// so far, counted even past the buffer, whose length is the engine's.
pub const Answer = struct {
    stream: ?u64 = null,
    http: response.Http = .{ .status = 0, .age_seconds = 0, .dns_message = false },
    len: usize = 0,
    bytes: [constants.answer_bytes_max]u8 = undefined,
};

/// What a connection that speaks HTTP/3 holds beside colibri's `quic`.
pub fn State(comptime answers: u16) type {
    return struct {
        connection: h3.Connection = undefined,
        /// The GET being built, which colibri encodes from.
        section: FieldSection = undefined,
        /// Where `h3` writes a piece of a response's content.
        body: [constants.h3_chunk_bytes]u8 = undefined,
        answers: [answers]Answer = @splat(.{}),
        /// The template's authority and path, which the configuration holds.
        authority: []const u8 = "",
        path: []const u8 = "",
        /// The first stream the server's GOAWAY says it will not process (RFC 9114 §5.2).
        goaway: ?u64 = null,
    };
}

/// The GET's six field lines, `:path` never indexed: its `dns` value could otherwise be probed
/// through what compresses (RFC 9204 §4.5.4, §7.1.3, request rule 12).
const indexing = [_]Indexing{ .may_insert, .may_insert, .may_insert, .never_indexed, .may_insert, .may_insert };

/// Readies a connection for a DoH server known by `https`, a split template: `h3` in its client
/// role, with its grease drawn from the connection's stream (colibri reads no randomness). A
/// template whose GET would not fit a request's slot is refused.
pub fn start(self: anytype, https: anytype, stream: *std.Random.ChaCha) error{Failed}!void {
    var grease: [@sizeOf(u64)]u8 = undefined;
    stream.fill(&grease);
    self.h3.connection.init(.{ .role = .client, .grease = std.mem.readInt(u64, &grease, .little) });
    self.h3.answers = @splat(.{});
    self.h3.goaway = null;
    self.h3.authority = https.authority;
    self.h3.path = https.path;
    // The longest GET the template makes: its path expanded with a `dns` value at its longest.
    var longest: [cocuyo.wire.constants.dns_variable_bytes_max]u8 = @splat('A');
    var path: [constants.doh_request_bytes_max]u8 = undefined;
    const expanded = template.expand(self.h3.path, &longest, &path) orelse return error.Failed;
    get(self, expanded) catch return error.Failed;
    const frame_len_max = h3.constants.frame_header_len_max + h3.constants.section_prefix_len_max + self.h3.section.size;
    if (frame_len_max > constants.doh_request_bytes_max) return error.Failed;
}

/// Starts `h3` once colibri says the handshake ended: it opens its control and QPACK streams and
/// writes SETTINGS, which "MUST be sent as soon as the transport is ready" (RFC 9114 §6.2.1,
/// §7.2.4.2). colibri asserts the server's transport parameters are there by then.
pub fn up(self: anytype) error{Failed}!void {
    assert(self.connection.handshake_complete);
    self.h3.connection.start(&self.connection) catch return error.Failed;
}

/// Builds the GET for `path` (RFC 8484 §4.1, RFC 9114 §4.3.1).
fn get(self: anytype, path: []const u8) error{Failed}!void {
    const section = &self.h3.section;
    section.init();
    const lines = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = self.h3.authority },
        .{ .name = ":path", .value = path },
        .{ .name = "accept", .value = "application/dns-message" },
        // Request rule 12: "identity" asks for no content coding (RFC 9110 §12.5.3).
        .{ .name = "accept-encoding", .value = "identity" },
    };
    comptime assert(lines.len == indexing.len);
    for (lines) |line| section.append(line.name, line.value) catch return error.Failed;
}

/// Opens a stream for `message`, a query without its prefix, as a GET whose `:path` carries it in
/// `dns` (RFC 8484 §4.1). Null when no answer buffer is free, or the server's stream credit or
/// `h3`'s table has no room: the request waits (request rule 4).
pub fn request(self: anytype, message: []const u8) error{Failed}!?u64 {
    // After a GOAWAY the server takes no new stream: the request waits for the close.
    if (self.h3.goaway != null) return null;
    const answer = free_answer(&self.h3.answers) orelse return null;
    const slot = self.streams.free() orelse return null;
    var variable: [cocuyo.wire.constants.dns_variable_bytes_max]u8 = undefined;
    const dns = cocuyo.wire.doh.dns_variable(message, &variable);
    var path: [constants.doh_request_bytes_max]u8 = undefined;
    // `start` expanded the template with a longer value, so this one fits.
    const expanded = template.expand(self.h3.path, dns, &path) orelse unreachable;
    try get(self, expanded);
    var writer = Writer.init(&slot.bytes);
    const id = self.h3.connection.write_request(&self.connection, &self.h3.section, &indexing, &writer) catch |err| switch (err) {
        error.StreamsExhausted => return null,
        else => return error.Failed,
    };
    const len = writer.written().len;
    // The frame is in the slot's bytes already, so the rest of the slot is set around them.
    slot.live = true;
    slot.id = id;
    slot.len = @intCast(len);
    slot.told = false;
    slot.cancelled = false;
    slot.sent = false;
    quic.connection_stream_send.supply(&self.connection, .{ .value = id }, len, true) catch return error.Failed;
    answer.* = .{ .stream = id };
    return id;
}

fn free_answer(answers: anytype) ?*Answer {
    for (answers) |*answer| if (answer.stream == null) return answer;
    return null;
}

fn answer_of(answers: anytype, stream_id: u64) ?*Answer {
    for (answers) |*answer| if (answer.stream == stream_id) return answer;
    return null;
}

/// Cancels a request the lookup left: `h3` resets its side and asks the server to stop sending,
/// with H3_REQUEST_CANCELLED (RFC 9114 §4.1.1), and drains the stream itself. Its buffer is free.
pub fn cancel(self: anytype, stream_id: u64) void {
    self.h3.connection.cancel(&self.connection, stream_id, constants.h3_request_cancelled);
    if (answer_of(&self.h3.answers, stream_id)) |answer| answer.* = .{};
    self.streams.cancelled(stream_id);
}

/// What the server's streams said since the last call, one thing at a time: a response whole, or
/// a stream reset. A connection error `h3` found closes the connection.
///
/// A GOAWAY names the first stream the server will not process, and it answers those before it:
/// "the client can retry any requests with ... identifiers greater than or equal to" it (RFC 9114
/// §5.2). `next` says it came, once, and the engine drains the connection (request rule 13): each
/// request from that stream on hears its stream reset, and no new one opens.
pub fn next(self: anytype, out: []u8) ?@TypeOf(self.*).Next {
    for (0..constants.h3_events_per_next_max) |_| {
        const event = self.h3.connection.receive(&self.connection, &self.h3.body) catch return closed(self);
        if (said_by(self, event orelse break, out)) |said| return said;
    } else return null;
    self.streams.sweep(&self.connection);
    return refused_by_goaway(self);
}

/// What one of `h3`'s events tells the engine, if anything.
fn said_by(self: anytype, event: h3.connection.Event, out: []u8) ?@TypeOf(self.*).Next {
    switch (event) {
        .response => |held| take_response(self, held.stream_id, held.response),
        .data => |held| take_data(self, held.stream_id, held.octets),
        .end => |stream_id| return ended(self, stream_id, out),
        .reset, .refused => |held| return reset(self, held.stream_id),
        .goaway => |first| return goaway(self, first),
        // A client hears no request, and reads nothing from SETTINGS or trailers.
        .settings, .trailers, .request => {},
    }
    return null;
}

/// A GOAWAY, whose first stream not processed is kept, the lowest of them: the first is told, and
/// "An endpoint MAY send multiple GOAWAY frames" (RFC 9114 §5.2), each told nothing more.
fn goaway(self: anytype, first: u64) ?@TypeOf(self.*).Next {
    const told = self.h3.goaway != null;
    self.h3.goaway = @min(first, self.h3.goaway orelse first);
    return if (told) null else .goaway;
}

/// After a GOAWAY: a request the server will not process is cancelled, which frees its stream,
/// and hears it reset.
fn refused_by_goaway(self: anytype) ?@TypeOf(self.*).Next {
    const first = self.h3.goaway orelse return null;
    for (&self.h3.answers) |*answer| {
        const stream_id = answer.stream orelse continue;
        if (stream_id < first) continue;
        self.h3.connection.cancel(&self.connection, stream_id, constants.h3_request_cancelled);
        return reset(self, stream_id);
    }
    return null;
}

fn closed(self: anytype) @TypeOf(self.*).Next {
    self.stage = .done;
    return .closed;
}

/// A response's header section: its status, its `Age`, and whether its content is a DNS message.
/// An interim one says nothing of the content (RFC 9114 §4.1), and the final one, which comes
/// before the stream ends or `h3` refuses the stream, writes over what it said.
fn take_response(self: anytype, stream_id: u64, held: h3.message.Response) void {
    const answer = answer_of(&self.h3.answers, stream_id) orelse return;
    const lines = self.h3.connection.field_section();
    answer.http = .{
        .status = held.status.code,
        .age_seconds = response.age_seconds(value_of(lines, "age")),
        .dns_message = response.is_dns_message(value_of(lines, "content-type")) and identity(lines),
    };
}

fn value_of(lines: *const FieldSection, name: []const u8) ?[]const u8 {
    const line = lines.find(name) orelse return null;
    return line.value;
}

/// Whether every `Content-Encoding` line names `identity` alone: the field is a list, and its lines
/// join into one (RFC 9110 §5.3, §8.4).
fn identity(lines: *const FieldSection) bool {
    var walk = lines.iterator();
    // Bounded by the section's lines.
    for (0..lines.len()) |_| {
        const line = walk.next() orelse break;
        if (!std.ascii.eqlIgnoreCase(line.name, "content-encoding")) continue;
        if (!response.is_identity(line.value)) return false;
    }
    return true;
}

/// A piece of a response's content, kept as far as the buffer holds and counted past it.
fn take_data(self: anytype, stream_id: u64, octets: []const u8) void {
    const answer = answer_of(&self.h3.answers, stream_id) orelse return;
    const room = answer.bytes.len -| answer.len;
    const kept = @min(room, octets.len);
    @memcpy(answer.bytes[answer.len..][0..kept], octets[0..kept]);
    answer.len += octets.len;
}

/// A response ended whole: its content goes into `out`, as far as it holds, with how long it was
/// and what its header section said. A stream the engine cancelled tells nobody.
fn ended(self: anytype, stream_id: u64, out: []u8) ?@TypeOf(self.*).Next {
    const answer = answer_of(&self.h3.answers, stream_id) orelse return null;
    const copied = @min(answer.len, out.len, answer.bytes.len);
    @memcpy(out[0..copied], answer.bytes[0..copied]);
    const said: @TypeOf(self.*).Next = .{ .answered = .{ .stream = stream_id, .len = answer.len, .http = answer.http } };
    answer.* = .{};
    self.streams.tell(stream_id);
    return said;
}

/// The server reset the stream, or `h3` refused its response as malformed (RFC 9114 §4.1.2).
fn reset(self: anytype, stream_id: u64) ?@TypeOf(self.*).Next {
    const answer = answer_of(&self.h3.answers, stream_id) orelse return null;
    answer.* = .{};
    self.streams.tell(stream_id);
    return .{ .reset = stream_id };
}

/// The CONNECTION_CLOSE of an idle close, with H3_NO_ERROR, or now and then a reserved code in its
/// place, as colibri draws it (RFC 9114 §8.1, request rule 9).
pub fn close(self: anytype) void {
    quic.connection_close.owe(&self.connection, .{
        .layer = .application,
        .error_code = self.h3.connection.no_error_code(),
        .frame_type = null,
        .reason = "",
    });
}

comptime {
    assert(constants.h3_peer_uni_streams == h3.constants.uni_streams_max);
    assert(constants.h3_request_cancelled == h3.constants.error_request_cancelled);
    assert(constants.h3_no_error == h3.constants.error_no_error);
}

// Tests.

const testing = std.testing;

test "content past an answer's buffer is counted, and not kept" {
    // The engine fails a connection whose answer is longer than its buffer (request rule 5), so
    // the length goes on counting where the octets stop.
    var held: struct { h3: struct { answers: [1]Answer } } = .{ .h3 = .{ .answers = .{.{ .stream = 0 }} } };
    const piece: [constants.h3_chunk_bytes]u8 = @splat(1);
    const pieces = constants.answer_bytes_max / piece.len + 1;
    for (0..pieces) |_| take_data(&held, 0, &piece);
    try testing.expectEqual(pieces * piece.len, held.h3.answers[0].len);
    try testing.expect(held.h3.answers[0].len > held.h3.answers[0].bytes.len);
}

test {
    _ = @import("io_quic_h3_test.zig");
}
