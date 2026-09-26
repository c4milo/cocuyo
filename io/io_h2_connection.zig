//! One of `cocuyo_h2`'s connections (docs/design.md §24, DoH over HTTP/2): colibri's `h2` client
//! over a record-mode TLS provider, the stream's octets that do not make a whole record yet, the
//! plaintext colibri reads frames from, the frames written and not yet sealed, and a buffer for
//! each response in flight. Free functions over the connection, as `io_quic_connection.zig`'s are.
//!
//! The engine hands over the stream's octets as they come, and `next` does the rest: through the
//! handshake it gives whole records to the provider, and once colibri has the provider it opens a
//! record at a time into the plaintext and reads a frame at a time out of it. A frame that leaves
//! colibri owing its peer, a SETTINGS acknowledgement, a WINDOW_UPDATE, has what it owes written
//! aside before the next frame is read, so a response that came in the same record is not left
//! waiting for octets that may never come.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const h2 = @import("h2");
const doh = @import("doh");
const constants = @import("io_h2_constants.zig");

const tls = h2.tls;
const FieldSection = h2.http.FieldSection;

/// One response in flight: the stream it answers, what its header section said, and its content
/// so far, counted even past the buffer, whose length is a DNS message's longest.
pub const Answer = struct {
    stream: ?u32 = null,
    http: doh.response.Http = .{ .status = 0, .age_seconds = 0, .dns_message = false },
    len: usize = 0,
    bytes: [cocuyo.constants.message_bytes_max]u8 = undefined,
};

pub const Stage = enum { idle, handshaking, up, closing, done };

/// What a connection holds beside its session.
pub fn State(comptime answers: u16) type {
    return struct {
        stage: Stage = .idle,
        connection: h2.Connection = undefined,
        records: [constants.records_bytes]u8 = undefined,
        records_len: usize = 0,
        plaintext: [constants.h2_plaintext_bytes]u8 = undefined,
        plaintext_len: usize = 0,
        outgoing: [constants.outgoing_bytes]u8 = undefined,
        outgoing_len: usize = 0,
        answers: [answers]Answer = @splat(.{}),
        /// The template's authority and path, which the configuration holds.
        authority: []const u8 = "",
        path: []const u8 = "",
        /// The last stream the server's GOAWAY says it may have processed (RFC 9113 §6.8), or,
        /// once colibri's stream identifiers have run out, the highest there is, which leaves every
        /// open stream to be answered (§5.1.1). Whether the engine was told.
        goaway: ?u32 = null,
        goaway_told: bool = false,
    };
}

// Starting (request rules 1, 2 and 10).

/// Readies the connection for a DoH server known by `https`, a split template: colibri's `h2` in
/// its client role, after the handshake the session has started. A template whose longest path
/// does not fit is refused.
pub fn start(self: anytype, https: anytype) error{Failed}!void {
    const state = &self.state;
    state.* = .{ .stage = .handshaking };
    state.connection.init(.client);
    state.authority = https.authority;
    state.path = https.path;
    // The longest path the template makes: its expansion with a `dns` value at its longest.
    var longest: [cocuyo.wire.constants.dns_variable_bytes_max]u8 = @splat('A');
    var path: [doh.constants.doh_request_bytes_max]u8 = undefined;
    _ = doh.template.expand(state.path, &longest, &path) orelse return error.Failed;
}

/// The handshake's step: whole records to the provider until it is complete, and then colibri
/// takes it, having checked what RFC 9113 §3.3 and §9.2 require of it. Then the connection is up,
/// on the protocol the handshake selected, which the engine checks (request rule 2). A record
/// after the handshake's last waits for the next call.
fn handshake(self: anytype, provider: tls.Provider) ?@TypeOf(self.*).Next {
    const state = &self.state;
    for (0..constants.events_per_next_max) |_| {
        if (provider.is_complete()) break;
        const read = provider.vtable.handshake_read(provider.context, state.records[0..state.records_len], 0) catch return refused(self);
        if (read == 0) break;
        consume(&state.records, &state.records_len, read);
    }
    if (!provider.is_complete()) return null;
    const selected = provider.vtable.negotiated_alpn(provider.context) orelse "";
    state.connection.attach_tls(provider) catch |err| switch (err) {
        // Another protocol: the engine hears it, and fails the connection (request rule 2).
        error.AlpnNotH2 => {
            state.stage = .done;
            return .{ .up = selected };
        },
        else => return refused(self),
    };
    state.stage = .up;
    // "Once TLS negotiation is complete, both the client and the server MUST send a connection
    // preface" (RFC 9113 §3.2): it goes ahead of the first request's HEADERS (§3.4).
    write_owed(self);
    return .{ .up = selected };
}

fn refused(self: anytype) @TypeOf(self.*).Next {
    self.state.stage = .done;
    return .refused;
}

fn closed(self: anytype) @TypeOf(self.*).Next {
    self.state.stage = .done;
    return .closed;
}

/// Drops `count` octets from the front of `buffer`'s first `len.*`.
fn consume(buffer: []u8, len: *usize, count: usize) void {
    assert(count <= len.*);
    std.mem.copyForwards(u8, buffer[0 .. len.* - count], buffer[count..len.*]);
    len.* -= count;
}

/// Keeps the stream's octets until they make whole records. A receive that leaves no room fails
/// the connection, as a record longer than the buffer does (request rule 7).
pub fn receive(self: anytype, bytes: []const u8) error{Failed}!void {
    const state = &self.state;
    if (state.stage == .idle or state.stage == .done) return error.Failed;
    if (state.records_len + bytes.len > state.records.len) return error.Failed;
    @memcpy(state.records[state.records_len..][0..bytes.len], bytes);
    state.records_len += bytes.len;
}

// Reading (request rules 5, 7, 10 and 13).

/// What the stream said since the last call, one thing at a time: the handshake's end, a response
/// whole, a stream reset, a ticket, a GOAWAY, the server's close, or a failure.
/// A closing connection reads nothing (request rule 9).
pub fn next(self: anytype, provider: tls.Provider, out: []u8) ?@TypeOf(self.*).Next {
    switch (self.state.stage) {
        .idle, .done, .closing => return null,
        .handshaking => return handshake(self, provider),
        .up => {},
    }
    if (told_goaway(self)) |said| return said;
    for (0..constants.events_per_next_max) |_| {
        switch (read_frame(self, out)) {
            .said => |said| return said,
            .read => continue,
            .none => {},
        }
        if (!open_record(self)) return refused_by_goaway(self);
        // A connection that ended says so now: the next call reads nothing.
        if (self.state.stage != .up) return closed(self);
        if (self.session.take_ticket()) |ticket| return .{ .ticket = ticket };
    }
    return null;
}

/// Opens the next whole record into the plaintext, when the plaintext has room for one. False
/// when no whole record is there, or no room. A `close_notify` is the server's end of its data,
/// which ends the connection (RFC 9846 §6.1, request rule 7).
fn open_record(self: anytype) bool {
    const state = &self.state;
    if (state.plaintext.len - state.plaintext_len < tls.constants.record_plaintext_len_max) return false;
    const room = state.plaintext[state.plaintext_len..];
    const opened = h2.connection_tls.decrypt(&state.connection, state.records[0..state.records_len], room, 0) catch {
        state.stage = .done;
        return true;
    };
    if (opened.consumed == 0) return false;
    consume(&state.records, &state.records_len, opened.consumed);
    state.plaintext_len += opened.plaintext_len;
    if (opened.end_of_data) state.stage = .done;
    return true;
}

/// What reading a frame did: said something, read a frame that meant nothing to the engine, or
/// found no whole frame.
fn Read(comptime Next: type) type {
    return union(enum) { said: Next, read, none };
}

/// Reads one frame of the plaintext, and says what it meant, if anything. A frame colibri cannot
/// read before it has written what it owes has that written aside first. A connection error colibri
/// found ends the connection (RFC 9113 §5.4.1). The event's octets are the plaintext's, so the
/// event is read before the frame is dropped from it: a DATA frame's content would otherwise be
/// the next frame's.
fn read_frame(self: anytype, out: []u8) Read(@TypeOf(self.*).Next) {
    const state = &self.state;
    var read = state.connection.receive(state.plaintext[0..state.plaintext_len], 0) catch return .{ .said = closed(self) };
    if (read.consumed == 0 and state.connection.has_pending()) {
        write_owed(self);
        read = state.connection.receive(state.plaintext[0..state.plaintext_len], 0) catch return .{ .said = closed(self) };
    }
    if (read.consumed == 0) return .none;
    defer consume(&state.plaintext, &state.plaintext_len, read.consumed);
    const event = read.event orelse return .read;
    const said = said_by(self, event, out) orelse return .read;
    return .{ .said = said };
}

/// Writes what colibri owes, as far as the outgoing buffer holds: the rest stays in colibri.
fn write_owed(self: anytype) void {
    const state = &self.state;
    state.outgoing_len += state.connection.write_pending(state.outgoing[state.outgoing_len..], 0);
}

/// What one of colibri's events tells the engine, if anything.
fn said_by(self: anytype, event: h2.Event, out: []u8) ?@TypeOf(self.*).Next {
    switch (event) {
        .response => |held| {
            take_response(self, held.stream_id, held.response);
            if (held.end_stream) return ended(self, held.stream_id, out);
        },
        .data => |held| {
            take_data(self, held.stream_id, held.payload);
            if (held.end_stream) return ended(self, held.stream_id, out);
        },
        .trailers => |held| return ended(self, held.stream_id, out),
        .stream_reset, .stream_refused => |held| return reset(self, held.stream_id),
        .goaway => |held| return goaway(self, held.last_stream_id),
        // A client hears no request, and the engine reads nothing from SETTINGS or a PING.
        .settings_acknowledged, .settings_applied, .ping_acknowledged, .request => {},
    }
    return null;
}

/// A GOAWAY: the last stream the server may have processed (RFC 9113 §6.8). colibri fails the
/// connection on one that names a higher stream than the last ("Endpoints MUST NOT increase the
/// value they send"), so each is the lowest yet.
fn goaway(self: anytype, last: u32) ?@TypeOf(self.*).Next {
    self.state.goaway = last;
    return told_goaway(self);
}

/// The first GOAWAY, or the stream identifiers running out, which `request` found, is told once,
/// and the engine drains the connection (request rule 13).
fn told_goaway(self: anytype) ?@TypeOf(self.*).Next {
    const state = &self.state;
    if (state.goaway == null or state.goaway_told) return null;
    state.goaway_told = true;
    return .goaway;
}

/// After a GOAWAY: a request on a stream above the last the server may have processed was never
/// processed, and "can be safely retried" (RFC 9113 §6.8): it hears its stream reset, and colibri
/// forgets the stream.
fn refused_by_goaway(self: anytype) ?@TypeOf(self.*).Next {
    const state = &self.state;
    const last = state.goaway orelse return null;
    for (&state.answers) |*answer| {
        const stream_id = answer.stream orelse continue;
        if (stream_id <= last) continue;
        state.connection.reset_stream(stream_id, h2.constants.error_cancel) catch {};
        return reset(self, stream_id);
    }
    return null;
}

fn answer_of(answers: anytype, stream_id: u32) ?*Answer {
    for (answers) |*answer| if (answer.stream == stream_id) return answer;
    return null;
}

fn free_answer(answers: anytype) ?*Answer {
    for (answers) |*answer| if (answer.stream == null) return answer;
    return null;
}

/// A response's header section: its status, its `Age`, and whether its content is a DNS message.
/// An interim one says nothing of the content (RFC 9113 §8.1), and the final one writes over what
/// it said.
fn take_response(self: anytype, stream_id: u32, held: h2.message.Response) void {
    const answer = answer_of(&self.state.answers, stream_id) orelse return;
    const lines = self.state.connection.field_section();
    answer.http = .{
        .status = held.status.code,
        .age_seconds = doh.response.age_seconds(value_of(lines, "age")),
        .dns_message = doh.response.is_dns_message(value_of(lines, "content-type")) and identity(lines),
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
    for (0..lines.len()) |_| {
        const line = walk.next() orelse break;
        if (!std.ascii.eqlIgnoreCase(line.name, "content-encoding")) continue;
        if (!doh.response.is_identity(line.value)) return false;
    }
    return true;
}

/// A piece of a response's content, kept as far as the buffer holds and counted past it.
fn take_data(self: anytype, stream_id: u32, octets: []const u8) void {
    const answer = answer_of(&self.state.answers, stream_id) orelse return;
    const room = answer.bytes.len -| answer.len;
    const kept = @min(room, octets.len);
    @memcpy(answer.bytes[answer.len..][0..kept], octets[0..kept]);
    answer.len += octets.len;
}

/// A response ended whole: its content goes into `out`, as far as it holds, with how long it was
/// and what its header section said. A stream the engine cancelled tells nobody.
fn ended(self: anytype, stream_id: u32, out: []u8) ?@TypeOf(self.*).Next {
    const answer = answer_of(&self.state.answers, stream_id) orelse return null;
    const copied = @min(answer.len, out.len, answer.bytes.len);
    @memcpy(out[0..copied], answer.bytes[0..copied]);
    const said: @TypeOf(self.*).Next = .{ .answered = .{ .stream = stream_id, .len = answer.len, .http = answer.http } };
    answer.* = .{};
    return said;
}

/// The server reset the stream, or colibri refused it as malformed (RFC 9113 §5.4.2, §8.1.1).
fn reset(self: anytype, stream_id: u32) ?@TypeOf(self.*).Next {
    const answer = answer_of(&self.state.answers, stream_id) orelse return null;
    answer.* = .{};
    return .{ .reset = stream_id };
}

// Requests (request rules 3, 4, 6 and 12).

/// The GET's field lines after its pseudo-header fields (RFC 8484 §4.1): the content it takes,
/// and, as request rule 12 has it, no content coding (RFC 9110 §12.5.3). colibri writes them as
/// literals without indexing (RFC 7541 §6.2.2).
const fields = [_]h2.hpack.Field{
    .{ .name = "accept", .value = "application/dns-message" },
    .{ .name = "accept-encoding", .value = "identity" },
};

/// `:path` is never indexed: its `dns` value is the query, which a table that indexed it would let
/// be probed through what compresses, and an intermediary must not index it either (RFC 7541
/// §6.2.3, §7.1.3, request rule 12).
const pseudo_indexing: h2.connection.PseudoIndexing = .{ .path = .never_indexed };

/// Opens a stream for `message`, a query without its prefix, as a GET whose `:path` carries it in
/// `dns` (RFC 8484 §4.1), with END_STREAM on its HEADERS, since a GET has no content (RFC 9113
/// §8.1). Null when no answer buffer is free, the server's SETTINGS_MAX_CONCURRENT_STREAMS is
/// reached (§5.1.2), the outgoing buffer has no room, or a GOAWAY came, which colibri refuses a
/// stream after (§6.8): the request waits (request rules 4 and 13).
pub fn request(self: anytype, message: []const u8) error{Failed}!?u64 {
    const state = &self.state;
    assert(state.stage == .up);
    const answer = free_answer(&state.answers) orelse return null;
    var variable: [cocuyo.wire.constants.dns_variable_bytes_max]u8 = undefined;
    const dns = cocuyo.wire.doh.dns_variable(message, &variable);
    var path: [doh.constants.doh_request_bytes_max]u8 = undefined;
    // `start` expanded the template with a longer value, so this one fits.
    const expanded = doh.template.expand(state.path, dns, &path) orelse unreachable;
    const target: h2.connection.Request_ = .{ .method = "GET", .scheme = "https", .path = expanded, .authority = state.authority, .indexing = pseudo_indexing };
    const sent = state.connection.write_request(state.outgoing[state.outgoing_len..], target, &fields, &.{}, true) catch |err| switch (err) {
        error.PeerLimitReached, error.Full, error.OutputTooSmall, error.AfterGoawayReceived => return null,
        // "A client that is unable to establish a new stream identifier can establish a new
        // connection for new streams" (RFC 9113 §5.1.1): the connection drains as on a GOAWAY,
        // which `next` tells.
        error.IdentifiersExhausted => return exhausted(self),
        else => return error.Failed,
    };
    state.outgoing_len += sent.written;
    answer.* = .{ .stream = sent.stream_id };
    return sent.stream_id;
}

/// Every stream is below the mark, and a GOAWAY that came first keeps its own.
fn exhausted(self: anytype) ?u64 {
    const state = &self.state;
    state.goaway = state.goaway orelse std.math.maxInt(u32);
    return null;
}

/// Cancels a request the lookup left: RST_STREAM with CANCEL, "the stream is no longer needed"
/// (RFC 9113 §7, request rule 6). Its buffer is free.
pub fn cancel(self: anytype, stream_id: u64) void {
    const state = &self.state;
    const id: u32 = @intCast(stream_id);
    state.connection.reset_stream(id, h2.constants.error_cancel) catch {};
    if (answer_of(&state.answers, id)) |answer| answer.* = .{};
}

// Writing (request rules 8, 9 and 15).

/// What the connection owes the server, sealed into `out`: the handshake's flights, the client's
/// Finished once it is up, then the frames written aside and what colibri owes, then, closing, the
/// `close_notify` after its GOAWAY (RFC 9113 §9.1, RFC 9846 §6.1). Nothing when it owes nothing.
pub fn output(self: anytype, provider: tls.Provider, out: []u8) usize {
    const state = &self.state;
    assert(out.len >= constants.output_bytes_max);
    if (state.stage == .idle or state.stage == .done) return 0;
    // The handshake's last flight goes before any frame (RFC 9846 §4.4.4).
    const flight = provider.vtable.handshake_write(provider.context, out, 0) catch {
        state.stage = .done;
        return 0;
    };
    if (flight > 0 or state.stage == .handshaking) return flight;
    write_owed(self);
    const sealed = h2.connection_tls.encrypt(&state.connection, state.outgoing[0..state.outgoing_len], out, 0) catch {
        state.stage = .done;
        return 0;
    };
    consume(&state.outgoing, &state.outgoing_len, sealed.consumed);
    if (sealed.written > 0 or state.stage != .closing or state.outgoing_len > 0) return sealed.written;
    // The provider writes one `close_notify`, and 0 when asked again (colibri's `tls.VTable`).
    return h2.connection_tls.close_notify(&state.connection, out) catch 0;
}

/// The close of an idle connection: a GOAWAY of NO_ERROR, then the `close_notify`, which `output`
/// writes (request rule 9, RFC 9113 §9.1: "the terminating endpoint SHOULD first send a GOAWAY").
pub fn close(self: anytype) void {
    const state = &self.state;
    assert(state.stage == .handshaking or state.stage == .up);
    if (state.stage == .up) state.connection.shutdown(h2.constants.error_no_error);
    state.stage = .closing;
}

const testing = std.testing;

/// A connection's state alone, placed outside any stack frame: `take_data` reads nothing else.
threadlocal var answering: struct { state: State(1) = .{} } = .{};
const content_test = [_]u8{0} ** cocuyo.constants.message_bytes_max;

test "content past an answer's buffer is counted, so the engine fails the answer as too long" {
    // Request rule 5: the engine fails an answer longer than its buffer, which it knows by the length.
    answering = .{};
    answering.state.answers[0].stream = 1;
    take_data(&answering, 1, &content_test);
    take_data(&answering, 1, &content_test);
    try testing.expectEqual(2 * content_test.len, answering.state.answers[0].len);
}
