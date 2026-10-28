//! The engine over TLS on the twin (docs/design.md §21): a handshake between the connect and the
//! first query, flights answered, a refused handshake failed over, a ticket kept and spent, and a
//! declined ticket answered by a full handshake. Every whole record of a chunk is read with it. An
//! idle connection says `close_notify`, and so does one that cannot read past a message. The
//! session is the twin's (`rotor.tls`), whose records carry their plaintext unsealed; what only
//! chapulin can show is chapulin's.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io.zig");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const question = sim_test.question;

/// An engine that speaks the twin's TLS, with a connection slot for each server (TLS rule 6).
const Resolver = io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_connections = fixtures.servers,
    .tls = rotor.tls.Session,
});
pub const Rig = sim_test.RigOf(Resolver);

/// The same engine, whose connections assemble only a small message.
const TinyRig = sim_test.RigOf(io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_connections = fixtures.servers,
    .tcp_message_bytes = fixtures.tiny_message_bytes,
    .tls = rotor.tls.Session,
}));

/// Both of the rig's servers known by a name, as a configuration names DoT servers.
pub fn encrypt(rig: anytype) !void {
    const tls: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text("dns.example.") };
    for (&rig.servers) |*server| server.tls = tls;
}

/// A rig whose servers speak TLS as `scripts` say, under a timeout long enough for any of them.
pub fn start(rig: anytype, seed: u64, scripts: [fixtures.servers]rotor.server.Script) !void {
    try encrypt(rig);
    try rig.init(seed, scripts, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
    rig.use_test_contexts();
}

test "a lookup over TLS handshakes, then is answered on the stream, and no UDP socket is opened" {
    var rig: Rig = .{};
    try start(&rig, 41, .{ .{}, .{} });
    try testing.expectEqual(@as(u8, 0), rig.engine.sockets.count);
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expect(rig.engine.connections[0].state == .up);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "flights before the handshake's end are answered, and both lookups wait for it" {
    var rig: Rig = .{};
    try start(&rig, 42, .{ .{ .tls = .{ .flights = 2 } }, .{} });
    _ = try rig.engine.start(question("one.example."), rig.loop.now());
    _ = try rig.engine.start(question("two.example."), rig.loop.now());
    var answered: usize = 0;
    while (answered < 2) : (answered += 1) {
        const result = try rig.until_result();
        try testing.expect(result.outcome == .answer);
    }
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a refused handshake says its alert, fails the connection, and the next server answers" {
    var rig: Rig = .{};
    try start(&rig, 43, .{ .{ .tls = .{ .refuse = true } }, .{} });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    // The session's fatal alert reached the server that refused (RFC 9846 §6.2, TLS rule 4), and
    // the next server heard none.
    try testing.expectEqual(@as(u32, 1), rig.loop.network().alerts_heard[0]);
    try testing.expectEqual(@as(u32, 0), rig.loop.network().alerts_heard[1]);
    // The refused connection freed its slot, which the next server's took.
    try testing.expect(up_to(&rig, 1));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a lookup every server refused over TLS ends in AllServersFailed, not Timeout" {
    // Strict mode's refusal is the server failing the lookup, as SERVFAIL is: the lookup did not
    // run out of time (docs/design.md §16 decision 25).
    var rig: Rig = .{};
    try start(&rig, 47, .{ .{ .tls = .{ .refuse = true } }, .{ .tls = .{ .refuse = true } } });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(cocuyo.Error.AllServersFailed, result.outcome.failure.err);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a refused handshake is the handshake's cause, and names the server that refused it" {
    // The lookup hears that a TLS connection is up only at the handshake's end (TLS rule 1), and a
    // refusal is the handshake's (docs/design.md §5, The cause of a failure). One pass, so the last
    // failure is the second server's own refusal, on a connection slot of its own.
    var rig: Rig = .{};
    try encrypt(&rig);
    const refusing: rotor.server.Script = .{ .tls = .{ .refuse = true } };
    try rig.init(119, .{ refusing, refusing }, .{ .servers = &.{}, .attempts = 1, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
    rig.use_test_contexts();
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(cocuyo.Error.AllServersFailed, result.outcome.failure.err);
    try testing.expectEqual(@as(?cocuyo.Cause, .{ .server_index = 1, .what = .{ .reason = .handshake } }), result.outcome.failure.cause);
    // Both servers heard the session's fatal alert, so each refused a handshake of its own.
    try testing.expectEqual(@as(u32, 1), rig.loop.network().alerts_heard[0]);
    try testing.expectEqual(@as(u32, 1), rig.loop.network().alerts_heard[1]);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

/// Whether a connection to `server` is up, in whichever slot.
fn up_to(rig: *const Rig, server: u8) bool {
    for (rig.engine.connections) |connection| {
        if (connection.server == server and connection.state == .up) return true;
    }
    return false;
}

/// Lets the idle close run: the clock moves past `tcp_idle_ns` with nothing due, twice, so the
/// timer the last lookup left is gone as well.
fn idle(rig: *Rig) !void {
    _ = try rig.step(fixtures.tcp_idle_jump_ns);
    _ = try rig.step(fixtures.tcp_idle_jump_ns);
    rig.engine.drive(rig.loop.now());
}

test "an idle TLS connection says close_notify, and closes once it has gone" {
    var rig: Rig = .{};
    try start(&rig, 44, .{ .{}, .{} });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    try idle(&rig);
    try testing.expect(rig.engine.connections[0].state == .closing);
    _ = try rig.step(fixtures.wait_ns);
    try testing.expect(rig.engine.connections[0].state == .closed);
    try rig.deinit();
}

test "a length prefix of 65535 in a record's plaintext is waited for, and the connection stays up" {
    // The session opens a record into the connection's frame, and the framing of a stream in the
    // clear reads it (TLS rule 7): the prefix's sum with its own two octets passes sixteen bits.
    var rig: Rig = .{};
    try start(&rig, 49, .{ .{}, .{} });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    const connection = &rig.engine.connections[0];
    try testing.expect(connection.state == .up and connection.used == 0);
    var prefix: [cocuyo.constants.tcp_prefix_bytes]u8 = undefined;
    std.mem.writeInt(u16, &prefix, cocuyo.limits.message_bytes_max, .big);
    var record: [rotor.constants.tls_record_header_bytes + prefix.len]u8 = undefined;
    const len = rotor.tls.write_record(rotor.constants.tls_content_application, &prefix, &record);
    try testing.expect(rig.loop.network().write_stream(connection.descriptor.?, record[0..len], rig.loop.now()));
    _ = try rig.step(fixtures.channel_read_ns);
    try testing.expect(connection.state == .up);
    try testing.expectEqual(@as(usize, prefix.len), connection.used);
    try rig.deinit();
}

/// A lookup answered over TLS, which leaves the connection to the first server up, and its record
/// buffer and its frame empty.
pub fn up(rig: anytype, seed: u64) !void {
    try start(rig, seed, .{ .{}, .{} });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    const connection = &rig.engine.connections[0];
    try testing.expect(connection.state == .up and connection.used == 0 and connection.tls.record_in_used == 0);
}

/// Writes a record of type `content` into `out`, and returns the record's octets. Its body is
/// `body` octets: one message of zeros with its prefix, which is nobody's answer. The twin's
/// session opens an application record's body as it is.
fn record_of_zeros(out: []u8, content: u8, body: usize) usize {
    const header = io.constants.tls_record_header_bytes;
    const prefix = cocuyo.constants.tcp_prefix_bytes;
    @memset(out[0 .. header + body], 0);
    out[0] = content;
    std.mem.writeInt(u16, out[rotor.constants.tls_record_version_at..][0..@sizeOf(u16)], rotor.constants.tls_legacy_version, .big);
    std.mem.writeInt(u16, out[io.constants.tls_record_length_at..][0..@sizeOf(u16)], @intCast(body), .big);
    std.mem.writeInt(u16, out[header..][0..prefix], @intCast(body - prefix), .big);
    return header + body;
}

/// Gives `stream` to the connection in the first slot as the loop gives a stream: in chunks of
/// `tcp_chunk_bytes_max`. It stops when the connection reads nothing more.
fn take_in_chunks(rig: anytype, stream: []const u8) void {
    const chunk_bytes = io.limits.tcp_chunk_bytes_max;
    var chunks = std.mem.window(u8, stream, chunk_bytes, chunk_bytes);
    while (chunks.next()) |chunk| {
        const state = rig.engine.connections[0].state;
        if (state != .up and state != .closing) return;
        io.tls.take(&rig.engine, 0, chunk, rig.loop.now());
    }
}

/// Two records back to back, of the types `contents` names and of the bodies `bodies` gives.
const BackToBack = struct {
    octets: [fixtures.records_back_to_back * (io.constants.tls_record_header_bytes + io.limits.tls_record_body_bytes_max)]u8 = undefined,
    len: usize = 0,

    fn init(self: *BackToBack, contents: [fixtures.records_back_to_back]u8, bodies: [fixtures.records_back_to_back]usize) []const u8 {
        for (contents, bodies) |content, body| self.len += record_of_zeros(self.octets[self.len..], content, body);
        return self.octets[0..self.len];
    }
};

test "a chunk that ends a record and starts the next keeps the connection up" {
    // The chunks of a stream do not stop where its records stop (TLS rule 7). Two records come
    // back to back, and the ninth chunk ends the first and starts the second. The first body is
    // the longest TLS allows, or a full record of AES-GCM (RFC 9846 §5.2).
    const application = rotor.constants.tls_content_application;
    for ([_]usize{ io.limits.tls_record_body_bytes_max, fixtures.full_record_body_bytes }) |body| {
        var rig: Rig = .{};
        try up(&rig, 52);
        var stream: BackToBack = .{};
        take_in_chunks(&rig, stream.init(.{ application, application }, .{ body, fixtures.short_record_body_bytes }));
        // Both records came whole, and the message in each went to the table.
        const connection = &rig.engine.connections[0];
        try testing.expect(connection.state == .up);
        try testing.expectEqual(@as(usize, 0), connection.tls.record_in_used);
        try testing.expectEqual(@as(usize, 0), connection.used);
        try rig.deinit();
    }
}

test "a record the session refuses leaves the rest of its chunk unread, and room for the next" {
    // The twin's session refuses a handshake record once up, and stages its alert. The connection
    // closes once the alert has gone, and reads nothing more meanwhile (TLS rules 4 and 5). The
    // rest of the chunk that ended the record leaves the buffer with it.
    var rig: Rig = .{};
    try up(&rig, 53);
    const body = io.limits.tls_record_body_bytes_max;
    var stream: BackToBack = .{};
    take_in_chunks(&rig, stream.init(.{ rotor.constants.tls_content_handshake, rotor.constants.tls_content_application }, .{ body, body }));
    const connection = &rig.engine.connections[0];
    try testing.expect(connection.state == .closing);
    try testing.expectEqual(@as(usize, 0), connection.tls.record_in_used);
    try rig.deinit();
}

test "a record opens into the frame after a partial message at its longest" {
    // The frame holds all but the last octet of a message of 65535. A record ends it and carries
    // a whole message after it. The record's plaintext fits after the partial message.
    var rig: Rig = .{};
    try up(&rig, 54);
    const connection = &rig.engine.connections[0];
    const prefix = cocuyo.constants.tcp_prefix_bytes;
    const partial = prefix + cocuyo.limits.message_bytes_max - 1;
    @memset(connection.frame[0..partial], 0);
    std.mem.writeInt(u16, connection.frame[0..prefix], cocuyo.limits.message_bytes_max, .big);
    connection.used = partial;
    // The record's body: the message's last octet, then a message of zeros with its prefix.
    const body = fixtures.record_plaintext_bytes_max;
    var record: [io.constants.tls_record_header_bytes + body]u8 = undefined;
    const len = record_of_zeros(&record, rotor.constants.tls_content_application, body);
    const header = io.constants.tls_record_header_bytes;
    std.mem.writeInt(u16, record[header + 1 ..][0..prefix], @intCast(body - 1 - prefix), .big);
    record[header] = 0;
    take_in_chunks(&rig, record[0..len]);
    try testing.expect(connection.state == .up);
    try testing.expectEqual(@as(usize, 0), connection.used);
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    try rig.deinit();
}

test "a prefix in a record that says more than the connection assembles ends it after close_notify" {
    // That message is never whole, and the stream cannot be read past it (the stream's rule 11).
    // The server drops every query, so the lookup waits until then, and hears the failure at once.
    // The peer is still there, so the session says close_notify, and the connection closes once
    // that has gone (TLS rule 5). It reads nothing more, so the record after it is not read. A
    // send the loop refuses fails the connection at once, and the rest of the chunk is not its.
    const body = cocuyo.constants.tcp_prefix_bytes + fixtures.tiny_message_bytes + 1;
    const application = rotor.constants.tls_content_application;
    for ([_]bool{ false, true }) |refused| {
        var rig: TinyRig = .{};
        try start(&rig, 58, .{ .{ .drop_per_256 = fixtures.always }, .{ .down = true } });
        const handle = try rig.engine.start(question("example.com."), rig.loop.now());
        try sim_test.until_sent(&rig);
        var stream: BackToBack = .{};
        rig.loop.refuse_submissions = refused;
        take_in_chunks(&rig, stream.init(.{ application, application }, .{ body, body }));
        rig.loop.refuse_submissions = false;
        const connection = &rig.engine.connections[0];
        const state: @TypeOf(connection.state) = if (refused) .closed else .closing;
        try testing.expect(connection.state == state);
        try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
        // The last record sealed is the session's close_notify (RFC 9846 §6.1).
        const notify = rotor.constants.tls_close_notify;
        const sealed = connection.tls.out[0..connection.tls.out_tail];
        if (!refused) try testing.expectEqualSlices(u8, &notify, sealed[sealed.len - notify.len ..]);
        if (!refused) try testing.expectEqual(rotor.constants.tls_content_alert, sealed[sealed.len - io.constants.tls_record_header_bytes - notify.len]);
        rig.engine.cancel(handle, rig.loop.now());
        _ = try rig.until_result();
        _ = rig.engine.take(rig.loop.now());
        _ = try rig.step(fixtures.wait_ns);
        try testing.expect(connection.state == .closed and connection.tls.record_in_used == 0);
        try rig.deinit();
    }
}

test "every whole record one chunk carries goes to the session with it, the last one too" {
    // Here the lookup's answer is in the last record of a full chunk. No chunk follows it,
    // because the server drops every query. The lookup has its answer before its deadline (TLS
    // rule 7).
    var rig: Rig = .{};
    try start(&rig, 55, .{ .{ .drop_per_256 = fixtures.always }, .{ .down = true } });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    try sim_test.until_sent(&rig);
    var answer: [rotor.limits.tls_payload_bytes_max]u8 = undefined;
    const answer_bytes = try sim_test.framed_answer(&rig.engine, handle, &answer);
    // Each record before the answer's record holds a header of zeros. Such a header is a query,
    // and no lookup takes a query (docs/design.md §7, check 4).
    const header = cocuyo.constants.header_bytes;
    var message: [cocuyo.constants.tcp_prefix_bytes + header]u8 = @splat(0);
    cocuyo.wire.header.write_message_len(&message, @intCast(header));
    const record_bytes = rotor.constants.tls_record_header_bytes;
    const others = (io.limits.tcp_chunk_bytes_max - record_bytes - answer_bytes) / (record_bytes + message.len);
    var chunk: [io.limits.tcp_chunk_bytes_max]u8 = undefined;
    var used: usize = 0;
    for (0..others) |_| used += rotor.tls.write_record(rotor.constants.tls_content_application, &message, chunk[used..]);
    used += rotor.tls.write_record(rotor.constants.tls_content_application, answer[0..answer_bytes], chunk[used..]);
    // `take_chunk` gives the chunk to `take`, and `apply` then drives the engine, as after each
    // event.
    io.tls.take(&rig.engine, 0, chunk[0..used], rig.loop.now());
    rig.engine.drive(rig.loop.now());
    try testing.expectEqual(@as(usize, 0), rig.engine.connections[0].tls.record_in_used);
    const result = try rig.until_result();
    try testing.expectEqual(handle, result.handle);
    try testing.expect(result.outcome == .answer);
    try testing.expect(rig.loop.now() < rig.config.timeout_ns);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a buffer of records that are their header alone goes to the session whole" {
    // Each record is at least its five-octet header, and a peer may send empty records (RFC 9846
    // §5.1). Thus the buffer holds no more records than its length in headers. No whole record
    // stays for a chunk that may not come (TLS rule 7).
    var rig: Rig = .{};
    try up(&rig, 57);
    const state = &rig.engine.connections[0].tls;
    const empty = rotor.tls.write_record(rotor.constants.tls_content_application, &.{}, &state.record_in);
    try testing.expectEqual(io.limits.tls_records_per_buffer_max, state.record_in.len / empty);
    var at: usize = empty;
    while (at + empty <= state.record_in.len) : (at += empty) @memcpy(state.record_in[at..][0..empty], state.record_in[0..empty]);
    state.record_in_used = at;
    io.tls.take(&rig.engine, 0, &.{}, rig.loop.now());
    try testing.expectEqual(@as(usize, 0), state.record_in_used);
    try testing.expect(rig.engine.connections[0].state == .up);
    try rig.deinit();
}

test "a ticket is kept and spent, and a declined one is answered in full, counting no failure" {
    var rig: Rig = .{};
    try start(&rig, 45, .{ .{ .tls = .{ .tickets = true, .decline_tickets = true } }, .{} });
    _ = try rig.engine.start(question("one.example."), rig.loop.now());
    _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    try testing.expect(rig.engine.tls_tickets[0] != null);
    try idle(&rig);
    _ = try rig.step(fixtures.wait_ns);
    try testing.expect(rig.engine.connections[0].state == .closed);
    // The next connection resumes, spending the ticket; the server declines it, and the
    // connection opens again in full before the lookup hears anything (TLS rule 8).
    _ = try rig.engine.start(question("two.example."), rig.loop.now());
    try testing.expect(rig.engine.tls_tickets[0] == null);
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a ticket seven days old is not spent: the opening handshakes in full" {
    var rig: Rig = .{};
    try start(&rig, 46, .{ .{}, .{} });
    // "Clients MUST NOT use tickets for longer than 7 days after issuance" (RFC 9846 §4.7.1).
    const week_ns = io.limits.tls_ticket_age_ns_max;
    rig.engine.tls_tickets[0] = .{ .ticket = .{}, .since_ns = 0 };
    io.tls.spend(&rig.engine, 0, 0, week_ns);
    try testing.expect(rig.engine.connections[0].tls.ticket == null);
    try testing.expect(rig.engine.tls_tickets[0] == null);
    // A nanosecond younger, it is spent.
    rig.engine.tls_tickets[0] = .{ .ticket = .{}, .since_ns = 0 };
    io.tls.spend(&rig.engine, 0, 0, week_ns - 1);
    try testing.expect(rig.engine.connections[0].tls.ticket != null);
    try rig.deinit();
}
