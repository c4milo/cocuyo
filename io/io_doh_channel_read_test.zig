//! The stream octets that `cocuyo_doh` keeps until colibri takes them (`io_doh_channel_read.zig`;
//! docs/design.md §16 decision 41, §24 the interface; c4milo/cocuyo#44). colibri's server writes
//! whole records back to back. Some lengths put many whole records in one chunk. Others leave a
//! long partial record before a chunk, or put a short record after two full ones. The test plays
//! the engine, as `io_doh_channel_test.zig` does. Each chunk goes to the type, then the type is
//! read as the engine's `hear` reads it. After each read no whole record stays in the buffer. So
//! the next chunk finds a partial record at most, and fits beside it.
const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const cocuyo = @import("cocuyo");
const io = @import("io");
const client = @import("client");
const rig = @import("io_doh_channel_test.zig");
const raw_module = @import("io_doh_channel_server_raw.zig");
const constants = rig.constants;
const limits = rig.limits;

/// The requests a test has in flight: one for each of the pair's answer buffers.
const requests: usize = 2;
/// The most that one read takes, as the engine's `hear` takes it. That is an end for each request,
/// and `channel_events_max` of the channel's own (`io/limits.zig`).
const events_per_read_max: usize = requests + io.limits.channel_events_max;

/// The room for a record of 2^14 octets of plaintext and nothing after it (RFC 9846 §5.2).
const full_record_bytes: usize = limits.record_plaintext_bytes_max + io.constants.tls_record_overhead_bytes;
/// The plaintext of a short record after two full ones, in each of two lists, and the room for it.
const short_plaintext_bytes: usize = 1_000;
const longer_short_plaintext_bytes: usize = 1_500;
const short_after_full_bytes = [_]usize{
    short_plaintext_bytes + io.constants.tls_record_overhead_bytes,
    longer_short_plaintext_bytes + io.constants.tls_record_overhead_bytes,
};
/// The room for a record of 78 octets of plaintext. About twenty such records fill one chunk.
const short_record_bytes: usize = 100;

/// The room that the server writes into, call after call, in each run. Each record is at most as
/// long as its room. A run takes one list, and starts it again at its end:
///
/// - One room alone: a record at its longest, one past the engine's chunk, one short of it, or
///   one of 100 octets.
/// - Two full records, then a short one. Over HTTP/2, the first full record holds the HEADERS
///   frame of the first answer, and most of its first DATA frame. The second full record ends
///   that frame and holds most of the next. The short record comes whole in the chunk that ends
///   the second. It does not fit beside the second in colibri's room, so it opens in a second
///   pass of the read.
const patterns = [_][]const usize{
    &.{limits.output_bytes_max},
    &.{limits.engine_chunk_bytes_max + 1},
    &.{limits.engine_chunk_bytes_max - 1},
    &.{short_record_bytes},
    &.{ full_record_bytes, full_record_bytes, short_after_full_bytes[0] },
    &.{ full_record_bytes, full_record_bytes, short_after_full_bytes[1] },
};

/// Each answer's length: one that one record holds, one that crosses records, and one past two
/// DATA frames at their longest (RFC 9113 §4.2). In the last, a frame with no END_STREAM can end
/// in a full record, and the next frame cannot end there (RFC 9113 §6.1).
const short_answer_bytes: usize = 2_000;
const long_answer_bytes: usize = 20_000;
const longest_answer_bytes: usize = 40_000;
const answer_lengths = [_]usize{ short_answer_bytes, long_answer_bytes, longest_answer_bytes };
/// What the server serves, and so selects: HTTP/2, then HTTP/1.1 (RFC 7301 §3.2).
const protocols = [_]rig.Versions{ .{ .h11 = false }, .{ .h2 = false } };
/// The octet the answer is filled with after the query. Test-only.
const filler: u8 = 0x41;

/// The most that the server writes in one round: a DNS message at its longest for each request.
/// That is more than the answers and their heads.
const burst_bytes: usize = requests * cocuyo.limits.message_bytes_max;

/// What the test saw over its runs:
///
/// - the chunks that came;
/// - the chunks that put two whole records or more in the buffer before the read;
/// - the most that the buffer held with a chunk.
const Tally = struct {
    chunks: usize = 0,
    back_to_back: usize = 0,
    most: usize = 0,
};

/// Answers a query with the query, the QR bit set, and filler to the length `context` names.
fn long_answer(context: *anyopaque, asked: []const u8, out: []u8) ?usize {
    const length: *const usize = @ptrCast(@alignCast(context));
    @memcpy(out[0..asked.len], asked);
    out[rig.flags_at] |= rig.qr_bit;
    @memset(out[asked.len..length.*], filler);
    return length.*;
}

/// The whole records at the start of `octets`. Each is its header, then the octets that the
/// header's length gives (RFC 9846 §5.1).
fn whole_records(octets: []const u8) usize {
    const header = io.constants.tls_record_header_bytes;
    var at: usize = 0;
    var count: usize = 0;
    // Bounded: each pass passes a header at least, or stops.
    for (0..octets.len / header + 1) |_| {
        if (octets.len - at < header) break;
        const length = std.mem.readInt(u16, octets[at + io.constants.tls_record_length_at ..][0..@sizeOf(u16)], .big);
        if (octets.len - at - header < length) break;
        at += header + length;
        count += 1;
    }
    return count;
}

/// Reads the type as the engine's `hear` reads it. A sound stream says less than the bound, so the
/// read ends with nothing more to say and leaves nothing for the next read.
fn read(pair: *rig.Pair) !void {
    for (0..events_per_read_max) |_| {
        const event = pair.doh.next(pair.now_ns) orelse return;
        try pair.note(event);
    }
    return error.ReadBoundReached;
}

/// How the server's octets reach the type: in records whose rooms follow `pattern`, in the engine's
/// chunks. With `stray`, a datagram that colibri takes and says nothing of comes before each chunk.
const Delivery = struct { pattern: []const usize, stray: bool = false };

/// A datagram of zeros for the QUIC link, whose attempt has no handshake: colibri takes it whole
/// and says nothing of it. Test-only.
const stray_datagram_bytes: usize = 64;
const stray_datagram: [stray_datagram_bytes]u8 = @splat(0);

/// One chunk to the type, after a stray datagram when `stray` says so, then a read. Every whole
/// record leaves with that read, and so does the datagram.
fn deliver(pair: *rig.Pair, chunk: []const u8, stray: bool, tally: *Tally) !void {
    tally.most = @max(tally.most, pair.doh.stream_len + chunk.len);
    if (stray) pair.doh.receive(.{ .datagram = &stray_datagram }, pair.now_ns);
    pair.doh.receive(.{ .stream = chunk }, pair.now_ns);
    try testing.expect(!pair.doh.stream_overrun);
    tally.chunks += 1;
    if (whole_records(pair.doh.stream[0..pair.doh.stream_len]) > 1) tally.back_to_back += 1;
    try read(pair);
    try testing.expectEqual(@as(usize, 0), whole_records(pair.doh.stream[0..pair.doh.stream_len]));
    try testing.expectEqual(@as(usize, 0), pair.doh.inbound_len);
}

/// What the TCP link owes goes to the server. What the server owes comes back as `delivery` says,
/// with a read after each chunk.
fn carry(pair: *rig.Pair, answer_length: *usize, delivery: Delivery, burst: []u8, tally: *Tally) !void {
    const pattern = delivery.pattern;
    _ = pair.doh.datagram(&pair.wire, pair.now_ns);
    const answerer: rig.Answerer = .{ .context = answer_length, .answer = long_answer };
    const up = pair.doh.output(&pair.wire, pair.now_ns);
    if (up > 0) pair.server.receive(pair.wire[0..up], answerer, pair.now_ns);
    var down: usize = 0;
    // Bounded: each pass writes an octet at least, or stops.
    for (0..burst.len) |call| {
        const room = @min(pattern[call % pattern.len], burst.len - down);
        const sent = if (room == 0) 0 else pair.server.send(burst[down..][0..room], answerer, pair.now_ns);
        if (sent == 0) break;
        down += sent;
    }
    pair.carried = pair.carried or up > 0 or down > 0;
    var at: usize = 0;
    while (at < down) : (at += limits.engine_chunk_bytes_max) {
        try deliver(pair, burst[at..@min(down, at + limits.engine_chunk_bytes_max)], delivery.stray, tally);
    }
}

/// Rounds until both requests have ended, as `Pair.run` moves the clock.
fn exchange(pair: *rig.Pair, answer_length: *usize, delivery: Delivery, burst: []u8, tally: *Tally) !void {
    for (0..rig.rounds_max) |_| {
        try read(pair);
        if (pair.count(.finished) == requests) return;
        const moved = pair.carried;
        pair.carried = false;
        try carry(pair, answer_length, delivery, burst, tally);
        pair.now_ns += rig.round_ns;
        const due = pair.doh.deadline() orelse continue;
        if (!moved and !pair.carried) pair.now_ns = @max(pair.now_ns, due);
        if (due <= pair.now_ns) pair.doh.expire(pair.now_ns);
    }
    return error.NotFinished;
}

/// Each request ended with its answer whole: the query, the QR bit set, then the filler.
fn expect_answers(pair: *const rig.Pair, answer_length: usize) !void {
    var expected: [rig.query.len]u8 = rig.query;
    expected[rig.flags_at] |= rig.qr_bit;
    for (pair.said[0..pair.said_len]) |event| {
        if (event != .finished) continue;
        const message = (if (event.finished.result == .answer) event.finished.result.answer else return error.NoAnswer).message;
        try testing.expectEqual(answer_length, message.len);
        try testing.expectEqualSlices(u8, &expected, message[0..expected.len]);
        try testing.expect(std.mem.allEqual(u8, message[expected.len..], filler));
    }
}

/// One run: two requests, both answered as `delivery` says.
fn run(versions: rig.Versions, delivery: Delivery, answer_length: usize, burst: []u8, tally: *Tally) !void {
    const pair = try rig.Pair.create(.{ .versions = versions });
    defer pair.free();
    var length = answer_length;
    for (0..requests) |index| try testing.expect(pair.doh.request(@intCast(index), &rig.query, pair.now_ns));
    try exchange(pair, &length, delivery, burst, tally);
    try expect_answers(pair, answer_length);
}

test "whole records back to back leave the buffer with the read after each chunk, so the next chunk fits beside a partial record" {
    // Decision 41's rule at the DoH channel (c4milo/cocuyo#44). Over HTTP/2 colibri holds a
    // partial frame and room for a record. Over HTTP/1.1 it holds a partial head of a usual length
    // and room for a record. A read goes on until the channel says nothing more. So no whole record
    // waits for the next chunk.
    const burst = try testing.allocator.alloc(u8, burst_bytes);
    defer testing.allocator.free(burst);
    var tally: Tally = .{};
    for (protocols) |versions| {
        for (patterns) |pattern| {
            for (answer_lengths) |answer_length| try run(versions, .{ .pattern = pattern }, answer_length, burst, &tally);
        }
    }
    // The runs put whole records back to back in a chunk, and a long partial record before a chunk.
    // With the chunk, that partial record passed a record at its longest. So the chunk used the
    // room that decision 41 gives it.
    try testing.expect(tally.back_to_back > 0);
    try testing.expect(tally.most > limits.record_bytes_max);
    try testing.expect(tally.most <= limits.stream_bytes_max);
}

test "a read hands colibri the stream's whole records after a datagram that it took and said nothing of" {
    // The type keeps a datagram and the stream's octets apart, and `next` hands colibri both, the
    // datagram first. The pass that takes the datagram says nothing, so the read goes on, and the
    // stream's whole records leave with the same read. Since colibri v0.8.0 one pass opens each
    // whole record of the stream, so a datagram before them is what makes the second pass.
    const burst = try testing.allocator.alloc(u8, burst_bytes);
    defer testing.allocator.free(burst);
    var tally: Tally = .{};
    for (protocols) |versions| {
        try run(versions, .{ .pattern = &.{short_record_bytes}, .stray = true }, short_answer_bytes, burst, &tally);
    }
    try testing.expect(tally.back_to_back > 0);
}

/// colibri's longest head, `h11.constants.head_len_max`, 32,768 octets at v0.8.0. No module here
/// imports `h11`, so it is read as `client.constants.stream_input_len_min`: the longest unit a TCP
/// connection takes whole, which is the head while the head is longer than a frame and a record.
const head_bytes_longest = client.constants.stream_input_len_min;
comptime {
    assert(head_bytes_longest > client.constants.frame_len_max);
    assert(head_bytes_longest > client.constants.stream_output_len_min);
}
/// A head longer than colibri v0.6.0's room held beside a full record, 16,632 octets
/// (docs/design.md §17 question 52).
const head_bytes_long: usize = 20_000;
/// The plaintext of the first record in the probe of 2026-10-17 (docs/mutations.md, The DoH
/// channel's stream buffer).
const first_record_plaintext_bytes: usize = 1_000;
/// The answer's length, so that the record after the head's long partial part is full.
const raw_answer_bytes: usize = 20_000;

/// A head's length, and the plaintext lengths of its records, the last again until the end.
const Case = struct { head_bytes: usize, lengths: []const usize };
const cases = [_]Case{
    // The probe's shape: after the second record, 17,384 octets of the head wait.
    .{ .head_bytes = head_bytes_long, .lengths = &.{ first_record_plaintext_bytes, limits.record_plaintext_bytes_max } },
    // The longest head: 32,767 octets of it wait before the full record that ends it.
    .{ .head_bytes = head_bytes_longest, .lengths = &.{ limits.record_plaintext_bytes_max - 1, limits.record_plaintext_bytes_max } },
};

/// The start of each head: a 200, the media type, and a field whose value has whitespace before
/// it to fill the head. The whitespace is no part of the value (RFC 9110 §5.5), so it counts in
/// the head, and not in the field section that colibri's client bounds.
const head_start = "HTTP/1.1 200 OK\r\ncontent-type: application/dns-message\r\ncontent-length: {d}\r\nx-fill:";
const head_tail = "v\r\n\r\n";

/// A response head of `length` octets, for content `content_length` octets long, written into
/// `out`.
fn head_of(out: []u8, length: usize, content_length: usize) []const u8 {
    const start = std.fmt.bufPrint(out, head_start, .{content_length}) catch unreachable;
    assert(length > start.len + head_tail.len);
    const fill = length - start.len - head_tail.len;
    @memset(out[start.len..][0..fill], ' ');
    @memcpy(out[start.len + fill ..][0..head_tail.len], head_tail);
    return out[0..length];
}

/// The raw server's answer of `length` octets: the query, the QR bit set, then the filler.
fn raw_answer(out: []u8, length: usize) []const u8 {
    @memcpy(out[0..rig.query.len], &rig.query);
    out[rig.flags_at] |= rig.qr_bit;
    @memset(out[rig.query.len..length], filler);
    return out[0..length];
}

/// The response the raw server sends: the case's head, then the answer.
const RawResponse = struct { head: []const u8, content: []const u8, lengths: []const usize };

/// What the TCP link owes goes to the raw server, which answers once the heads it waits for are
/// whole. What it owes comes back in the engine's chunks, with a read after each.
fn carry_raw(pair: *rig.Pair, raw: *raw_module.RawServer, response: RawResponse, burst: []u8, tally: *Tally) !void {
    _ = pair.doh.datagram(&pair.wire, pair.now_ns);
    const up = pair.doh.output(&pair.wire, pair.now_ns);
    if (up > 0) try raw.receive(pair.wire[0..up]);
    if (raw.asked and !raw.answered) try raw.respond(response.head, response.content, response.lengths);
    const down = raw.send(burst);
    pair.carried = pair.carried or up > 0 or down > 0;
    var at: usize = 0;
    while (at < down) : (at += limits.engine_chunk_bytes_max) {
        try deliver(pair, burst[at..@min(down, at + limits.engine_chunk_bytes_max)], false, tally);
    }
}

/// Rounds until `ended` requests have ended, as `exchange` moves the clock.
fn exchange_raw(pair: *rig.Pair, raw: *raw_module.RawServer, response: RawResponse, ended: usize, burst: []u8, tally: *Tally) !void {
    for (0..rig.rounds_max) |_| {
        try read(pair);
        if (pair.count(.finished) == ended) return;
        const moved = pair.carried;
        pair.carried = false;
        try carry_raw(pair, raw, response, burst, tally);
        pair.now_ns += rig.round_ns;
        const due = pair.doh.deadline() orelse continue;
        if (!moved and !pair.carried) pair.now_ns = @max(pair.now_ns, due);
        if (due <= pair.now_ns) pair.doh.expire(pair.now_ns);
    }
    return error.NotFinished;
}

test "a head longer than colibri v0.6.0 held beside a record arrives whole over HTTP/1.1, and is answered" {
    // c4milo/cocuyo#44 and docs/design.md §17 question 52: colibri v0.6.0 kept 33,033 octets of
    // room. After 16,632 octets of a head, a full record did not fit, and the next chunks ended the
    // link. colibri v0.8.0 keeps its longest partial head and one record more.
    const burst = try testing.allocator.alloc(u8, burst_bytes);
    defer testing.allocator.free(burst);
    const head = try testing.allocator.alloc(u8, head_bytes_longest);
    defer testing.allocator.free(head);
    const raw = try testing.allocator.create(raw_module.RawServer);
    defer testing.allocator.destroy(raw);
    var content: [raw_answer_bytes]u8 = undefined;
    var tally: Tally = .{};
    for (cases) |case| {
        const pair = try rig.Pair.create(.{});
        defer pair.free();
        try raw.init(rig.identity_seconds, 1);
        const response: RawResponse = .{ .head = head_of(head, case.head_bytes, raw_answer_bytes), .content = raw_answer(&content, raw_answer_bytes), .lengths = case.lengths };
        try testing.expect(pair.doh.request(0, &rig.query, pair.now_ns));
        try exchange_raw(pair, raw, response, 1, burst, &tally);
        try expect_answers(pair, raw_answer_bytes);
        try testing.expectEqual(.h11, pair.doh.connected().?.protocol);
    }
    // A long partial record waited before a chunk, as the records of the head came.
    try testing.expect(tally.most > limits.record_bytes_max);
}

/// The answers of the trailer test, and its trailer section with the empty line that ends it.
/// colibri v0.8.0 reads a trailer section of up to 24,576 octets (`h11.constants.trailer_len_max`).
const trailer_answer_bytes: usize = 10_000;
const trailer_bytes: usize = 24_000;
/// The octets of the trailer section that wait before the full record after them: more than the
/// 16,632 that colibri v0.6.0 held beside a full record (docs/design.md §17 question 52).
const trailer_waiting_bytes: usize = 17_000;

/// The first response: a chunked body of one chunk, then a trailer section that whitespace before
/// a value fills (RFC 9110 §5.5, §6.5). The second response has a head of a usual length.
const chunked_head = "HTTP/1.1 200 OK\r\ncontent-type: application/dns-message\r\ntransfer-encoding: chunked\r\n\r\n";
const chunk_line = "{x}\r\n";
const chunk_end = "\r\n";
const last_chunk = "0\r\n";
const trailer_start = "x-fill:";
const trailer_tail = "v\r\n\r\n";
const length_head = "HTTP/1.1 200 OK\r\ncontent-type: application/dns-message\r\ncontent-length: {d}\r\n\r\n";

/// Both responses, back to back, and where the first one's trailer section starts.
const TwoResponses = struct { octets: []const u8, trailer_at: usize };

fn put(out: []u8, octets: []const u8) usize {
    @memcpy(out[0..octets.len], octets);
    return octets.len;
}

/// Writes both responses into `out`.
fn two_responses(out: []u8) TwoResponses {
    var at = put(out, chunked_head);
    at += (std.fmt.bufPrint(out[at..], chunk_line, .{trailer_answer_bytes}) catch unreachable).len;
    at += raw_answer(out[at..], trailer_answer_bytes).len;
    at += put(out[at..], chunk_end);
    at += put(out[at..], last_chunk);
    const trailer_at = at;
    at += put(out[at..], trailer_start);
    const fill = trailer_bytes - trailer_start.len - trailer_tail.len;
    @memset(out[at..][0..fill], ' ');
    at += fill;
    at += put(out[at..], trailer_tail);
    assert(at - trailer_at == trailer_bytes);
    at += (std.fmt.bufPrint(out[at..], length_head, .{trailer_answer_bytes}) catch unreachable).len;
    at += raw_answer(out[at..], trailer_answer_bytes).len;
    return .{ .octets = out[0..at], .trailer_at = trailer_at };
}

test "a trailer section longer than colibri v0.6.0 held beside a record arrives whole over HTTP/1.1" {
    // docs/design.md §17 question 52: colibri reads a trailer section only when it is whole, as it
    // reads a head. After the second record, 17,000 octets of the first response's trailer section
    // wait. The second response, pipelined behind it, fills the full record that comes next.
    const burst = try testing.allocator.alloc(u8, burst_bytes);
    defer testing.allocator.free(burst);
    const plaintext = try testing.allocator.alloc(u8, limits.server_response_bytes_max);
    defer testing.allocator.free(plaintext);
    const raw = try testing.allocator.create(raw_module.RawServer);
    defer testing.allocator.destroy(raw);
    var tally: Tally = .{};
    const pair = try rig.Pair.create(.{});
    defer pair.free();
    try raw.init(rig.identity_seconds, requests);
    const responses = two_responses(plaintext);
    const record_after_bytes = responses.trailer_at + trailer_waiting_bytes + limits.record_plaintext_bytes_max;
    try testing.expect(record_after_bytes <= responses.octets.len);
    const lengths = [_]usize{ responses.trailer_at + trailer_waiting_bytes - limits.record_plaintext_bytes_max, limits.record_plaintext_bytes_max };
    for (0..requests) |index| try testing.expect(pair.doh.request(@intCast(index), &rig.query, pair.now_ns));
    try exchange_raw(pair, raw, .{ .head = responses.octets, .content = "", .lengths = &lengths }, requests, burst, &tally);
    try expect_answers(pair, trailer_answer_bytes);
    try testing.expectEqual(@as(usize, requests), pair.count(.finished));
    try testing.expectEqual(.h11, pair.doh.connected().?.protocol);
    try testing.expect(tally.most > limits.record_bytes_max);
}
