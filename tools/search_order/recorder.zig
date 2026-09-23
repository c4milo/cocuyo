//! A DNS server that writes down every question it is asked, for `tools/search_order/run.sh`
//! (docs/design.md §5, §17 question 7). It answers from a script given on the command line:
//!
//!     recorder <port> [answer:<name>] [nodata:<name>] [servfail:<name>] ...
//!
//! A name listed under `answer` gets one A record, 192.0.2.1 (RFC 5737), and no record of any other
//! type. One under `nodata` gets NOERROR with no record, and one under `servfail` gets SERVFAIL.
//! Every other name gets NXDOMAIN, so a resolver walking a search list walks all of it and the
//! log shows the order it walked. Each question is printed as `<name> <type>` on its own line.
//!
//! It is a probe, not a server: it reads the header and the question and nothing else, and it
//! never compresses a name but the one pointer an answer needs to the question.
const std = @import("std");

/// A question's name in text, lower-cased and without its trailing dot: at most 253 octets
/// (RFC 1035 §2.3.4), with room for the dots.
const name_text_bytes_max = 256;
/// Past the 512 octets of RFC 1035 §4.2.1 that a query without EDNS may use.
const datagram_bytes_max = 4096;
const header_bytes = 12;
const rules_max = 16;

const type_a = 1;
const type_aaaa = 28;
const rcode_servfail = 2;
const rcode_nxdomain = 3;

const Rule = struct {
    kind: enum { answer, nodata, servfail },
    name: []const u8,
};

const Question = struct {
    name: []const u8,
    qtype: u16,
    /// Where the question ends in the query: the reply copies it that far.
    end: usize,
};

/// The first question of `query`, its name written into `text`, or null for anything that is not
/// a plain query with one uncompressed question.
fn question_of(query: []const u8, text: *[name_text_bytes_max]u8) ?Question {
    if (query.len < header_bytes) return null;
    var at: usize = header_bytes;
    var length: usize = 0;
    while (at < query.len) {
        const label = query[at];
        at += 1;
        if (label == 0) break;
        if (label & 0xc0 != 0 or at + label > query.len or length + label + 1 > text.len) return null;
        if (length > 0) {
            text[length] = '.';
            length += 1;
        }
        for (query[at .. at + label], text[length .. length + label]) |from, *to| to.* = std.ascii.toLower(from);
        length += label;
        at += label;
    } else return null;
    if (at + 4 > query.len) return null;
    const qtype = std.mem.readInt(u16, query[at..][0..2], .big);
    return .{ .name = text[0..length], .qtype = qtype, .end = at + 4 };
}

/// The reply to `query` under `rules`, written into `out`.
fn reply(query: []const u8, question: Question, rules: []const Rule, out: []u8) []const u8 {
    var rcode: u8 = rcode_nxdomain;
    var answer = false;
    for (rules) |rule| {
        if (!std.mem.eql(u8, rule.name, question.name)) continue;
        switch (rule.kind) {
            .answer => {
                rcode = 0;
                answer = question.qtype == type_a;
            },
            .nodata => rcode = 0,
            .servfail => rcode = rcode_servfail,
        }
    }
    @memcpy(out[0..2], query[0..2]);
    // QR set; the opcode and RD copied; RA set (RFC 1035 §4.1.1).
    out[2] = 0x80 | (query[2] & 0x79);
    out[3] = 0x80 | rcode;
    std.mem.writeInt(u16, out[4..6], 1, .big);
    std.mem.writeInt(u16, out[6..8], @intFromBool(answer), .big);
    @memset(out[8..header_bytes], 0);
    const question_bytes = query[header_bytes..question.end];
    @memcpy(out[header_bytes..][0..question_bytes.len], question_bytes);
    var at = header_bytes + question_bytes.len;
    if (answer) {
        // A pointer to the question's name, type A, class IN, a TTL of 60 and 192.0.2.1.
        const record = [_]u8{ 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1 };
        @memcpy(out[at..][0..record.len], &record);
        at += record.len;
    }
    return out[0..at];
}

fn parse_rule(argument: []const u8) !Rule {
    const colon = std.mem.indexOfScalar(u8, argument, ':') orelse return error.BadRule;
    const kind = argument[0..colon];
    const name = std.mem.trimEnd(u8, argument[colon + 1 ..], ".");
    if (std.mem.eql(u8, kind, "answer")) return .{ .kind = .answer, .name = name };
    if (std.mem.eql(u8, kind, "nodata")) return .{ .kind = .nodata, .name = name };
    if (std.mem.eql(u8, kind, "servfail")) return .{ .kind = .servfail, .name = name };
    return error.BadRule;
}

fn type_name(qtype: u16) []const u8 {
    return switch (qtype) {
        type_a => "A",
        type_aaaa => "AAAA",
        else => "other",
    };
}

pub fn main(init: std.process.Init) !void {
    const arguments = try init.minimal.args.toSlice(init.arena.allocator());
    if (arguments.len < 2 or arguments.len - 2 > rules_max) {
        std.debug.print("usage: recorder <port> [answer|nodata|servfail:<name>] ...\n", .{});
        return error.Usage;
    }
    const port = try std.fmt.parseInt(u16, arguments[1], 10);
    var rules: [rules_max]Rule = undefined;
    for (arguments[2..], rules[0 .. arguments.len - 2]) |argument, *rule| rule.* = try parse_rule(argument);
    const io = init.io;
    var address: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } };
    const socket = try address.bind(io, .{ .mode = .dgram });
    defer socket.close(io);
    var buffer: [datagram_bytes_max]u8 = undefined;
    var out: [datagram_bytes_max]u8 = undefined;
    var text: [name_text_bytes_max]u8 = undefined;
    while (true) {
        const message = try socket.receive(io, &buffer);
        const question = question_of(message.data, &text) orelse continue;
        std.debug.print("{s} {s}\n", .{ question.name, type_name(question.qtype) });
        try socket.send(io, &message.from, reply(message.data, question, rules[0 .. arguments.len - 2], &out));
    }
}

// Tests.

const testing = std.testing;

/// A query for `www.Example.test` type A, id 0x1234, RD set.
const sample_query = [_]u8{ 0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 } ++
    [_]u8{3} ++ "www".* ++ [_]u8{7} ++ "Example".* ++ [_]u8{4} ++ "test".* ++ [_]u8{ 0, 0, 1, 0, 1 };

test "a question reads back as its name in lower case, and its type" {
    var text: [name_text_bytes_max]u8 = undefined;
    const question = question_of(&sample_query, &text).?;
    try testing.expectEqualStrings("www.example.test", question.name);
    try testing.expectEqual(@as(u16, type_a), question.qtype);
    try testing.expectEqual(sample_query.len, question.end);
    try testing.expectEqual(@as(?Question, null), question_of(sample_query[0..20], &text));
}

test "a listed name gets its answer, and any other name NXDOMAIN" {
    var text: [name_text_bytes_max]u8 = undefined;
    var out: [datagram_bytes_max]u8 = undefined;
    const question = question_of(&sample_query, &text).?;
    const answered = reply(&sample_query, question, &.{try parse_rule("answer:www.example.test.")}, &out);
    // The query's id, the response bit with the query's RD, and RA (RFC 1035 §4.1.1).
    try testing.expectEqualSlices(u8, &.{ 0x12, 0x34, 0x81 }, answered[0..3]);
    try testing.expectEqual(@as(u8, 0x80), answered[3]);
    try testing.expectEqual(@as(u8, 1), answered[7]);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, answered[answered.len - 4 ..]);
    const missing = reply(&sample_query, question, &.{try parse_rule("servfail:other.test")}, &out);
    try testing.expectEqual(@as(u8, 0x80 | rcode_nxdomain), missing[3]);
    try testing.expectEqual(@as(u8, 0), missing[7]);
    const failing = reply(&sample_query, question, &.{try parse_rule("servfail:www.example.test")}, &out);
    try testing.expectEqual(@as(u8, 0x80 | rcode_servfail), failing[3]);
}
