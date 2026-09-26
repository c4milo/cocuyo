//! The records beyond A that `tools/interop/run.sh` asks dnsproxy for (c4milo/cocuyo#20), served
//! over UDP on the loopback as dnsproxy's upstream. dnsproxy's hosts file answers addresses
//! alone, so this answers every other type, for two names under `.example` (RFC 2606 §3):
//!
//!     zone <port>
//!
//! - `typed.example` has an A, 192.0.2.5 (RFC 5737), two AAAA, 2001:db8::5 and 2001:db8::6
//!   (RFC 3849), two MX, `10 mail.typed.example` and `20 backup.typed.example`, two TXT, one of
//!   one string and one of two, and an HTTPS record, `1 . alpn=h3,h2 port=8443` (RFC 9460).
//! - `alias.typed.example` is a CNAME to `typed.example`, and an answer for it carries the CNAME
//!   and then `typed.example`'s records of the type asked (RFC 1034 §3.6.2).
//!
//! Any other type of these names is NODATA, and any other name NXDOMAIN. It writes every name in
//! full, but the owner of a first record, which points at the question: dnsproxy reads the answer
//! and writes it out again, compressed as it chooses, which is what cocuyo reads.
const std = @import("std");

/// A question's name in text, lower-cased and without its trailing dot: at most 253 octets
/// (RFC 1035 §2.3.4), with room for the dots.
const name_text_bytes_max = 256;
/// Past the 512 octets of RFC 1035 §4.2.1 that a query without EDNS may use.
const datagram_bytes_max = 4096;
const header_bytes = 12;
/// A pointer to the question's name, which starts right after the header (RFC 1035 §4.1.4).
const question_pointer = [_]u8{ 0xc0, header_bytes };
const class_internet = 1;
const ttl_seconds = 60;
const rcode_nxdomain = 3;

const type_a = 1;
const type_cname = 5;
const type_mx = 15;
const type_txt = 16;
const type_aaaa = 28;
const type_https = 65;

const typed_name = "typed.example";
const alias_name = "alias.typed.example";
const typed_wire = "\x05typed\x07example\x00";

const Record = struct { kind: u16, rdata: []const u8 };

/// `typed.example`'s records, each type's in the order they are written.
const typed_records = [_]Record{
    .{ .kind = type_a, .rdata = &.{ 192, 0, 2, 5 } },
    .{ .kind = type_aaaa, .rdata = &(.{ 0x20, 0x01, 0x0d, 0xb8 } ++ .{0} ** 11 ++ .{5}) },
    .{ .kind = type_aaaa, .rdata = &(.{ 0x20, 0x01, 0x0d, 0xb8 } ++ .{0} ** 11 ++ .{6}) },
    .{ .kind = type_mx, .rdata = "\x00\x0a\x04mail" ++ typed_wire },
    .{ .kind = type_mx, .rdata = "\x00\x14\x06backup" ++ typed_wire },
    .{ .kind = type_txt, .rdata = "\x0bv=spf1 -all" },
    .{ .kind = type_txt, .rdata = "\x05first\x06second" },
    // Priority 1, the root as target, then alpn (key 1) with `h3` and `h2`, and port (key 3) with
    // 8443, the keys in ascending order (RFC 9460 §2.2).
    .{ .kind = type_https, .rdata = "\x00\x01\x00" ++ "\x00\x01\x00\x06\x02h3\x02h2" ++ "\x00\x03\x00\x02\x20\xfb" },
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
    for (0..query.len) |_| {
        if (at >= query.len) return null;
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
    }
    if (at + 4 > query.len) return null;
    const qtype = std.mem.readInt(u16, query[at..][0..2], .big);
    return .{ .name = text[0..length], .qtype = qtype, .end = at + 4 };
}

/// Writes records one after another into a reply, counting them.
const Writer = struct {
    out: []u8,
    at: usize,
    count: u16 = 0,

    fn record(self: *Writer, owner: []const u8, kind: u16, rdata: []const u8) void {
        @memcpy(self.out[self.at..][0..owner.len], owner);
        self.at += owner.len;
        std.mem.writeInt(u16, self.out[self.at..][0..2], kind, .big);
        std.mem.writeInt(u16, self.out[self.at + 2 ..][0..2], class_internet, .big);
        std.mem.writeInt(u32, self.out[self.at + 4 ..][0..4], ttl_seconds, .big);
        std.mem.writeInt(u16, self.out[self.at + 8 ..][0..2], @intCast(rdata.len), .big);
        self.at += 10;
        @memcpy(self.out[self.at..][0..rdata.len], rdata);
        self.at += rdata.len;
        self.count += 1;
    }

    /// `typed.example`'s records of `qtype`, each owned by `owner`.
    fn typed(self: *Writer, owner: []const u8, qtype: u16) void {
        for (typed_records) |entry| {
            if (entry.kind == qtype) self.record(owner, entry.kind, entry.rdata);
        }
    }
};

/// The reply to `query`, written into `out`.
fn reply(query: []const u8, question: Question, out: []u8) []const u8 {
    const typed = std.mem.eql(u8, question.name, typed_name);
    const alias = std.mem.eql(u8, question.name, alias_name);
    const question_bytes = query[header_bytes..question.end];
    @memcpy(out[header_bytes..][0..question_bytes.len], question_bytes);
    var writer: Writer = .{ .out = out, .at = header_bytes + question_bytes.len };
    if (typed) writer.typed(&question_pointer, question.qtype);
    if (alias) {
        writer.record(&question_pointer, type_cname, typed_wire);
        if (question.qtype != type_cname) writer.typed(typed_wire, question.qtype);
    }
    @memcpy(out[0..2], query[0..2]);
    // QR and AA set; the opcode and RD copied; RA set (RFC 1035 §4.1.1).
    out[2] = 0x84 | (query[2] & 0x79);
    out[3] = 0x80 | @as(u8, if (typed or alias) 0 else rcode_nxdomain);
    std.mem.writeInt(u16, out[4..6], 1, .big);
    std.mem.writeInt(u16, out[6..8], writer.count, .big);
    @memset(out[8..header_bytes], 0);
    return out[0..writer.at];
}

pub fn main(init: std.process.Init) !void {
    const arguments = try init.minimal.args.toSlice(init.arena.allocator());
    if (arguments.len != 2) {
        std.debug.print("usage: zone <port>\n", .{});
        return error.Usage;
    }
    const port = try std.fmt.parseInt(u16, arguments[1], 10);
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
        try socket.send(io, &message.from, reply(message.data, question, &out));
    }
}

// Tests.

const testing = std.testing;

/// A query for `name` of type `qtype`, id 0x1234, RD set.
fn query_for(comptime name: []const u8, comptime qtype: u16) []const u8 {
    return comptime [_]u8{ 0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 } ++ name ++ [_]u8{ 0, qtype, 0, 1 };
}

fn answer_count(answer: []const u8) u16 {
    return std.mem.readInt(u16, answer[6..8], .big);
}

test "typed.example answers each type with its records, in any case, and NODATA for another" {
    var text: [name_text_bytes_max]u8 = undefined;
    var out: [datagram_bytes_max]u8 = undefined;
    const cases = .{ .{ type_a, 1 }, .{ type_aaaa, 2 }, .{ type_mx, 2 }, .{ type_txt, 2 }, .{ type_https, 1 }, .{ type_cname, 0 } };
    inline for (cases) |case| {
        const query = query_for("\x05TyPeD\x07example\x00", case[0]);
        const answer = reply(query, question_of(query, &text).?, &out);
        try testing.expectEqualSlices(u8, &.{ 0x12, 0x34, 0x85, 0x80 }, answer[0..4]);
        try testing.expectEqual(@as(u16, case[1]), answer_count(answer));
    }
}

test "the alias answers its CNAME, then typed.example's records of the type asked" {
    var text: [name_text_bytes_max]u8 = undefined;
    var out: [datagram_bytes_max]u8 = undefined;
    const query = query_for("\x05alias\x05typed\x07example\x00", type_mx);
    const answer = reply(query, question_of(query, &text).?, &out);
    try testing.expectEqual(@as(u16, 3), answer_count(answer));
    const cname_at = query.len;
    try testing.expectEqualSlices(u8, &(question_pointer ++ [_]u8{ 0, type_cname }), answer[cname_at..][0..4]);
    const only = query_for("\x05alias\x05typed\x07example\x00", type_cname);
    try testing.expectEqual(@as(u16, 1), answer_count(reply(only, question_of(only, &text).?, &out)));
}

test "any other name is NXDOMAIN, and a query with no whole question gets no reply" {
    var text: [name_text_bytes_max]u8 = undefined;
    var out: [datagram_bytes_max]u8 = undefined;
    const query = query_for("\x05other\x07example\x00", type_a);
    const answer = reply(query, question_of(query, &text).?, &out);
    try testing.expectEqual(@as(u8, 0x80 | rcode_nxdomain), answer[3]);
    try testing.expectEqual(@as(u16, 0), answer_count(answer));
    try testing.expectEqual(@as(?Question, null), question_of(query[0 .. query.len - 1], &text));
}
