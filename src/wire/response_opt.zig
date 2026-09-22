//! The OPT record of a response, wherever the responder put it: the additional section is where
//! it belongs (RFC 6891 §6.1.1), which is after the answers and the authority records, so the
//! walk passes both. Split from `response.zig` by the file-length rule.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const Name = core.Name;
const header_codec = @import("header.zig");
const record_codec = @import("record.zig");
const response = @import("response.zig");

/// The first OPT record of the message, or null when it carries none. An OPT owned by anything
/// but the root is malformed: "NAME ... MUST be 0 (root domain)" (RFC 6891 §6.1.2).
pub fn find(message: []const u8, question: *const Name) Error!?record_codec.Record {
    assert(question.len >= 1);
    const header = try header_codec.parse(message);
    if (header.qdcount != 1) return Error.MalformedMessage;
    var offset = response.section_start(question);
    if (offset > message.len) return Error.MalformedMessage;
    const counts = [_]u16{ header.ancount, header.nscount, header.arcount };
    for (counts) |count| {
        var walk = record_codec.Iterator.init(message, offset, count);
        while (try walk.next()) |record| {
            offset = record.end;
            if (record.kind_code != core.Kind.opt.code()) continue;
            if (message[record.owner_offset] != 0) return Error.MalformedMessage;
            assert(record.end <= message.len);
            return record;
        }
    }
    return null;
}

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");
const edns = @import("edns.zig");

test "an OPT in the additional section is found, past the answers and other additional records" {
    const question = try Name.from_text("example.com");
    const opt = (try find(&fixtures.answer_a_with_opt, &question)).?;
    try testing.expectEqual(@as(usize, 0), opt.rdata.len);
    try testing.expectEqual(@as(u16, core.constants.udp_payload_bytes_default), opt.class);
    const after = (try find(&fixtures.answer_a_opt_after_additional, &question)).?;
    try testing.expectEqual(@as(usize, 0), after.rdata.len);
    try testing.expectEqual(@as(?record_codec.Record, null), try find(&fixtures.answer_a, &question));
}

test "the OPT's cookie option reads through its rdata" {
    const question = try Name.from_text("example.com");
    const opt = (try find(&fixtures.answer_a_with_cookie, &question)).?;
    const cookie = (try edns.find_cookie(opt.rdata)).?;
    try testing.expectEqualSlices(u8, &fixtures.cookie_client, cookie.client);
    try testing.expectEqualSlices(u8, &fixtures.cookie_server, cookie.server);
}

test "an OPT owned by a name is malformed" {
    const question = try Name.from_text("example.com");
    try testing.expectError(Error.MalformedMessage, find(&fixtures.answer_a_with_opt_bad_owner, &question));
}
