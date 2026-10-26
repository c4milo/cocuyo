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
    // The question is read for its length alone: a lookup passes the name it holds, not the case
    // its query carried (docs/design.md §7).
    const capitals = try Name.from_text("EXAMPLE.COM");
    try testing.expectEqual(opt.end, (try find(&fixtures.answer_a_with_opt, &capitals)).?.end);
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

/// A label of 63 octets, the longest, after its length octet.
const label_longest = [_]u8{core.limits.label_bytes_max} ++ [_]u8{'a'} ** core.limits.label_bytes_max;

/// `fixtures.answer_a_with_opt` with `labels` put before the A record's owner. That owner was a
/// pointer to the question's name, 13 octets, so it is now `labels` and those 13.
fn opt_after_owner_through_pointer(comptime labels: []const u8) [fixtures.answer_a_with_opt.len + labels.len]u8 {
    const at = fixtures.answer_offset;
    const message = fixtures.answer_a_with_opt;
    return message[0..at].* ++ labels[0..labels.len].* ++ message[at..].*;
}

test "an owner longer than 255 octets through its pointer, before the OPT, fails the search" {
    // "label octets and label length octets" count (RFC 1035 §3.1), those a pointer reaches too
    // (§4.1.4), in a name of "255 octets or less" (§2.3.4). Until 2026-10-14 the search did not
    // follow the owner's pointer, and found the OPT of the second message.
    const question = try Name.from_text("example.com");
    // Labels of 242 octets, and the 13 that the pointer reaches: 255 octets.
    const longest = opt_after_owner_through_pointer(&(label_longest ** 3 ++ [_]u8{49} ++ [_]u8{'b'} ** 49));
    try testing.expectEqual(longest.len, (try find(&longest, &question)).?.end);
    // A label of one octet more: 256 octets.
    const one_past = opt_after_owner_through_pointer(&(label_longest ** 3 ++ [_]u8{50} ++ [_]u8{'b'} ** 50));
    try testing.expectError(Error.NameTooLong, find(&one_past, &question));
}
