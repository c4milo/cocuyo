//! The reply of the threads example's responder (docs/design.md §24 step 6): the server the two
//! engines ask, not code a consumer of cocuyo writes. It reads the query with cocuyo's internal
//! `wire` module, which the build hands this file alone, so the example itself names only the
//! public surface of §20.
const std = @import("std");
const core = @import("core");
const wire = @import("wire");

/// What the responder answers every query with: 192.0.2.1 (RFC 5737 §3), for a minute.
const answer_v4 = [_]u8{ 192, 0, 2, 1 };
const answer_ttl_seconds = 60;
/// The answer's owner, a pointer to the question's name at the header's end, its type A and its
/// class IN (RFC 1035 §4.1.3, §4.1.4), and its RDLENGTH of four.
const record_head = [_]u8{ 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01 };
const record_rdlength = [_]u8{ 0x00, 0x04 };

/// The reply to `query`: its header with QR and RA set and one answer, its question as it came,
/// and the A record. Null for a datagram that is not a query.
pub fn build_reply(query: []const u8, reply: []u8) ?usize {
    const header_bytes = core.constants.header_bytes;
    if (query.len < header_bytes) return null;
    const name_end = wire.name.skip(query, header_bytes) catch return null;
    const question_end = name_end + core.constants.question_fixed_bytes;
    if (question_end > query.len) return null;
    @memcpy(reply[0..question_end], query[0..question_end]);
    var header = wire.header.parse(query) catch return null;
    header.flags = (header.flags | wire.constants.flag_response | wire.constants.flag_recursion_available) &
        ~@as(u16, wire.constants.rcode_mask);
    header.ancount = 1;
    header.nscount = 0;
    header.arcount = 0;
    wire.header.write(&header, reply);
    var ttl: [@sizeOf(u32)]u8 = undefined;
    std.mem.writeInt(u32, &ttl, answer_ttl_seconds, .big);
    var at = question_end;
    for ([_][]const u8{ &record_head, &ttl, &record_rdlength, &answer_v4 }) |part| {
        @memcpy(reply[at..][0..part.len], part);
        at += part.len;
    }
    return at;
}
