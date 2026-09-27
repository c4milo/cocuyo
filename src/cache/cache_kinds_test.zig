//! What the cache gives back for an answer that is not addresses: a PTR question's names, and the
//! records of every other type with their rdata (docs/design.md §18, §19 step 9). A put copies only
//! the storage an answer's type uses (`wire.Answers.assign`), so each storage is put and read back
//! whole. Split from `cache.zig` to keep it under 500 lines.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const wire = @import("wire");
const fixtures = @import("fixtures.zig");

/// Enough slots that no test here fills the table.
const slot_count = 4;

test "a PTR answer comes back from the cache with its name" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const asked = try core.Question.from_text("2.2.0.192.in-addr.arpa", .ptr);
    var answers = wire.Answers.init(.ptr);
    answers.items.names[0] = try core.Name.from_text("host.example");
    answers.count = 1;
    answers.ttl_seconds = 300;
    table.put(&asked, &answers, null, 0);
    const hit = table.get(&asked, 0).?;
    try testing.expectEqual(@as(usize, 1), hit.answers.names().len);
    try testing.expect(hit.answers.names()[0].equal(&answers.names()[0]));
}

test "an MX answer comes back from the cache with each record's type, TTL and rdata" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const asked = try core.Question.from_text("example.com", .mx);
    // Two records one after the other in the buffer, as the codec keeps them, the second with a
    // preference and a TTL of its own so that a copy that mixed them up would show.
    const mx = wire.rdata.fixtures.mx;
    var answers = wire.Answers.init(.mx);
    const records = &answers.items.records;
    @memcpy(records.bytes[0..mx.len], &mx);
    @memcpy(records.bytes[mx.len..][0..mx.len], &mx);
    records.bytes[mx.len + 1] = 20;
    records.refs[0] = .{ .kind_code = core.Kind.mx.code(), .ttl_seconds = 300, .offset = 0, .len = mx.len };
    records.refs[1] = .{ .kind_code = core.Kind.mx.code(), .ttl_seconds = 200, .offset = mx.len, .len = mx.len };
    records.used = 2 * mx.len;
    answers.count = 2;
    answers.ttl_seconds = 200;
    table.put(&asked, &answers, null, 0);
    const hit = table.get(&asked, 0).?;
    try testing.expectEqual(@as(u8, 2), hit.answers.count);
    for (0..2) |index| {
        const put = answers.records().at(index);
        const got = hit.answers.records().at(index);
        try testing.expectEqual(put.kind_code, got.kind_code);
        try testing.expectEqual(put.ttl_seconds, got.ttl_seconds);
        try testing.expectEqualSlices(u8, put.rdata, got.rdata);
    }
    try testing.expectEqual(@as(u16, 20), (try wire.rdata.Mx.parse(hit.answers.records().at(1).rdata)).preference);
}
