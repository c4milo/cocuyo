//! What a hit says of the CNAME chain an answer or a negative was reached through: its end
//! (docs/design.md §17 question 13) and its links (§5, §17 question 122). Split from `cache.zig`
//! to keep it under 500 lines.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const Name = core.Name;
const cache = @import("cache.zig");
const fixtures = @import("fixtures.zig");
const ask = fixtures.question;

/// Enough slots that no test here fills the table.
const slot_count: usize = 4;
/// A link's TTL: any value, since a hit reports the links as they were put.
const link_ttl_seconds: u32 = 60;

/// One link, from `www.example` to the end.
fn one_link(owner: []const u8) !core.Aliases {
    var aliases: core.Aliases = .{};
    try testing.expect(aliases.append(&try Name.parse(owner), link_ttl_seconds));
    return aliases;
}

test "a hit reports the chain it was put with, and none when there was none" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const answers = fixtures.answers_v4(1, 300);
    const target = try Name.parse("edge.cdn.example");
    const aliases = try one_link("www.example");

    table.put(&ask("www.example"), &answers, cache.Chain{ .end = &target, .aliases = &aliases }, .unchecked, 0);
    table.put(&ask("plain.example"), &answers, null, .unchecked, 0);

    const aliased = table.get(&ask("www.example"), 0).?;
    try testing.expect(aliased.canonical_name.?.equal(&target));
    try testing.expectEqual(@as(u8, 1), aliased.aliases.count);
    try testing.expectEqualSlices(u8, (try Name.parse("www.example")).wire(), aliased.aliases.at(0).owner);
    const plain = table.get(&ask("plain.example"), 0).?;
    try testing.expectEqual(@as(?*const Name, null), plain.canonical_name);
    try testing.expectEqual(@as(u8, 0), plain.aliases.count);
}

test "a negative keeps the chain that reached the name with no data" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const target = try Name.parse("edge.cdn.example");
    const aliases = try one_link("www.example");
    table.put_negative(&ask("www.example"), .no_data, 300, .{ .end = &target, .aliases = &aliases }, .unchecked, 0);
    const hit = table.get(&ask("www.example"), 0).?;
    try testing.expect(hit.canonical_name.?.equal(&target));
    try testing.expectEqual(@as(u8, 1), hit.aliases.count);
}

test "a put in place replaces the chain with the new one, or with none" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const answers = fixtures.answers_v4(1, 300);
    const earlier = try Name.parse("one.cdn.example");
    const later = try Name.parse("two.cdn.example");
    const aliases = try one_link("www.example");

    table.put(&ask("www.example"), &answers, .{ .end = &earlier, .aliases = &aliases }, .unchecked, 0);
    table.put(&ask("www.example"), &answers, .{ .end = &later, .aliases = &aliases }, .unchecked, 0);
    try testing.expect(table.get(&ask("www.example"), 0).?.canonical_name.?.equal(&later));
    // The same name answered later with no chain: what a hit says must follow the answer.
    table.put(&ask("www.example"), &answers, null, .unchecked, 0);
    const plain = table.get(&ask("www.example"), 0).?;
    try testing.expectEqual(@as(?*const Name, null), plain.canonical_name);
    try testing.expectEqual(@as(u8, 0), plain.aliases.count);
}
