//! What a hit says of the end of the CNAME chain an answer was reached through (docs/design.md
//! §17 question 13). Split from `cache.zig` to keep it under 500 lines.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const Name = core.Name;
const fixtures = @import("fixtures.zig");
const ask = fixtures.question;

/// Enough slots that no test here fills the table.
const slot_count: usize = 4;

test "a hit reports the chain's end it was put with, and none when there was none" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const answers = fixtures.answers_v4(1, 300);
    const target = try Name.from_text("edge.cdn.example");

    table.put(&ask("www.example"), &answers, &target, 0);
    table.put(&ask("plain.example"), &answers, null, 0);

    const aliased = table.get(&ask("www.example"), 0).?;
    try testing.expect(aliased.canonical_name.?.equal(&target));
    const plain = table.get(&ask("plain.example"), 0).?;
    try testing.expectEqual(@as(?*const Name, null), plain.canonical_name);
}

test "a put in place replaces the chain's end with the new one, or with none" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const answers = fixtures.answers_v4(1, 300);
    const earlier = try Name.from_text("one.cdn.example");
    const later = try Name.from_text("two.cdn.example");

    table.put(&ask("www.example"), &answers, &earlier, 0);
    table.put(&ask("www.example"), &answers, &later, 0);
    try testing.expect(table.get(&ask("www.example"), 0).?.canonical_name.?.equal(&later));
    // The same name answered later with no chain: what a hit says must follow the answer.
    table.put(&ask("www.example"), &answers, null, 0);
    try testing.expectEqual(@as(?*const Name, null), table.get(&ask("www.example"), 0).?.canonical_name);
}
