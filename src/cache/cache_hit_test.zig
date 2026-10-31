//! A get and a put at the cache's own surface: what a hit matches, the visited bit, a put over a
//! held entry, and a flush (docs/design.md §18). Split from `cache.zig` to keep it under 500
//! lines.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const cache = @import("cache.zig");
const fixtures = @import("fixtures.zig");
const Cache = cache.Cache;
const Outcome = cache.Outcome;
const Key = cache.Key;
const Question = core.Question;
const ask = fixtures.question;
const second = fixtures.second;

/// Enough slots that no test here fills the table: the hand is cache_sweep.zig's to drive.
const slot_count: usize = 4;

test "a put is a hit whatever the case, and a miss for another type, name or absoluteness" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const asked = ask("Example.COM");
    try testing.expect(table.get(&asked, 0) == null);
    const answers = fixtures.answers_v4(1, 300);
    table.put(&asked, &answers, null, .unchecked, 0);
    try testing.expectEqual(@as(usize, 1), table.len());

    const hit = table.get(&ask("EXAMPLE.com"), 0).?;
    try testing.expectEqual(Outcome.answered, hit.outcome);
    try testing.expectEqual(@as(u32, 300), hit.ttl_seconds);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, hit.answers.addresses()[0].slice());
    // The name comes back folded, whatever case it was put or asked in.
    try testing.expectEqualSlices(u8, ask("example.com").name.wire(), hit.name.wire());

    const aaaa = try Question.from_text("example.com", .aaaa);
    try testing.expect(table.get(&aaaa, 0) == null);
    try testing.expect(table.get(&ask("example.org"), 0) == null);
    var absolute = asked;
    absolute.absolute = true;
    try testing.expect(table.get(&absolute, 0) == null);
}

test "a hit sets the visited bit and moves nothing" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const answers = fixtures.answers_v4(1, 300);
    table.put(&ask("a.example"), &answers, null, .unchecked, 0);
    table.put(&ask("b.example"), &answers, null, .unchecked, 0);
    table.put(&ask("c.example"), &answers, null, .unchecked, 0);
    const oldest = table.order.oldest;
    const newest = table.order.newest;
    try testing.expect(table.get(&ask("b.example"), 0) != null);
    const b = table.find(&ask("b.example"), table.hash_of(&ask("b.example"))).?;
    try testing.expect(table.slots[b].visited);
    try testing.expect(!table.slots[oldest].visited);
    try testing.expect(!table.slots[newest].visited);
    try testing.expectEqual(oldest, table.order.oldest);
    try testing.expectEqual(newest, table.order.newest);
    try testing.expectEqual(b, table.order.after(table.slots, oldest));
}

test "a put for a question the cache holds replaces it in place, sets the bit, and moves nothing" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const first = fixtures.answers_v4(1, 300);
    table.put(&ask("a.example"), &first, null, .unchecked, 0);
    table.put(&ask("b.example"), &first, null, .unchecked, 0);
    const oldest = table.order.oldest;
    const later = fixtures.answers_v4(2, 600);
    table.put(&ask("A.EXAMPLE"), &later, null, .unchecked, 10 * second);
    try testing.expectEqual(@as(usize, 2), table.len());
    try testing.expectEqual(oldest, table.order.oldest);
    try testing.expect(table.slots[oldest].visited);
    const hit = table.get(&ask("a.example"), 10 * second).?;
    try testing.expectEqual(@as(u32, 600), hit.ttl_seconds);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 2 }, hit.answers.addresses()[0].slice());
}

test "flush empties the table, and a put after it works" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const answers = fixtures.answers_v4(1, 300);
    table.put(&ask("a.example"), &answers, null, .unchecked, 0);
    table.put(&ask("b.example"), &answers, null, .unchecked, 0);
    try testing.expect(table.get(&ask("a.example"), 0) != null);
    table.flush();
    try testing.expectEqual(@as(usize, 0), table.len());
    try testing.expect(table.get(&ask("a.example"), 0) == null);
    try testing.expect(table.get(&ask("b.example"), 0) == null);
    for (table.keys) |key| try testing.expectEqual(Key.State.empty, key.state);
    table.put(&ask("a.example"), &answers, null, .unchecked, 0);
    try testing.expectEqual(@as(usize, 1), table.len());
    try testing.expect(table.get(&ask("a.example"), 0) != null);
}

test "a hit reports the status its entry was put with, and a failure is unchecked" {
    // docs/design.md §25, Stage A rule 5: the status stays with the entry, a put over it
    // replaces it, and a failure says nothing of where an answer came from.
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const answers = fixtures.answers_v4(1, 300);
    table.put(&ask("a.example"), &answers, null, .authenticated, 0);
    try testing.expectEqual(core.Security.authenticated, table.get(&ask("a.example"), 0).?.security);
    table.put(&ask("a.example"), &answers, null, .unchecked, 0);
    try testing.expectEqual(core.Security.unchecked, table.get(&ask("a.example"), 0).?.security);
    table.put_negative(&ask("b.example"), .name_not_found, 300, .authenticated, 0);
    try testing.expectEqual(core.Security.authenticated, table.get(&ask("b.example"), 0).?.security);
    table.put(&ask("c.example"), &answers, null, .authenticated, 0);
    table.put_failure(&ask("c.example"), core.Error.Timeout, 301 * second);
    try testing.expectEqual(core.Security.unchecked, table.get(&ask("c.example"), 301 * second).?.security);
}
