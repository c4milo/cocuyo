//! The probe bound at the cache's own surface: a chain longer than `probe_max` is a refusal on
//! `put` and a miss on `get`, never a longer walk (docs/design.md §18). `cache_keys.zig` shows
//! the bound on the index alone; this shows the slot goes back when the index refuses.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const cache = @import("cache.zig");
const constants = @import("constants.zig");
const fixtures = @import("fixtures.zig");

/// One slot more than the probe bound: after the bound's worth of colliding names and one
/// refusal, exactly one slot is free, so a refusal that kept its slot would leave the table one
/// short of full and the next put would trip the sweep's own assertion.
const slot_count = constants.probe_max + 1;

/// The most names tried while looking for ones that share a start index. The fixture rounds the
/// key index up to 64 entries, so one name in 64 lands on any given index and this is several
/// times what finding `probe_max + 1` of them needs; the seed is fixed, so the search is the same
/// every run.
const names_tried_max = 8192;

test "a chain longer than the probe bound is a refusal on put and the slot goes back" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const answers = fixtures.answers_v4(1, 300);
    var buffer: [24]u8 = undefined;
    var found: usize = 0;
    var tried: usize = 0;
    var last: core.Question = undefined;
    while (tried < names_tried_max and found <= constants.probe_max) : (tried += 1) {
        const text = try std.fmt.bufPrint(&buffer, "n{d}.example", .{tried});
        const asked = fixtures.question(text);
        const hash = table.hash_of(&asked);
        if (@as(usize, hash) & (table.keys.len - 1) != 0) continue;
        found += 1;
        last = asked;
        table.put(&asked, &answers, 0);
    }
    try testing.expectEqual(constants.probe_max + 1, found);
    // The first sixteen went in; the seventeenth was refused and misses.
    try testing.expectEqual(@as(usize, constants.probe_max), table.len());
    try testing.expect(table.get(&last, 0) == null);
    // The refused put released its slot: another name, off that chain, fills the table.
    const elsewhere = fixtures.question("elsewhere.example");
    try testing.expect(@as(usize, table.hash_of(&elsewhere)) & (table.keys.len - 1) != 0);
    table.put(&elsewhere, &answers, 0);
    try testing.expectEqual(@as(usize, slot_count), table.len());
    try testing.expect(table.get(&elsewhere, 0) != null);
}

test "find checks the type and the flag the hash already mixed, because a hash is not a proof" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const answers = fixtures.answers_v4(1, 300);
    const asked = fixtures.question("example.com");
    table.put(&asked, &answers, 0);
    const hash = table.hash_of(&asked);
    try testing.expect(table.find(&asked, hash) != null);
    var absolute = asked;
    absolute.absolute = true;
    try testing.expect(table.find(&absolute, hash) == null);
    const aaaa = try core.Question.from_text("example.com", .aaaa);
    try testing.expect(table.find(&aaaa, hash) == null);
}
