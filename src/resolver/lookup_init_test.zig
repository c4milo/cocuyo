//! What `init` sets up: the first query, the case of the name on the wire, the rotation, the
//! cancel, and the sizes pinned. Split from `lookup.zig` by the file-length rule.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const wire = @import("wire");
const Config = core.Config;
const Question = core.Question;
const Name = core.Name;
const lookup_module = @import("lookup.zig");
const Lookup = lookup_module.Lookup;
const State = lookup_module.State;
const Servers = @import("servers.zig").Servers;
const entropy_module = @import("entropy.zig");
const fixtures = @import("fixtures.zig");

const one_server = fixtures.servers_one;
const three_servers = fixtures.servers_three;

test "a lookup starts ready to send its first query" {
    const config: Config = .{ .servers = &one_server };
    var servers_config = Servers.init(&config, 1);
    var lookup = Lookup.init(&config, &servers_config, try Question.from_text("example.com", .a), 1);
    try testing.expectEqual(State.query_ready, lookup.state);
    try testing.expect(lookup.current.equal(&try Name.from_text("example.com")));
    try testing.expect(lookup.flags.edns_enabled);
    try testing.expect(lookup.flags.mix_case);
    try testing.expectEqual(@as(u8, 0), lookup.server_index);
    try testing.expect(!lookup.is_settled());
}

test "the name on the wire is cased and the name held is not" {
    const config: Config = .{ .servers = &one_server };
    var servers_config = Servers.init(&config, 1);
    var lookup = Lookup.init(&config, &servers_config, try Question.from_text("example.com", .a), 1);
    const cased = lookup.cased_name();
    try testing.expect(cased.equal(&lookup.current));
    try testing.expect(!std.mem.eql(u8, cased.wire(), lookup.current.wire()));

    const plain: Config = .{ .servers = &one_server, .mix_case = false };
    var servers_plain = Servers.init(&plain, 1);
    var without = Lookup.init(&plain, &servers_plain, lookup.question, 1);
    try testing.expectEqualSlices(u8, without.current.wire(), without.cased_name().wire());
}

test "rotation starts somewhere in the list, and a lookup without it starts at the first" {
    const rotating: Config = .{ .servers = &three_servers, .rotate = true };
    var servers_rotating = Servers.init(&rotating, 1);
    const plain: Config = .{ .servers = &three_servers };
    var servers_plain = Servers.init(&plain, 1);
    var seen: [three_servers.len]bool = @splat(false);
    var seed: u64 = 0;
    while (seed < 64) : (seed += 1) {
        const lookup = Lookup.init(&rotating, &servers_rotating, try Question.from_text("example.com.", .a), seed);
        var polled = lookup;
        var out: [core.constants.query_bytes_max]u8 = @splat(0);
        _ = polled.poll(0, &out);
        seen[polled.server_slot()] = true;
        const fixed = Lookup.init(&plain, &servers_plain, try Question.from_text("example.com.", .a), seed);
        var fixed_polled = fixed;
        _ = fixed_polled.poll(0, &out);
        try testing.expectEqual(@as(u8, 0), fixed_polled.server_slot());
    }
    for (seen) |reached| try testing.expect(reached);
}

test "cancel settles a lookup without an answer" {
    const config: Config = .{ .servers = &one_server };
    var servers_config = Servers.init(&config, 1);
    var lookup = Lookup.init(&config, &servers_config, try Question.from_text("example.com.", .a), 1);
    lookup.cancel();
    try testing.expect(lookup.is_settled());
    try testing.expectEqual(core.Error.Canceled, lookup.failure_of().err);
}

test "a lookup started in its slot leaves the answers' storage as the last lookup left it" {
    const config: Config = .{ .servers = &one_server };
    var servers_config = Servers.init(&config, 1);
    var lookup: Lookup = undefined;
    // What a lookup that ended in the slot left, and nothing reads again: `reset` sets the count
    // to zero. Assigning the whole lookup would write it, as a safe build fills whatever is
    // `undefined` with 0xAA (docs/design.md §16 decision 34).
    const left: u8 = 0x5a;
    @memset(std.mem.asBytes(&lookup.answers.items), left);
    lookup.init_in_place(&config, &servers_config, try Question.from_text("example.com", .mx), 1);
    try testing.expectEqual(core.Kind.mx, lookup.answers.kind);
    try testing.expectEqual(@as(u8, 0), lookup.answers.count);
    try testing.expectEqual(@as(u16, 0), lookup.answers.items.records.used);
    for (lookup.answers.items.records.bytes) |octet| try testing.expectEqual(left, octet);
    try testing.expectEqual(State.query_ready, lookup.state);
}

test "the size of a lookup slot is pinned" {
    // docs/design.md §9 budgets the memory a caller provides, and a caller sizing a table needs
    // this number. It is measured, not computed: Zig chooses the field order, so a field added
    // here can cost more than its own width in padding.
    try testing.expectEqual(@as(usize, 3048), @sizeOf(Lookup));
    try testing.expectEqual(@as(usize, 2448), @sizeOf(wire.Answers));
    try testing.expectEqual(@as(usize, 16), @sizeOf(entropy_module.Transaction));
}
