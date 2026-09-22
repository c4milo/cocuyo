//! What a consumer writes: `@import("cocuyo")` and nothing else from this package.
//!
//! This is the positive control of `zig build consumer-check` (docs/design.md §20). It resolves
//! nothing — there is no socket here — it asks the library for the first thing it would do, which
//! is the whole of what a dependent needs to compile and link: the types, the table, the cache
//! under it, and the query bytes handed back.
const std = @import("std");
const cocuyo = @import("cocuyo");

/// Small on purpose: this proves the package, not the library.
const lookups = 2;
const keys_per_lookup = 4;
const cache_entries = 4;
const cache_keys = 8;
const seed = 1;
const now_ns = 1;

pub fn main() !void {
    var slots: [lookups]cocuyo.Slot = @splat(.{});
    var keys: [lookups * keys_per_lookup]cocuyo.MatchKey = @splat(.{});
    var entries: [cache_entries]cocuyo.cache.Slot = @splat(cocuyo.cache.Slot.empty);
    var index: [cache_keys]cocuyo.cache.Key = @splat(.{});

    const servers = [_]cocuyo.Server{
        .{ .endpoint = .{ .address = cocuyo.Address.from_v4(.{ 127, 0, 0, 1 }) } },
    };
    const config: cocuyo.Config = .{ .servers = &servers, .search = &.{} };

    var store = cocuyo.Cache.init(&entries, &index, seed, cocuyo.cache.constants.ttl_seconds_max_default);
    var table = cocuyo.Resolver.init(&slots, &keys, &config, seed);
    table.remember_with(cocuyo.remembered_by(&store));

    _ = try table.start(try cocuyo.Question.from_text("example.com.", .a));
    var query: [cocuyo.constants.query_bytes_max]u8 = undefined;
    const event = table.poll(now_ns, &query) orelse return error.NothingToDo;
    if (event.action != .send_udp) return error.NotAQuery;
    std.debug.print(
        "cocuyo built a {d}-octet query for the consumer to send\n",
        .{event.action.send_udp.message_bytes.len},
    );
}
