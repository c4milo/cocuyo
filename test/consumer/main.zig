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
const cache_entries = 4;
const seed = 1;
const now_ns = 1;

comptime {
    // What the files of a type call of it is no declaration of the type, so a consumer cannot
    // call it (c4milo/cocuyo#65; docs/mutations.md, SF6 to SF9).
    for ([_][]const u8{ "evict", "find", "hash_of" }) |name| {
        if (@hasDecl(cocuyo.Cache, name)) @compileError("a consumer reached cocuyo.Cache." ++ name);
    }
    // Each thing has one name: the setters are `use_memory` and `use_trust` (docs/mutations.md,
    // ON2 and ON3).
    for ([_][]const u8{ "occupy", "remember_with", "validate_with" }) |name| {
        if (@hasDecl(cocuyo.Resolver, name)) @compileError("a consumer reached cocuyo.Resolver." ++ name);
    }
    // `Cache` declares what sizes its memory, and no namespace says it again (docs/mutations.md,
    // CF1).
    if (@hasDecl(cocuyo, "cache")) @compileError("a consumer reached cocuyo.cache");
    // A text is read by `parse`, as `std.Uri.parse` reads one, and by no second name
    // (docs/mutations.md, PT1 to PT3).
    for (.{ cocuyo.Name, cocuyo.Question, cocuyo.Address }) |Read| {
        if (@hasDecl(Read, "from_text")) @compileError("a consumer reached from_text of " ++ @typeName(Read));
    }
}

pub fn main() !void {
    var slots: [lookups]cocuyo.Slot = @splat(.{});
    // The table asserts a floor of keys for each slot (docs/design.md §17 question 123), and gives
    // the length that meets it. `zig build consumer-check` runs this program, so the assertion runs.
    var keys: [cocuyo.Resolver.keys_for(lookups)]cocuyo.MatchKey = @splat(.{});
    var cache_memory: cocuyo.Cache.Storage(cache_entries) = undefined;

    const servers = [_]cocuyo.Server{
        .{ .endpoint = .{ .address = cocuyo.Address.from_v4(.{ 127, 0, 0, 1 }) } },
    };
    const config: cocuyo.Config = .{
        .servers = &servers,
        .search = &.{},
        .ndots = cocuyo.constants.ndots_default,
        .attempts = cocuyo.constants.attempts_default,
        .timeout_ns = cocuyo.constants.timeout_ns_default,
        .udp_payload_bytes = cocuyo.constants.udp_payload_bytes_default,
        .mix_case = true,
        .rotate = false,
        .timeout_ns_max = cocuyo.constants.timeout_ns_max_default,
        .use_tcp = false,
        .ignore_truncation = false,
        .recursion_desired = true,
        .check_response = true,
        .primary = false,
        .authenticated_data = .ignored,
        .lookups = &.{ .file, .dns },
        .failover_retry_chance = cocuyo.constants.failover_retry_chance_default,
        .local_address = null,
        .socket_receive_bytes = 0,
        .socket_send_bytes = 0,
        .udp_queries_per_port = 0,
        .failover_retry_delay_ns = cocuyo.constants.failover_retry_delay_ns_default,
        .cache_ttl_seconds_max = cocuyo.constants.cache_ttl_seconds_max_default,
        .cache_failure_seconds_min = cocuyo.constants.cache_failure_seconds_min_default,
    };

    var store = cocuyo.Cache.init(&cache_memory.slots, &cache_memory.keys, seed, config.cache_ttl_seconds_max);
    var table = cocuyo.Resolver.init(&slots, &keys, &config, seed);
    table.use_memory(cocuyo.remembered_by(&store));

    _ = try table.start(&try cocuyo.Question.parse("example.com.", .a));
    var query: [cocuyo.limits.query_bytes_max]u8 = undefined;
    const event = table.poll(now_ns, &query) orelse return error.NothingToDo;
    if (event.action != .send_udp) return error.NotAQuery;
    std.debug.print(
        "cocuyo built a {d}-octet query for the consumer to send\n",
        .{event.action.send_udp.message_bytes.len},
    );
}
