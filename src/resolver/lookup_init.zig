//! Where a lookup starts, split from `lookup.zig`: every field set but the answers, which are
//! reset rather than written (docs/design.md §16 decision 34).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Config = core.Config;
const Question = core.Question;
const lookup_module = @import("lookup.zig");
const Lookup = lookup_module.Lookup;
const Servers = @import("servers.zig").Servers;
const entropy_module = @import("entropy.zig");

/// The order before the first poll computes one: the configured order.
const identity_order: [core.constants.servers_max]u8 = blk: {
    var order: [core.constants.servers_max]u8 = undefined;
    for (&order, 0..) |*slot, index| slot.* = @intCast(index);
    break :blk order;
};

/// Every field of `Lookup` but its answers. `init_in_place` builds one of these whole, so the
/// compiler refuses a field left out, and copies it into the lookup field by field, so that the
/// answers' storage, which nothing reads before `collect` writes it, is not written: assigning the
/// whole lookup would write it, since a safe build fills whatever is `undefined` with 0xAA
/// (docs/design.md §16 decision 34).
const Head = head: {
    const fields = @typeInfo(Lookup).@"struct".fields;
    var names: [fields.len - 1][]const u8 = undefined;
    var types: [fields.len - 1]type = undefined;
    var at: usize = 0;
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, "answers")) continue;
        names[at] = field.name;
        types[at] = field.type;
        at += 1;
    }
    assert(at == names.len);
    break :head @Struct(.auto, null, &names, &types, &@splat(.{}));
};

/// `Lookup.init_in_place`: a lookup started in memory the caller owns.
pub fn init_in_place(
    self: *Lookup,
    config: *const Config,
    servers: *Servers,
    question: Question,
    seed: u64,
) void {
    config.assert_valid();
    assert(question.kind.queryable());
    assert(servers.count == config.servers.len);
    var entropy = entropy_module.Entropy.init(seed);
    const transaction = entropy.transaction();
    const head: Head = .{
        .state = .query_ready,
        .flags = .{
            .edns_enabled = true,
            // A query over DoH or DoQ asks for the name as it was given, so the same
            // question makes the same octets for an HTTP cache (docs/design.md §22, §23).
            .mix_case = config.mix_case and !config.sends_requests(),
            .had_no_data = false,
            .had_server_failure = false,
            .aliased = false,
            .cookie_retried = false,
            .ordered = false,
            // No query is built yet, so none mixed the case.
            .query_mixed = false,
        },
        .server_index = 0,
        .order = identity_order,
        .round = 0,
        .candidate_index = 0,
        .cname_hops = 0,
        .transaction = transaction,
        .deadline_ns = 0,
        .sent_at_ns = 0,
        .now_ns_seen = 0,
        .entropy = entropy,
        .failure = core.Error.Timeout,
        // No candidate has answered NXDOMAIN or NODATA, so nothing bounds the walk's end yet
        // (docs/design.md §5): the largest TTL, which a smaller one replaces.
        .negative_ttl_seconds = std.math.maxInt(u32),
        .chain_ttl_seconds = 0,
        .config = config,
        .servers = servers,
        // No query is built yet, so none carries a cookie.
        .cookie_form = .none,
        .cookie_client = @splat(0),
        .question = question,
        .current = question.name,
    };
    inline for (@typeInfo(Head).@"struct".fields) |field| @field(self, field.name) = @field(head, field.name);
    self.answers.reset(question.kind);
    // A configuration with no server is one a `resolv.conf` with none gave, read without
    // the default: every lookup on it fails at once (§19 step 11).
    if (config.server_count() == 0) {
        self.fail(core.Error.NoServers);
        return;
    }
    self.take_candidate(self.candidate_index);
    if (self.state == .query_ready and config.streams_only()) self.state = .tcp_needed;
    assert(self.state == .query_ready or self.state == .tcp_needed or self.state == .failed);
}
