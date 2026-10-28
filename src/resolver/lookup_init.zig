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
const identity_order: [core.limits.servers_max]u8 = blk: {
    var order: [core.limits.servers_max]u8 = undefined;
    for (&order, 0..) |*slot, index| slot.* = @intCast(index);
    break :blk order;
};

/// The fields of `Lookup` that `Head` leaves out. The answers' storage is not written: nothing
/// reads it before `collect` writes it, and assigning the whole lookup would write it, since a
/// safe build fills whatever is `undefined` with 0xAA (docs/design.md §16 decision 34). The
/// question and the current name are written once each, straight into the lookup. Through `Head`
/// each name was copied twice more (c4milo/cocuyo#41).
const outside_head = [_][]const u8{ "answers", "question", "current" };

fn in_head(comptime name: []const u8) bool {
    for (outside_head) |outside| {
        if (std.mem.eql(u8, name, outside)) return false;
    }
    return true;
}

/// Every field of `Lookup` but those of `outside_head`. `init_in_place` builds one of these whole,
/// so the compiler refuses a field left out, and copies it into the lookup field by field.
const Head = head: {
    const fields = @typeInfo(Lookup).@"struct".fields;
    var names: [fields.len - outside_head.len][]const u8 = undefined;
    var types: [fields.len - outside_head.len]type = undefined;
    var at: usize = 0;
    for (fields) |field| {
        if (!in_head(field.name)) continue;
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
            .aliased = false,
            .cookie_retried = false,
            .ordered = false,
            // No query is built yet, so none mixed the case.
            .query_mixed = false,
            // No query is sent yet, so no reply marked a try.
            .reply_marked = false,
        },
        .server_index = 0,
        .order = identity_order,
        // No query is sent yet.
        .sends = .{},
        .round = 0,
        .candidate_index = 0,
        .cname_hops = 0,
        .transaction = transaction,
        .deadline_ns = 0,
        .sent_at_ns = 0,
        .now_ns_seen = 0,
        .entropy = entropy,
        .failure = core.Error.Timeout,
        // No server has failed the lookup yet (docs/design.md §5, The cause of a failure).
        .cause = .none,
        // No candidate has answered NXDOMAIN or NODATA, so nothing bounds the walk's end yet
        // (docs/design.md §5): the largest TTL, which a smaller one replaces.
        .negative_ttl_seconds = std.math.maxInt(u32),
        .chain_ttl_seconds = 0,
        .config = config,
        .servers = servers,
        // No query is built yet, so none carries a cookie.
        .cookie_form = .none,
        .cookie_client = @splat(0),
    };
    inline for (@typeInfo(Head).@"struct".fields) |field| @field(self, field.name) = @field(head, field.name);
    self.question = question;
    self.answers.reset(question.kind);
    // A configuration with no server is one a `resolv.conf` with none gave, read without
    // the default: every lookup on it fails at once (§19 step 11).
    if (config.server_count() == 0) {
        self.current = self.question.name;
        self.fail(core.Error.NoServers);
        return;
    }
    // The first candidate taken writes the current name. The name as asked is a candidate at an
    // index below `candidates_max`, so the walk takes one, and `current` is always written.
    self.take_candidate(self.candidate_index);
    assert(self.state == .query_ready);
    if (config.streams_only()) self.state = .tcp_needed;
    assert(self.state == .query_ready or self.state == .tcp_needed);
}
