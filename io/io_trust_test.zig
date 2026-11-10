//! The engine under a key store (docs/design.md §25 step 15, §17 questions 98 and 100), over the
//! twin's signed servers: `use_trust` validates every lookup, a walk's lookups never come out of
//! `take`, and `reinit` keeps the store. The rig is the one `io_sim_test.zig` builds.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const core = @import("core");
const rotor = @import("rotor");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const Rig = sim_test.Rig;
const signed = rotor.signed;
const Result = sim_test.Resolver.Result;

/// The store's entries: the three signed zones, and the delegation that is not.
const entries_count: usize = 4;

/// Signed servers, the first of which lies about `signed.example` when `lying` is set.
fn scripts(lying: bool) [fixtures.servers]rotor.server.Script {
    const fault: signed.Fault = if (lying) .lies else .none;
    return .{
        .{ .signed = .{ .on = true, .fault = fault } },
        .{ .signed = .{ .on = true, .fault = fault } },
    };
}

/// A key store under the root's DS of the twin's tree, and what it reads. Started in place.
const Trust = struct {
    entries: [entries_count]cocuyo.KeyStore.Entry = undefined,
    anchor_rdata: signed.DsRdata = undefined,
    anchors: [1]cocuyo.Anchor = undefined,
    sums: signed.Sums = .{},
    hashes: signed.Hashes = .{},
    store: cocuyo.KeyStore = undefined,

    fn init(self: *Trust, now_ns: u64) void {
        self.anchor_rdata = signed.root_anchor();
        self.anchors = .{.{ .zone = cocuyo.Name.root, .kind = .ds, .rdata = &self.anchor_rdata }};
        self.store.init(&self.entries, &self.anchors, self.sums.verifier(), self.hashes.hasher(), .{ .unix_seconds = signed.now_seconds, .monotonic_ns = now_ns });
    }
};

/// Asks `text` of `kind` and takes its result, which must be the lookup's own.
fn ask(rig: *Rig, text: []const u8, kind: cocuyo.Kind) !Result {
    const handle = try rig.engine.start(&try cocuyo.Question.parse(text, kind), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(handle, result.handle);
    return result;
}

test "an engine handed a key store validates from the root's anchor, and its walks stay inside" {
    var rig: Rig = .{};
    var trust: Trust = .{};
    try rig.init(51, scripts(false), .{ .servers = &.{} });
    trust.init(rig.loop.now());
    rig.engine.use_trust(&trust.store);
    const first = try ask(&rig, "www.signed.example.", .a);
    try testing.expectEqual(core.Security.secure, first.outcome.answer.security);
    // Five walk questions went out beside the lookup's own, and none of them came out of `take`.
    try testing.expectEqual(@as(?Result, null), rig.engine.take(rig.loop.now()));
    try testing.expectEqual(@as(usize, 0), rig.engine.resolver.in_flight());
    const plain = try ask(&rig, "www.plain.example.", .a);
    try testing.expectEqual(core.Security.insecure, plain.outcome.answer.security);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "an engine under a key store ends Bogus at a server that lies" {
    var rig: Rig = .{};
    var trust: Trust = .{};
    try rig.init(52, scripts(true), .{ .servers = &.{} });
    trust.init(rig.loop.now());
    rig.engine.use_trust(&trust.store);
    const result = try ask(&rig, "www.signed.example.", .a);
    try testing.expectEqual(cocuyo.Error.Bogus, result.outcome.failure.err);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a reinit keeps the key store, and validates every lookup after it" {
    var rig: Rig = .{};
    var trust: Trust = .{};
    try rig.init(53, scripts(false), .{ .servers = &.{} });
    trust.init(rig.loop.now());
    rig.engine.use_trust(&trust.store);
    try rig.engine.reinit(&rig.config, rig.cache_memory.slices(), 54, rig.loop.now());
    try testing.expectEqual(@as(?*cocuyo.KeyStore, &trust.store), rig.engine.trust);
    const result = try ask(&rig, "www.signed.example.", .aaaa);
    try testing.expectEqual(core.Security.secure, result.outcome.answer.security);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}
