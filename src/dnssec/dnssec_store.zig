//! The key store: what is known of each zone, in memory the caller hands in, beside the trust
//! anchors the caller supplies (docs/design.md §25, Stage B: where the keys come from, and step
//! 9). Nothing enters it that was not validated: `dnssec_store_keys.zig` admits a DNSKEY set.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Kind = core.Kind;
const Name = core.Name;
const constants = @import("constants.zig");
const limits = @import("limits.zig");
const rrset = @import("dnssec_rrset.zig");

/// What an entry knows of its zone.
pub const Known = enum(u8) {
    free,
    /// The zone's validated DNSKEY set.
    keys,
    /// A validated DS set, whose keys have not come yet.
    ds,
    /// An insecure delegation: everything at or under the zone is `insecure`.
    insecure,
};

/// One zone's entry: its name, what is known of it, when that expires, and its records' rdata,
/// end to end.
pub const Entry = struct {
    zone: Name = Name.empty,
    known: Known = .free,
    expires_ns: u64 = 0,
    len: u8 = 0,
    ends: [limits.zone_keys_max]u16 = undefined,
    bytes: [limits.zone_keys_bytes_max]u8 = undefined,

    pub fn record(self: *const Entry, index: usize) []const u8 {
        assert(index < self.len);
        const start: usize = if (index == 0) 0 else self.ends[index - 1];
        return self.bytes[start..self.ends[index]];
    }

    pub fn keys(self: *const Entry) rrset.Keys {
        assert(self.known == .keys);
        assert(self.len <= limits.zone_keys_max);
        return .{ .entry = self };
    }

    fn live(self: *const Entry, now_ns: u64) bool {
        return self.known != .free and now_ns < self.expires_ns;
    }
};

/// A trust anchor: a DS or a DNSKEY record the caller supplies for a zone (RFC 4035 §4.4). Its
/// rdata is the caller's memory, which must outlive the store.
pub const Anchor = struct {
    zone: Name,
    kind: Kind,
    rdata: []const u8,
};

pub const Store = struct {
    entries: []Entry,
    anchors: []const Anchor,
    /// Unix seconds at `clock_ns` (§25, Time).
    unix_seconds: u64 = 0,
    clock_ns: u64 = 0,

    pub fn init(entries: []Entry, anchors: []const Anchor) Store {
        assert(entries.len >= 1);
        assert(anchors.len <= limits.anchors_max);
        for (anchors) |anchor| assert(anchor.kind == .ds or anchor.kind == .dnskey);
        for (entries) |*entry| entry.* = .{};
        return .{ .entries = entries, .anchors = anchors };
    }

    /// Pins the time of day: `timestamp.unix_seconds` holds at `timestamp.monotonic_ns`. The caller
    /// passes it at init and whenever it corrects its clock. So `unix_seconds` may go backwards, and
    /// `monotonic_ns` never does.
    pub fn set_clock(self: *Store, timestamp: core.Timestamp) void {
        self.unix_seconds = timestamp.unix_seconds;
        self.clock_ns = timestamp.monotonic_ns;
    }

    /// The time of day at `now_ns`, in the 32 bits a signature's dates are compared in (RFC 4034
    /// §3.1.5).
    pub fn now_seconds(self: *const Store, now_ns: u64) u32 {
        assert(now_ns >= self.clock_ns);
        return @truncate(self.unix_seconds + (now_ns - self.clock_ns) / constants.ns_per_second);
    }

    /// The live entry for exactly `zone`.
    pub fn find(self: *const Store, zone: *const Name, now_ns: u64) ?*const Entry {
        for (self.entries) |*entry| {
            if (entry.live(now_ns) and entry.zone.equal(zone)) return entry;
        }
        return null;
    }

    /// The deepest live entry at or above `name`, which speaks for it.
    pub fn deepest(self: *const Store, name: *const Name, now_ns: u64) ?*const Entry {
        var best: ?*const Entry = null;
        for (self.entries) |*entry| {
            if (!entry.live(now_ns) or !above(&entry.zone, name)) continue;
            if (best) |held| if (held.zone.label_count() >= entry.zone.label_count()) continue;
            best = entry;
        }
        return best;
    }

    /// Whether an anchor is at or above `name`. A name under none is `insecure` (§25).
    pub fn anchored(self: *const Store, name: *const Name) bool {
        for (self.anchors) |*anchor| if (above(&anchor.zone, name)) return true;
        return false;
    }

    /// Keeps `records` as what is known of `zone` until `expires_ns`, in the entry the zone
    /// already holds, else the one that expires first. False when the records do not fit.
    pub fn put(self: *Store, zone: *const Name, known: Known, records: []const []const u8, expires_ns: u64) bool {
        assert(known != .free);
        if (records.len > limits.zone_keys_max) return false;
        var total: usize = 0;
        for (records) |rdata| total += rdata.len;
        if (total > limits.zone_keys_bytes_max) return false;
        const entry = self.slot(zone);
        entry.* = .{ .zone = zone.*, .known = known, .expires_ns = expires_ns };
        entry.zone.fold_case();
        var at: usize = 0;
        for (records, 0..) |rdata, index| {
            @memcpy(entry.bytes[at..][0..rdata.len], rdata);
            at += rdata.len;
            entry.ends[index] = @intCast(at);
        }
        entry.len = @intCast(records.len);
        assert(at == total);
        return true;
    }

    /// The entry of `zone`, else the one that expires first. A free entry expires at 0, and an
    /// expired one before every live one, so either comes before a live entry.
    fn slot(self: *Store, zone: *const Name) *Entry {
        var chosen: *Entry = &self.entries[0];
        for (self.entries) |*entry| {
            if (entry.known != .free and entry.zone.equal(zone)) return entry;
            if (entry.expires_ns < chosen.expires_ns) chosen = entry;
        }
        return chosen;
    }

    /// The store as the signers an RRset check reads, at `now_ns`.
    pub fn signers(self: *const Store, at: *const At) rrset.Signers {
        assert(at.store == self);
        return .{ .context = at, .keys = signer_keys };
    }
};

/// The store at one instant, which an RRset check reads its signers from.
pub const At = struct { store: *const Store, now_ns: u64 };

fn signer_keys(context: *const anyopaque, signer: *const Name) rrset.Held {
    const at: *const At = @ptrCast(@alignCast(context));
    if (at.store.find(signer, at.now_ns)) |entry| if (entry.known == .keys) return .{ .keys = entry.keys() };
    return if (at.store.anchored(signer)) .wanted else .outside;
}

/// Whether `zone` is `name` or an ancestor of it.
fn above(zone: *const Name, name: *const Name) bool {
    return core.canonical.shared_labels(zone, name) == zone.label_count();
}

// Tests.

const testing = std.testing;

fn named(text: []const u8) Name {
    return Name.parse(text) catch unreachable;
}

test "the time of day adds the now_ns that passed, in 32 bits" {
    var entries: [1]Entry = undefined;
    var store = Store.init(&entries, &.{});
    store.set_clock(.{ .unix_seconds = 1000, .monotonic_ns = 5 * constants.ns_per_second });
    try testing.expectEqual(@as(u32, 1002), store.now_seconds(7 * constants.ns_per_second + 1));
    // RFC 4034 §3.1.5: the dates are the low 32 bits, compared in serial number arithmetic.
    store.set_clock(.{ .unix_seconds = (1 << 32) + 5, .monotonic_ns = 0 });
    try testing.expectEqual(@as(u32, 5), store.now_seconds(0));
}

test "the deepest live entry at or above a name speaks for it, and an anchor makes it wanted" {
    var entries: [5]Entry = undefined;
    const anchors = [_]Anchor{.{ .zone = named("example"), .kind = .dnskey, .rdata = "key" }};
    var store = Store.init(&entries, &anchors);
    try testing.expect(store.put(&named("EXAMPLE"), .keys, &.{"key"}, 100));
    try testing.expect(store.put(&named("b.example"), .insecure, &.{}, 100));
    try testing.expect(store.put(&named("c.example"), .keys, &.{"key"}, 10));
    try testing.expect(store.put(&named("d.example"), .ds, &.{"digest"}, 100));
    try testing.expectEqual(Known.insecure, store.deepest(&named("x.b.example"), 0).?.known);
    try testing.expect(store.deepest(&named("x.w.example"), 0).?.zone.equal(&named("example")));
    try testing.expect(store.deepest(&named("org"), 0) == null);
    // An entry that expired speaks for nothing.
    try testing.expect(store.deepest(&named("x.c.example"), 10).?.zone.equal(&named("example")));
    try testing.expect(store.anchored(&named("x.w.example")));
    try testing.expect(!store.anchored(&named("org")));
    const at: At = .{ .store = &store, .now_ns = 0 };
    const signers = store.signers(&at);
    try testing.expectEqual(@as(usize, 1), signers.keys(signers.context, &named("example")).keys.len());
    try testing.expect(signers.keys(signers.context, &named("w.example")) == .wanted);
    // A DS set is no key set.
    try testing.expect(signers.keys(signers.context, &named("d.example")) == .wanted);
    try testing.expect(signers.keys(signers.context, &named("org")) == .outside);
}

test "a full store replaces the entry of the same zone, then an expired one, then the soonest" {
    var entries: [2]Entry = undefined;
    var store = Store.init(&entries, &.{});
    try testing.expect(store.put(&named("a"), .insecure, &.{}, 50));
    try testing.expect(store.put(&named("b"), .insecure, &.{}, 20));
    try testing.expect(store.put(&named("A"), .keys, &.{"key"}, 60));
    try testing.expectEqual(Known.keys, store.find(&named("a"), 0).?.known);
    try testing.expect(store.find(&named("b"), 0) != null);
    try testing.expect(store.put(&named("c"), .insecure, &.{}, 70));
    try testing.expect(store.find(&named("b"), 0) == null);
    try testing.expect(store.find(&named("a"), 0) != null);
    try testing.expect(store.put(&named("d"), .insecure, &.{}, 80));
    try testing.expect(store.find(&named("a"), 65) == null);
    try testing.expect(store.find(&named("c"), 65) != null);
}

test "records past zone_keys_max or zone_keys_bytes_max do not enter the store" {
    var entries: [1]Entry = undefined;
    var store = Store.init(&entries, &.{});
    const many = [_][]const u8{"k"} ** (limits.zone_keys_max + 1);
    try testing.expect(!store.put(&named("a"), .keys, &many, 50));
    const big: [limits.zone_keys_bytes_max / 2 + 1]u8 = @splat(0);
    try testing.expect(!store.put(&named("a"), .keys, &.{ &big, &big }, 50));
    try testing.expect(store.put(&named("a"), .keys, &.{ "first", "second" }, 50));
    const entry = store.find(&named("a"), 0).?;
    try testing.expectEqualSlices(u8, "second", entry.record(1));
}
