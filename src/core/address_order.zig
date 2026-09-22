//! Destination address ordering, RFC 6724 §6 (docs/design.md §19 step 15, §16 decision 19): the
//! ten rules as a pair-wise comparison, applied by a stable sort. The rules that need the source
//! address the host would use for a destination read it from a `Route` the consumer supplies,
//! learned by connecting a datagram socket or read from a routing table, which is I/O and so the
//! consumer's; with no routes those rules never decide. The attributes of an address, its scope,
//! precedence and label, are §3 and §2.1 of the RFC.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const address_module = @import("address.zig");
const Address = address_module.Address;
const Family = address_module.Family;

/// What the consumer knows about reaching one destination.
pub const Route = struct {
    /// The source address the host would use, or null when it has none, which rule 1 puts last.
    source: ?Address = null,
    /// Rule 1: the destination is known to be unreachable.
    known_unreachable: bool = false,
    /// Rule 3: the source is deprecated, in RFC 4862's sense.
    deprecated: bool = false,
    /// Rule 4: the source is a home address, a care-of address, or both, as mobile IPv6 has them.
    home: bool = false,
    care_of: bool = false,
    /// Rule 7: the destination is reached through an encapsulating transition mechanism, which
    /// the RFC leaves to what an implementation knows of its interfaces.
    encapsulated: bool = false,
};

/// Which of two destinations goes first, or neither, which is rule 10's tie.
pub const Preference = enum { first, second, neither };

/// Orders `addresses` in place by RFC 6724 §6. `routes`, when given, describes each address by
/// index and is as long; null applies the rules that need no source, which are 1, 6 and 8, and
/// leaves ties in the order given, which is rule 10. The sort is stable and bounded by
/// `address_lookup_addresses_max`, so it allocates nothing.
pub fn order(addresses: []Address, routes: ?[]const Route) void {
    assert(addresses.len <= constants.address_lookup_addresses_max);
    if (routes) |given| assert(given.len == addresses.len);
    var indexes: [constants.address_lookup_addresses_max]u8 = undefined;
    for (addresses, 0..) |_, index| indexes[index] = @intCast(index);
    sort_indexes(addresses, routes, indexes[0..addresses.len]);
    var sorted: [constants.address_lookup_addresses_max]Address = undefined;
    for (indexes[0..addresses.len], 0..) |from, to| sorted[to] = addresses[from];
    @memcpy(addresses, sorted[0..addresses.len]);
}

/// An insertion sort over the indexes, which is stable: an index moves ahead of another only
/// when the rules prefer its address, never when they say neither.
fn sort_indexes(addresses: []const Address, routes: ?[]const Route, indexes: []u8) void {
    var sorted: usize = 1;
    while (sorted < indexes.len) : (sorted += 1) {
        var at = sorted;
        while (at > 0) : (at -= 1) {
            const before = indexes[at - 1];
            const here = indexes[at];
            if (compare(addresses[before], route_of(routes, before), addresses[here], route_of(routes, here)) != .second) break;
            indexes[at - 1] = here;
            indexes[at] = before;
        }
    }
}

fn route_of(routes: ?[]const Route, index: usize) Route {
    const given = routes orelse return .{};
    return given[index];
}

/// The pair-wise comparison of RFC 6724 §6, the rules in order: the first that decides does.
pub fn compare(da: Address, ra: Route, db: Address, rb: Route) Preference {
    if (rule_1(ra, rb)) |preference| return preference;
    if (rule_2(da, ra, db, rb)) |preference| return preference;
    if (rule_3(ra, rb)) |preference| return preference;
    if (rule_4(ra, rb)) |preference| return preference;
    if (rule_5(da, ra, db, rb)) |preference| return preference;
    if (rule_6(da, db)) |preference| return preference;
    if (rule_7(ra, rb)) |preference| return preference;
    if (rule_8(da, db)) |preference| return preference;
    if (rule_9(da, ra, db, rb)) |preference| return preference;
    // Rule 10: otherwise, leave the order unchanged.
    return .neither;
}

/// Rule 1: avoid unusable destinations. One known unreachable, or with no source, goes after
/// the other; two such stay as they are.
fn rule_1(ra: Route, rb: Route) ?Preference {
    const a_usable = !ra.known_unreachable and ra.source != null;
    const b_usable = !rb.known_unreachable and rb.source != null;
    if (a_usable == b_usable) return null;
    return if (a_usable) .first else .second;
}

/// Rule 2: prefer matching scope, between a destination and its source.
fn rule_2(da: Address, ra: Route, db: Address, rb: Route) ?Preference {
    const sa = ra.source orelse return null;
    const sb = rb.source orelse return null;
    const a_matches = scope_of(da) == scope_of(sa);
    const b_matches = scope_of(db) == scope_of(sb);
    if (a_matches == b_matches) return null;
    return if (a_matches) .first else .second;
}

/// Rule 3: avoid deprecated addresses.
fn rule_3(ra: Route, rb: Route) ?Preference {
    if (ra.deprecated == rb.deprecated) return null;
    return if (rb.deprecated) .first else .second;
}

/// Rule 4: prefer home addresses. A source that is both home and care-of first, then a home
/// address over a care-of address.
fn rule_4(ra: Route, rb: Route) ?Preference {
    const a_both = ra.home and ra.care_of;
    const b_both = rb.home and rb.care_of;
    if (a_both != b_both) return if (a_both) .first else .second;
    const a_home_only = ra.home and !ra.care_of;
    const b_home_only = rb.home and !rb.care_of;
    const a_care_only = ra.care_of and !ra.home;
    const b_care_only = rb.care_of and !rb.home;
    if (a_home_only and b_care_only) return .first;
    if (a_care_only and b_home_only) return .second;
    return null;
}

/// Rule 5: prefer matching label, between a destination and its source.
fn rule_5(da: Address, ra: Route, db: Address, rb: Route) ?Preference {
    const sa = ra.source orelse return null;
    const sb = rb.source orelse return null;
    const a_matches = policy_of(da).label == policy_of(sa).label;
    const b_matches = policy_of(db).label == policy_of(sb).label;
    if (a_matches == b_matches) return null;
    return if (a_matches) .first else .second;
}

/// Rule 6: prefer higher precedence.
fn rule_6(da: Address, db: Address) ?Preference {
    const pa = policy_of(da).precedence;
    const pb = policy_of(db).precedence;
    if (pa == pb) return null;
    return if (pa > pb) .first else .second;
}

/// Rule 7: prefer native transport.
fn rule_7(ra: Route, rb: Route) ?Preference {
    if (ra.encapsulated == rb.encapsulated) return null;
    return if (rb.encapsulated) .first else .second;
}

/// Rule 8: prefer smaller scope.
fn rule_8(da: Address, db: Address) ?Preference {
    const sa = scope_of(da);
    const sb = scope_of(db);
    if (sa == sb) return null;
    return if (sa < sb) .first else .second;
}

/// Rule 9: use longest matching prefix, between a destination and its source, when both
/// destinations are of one family.
fn rule_9(da: Address, ra: Route, db: Address, rb: Route) ?Preference {
    const sa = ra.source orelse return null;
    const sb = rb.source orelse return null;
    if (is_v4(da) != is_v4(db)) return null;
    const la = common_prefix_len(sa, da);
    const lb = common_prefix_len(sb, db);
    if (la == lb) return null;
    return if (la > lb) .first else .second;
}

// The attributes of an address.

/// The scope of an address (RFC 6724 §3.1 to §3.4): link-local for `fe80::/10`, `::1`, `127/8`
/// and `169.254/16`; site-local for `fec0::/10`; a multicast address's own scope field; and
/// global for everything else, ULAs and the embedded-IPv4 forms included.
pub fn scope_of(address: Address) u8 {
    const octets = mapped_form(address);
    if (is_v4(address)) return scope_of_v4(octets[constants.v4_mapped_prefix.len..].*);
    if (octets[0] == constants.v6_multicast_first_octet) return octets[1] & constants.v6_multicast_scope_mask;
    if (masked_equal(octets[0..prefix_octets].*, constants.v6_link_local_prefix)) return constants.scope_link_local;
    if (masked_equal(octets[0..prefix_octets].*, constants.v6_site_local_prefix)) return constants.scope_site_local;
    if (address.equal(&loopback_v6())) return constants.scope_link_local;
    return constants.scope_global;
}

fn scope_of_v4(octets: [constants.address_v4_bytes]u8) u8 {
    if (octets[0] == constants.v4_loopback_first_octet) return constants.scope_link_local;
    if (std.mem.eql(u8, octets[0..constants.v4_link_local_prefix.len], &constants.v4_link_local_prefix)) {
        return constants.scope_link_local;
    }
    return constants.scope_global;
}

/// The octets the ten-bit prefixes are read from.
const prefix_octets = constants.v6_ten_bit_mask.len;

fn masked_equal(head: [prefix_octets]u8, prefix: [prefix_octets]u8) bool {
    return (head[0] & constants.v6_ten_bit_mask[0]) == prefix[0] and
        (head[1] & constants.v6_ten_bit_mask[1]) == prefix[1];
}

fn loopback_v6() Address {
    return Address.from_v6(constants.address_policy_table[0].prefix);
}

/// The precedence and label of an address: the longest matching row of RFC 6724 §2.1's default
/// policy table, over the IPv4-mapped form of an IPv4 address (§3.2).
pub fn policy_of(address: Address) constants.PolicyRow {
    const octets = mapped_form(address);
    var best: ?constants.PolicyRow = null;
    for (constants.address_policy_table) |row| {
        if (!prefix_matches(octets, row.prefix, row.bits)) continue;
        if (best == null or row.bits > best.?.bits) best = row;
    }
    // `::/0` matches every address, so a row is always found.
    assert(best != null);
    return best.?;
}

fn prefix_matches(octets: [constants.address_v6_bytes]u8, prefix: [constants.address_v6_bytes]u8, bits: u8) bool {
    assert(bits <= constants.address_v6_bytes * constants.bits_per_octet);
    const whole = bits / constants.bits_per_octet;
    if (!std.mem.eql(u8, octets[0..whole], prefix[0..whole])) return false;
    const rest: u3 = @intCast(bits % constants.bits_per_octet);
    if (rest == 0) return true;
    const mask: u8 = ~(@as(u8, std.math.maxInt(u8)) >> rest);
    return (octets[whole] & mask) == (prefix[whole] & mask);
}

/// The common prefix length of a source and a destination (RFC 6724 §2.2), in bits, up to the
/// source's prefix: 64 for IPv6, the whole address for IPv4. Two addresses of different
/// families share nothing.
pub fn common_prefix_len(source: Address, destination: Address) u8 {
    if (is_v4(source) != is_v4(destination)) return 0;
    const a = mapped_form(source);
    const b = mapped_form(destination);
    const cap: u8 = if (is_v4(source)) constants.common_prefix_bits_v4_max else constants.common_prefix_bits_v6_max;
    const from: usize = if (is_v4(source)) constants.v4_mapped_prefix.len else 0;
    var bits: u8 = 0;
    for (a[from..], b[from..]) |mine, theirs| {
        if (bits == cap) break;
        const differing = mine ^ theirs;
        const same: u8 = @intCast(@clz(differing));
        bits = @min(cap, bits + same);
        if (differing != 0) break;
    }
    assert(bits <= cap);
    return bits;
}

/// Whether the address is IPv4, plainly or as an IPv4-mapped IPv6 address (RFC 4291 §2.5.5.2).
fn is_v4(address: Address) bool {
    if (address.family == .ipv4) return true;
    return std.mem.eql(u8, address.octets[0..constants.v4_mapped_prefix.len], &constants.v4_mapped_prefix);
}

/// The sixteen octets the policy table and the scopes read: an IPv4 address in its mapped form
/// (RFC 6724 §3.2), an IPv6 address as it is.
fn mapped_form(address: Address) [constants.address_v6_bytes]u8 {
    return switch (address.family) {
        .ipv4 => address.v4_mapped().octets,
        .ipv6 => address.octets,
    };
}

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");

fn addr(text: []const u8) Address {
    return Address.from_text(text) orelse unreachable;
}

fn via(text: []const u8) Route {
    return .{ .source = addr(text) };
}

/// One worked example of RFC 6724 §10.2: two destinations with the source the RFC selects for
/// each, and which comes first.
const Example = struct {
    first: []const u8,
    first_route: Route,
    second: []const u8,
    second_route: Route,
    rule: []const u8,
};

/// Built at run time: parsing nine addresses is past what the compiler evaluates at compile time.
fn examples() [fixtures.ordering_examples]Example {
    return .{
        .{ .first = "2001:db8:1::1", .first_route = via("2001:db8:1::2"), .second = "198.51.100.121", .second_route = via("169.254.13.78"), .rule = "prefer matching scope" },
        .{ .first = "198.51.100.121", .first_route = via("198.51.100.117"), .second = "2001:db8:1::1", .second_route = via("fe80::1"), .rule = "prefer matching scope" },
        .{ .first = "2001:db8:1::1", .first_route = via("2001:db8:1::2"), .second = "10.1.2.3", .second_route = via("10.1.2.4"), .rule = "prefer higher precedence" },
        .{ .first = "fe80::1", .first_route = via("fe80::2"), .second = "2001:db8:1::1", .second_route = via("2001:db8:1::2"), .rule = "prefer smaller scope" },
        .{ .first = "2001:db8:1::1", .first_route = .{ .source = addr("2001:db8:3::1"), .home = true }, .second = "fe80::1", .second_route = .{ .source = addr("fe80::2"), .care_of = true }, .rule = "prefer home address" },
        .{ .first = "2001:db8:1::1", .first_route = via("2001:db8:1::2"), .second = "fe80::1", .second_route = .{ .source = addr("fe80::2"), .deprecated = true }, .rule = "avoid deprecated addresses" },
        .{ .first = "2001:db8:1::1", .first_route = via("2001:db8:1::2"), .second = "2001:db8:3ffe::1", .second_route = via("2001:db8:3f44::2"), .rule = "longest matching prefix" },
        .{ .first = "2002:c633:6401::1", .first_route = via("2002:c633:6401::2"), .second = "2001:db8:1::1", .second_route = via("2002:c633:6401::2"), .rule = "prefer matching label" },
        .{ .first = "2001:db8:1::1", .first_route = via("2001:db8:1::2"), .second = "2002:c633:6401::1", .second_route = via("2002:c633:6401::2"), .rule = "prefer higher precedence" },
    };
}

test "the nine examples of RFC 6724 §10.2 come out as the RFC says, given the sources it selects" {
    for (examples()) |example| {
        // Listed the wrong way round, so the sort has to move one.
        var addresses = [_]Address{ addr(example.second), addr(example.first) };
        const routes = [_]Route{ example.second_route, example.first_route };
        order(&addresses, &routes);
        try testing.expect(addresses[0].equal(&addr(example.first)));
        try testing.expect(addresses[1].equal(&addr(example.second)));
        try testing.expectEqual(Preference.first, compare(addr(example.first), example.first_route, addr(example.second), example.second_route));
        try testing.expectEqual(Preference.second, compare(addr(example.second), example.second_route, addr(example.first), example.first_route));
    }
}

test "with no routes, precedence then scope order the list, and ties keep their order" {
    var addresses = [_]Address{ addr("192.0.2.1"), addr("2001:db8::1"), addr("192.0.2.2"), addr("fe80::1"), addr("2001:db8::2") };
    order(&addresses, null);
    // Global IPv6 (precedence 40) before IPv4 (35, as ::ffff:0:0/96); among the IPv6, the
    // link-local one first by scope, and the two global ones as they were.
    try testing.expect(addresses[0].equal(&addr("fe80::1")));
    try testing.expect(addresses[1].equal(&addr("2001:db8::1")));
    try testing.expect(addresses[2].equal(&addr("2001:db8::2")));
    try testing.expect(addresses[3].equal(&addr("192.0.2.1")));
    try testing.expect(addresses[4].equal(&addr("192.0.2.2")));
}

test "an unreachable destination, or one with no source, goes last" {
    var addresses = [_]Address{ addr("2001:db8::1"), addr("2001:db8::2"), addr("2001:db8::3") };
    const routes = [_]Route{ .{ .source = addr("2001:db8::9"), .known_unreachable = true }, .{}, via("2001:db8::9") };
    order(&addresses, &routes);
    try testing.expect(addresses[0].equal(&addr("2001:db8::3")));
    try testing.expect(addresses[1].equal(&addr("2001:db8::1")));
    try testing.expect(addresses[2].equal(&addr("2001:db8::2")));
}

test "a native transport is preferred to an encapsulated one, all else equal" {
    var addresses = [_]Address{ addr("2001:db8::1"), addr("2001:db8::2") };
    const routes = [_]Route{ .{ .source = addr("2001:db8::9"), .encapsulated = true }, via("2001:db8::9") };
    order(&addresses, &routes);
    try testing.expect(addresses[0].equal(&addr("2001:db8::2")));
}

test "the scopes are RFC 6724 §3's: loopback and IPv4 link-local are link-local, ULAs global" {
    try testing.expectEqual(@as(u8, constants.scope_link_local), scope_of(addr("::1")));
    try testing.expectEqual(@as(u8, constants.scope_link_local), scope_of(addr("fe80::1")));
    try testing.expectEqual(@as(u8, constants.scope_site_local), scope_of(addr("fec0::1")));
    try testing.expectEqual(@as(u8, constants.scope_link_local), scope_of(addr("127.0.0.1")));
    try testing.expectEqual(@as(u8, constants.scope_link_local), scope_of(addr("169.254.13.78")));
    try testing.expectEqual(@as(u8, constants.scope_link_local), scope_of(addr("::ffff:127.0.0.1")));
    try testing.expectEqual(@as(u8, constants.scope_global), scope_of(addr("10.1.2.3")));
    try testing.expectEqual(@as(u8, constants.scope_global), scope_of(addr("fd00::1")));
    try testing.expectEqual(@as(u8, constants.scope_global), scope_of(addr("2001:db8::1")));
    try testing.expectEqual(@as(u8, 0x5), scope_of(addr("ff05::1")));
    try testing.expectEqual(@as(u8, 0x2), scope_of(addr("ff02::1")));
}

test "the policy table is matched by longest prefix, over the mapped form of an IPv4 address" {
    try testing.expectEqual(@as(u8, 50), policy_of(addr("::1")).precedence);
    try testing.expectEqual(@as(u8, 35), policy_of(addr("192.0.2.1")).precedence);
    try testing.expectEqual(@as(u8, 4), policy_of(addr("::ffff:192.0.2.1")).label);
    try testing.expectEqual(@as(u8, 30), policy_of(addr("2002:c633:6401::1")).precedence);
    try testing.expectEqual(@as(u8, 5), policy_of(addr("2001::1")).precedence);
    try testing.expectEqual(@as(u8, 40), policy_of(addr("2001:db8::1")).precedence);
    try testing.expectEqual(@as(u8, 13), policy_of(addr("fc00::1")).label);
    try testing.expectEqual(@as(u8, 3), policy_of(addr("::192.0.2.1")).label);
    try testing.expectEqual(@as(u8, 11), policy_of(addr("fec0::1")).label);
    try testing.expectEqual(@as(u8, 12), policy_of(addr("3ffe::1")).label);
}

test "the common prefix stops at the source's prefix: 64 bits for IPv6, and never across families" {
    try testing.expectEqual(@as(u8, 64), common_prefix_len(addr("fe80::1"), addr("fe80::2")));
    try testing.expectEqual(@as(u8, 40), common_prefix_len(addr("2001:db8:3f44::2"), addr("2001:db8:3ffe::1")));
    try testing.expectEqual(@as(u8, 32), common_prefix_len(addr("10.1.2.4"), addr("10.1.2.4")));
    try testing.expectEqual(@as(u8, 30), common_prefix_len(addr("10.1.2.4"), addr("10.1.2.7")));
    try testing.expectEqual(@as(u8, 0), common_prefix_len(addr("10.1.2.4"), addr("2001:db8::1")));
}
