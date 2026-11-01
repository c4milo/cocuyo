//! Canonical DNS name order, which DNSSEC sorts names and records by (RFC 4034 §6.1): the most
//! significant label first, each label an unsigned octet string compared from the left, a missing
//! octet before a zero octet, and an ASCII capital letter as its lowercase (docs/design.md §25).
const std = @import("std");
const assert = std.debug.assert;
const limits = @import("limits.zig");
const Name = @import("name.zig").Name;

/// Where each label of `name` starts, from the leftmost, and how many there are, the root not
/// counted.
const Labels = struct {
    starts: [limits.labels_max]u8,
    count: usize,

    fn of(name: *const Name) Labels {
        var labels: Labels = .{ .starts = undefined, .count = 0 };
        var offset: usize = 0;
        // Bounded: `Name` holds `labels_max` labels at most.
        for (0..limits.labels_max + 1) |_| {
            const length = name.bytes[offset];
            if (length == 0) break;
            assert(labels.count < limits.labels_max);
            labels.starts[labels.count] = @intCast(offset);
            labels.count += 1;
            offset += 1 + length;
        }
        assert(offset < name.len);
        return labels;
    }
};

/// How `a` sorts against `b` in canonical order (RFC 4034 §6.1).
pub fn order(a: *const Name, b: *const Name) std.math.Order {
    const labels_a = Labels.of(a);
    const labels_b = Labels.of(b);
    const common = @min(labels_a.count, labels_b.count);
    // "start by sorting the names according to their most significant (rightmost) labels".
    for (1..common + 1) |from_right| {
        const label_a = label(a, labels_a.starts[labels_a.count - from_right]);
        const label_b = label(b, labels_b.starts[labels_b.count - from_right]);
        const by_label = order_label(label_a, label_b);
        if (by_label != .eq) return by_label;
    }
    // A name whose labels all match the other's rightmost ones is the shorter, and sorts first:
    // "example" before "a.example".
    return std.math.order(labels_a.count, labels_b.count);
}

fn label(name: *const Name, start: u8) []const u8 {
    const length = name.bytes[start];
    return name.bytes[start + 1 ..][0..length];
}

/// Octet by octet from the left, a capital letter as its lowercase, and a label that ends first
/// before one that goes on: "The absence of a octet sorts before a zero value octet".
fn order_label(a: []const u8, b: []const u8) std.math.Order {
    for (a[0..@min(a.len, b.len)], b[0..@min(a.len, b.len)]) |octet_a, octet_b| {
        const by_octet = std.math.order(std.ascii.toLower(octet_a), std.ascii.toLower(octet_b));
        if (by_octet != .eq) return by_octet;
    }
    return std.math.order(a.len, b.len);
}

// Tests.

const testing = std.testing;

/// A name of the labels given, leftmost first, as octets off the wire.
fn of_labels(labels: []const []const u8) !Name {
    var name: Name = Name.empty;
    for (labels) |each| try name.append_label(each);
    try name.terminate();
    return name;
}

test "RFC 4034 §6.1's nine names are in canonical order, each before the next" {
    const sorted = [_][]const []const u8{
        &.{"example"},                    &.{ "a", "example" },
        &.{ "yljkjljk", "a", "example" }, &.{ "Z", "a", "example" },
        &.{ "zABC", "a", "EXAMPLE" },     &.{ "z", "example" },
        &.{ "\x01", "z", "example" },     &.{ "*", "z", "example" },
        &.{ "\x80", "z", "example" },
    };
    var names: [sorted.len]Name = undefined;
    for (sorted, &names) |labels, *name| name.* = try of_labels(labels);
    for (names[0 .. names.len - 1], names[1..]) |*before, *after| {
        try testing.expectEqual(std.math.Order.lt, order(before, after));
        try testing.expectEqual(std.math.Order.gt, order(after, before));
    }
}

test "a name is equal to itself in canonical order, whatever the case of its letters" {
    const lower = try Name.from_text("www.example.com");
    const upper = try Name.from_text("WWW.Example.COM");
    try testing.expectEqual(std.math.Order.eq, order(&lower, &upper));
    try testing.expectEqual(std.math.Order.eq, order(&Name.root, &Name.root));
    try testing.expectEqual(std.math.Order.lt, order(&Name.root, &lower));
}
