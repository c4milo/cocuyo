//! Setting a value back to its defaults one field at a time, so that a buffer whose bytes nothing
//! reads past its count keeps them. Assigning the whole default value writes every field, and a
//! safe build writes 0xAA over whatever the default leaves `undefined`, through `memset`: a TCP
//! connection's frame alone is 64 KiB, and the loop may still hold part of the slot (docs/design.md
//! §16 decision 34, and §19 step 13, the stream's rule 10).
const std = @import("std");

/// Sets every field of `value` to its default but the fields `kept` names, which keep what they
/// hold. A field with no default does not compile, and nor does a kept name that names no field.
pub fn defaults_except(comptime T: type, value: *T, comptime kept: []const []const u8) void {
    comptime for (kept) |name| {
        if (!@hasField(T, name)) @compileError(@typeName(T) ++ " has no field " ++ name);
    };
    inline for (@typeInfo(T).@"struct".fields) |field| {
        if (comptime named(kept, field.name)) continue;
        @field(value, field.name) = comptime field.defaultValue().?;
    }
}

fn named(comptime names: []const []const u8, comptime name: []const u8) bool {
    for (names) |candidate| {
        if (std.mem.eql(u8, candidate, name)) return true;
    }
    return false;
}

// Tests.

const testing = std.testing;

/// The octet a test's buffer holds before the reset, which no reset writes.
const untouched: u8 = 0x5a;

const Sample = struct {
    count: u16 = 0,
    open: bool = false,
    next: ?u8 = null,
    kept: u32 = 0,
    bytes: [@sizeOf(u64)]u8 = undefined,
};

test "every field goes back to its default but those kept, whose bytes stay as they were" {
    var sample: Sample = .{ .count = 7, .open = true, .next = 3, .kept = 9, .bytes = @splat(untouched) };
    defaults_except(Sample, &sample, &.{ "kept", "bytes" });
    try testing.expectEqual(@as(u16, 0), sample.count);
    try testing.expect(!sample.open);
    try testing.expectEqual(@as(?u8, null), sample.next);
    try testing.expectEqual(@as(u32, 9), sample.kept);
    for (sample.bytes) |octet| try testing.expectEqual(untouched, octet);
}
