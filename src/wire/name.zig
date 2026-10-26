//! Name decoding and encoding, and the entry point of the DNS-0x20 case mixer, which
//! `name_case.zig` holds (split from this file by the file-length rule).
//!
//! This is the file an attacker reaches first, so it is the file with the most bounds. A name in a
//! message may be a sequence of labels, or a compression pointer to a name earlier in the message,
//! or labels ending in such a pointer (RFC 1035 §4.1.4). Three rules bound it:
//!
//! 1. A pointer must point **strictly backwards**, at an offset below the pointer's own first
//!    octet. So a pointer at itself or ahead of itself is refused. A loop back through labels
//!    passes this rule: a pointer that aims at labels that lead to the same pointer again.
//! 2. The hops are bounded by `compression_hops_max`. That ends such a loop, and a long legal
//!    chain stays cheap.
//! 3. The name is bounded by `name_bytes_max` and `labels_max`, so the labels cannot grow without
//!    end between hops.
//!
//! Together those make the walk end. Every iteration takes a label, of which there can be
//! `labels_max`, or follows a pointer, of which there can be `compression_hops_max`. Nothing
//! recurses.
//!
//! Each of the three is a check that returns an error and an assertion that must not fire
//! (CLAUDE.md non-negotiable 6). The reserved label kinds `01` and `10` are refused rather than
//! ignored: RFC 6891 §6.1.1 retired the one experiment that used them.
//!
//! `decode` and `skip` share the walk, so each refuses what the other refuses, with the same
//! error (docs/design.md §8). `decode` copies each label into a `Name`. `skip` counts the octets
//! in a `Measure`, and copies nothing.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const Name = core.Name;
const constants = @import("constants.zig");
const integer = @import("integer.zig");
const case = @import("name_case.zig");

/// DNS-0x20's mixer, and check 5's compare of an echo with the name it makes (`name_case.zig`).
pub const mix_case = case.mix_case;
pub const is_mix_of = case.is_mix_of;

/// Decodes the name encoded at `offset` into `out`, and returns the offset of the first octet
/// after that encoding: after the root octet, or after the first pointer, whichever ends it.
///
/// `out` holds an uncompressed copy, so the caller may reuse the message buffer the moment this
/// returns.
pub fn decode(message: []const u8, offset: usize, out: *Name) Error!usize {
    out.* = Name.empty;
    const end = try walk_name(message, offset, out);
    assert(out.len >= 1);
    assert(out.len <= core.limits.name_bytes_max);
    return end;
}

/// The offset `decode` returns for the name at `offset`, without a copy of the name. The record
/// walk uses this to reach a record's type. The type then says whether to decode the owner name
/// (docs/design.md §11).
///
/// It walks the name as `decode` does, through every pointer (RFC 1035 §4.1.4). It counts each
/// octet of the name, also the octets that a pointer reaches: the labels, their length octets and
/// the root (§3.1). So it refuses each name that `decode` refuses, with the same error. A name over
/// 255 octets is one of them (§2.3.4). The end is where the name ends in the message: the octet
/// after the root, or after the first pointer.
pub fn skip(message: []const u8, offset: usize) Error!usize {
    var measure: Measure = .{};
    const end = try walk_name(message, offset, &measure);
    assert(measure.len >= 1);
    assert(measure.len <= core.limits.name_bytes_max);
    return end;
}

/// The walk `decode` and `skip` share. `out` takes each label and then the root: a `Name` copies
/// them, and a `Measure` counts their octets.
fn walk_name(message: []const u8, offset: usize, out: anytype) Error!usize {
    assert(message.len <= core.limits.message_bytes_max);
    assert(offset <= message.len);
    var walk: Walk = .{ .message = message, .cursor = offset };
    // Every step either takes a label or follows a pointer, and both are bounded, so the walk
    // ends whatever the message says.
    while (walk.labels <= core.limits.labels_max) {
        if (try walk.step(out)) |end| {
            assert(walk.hops <= core.limits.compression_hops_max);
            return end;
        }
    }
    assert(walk.labels > core.limits.labels_max);
    return Error.MalformedName;
}

/// What `skip` keeps of a name in place of a `Name`: its length in octets, and no copy. It takes a
/// label and the root as `Name.append_label` and `Name.terminate` take them. So `skip` refuses a
/// name at the label where `decode` refuses it, with the same error.
const Measure = struct {
    len: usize = 0,

    fn append_label(self: *Measure, label: []const u8) Error!void {
        assert(label.len >= 1);
        assert(label.len <= core.limits.label_bytes_max);
        // The label, its length octet and a root after them: "label octets and label length
        // octets" count (RFC 1035 §3.1), in a name of "255 octets or less" (§2.3.4).
        if (self.len + 1 + label.len + 1 > core.limits.name_bytes_max) return Error.NameTooLong;
        self.len += 1 + label.len;
        assert(self.len < core.limits.name_bytes_max);
    }

    /// The root. Each label left room for it, so this is an assertion and not a check.
    fn terminate(self: *Measure) Error!void {
        assert(self.len < core.limits.name_bytes_max);
        self.len += 1;
    }
};

/// What the octet at a cursor introduces (RFC 1035 §4.1.4).
const LabelKind = enum { label, pointer, reserved };

fn kind_of(length: u8) LabelKind {
    return switch (length & constants.label_kind_mask) {
        constants.label_kind_label => .label,
        constants.label_kind_pointer => .pointer,
        // `01` and `10`: RFC 6891 §5 retired the one experiment that used them.
        else => .reserved,
    };
}

/// One walk over one name. `end` is the offset after the name *as encoded where the walk started*,
/// which a pointer fixes at the pointer's own two octets however far the walk then jumps.
const Walk = struct {
    message: []const u8,
    cursor: usize,
    end: ?usize = null,
    hops: usize = 0,
    labels: usize = 0,

    /// One step. Returns the end offset when the name is complete, and null while it is not.
    fn step(self: *Walk, out: anytype) Error!?usize {
        if (self.cursor >= self.message.len) return Error.MalformedMessage;
        const length = self.message[self.cursor];
        return switch (kind_of(length)) {
            .pointer => try self.follow(),
            .label => try self.take(length, out),
            .reserved => return Error.MalformedName,
        };
    }

    /// Follows one compression pointer, which must point strictly backwards.
    fn follow(self: *Walk) Error!?usize {
        if (self.hops == core.limits.compression_hops_max) return Error.BadCompressionPointer;
        const target = try read_pointer(self.message, self.cursor);
        // Strictly backwards, at "a prior occurance of the same name" (RFC 1035 §4.1.4). This
        // refuses a pointer at itself or ahead of itself. The hop bound ends a loop through labels.
        if (target >= self.cursor) return Error.BadCompressionPointer;
        if (self.end == null) self.end = self.cursor + constants.pointer_bytes;
        self.cursor = target;
        self.hops += 1;
        assert(self.hops <= core.limits.compression_hops_max);
        return null;
    }

    /// Takes one label, or ends the name when the length octet is the root.
    fn take(self: *Walk, length: u8, out: anytype) Error!?usize {
        assert(length <= core.limits.label_bytes_max);
        if (length == 0) {
            try out.terminate();
            return self.end orelse self.cursor + 1;
        }
        try out.append_label(try label_at(self.message, self.cursor, length));
        self.cursor += 1 + length;
        self.labels += 1;
        return null;
    }
};

/// Writes `name`'s wire bytes into `out` and returns the count. cocuyo compresses nothing it
/// sends: a query carries one question and has no earlier name to point at.
pub fn encode(name: *const Name, out: []u8) usize {
    assert(name.len >= 1);
    assert(out.len >= name.len);
    @memcpy(out[0..name.len], name.wire());
    return name.len;
}

fn read_pointer(message: []const u8, cursor: usize) Error!usize {
    if (cursor + constants.pointer_bytes > message.len) return Error.MalformedMessage;
    assert(cursor + constants.u16_bytes <= message.len);
    return integer.read_u16(message, cursor) & constants.pointer_offset_mask;
}

/// The octets of the label whose length octet is at `cursor`, once they are inside the message.
fn label_at(message: []const u8, cursor: usize, length: u8) Error![]const u8 {
    // The kind bits are `00` here, so the length cannot exceed the label limit.
    assert(length <= core.limits.label_bytes_max);
    assert(length != 0);
    const start = cursor + 1;
    if (start + length > message.len) return Error.MalformedMessage;
    return message[start..][0..length];
}

// Tests.

const testing = std.testing;

/// A message holding `example.com` at offset 12, then `www` followed by a pointer to it at 25.
/// The offsets are what a real query plus answer would produce, so the fixtures read like messages
/// rather than like arrays.
const compressed_message = [_]u8{0} ** core.constants.header_bytes ++
    "\x07example\x03com\x00".* ++ // offset 12, 13 octets
    "\x03www\xc0\x0c".*; // offset 25: one label then a pointer to offset 12
const name_example = "\x07example\x03com\x00";

test "a name of labels decodes and reports the octet after the root" {
    var name: Name = Name.empty;
    const end = try decode(&compressed_message, core.constants.header_bytes, &name);
    try testing.expectEqualStrings("\x07example\x03com\x00", name.wire());
    try testing.expectEqual(@as(usize, 25), end);
}

test "a name ending in a pointer decodes to the whole name and ends after the pointer" {
    var name: Name = Name.empty;
    const end = try decode(&compressed_message, 25, &name);
    try testing.expect(name.equal(&try Name.from_text("www.example.com")));
    try testing.expectEqual(@as(usize, compressed_message.len), end);
}

test "a pointer that does not point strictly backwards is refused" {
    // A pointer at offset 12 pointing at offset 12: the classic self-loop.
    const message = [_]u8{0} ** core.constants.header_bytes ++ "\xc0\x0c".*;
    var name: Name = Name.empty;
    try testing.expectError(Error.BadCompressionPointer, decode(&message, core.constants.header_bytes, &name));

    // A pointer pointing forwards, at a name later in the message.
    const forwards = [_]u8{0} ** core.constants.header_bytes ++ "\xc0\x10\x00\x00\x03www\x00".*;
    try testing.expectError(Error.BadCompressionPointer, decode(&forwards, core.constants.header_bytes, &name));
}

test "a chain of pointers longer than the hop bound is refused, by decode and by skip" {
    // Each pointer points at the one before it, so every hop is strictly backwards and legal; only
    // the hop bound stops the chain. Seventeen pointers: one more than compression_hops_max.
    const hops = core.limits.compression_hops_max + 1;
    var message: [core.constants.header_bytes + hops * constants.pointer_bytes]u8 = @splat(0);
    var index: usize = 0;
    while (index < hops) : (index += 1) {
        const at = core.constants.header_bytes + index * constants.pointer_bytes;
        const target = if (index == 0) 0 else at - constants.pointer_bytes;
        message[at] = constants.label_kind_pointer | @as(u8, @intCast(target >> constants.octet_bits));
        message[at + 1] = @intCast(target & 0xff);
    }
    // Start at the last pointer, so the walk chases every hop backwards.
    const last = core.constants.header_bytes + (hops - 1) * constants.pointer_bytes;
    try expect_both(Error.BadCompressionPointer, &message, last);
}

test "a name may chase as many pointers as the hop bound allows, and skip chases them too" {
    // Real servers point at a name that itself ends in a pointer: an MX exchange at the tail of the
    // one before it, which ends at the question. So the bound's own count of hops must decode.
    const hops = core.limits.compression_hops_max;
    const first = core.constants.header_bytes + name_example.len;
    var message: [first + hops * constants.pointer_bytes]u8 = @splat(0);
    @memcpy(message[core.constants.header_bytes..first], name_example);
    for (0..hops) |index| {
        const at = first + index * constants.pointer_bytes;
        const target = if (index == 0) core.constants.header_bytes else at - constants.pointer_bytes;
        message[at] = constants.label_kind_pointer | @as(u8, @intCast(target >> constants.octet_bits));
        message[at + 1] = @intCast(target & 0xff);
    }
    var name: Name = Name.empty;
    const end = try decode(&message, message.len - constants.pointer_bytes, &name);
    try testing.expectEqualStrings(name_example, name.wire());
    try testing.expectEqual(message.len, end);
    try testing.expectEqual(message.len, try skip(&message, message.len - constants.pointer_bytes));
}

test "a reserved label kind is refused" {
    for ([_]u8{ 0x40, 0x80 }) |kind| {
        const message = [_]u8{0} ** core.constants.header_bytes ++ [_]u8{ kind, 0x00 };
        var name: Name = Name.empty;
        try testing.expectError(Error.MalformedName, decode(&message, core.constants.header_bytes, &name));
    }
}

test "a label running past the end of the message is malformed" {
    const message = [_]u8{0} ** core.constants.header_bytes ++ "\x07exam".*;
    var name: Name = Name.empty;
    try testing.expectError(Error.MalformedMessage, decode(&message, core.constants.header_bytes, &name));
}

test "a name with no root octet is malformed rather than accepted at the end" {
    const message = [_]u8{0} ** core.constants.header_bytes ++ "\x03www".*;
    var name: Name = Name.empty;
    try testing.expectError(Error.MalformedMessage, decode(&message, core.constants.header_bytes, &name));
}

test "a pointer whose second octet is past the end is malformed" {
    const message = [_]u8{0} ** core.constants.header_bytes ++ [_]u8{constants.label_kind_pointer};
    var name: Name = Name.empty;
    try testing.expectError(Error.MalformedMessage, decode(&message, core.constants.header_bytes, &name));
}

test "skip reaches the octet after a name: after its root, or after its first pointer" {
    try testing.expectEqual(@as(usize, 25), try skip(&compressed_message, core.constants.header_bytes));
    try testing.expectEqual(@as(usize, compressed_message.len), try skip(&compressed_message, 25));
}

test "skip refuses a reserved kind and a truncated name" {
    const reserved = [_]u8{0} ** core.constants.header_bytes ++ [_]u8{0x40};
    try testing.expectError(Error.MalformedName, skip(&reserved, core.constants.header_bytes));
    const truncated = [_]u8{0} ** core.constants.header_bytes ++ "\x07exam".*;
    try testing.expectError(Error.MalformedMessage, skip(&truncated, core.constants.header_bytes));
}

test "encode writes the wire bytes and nothing else" {
    const name = try Name.from_text("example.com");
    var out: [core.limits.name_bytes_max]u8 = @splat(0xff);
    try testing.expectEqual(@as(usize, 13), encode(&name, &out));
    try testing.expectEqualStrings("\x07example\x03com\x00", out[0..13]);
}

/// A label of `length` octets, every one an `a`, after its length octet.
fn label_of(comptime length: usize) [1 + length]u8 {
    return [_]u8{@intCast(length)} ++ [_]u8{'a'} ** length;
}

test "skip refuses a name longer than 255 octets, as decode does" {
    // "names 255 octets or less" (RFC 1035 §2.3.4), "label octets and label length octets"
    // counted (§3.1).
    const header = [_]u8{0} ** core.constants.header_bytes;
    const three_longest = label_of(core.limits.label_bytes_max) ** 3;
    var name: Name = Name.empty;
    // Three labels of 63, one of 61, and the root: 255 octets.
    const longest = header ++ three_longest ++ label_of(61) ++ [_]u8{0};
    try testing.expectEqual(header.len + core.limits.name_bytes_max, longest.len);
    try testing.expectEqual(longest.len, try decode(&longest, header.len, &name));
    try testing.expectEqual(longest.len, try skip(&longest, header.len));
    // One of 62 in place of 61: 256 octets.
    const one_past = header ++ three_longest ++ label_of(62) ++ [_]u8{0};
    try testing.expectError(Error.NameTooLong, decode(&one_past, header.len, &name));
    try testing.expectError(Error.NameTooLong, skip(&one_past, header.len));
    // The most labels the walk counts, each of 63, and the root: 8,193 octets.
    const most = header ++ label_of(core.limits.label_bytes_max) ** core.limits.labels_max ++ [_]u8{0};
    try testing.expectError(Error.NameTooLong, decode(&most, header.len, &name));
    try testing.expectError(Error.NameTooLong, skip(&most, header.len));
}

test "skip refuses labels that leave a pointer no room for the root its name ends in" {
    // A root at offset 12 for the pointer to reach: the shortest name a pointer can end in.
    const before = [_]u8{0} ** (core.constants.header_bytes + 1);
    const pointer = [_]u8{ constants.label_kind_pointer, @intCast(core.constants.header_bytes) };
    const three_longest = label_of(core.limits.label_bytes_max) ** 3;
    var name: Name = Name.empty;
    // 254 octets of labels, and the root the pointer reaches: 255 octets.
    const longest = before ++ three_longest ++ label_of(61) ++ pointer;
    try testing.expectEqual(longest.len, try decode(&longest, before.len, &name));
    try testing.expectEqual(longest.len, try skip(&longest, before.len));
    // 255 octets of labels, so the name the pointer ends is 256 octets at least.
    const one_past = before ++ three_longest ++ label_of(62) ++ pointer;
    try testing.expectError(Error.NameTooLong, decode(&one_past, before.len, &name));
    try testing.expectError(Error.NameTooLong, skip(&one_past, before.len));
}

test "a pointer to offset 16383, the farthest its fourteen bits reach, is followed" {
    // A pointer's offset is the fourteen bits after its two kind bits (RFC 1035 §4.1.4), so
    // 0x3FFF is the farthest name it names, and no pointer names an offset past it.
    const target = constants.pointer_offset_mask;
    var message: [target + name_example.len + constants.pointer_bytes]u8 = @splat(0);
    @memcpy(message[target..][0..name_example.len], name_example);
    const pointer_at = target + name_example.len;
    integer.write_u16(&message, pointer_at, @as(u16, constants.label_kind_pointer) << constants.octet_bits | target);
    var name: Name = Name.empty;
    try testing.expectEqual(message.len, try decode(&message, pointer_at, &name));
    try testing.expectEqualStrings(name_example, name.wire());
    try testing.expectEqual(message.len, try skip(&message, pointer_at));
}

/// Holds `decode` and `skip` to one result for the name at `offset`: the end `expected` names, or
/// its error.
fn expect_both(expected: Error!usize, message: []const u8, offset: usize) !void {
    var name: Name = Name.empty;
    if (expected) |end| {
        try testing.expectEqual(end, try decode(message, offset, &name));
        try testing.expectEqual(end, try skip(message, offset));
    } else |err| {
        try testing.expectError(err, decode(message, offset, &name));
        try testing.expectError(err, skip(message, offset));
    }
}

/// A compression pointer to `target`: the offset's high six bits beside the two that say pointer,
/// then its low eight (RFC 1035 §4.1.4).
fn pointer_of(comptime target: u16) [constants.pointer_bytes]u8 {
    const value = @as(u16, constants.label_kind_pointer) << constants.octet_bits | target;
    return .{ @intCast(value >> constants.octet_bits), @truncate(value) };
}

const header_zeros = [_]u8{0} ** core.constants.header_bytes;
/// The type, class, TTL and rdlength of a record after its owner, so a name's end is not the
/// message's.
const record_after = [_]u8{0} ** core.constants.record_fixed_bytes;

test "skip measures a name through its pointer, and refuses one past 255 octets, as decode does" {
    // "label octets and label length octets" count (RFC 1035 §3.1), those a pointer reaches too
    // (§4.1.4), and a name is "255 octets or less" (§2.3.4).
    // A name of 251 octets at offset 12: three labels of 63, one of 57, and the root.
    const long_target = label_of(core.limits.label_bytes_max) ** 3 ++ label_of(57) ++ [_]u8{0};
    const owner_at = header_zeros.len + long_target.len;
    const to_target = comptime pointer_of(core.constants.header_bytes);
    // A label of 3 and the pointer: 255 octets whole. The name ends after the pointer.
    const longest = header_zeros ++ long_target ++ label_of(3) ++ to_target ++ record_after;
    try expect_both(longest.len - record_after.len, &longest, owner_at);
    // A label of 4: 256 octets.
    const one_past = header_zeros ++ long_target ++ label_of(4) ++ to_target ++ record_after;
    try expect_both(Error.NameTooLong, &one_past, owner_at);
}

test "skip counts the octets of every hop, and ends the name at its first pointer" {
    // A name of 251 octets at offset 12, and a name between: a label of 1 and a pointer to the
    // first, 253 octets whole.
    const long_target = label_of(core.limits.label_bytes_max) ** 3 ++ label_of(57) ++ [_]u8{0};
    const between_at = header_zeros.len + long_target.len;
    const between = label_of(1) ++ comptime pointer_of(core.constants.header_bytes);
    const to_between = comptime pointer_of(between_at);
    const owner_at = between_at + between.len;
    // A label of 1 and a pointer to the name between: 255 octets whole, through two hops.
    const longest = header_zeros ++ long_target ++ between ++ label_of(1) ++ to_between ++ record_after;
    try expect_both(longest.len - record_after.len, &longest, owner_at);
    // A label of 2: 256 octets.
    const one_past = header_zeros ++ long_target ++ between ++ label_of(2) ++ to_between ++ record_after;
    try expect_both(Error.NameTooLong, &one_past, owner_at);
}

/// A pointer to offset 12, where the first name of a message starts.
const to_first_name = pointer_of(core.constants.header_bytes);

test "skip refuses a pointer at itself, as decode does" {
    // It does not point strictly backwards, at a prior name (RFC 1035 §4.1.4).
    try expect_both(Error.BadCompressionPointer, &(header_zeros ++ to_first_name), header_zeros.len);
}

test "skip ends a loop back through a label at the hop bound, as decode does" {
    // A label, then a pointer back at it. Each hop points backwards, and the walk comes back to the
    // pointer. The hop bound ends the loop at the seventeenth pointer.
    const loop = header_zeros ++ "\x03www".* ++ to_first_name;
    try expect_both(Error.BadCompressionPointer, &loop, header_zeros.len);
}

test "skip ends a loop back through a label of 63 at 255 octets, as decode does" {
    // The length of the name ends this loop in its fourth round, before the hop bound.
    const loop = header_zeros ++ label_of(core.limits.label_bytes_max) ++ to_first_name;
    try expect_both(Error.NameTooLong, &loop, header_zeros.len);
}

test "skip refuses a pointer forward, as decode does" {
    // A pointer at a name after it.
    const forward = header_zeros ++ comptime pointer_of(core.constants.header_bytes + 4) ++ "\x00\x00\x03www\x00".*;
    try expect_both(Error.BadCompressionPointer, &forward, header_zeros.len);
}

test "skip refuses a pointer past the end of the message, as decode does" {
    // The pointer names the farthest offset that its fourteen bits can name. That offset is past
    // the end, so the pointer points forward.
    const past_end = header_zeros ++ "\x03www".* ++ comptime pointer_of(constants.pointer_offset_mask);
    try expect_both(Error.BadCompressionPointer, &past_end, header_zeros.len);
}

test "skip refuses a pointer whose second octet is past the end, as decode does" {
    const truncated = header_zeros ++ "\x03www".* ++ [_]u8{constants.label_kind_pointer};
    try expect_both(Error.MalformedMessage, &truncated, header_zeros.len);
}
