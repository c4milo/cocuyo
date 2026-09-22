//! Copies one record's rdata out of a message into a buffer of the caller's, writing every
//! compressed name out in full on the way (docs/design.md §19 step 9). The layout of
//! `rdata/rdata_layout.zig` says where the names are; everything else is copied as it is.
//!
//! The copy is what lets a lookup keep a record after the message buffer is gone, and what lets a
//! typed view read the record with no message in hand: a compression pointer means nothing
//! outside the message it points into (RFC 3597 §4).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const Name = core.Name;
const name_codec = @import("name.zig");
const record_codec = @import("record.zig");
const rdata_string = @import("rdata/rdata_string.zig");
const layout_table = @import("rdata/rdata_layout.zig");

/// Writes `record`'s rdata into `out`, names decompressed, and returns how many octets it wrote;
/// or null when the rdata does not fit, which is the caller's `truncated` and not an error, since
/// a message can be well-formed and larger than the room a lookup has.
pub fn copy_out(message: []const u8, record: *const record_codec.Record, out: []u8) Error!?usize {
    const start = record.end - record.rdata.len;
    assert(start + record.rdata.len == record.end);
    const layout = layout_table.of(record.kind_code);
    var cursor: usize = start;
    var written: usize = 0;
    for (layout) |segment| {
        const step = try copy_segment(message, segment, cursor, record.end, out[written..]) orelse return null;
        cursor = step.read_end;
        written += step.written;
    }
    // A layout without `rest` has to consume the rdata exactly: octets after the last field are
    // ones a reader would have to guess at (RFC 1035 §3.3).
    if (cursor != record.end) return Error.MalformedMessage;
    assert(written <= out.len);
    return written;
}

const Step = struct { read_end: usize, written: usize };

fn copy_segment(
    message: []const u8,
    segment: layout_table.Segment,
    cursor: usize,
    end: usize,
    out: []u8,
) Error!?Step {
    switch (segment) {
        .fixed => |count| return copy_bytes(message, cursor, cursor + count, end, out),
        .rest => return copy_bytes(message, cursor, end, end, out),
        .character_string => {
            // Read against the record's end, so a string cannot run into the next record.
            const string = try rdata_string.read(message[0..end], cursor);
            return copy_bytes(message, cursor, string.end, end, out);
        },
        .name => {
            var name: Name = Name.empty;
            const after = try name_codec.decode(message, cursor, &name);
            // The pointer may reach anywhere behind it; the encoding itself ends inside the record.
            if (after > end) return Error.MalformedMessage;
            const wire = name.wire();
            if (wire.len > out.len) return null;
            @memcpy(out[0..wire.len], wire);
            assert(after > cursor);
            return .{ .read_end = after, .written = wire.len };
        },
    }
}

/// Copies `message[from..to]` as it is, refusing a range that leaves the record.
fn copy_bytes(message: []const u8, from: usize, to: usize, end: usize, out: []u8) Error!?Step {
    if (to > end) return Error.MalformedMessage;
    assert(from <= to);
    const count = to - from;
    if (count > out.len) return null;
    @memcpy(out[0..count], message[from..to]);
    return .{ .read_end = to, .written = count };
}

// Tests. The message-level tests, through `collect`, are in response_take.zig; these pin the copy.

const testing = std.testing;
const fixtures = @import("fixtures.zig");
const rdata = @import("rdata/rdata.zig");

fn first_record(message: []const u8) !record_codec.Record {
    var walk = record_codec.Iterator.init(message, fixtures.answer_offset_mx, 1);
    return (try walk.next()).?;
}

test "an MX with a compressed exchange is copied with the name written out" {
    const record = try first_record(&fixtures.answer_mx);
    var out: [core.constants.rdata_bytes_max]u8 = undefined;
    const written = (try copy_out(&fixtures.answer_mx, &record, &out)).?;
    try testing.expectEqualSlices(u8, &rdata.fixtures.mx, out[0..written]);
}

test "a record that does not fit is not an error, it is nothing written" {
    const record = try first_record(&fixtures.answer_mx);
    var out: [4]u8 = undefined;
    try testing.expectEqual(@as(?usize, null), try copy_out(&fixtures.answer_mx, &record, &out));
    var exact: [rdata.fixtures.mx.len]u8 = undefined;
    try testing.expectEqual(@as(?usize, exact.len), try copy_out(&fixtures.answer_mx, &record, &exact));
}

test "a name whose encoding runs past its record, or a record with octets after its name, is malformed" {
    const past = try first_record(&fixtures.answer_mx_name_past_record);
    var out: [core.constants.rdata_bytes_max]u8 = undefined;
    try testing.expectError(Error.MalformedMessage, copy_out(&fixtures.answer_mx_name_past_record, &past, &out));
    const trailing = try first_record(&fixtures.answer_mx_trailing_octet);
    try testing.expectError(Error.MalformedMessage, copy_out(&fixtures.answer_mx_trailing_octet, &trailing, &out));
    // With `rest` after the name, nothing else would notice the name running into the record
    // that follows: the copy would keep `foo.example.com` and take the rest from past the end.
    const into_next = try first_record(&fixtures.answer_svcb_name_past_record);
    try testing.expectError(Error.MalformedMessage, copy_out(&fixtures.answer_svcb_name_past_record, &into_next, &out));
}
