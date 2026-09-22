//! A name inside a record's rdata, read from the uncompressed form the collector stores
//! (docs/design.md §19 step 9). `NS`, `CNAME` and `PTR` are a name and nothing else
//! (RFC 1035 §3.3.11, §3.3.1 and §3.3.12).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const Name = core.Name;
const constants = @import("../constants.zig");

/// Reads the name at `offset` into `out` and returns the offset after its root octet.
///
/// Only labels are accepted. A compression pointer cannot be followed here, because there is no
/// message to follow it into: the collector writes every name out in full before anything reads
/// it back (`record_copy.zig`, RFC 3597 §4), and a caller reading rdata straight off a message
/// decodes through `wire.name.decode` instead.
pub fn read(rdata: []const u8, offset: usize, out: *Name) Error!usize {
    assert(offset <= rdata.len);
    out.* = Name.empty;
    var cursor = offset;
    var labels: usize = 0;
    while (labels <= core.constants.labels_max) : (labels += 1) {
        if (cursor >= rdata.len) return Error.MalformedMessage;
        const length: usize = rdata[cursor];
        // A pointer, or one of the two reserved label kinds (RFC 1035 §4.1.4).
        if (length & constants.label_kind_mask != constants.label_kind_label) return Error.MalformedName;
        cursor += 1;
        if (length == 0) {
            try out.terminate();
            assert(cursor > offset);
            return cursor;
        }
        if (cursor + length > rdata.len) return Error.MalformedMessage;
        try out.append_label(rdata[cursor..][0..length]);
        cursor += length;
    }
    assert(labels > core.constants.labels_max);
    return Error.MalformedName;
}

/// The whole rdata as one name, which `NS`, `CNAME` and `PTR` are: the name must fill it exactly,
/// because octets after the root would be ones a reader had to guess at (RFC 1035 §3.3).
pub fn whole(rdata: []const u8) Error!Name {
    var name: Name = Name.empty;
    const end = try read(rdata, 0, &name);
    if (end != rdata.len) return Error.MalformedMessage;
    assert(name.len >= 1);
    return name;
}

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");

test "a name reads back from uncompressed rdata, and the root alone is a name" {
    const name = try whole(&fixtures.name_example);
    try testing.expect(name.equal(&try Name.from_text("example.com")));
    const root = try whole(&fixtures.name_root);
    try testing.expect(root.is_root());
}

test "a compression pointer in rdata is refused, because nothing here can follow it" {
    try testing.expectError(Error.MalformedName, whole(&fixtures.name_pointer));
}

test "a name that ends inside a label, or past the rdata, is malformed" {
    try testing.expectError(Error.MalformedMessage, whole(&fixtures.name_short_label));
    try testing.expectError(Error.MalformedMessage, whole(&fixtures.name_unterminated));
    try testing.expectError(Error.MalformedMessage, whole(&.{}));
}

test "a name must fill the rdata it is read as the whole of" {
    try testing.expectError(Error.MalformedMessage, whole(&fixtures.name_trailing));
    var name: Name = Name.empty;
    try testing.expectEqual(fixtures.name_example.len, try read(&fixtures.name_trailing, 0, &name));
}

test "a name longer than a name may be is refused, before the label bound can matter" {
    try testing.expectError(Error.NameTooLong, whole(&fixtures.name_too_long));
}
