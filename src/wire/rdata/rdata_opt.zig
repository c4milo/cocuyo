//! The options inside an OPT record's rdata: a 16-bit code, a 16-bit length and the data, one
//! after another (RFC 6891 §6.1.2). The record itself is read by `edns.zig`; the COOKIE option
//! (RFC 7873 §4) is the first one cocuyo reads, in docs/design.md §19 step 10.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const constants = @import("../constants.zig");
const integer = @import("../integer.zig");

pub const Option = struct { code: u16, data: []const u8 };

/// The options in order. Each step consumes at least the code and the length, so the walk ends
/// within the rdata; an rdata that ends inside an option is malformed.
pub const Options = struct {
    rdata: []const u8,
    offset: usize = 0,

    pub fn next(self: *Options) Error!?Option {
        if (self.offset == self.rdata.len) return null;
        assert(self.offset < self.rdata.len);
        if (self.offset + constants.opt_option_fixed_bytes > self.rdata.len) return Error.MalformedMessage;
        const code = integer.read_u16(self.rdata, self.offset);
        const length: usize = integer.read_u16(self.rdata, self.offset + constants.opt_option_length_offset);
        const start = self.offset + constants.opt_option_fixed_bytes;
        if (start + length > self.rdata.len) return Error.MalformedMessage;
        self.offset = start + length;
        assert(self.offset <= self.rdata.len);
        return .{ .code = code, .data = self.rdata[start..][0..length] };
    }
};

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");

test "the options of an OPT record come back in order, an empty one included" {
    var options: Options = .{ .rdata = &fixtures.opt_options };
    const cookie = (try options.next()).?;
    try testing.expectEqual(@as(u16, 10), cookie.code);
    try testing.expectEqual(@as(usize, 8), cookie.data.len);
    const nsid = (try options.next()).?;
    try testing.expectEqual(@as(u16, 3), nsid.code);
    try testing.expectEqual(@as(usize, 0), nsid.data.len);
    try testing.expectEqual(@as(?Option, null), try options.next());
}

test "an rdata that ends inside an option is malformed, and no options is no options" {
    var short: Options = .{ .rdata = &fixtures.opt_option_short };
    try testing.expectError(Error.MalformedMessage, short.next());
    var header_only: Options = .{ .rdata = &fixtures.opt_option_header_only };
    try testing.expectError(Error.MalformedMessage, header_only.next());
    var none: Options = .{ .rdata = &.{} };
    try testing.expectEqual(@as(?Option, null), try none.next());
}
