//! core: the types, the limits and the errors more than one module needs. It imports nothing,
//! which is what lets every other module reach it without reaching sideways (docs/design.md §2).
//!
//! Assertions stay on in production (CLAUDE.md non-negotiable 3), which is why the build offers
//! Debug and ReleaseSafe only: `std.debug.assert` is compiled out in ReleaseFast and ReleaseSmall,
//! and a library whose assertions vanish in the mode people ship is a library with no assertions.
const std = @import("std");

pub const constants = @import("constants.zig");
pub const mix = @import("mix.zig");
pub const Error = @import("errors.zig").Error;

const address = @import("address.zig");
pub const Family = address.Family;
pub const Address = address.Address;
pub const Endpoint = address.Endpoint;

pub const name_text = @import("name_text.zig");
pub const name_reverse = @import("name_reverse.zig");
pub const Name = @import("name.zig").Name;

const question = @import("question.zig");
pub const Kind = question.Kind;
pub const Question = question.Question;

pub const Config = @import("config.zig").Config;
pub const Server = @import("config.zig").Server;
pub const Source = @import("config.zig").Source;

test {
    _ = constants;
    _ = mix;
    _ = address;
    _ = name_text;
    _ = name_reverse;
    _ = question;
    _ = @import("name.zig");
    _ = @import("config.zig");
}

test "the limits hold the relations the design states" {
    // docs/design.md §12. A limit changed without its neighbour fails here rather than in a parser.
    try std.testing.expect(constants.name_bytes_max < constants.message_bytes_max);
    try std.testing.expect(constants.label_bytes_max < constants.name_bytes_max);
    try std.testing.expect(constants.query_bytes_max < constants.udp_payload_bytes_min);
    try std.testing.expect(constants.ptr_names_max <= constants.addresses_max);
}

test "the size of every stored type is pinned" {
    // docs/design.md §9 gives the memory a caller provides. These sizes are what that table adds
    // up, so a field added to one of them shows up here as a number to re-justify rather than as a
    // slot that quietly grew.
    try std.testing.expectEqual(@as(usize, 256), @sizeOf(Name));
    try std.testing.expectEqual(@as(usize, 17), @sizeOf(Address));
    try std.testing.expectEqual(@as(usize, 20), @sizeOf(Endpoint));
    try std.testing.expectEqual(@as(usize, 260), @sizeOf(Question));
}
