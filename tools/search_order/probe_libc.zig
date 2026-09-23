//! `getaddrinfo(3)` for one name, through whichever C library it is linked against, for
//! `tools/search_order/run.sh`:
//!
//!     probe_libc <name> [any]
//!
//! IPv4 only unless `any` is given, so each search candidate costs one question and the recorder's
//! log reads as the order the library walked. It prints what `getaddrinfo` returned, and nothing
//! of how: the library is observed on the wire, not read.
const std = @import("std");
const c = @cImport({
    @cInclude("netdb.h");
    @cInclude("sys/socket.h");
});

pub fn main(init: std.process.Init) !void {
    const arguments = try init.minimal.args.toSlice(init.arena.allocator());
    if (arguments.len < 2 or arguments.len > 3) {
        std.debug.print("usage: probe_libc <name> [any]\n", .{});
        return error.Usage;
    }
    var hints = std.mem.zeroes(c.struct_addrinfo);
    hints.ai_family = if (arguments.len == 3) c.AF_UNSPEC else c.AF_INET;
    hints.ai_socktype = c.SOCK_STREAM;
    var result: ?*c.struct_addrinfo = null;
    const status = c.getaddrinfo(arguments[1].ptr, null, &hints, &result);
    defer if (result) |list| c.freeaddrinfo(list);
    std.debug.print("getaddrinfo: {d} ({s})\n", .{ status, c.gai_strerror(status) });
}
