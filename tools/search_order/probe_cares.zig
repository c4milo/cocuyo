//! `ares_getaddrinfo` for one name, for `tools/search_order/run.sh`: c-ares given the server, the
//! search list and `ndots` as options rather than read from the system, so it walks the same list
//! glibc and musl read from `resolv.conf`:
//!
//!     probe_cares <port> <ndots> <name> [search ...]
//!
//! IPv4 only, one try and a one-second timeout, as the containers' `resolv.conf` sets. It prints
//! the status c-ares reported, and nothing of how: c-ares is observed on the wire, not read.
const std = @import("std");
const c = @cImport(@cInclude("ares.h"));

/// As `options attempts:1 timeout:1` in the containers.
const tries = 1;
const timeout_ms = 1000;
/// Long past every try the lookup can make: a probe that waited this long is stuck.
const wait_ms_max = 10_000;
const search_max = 6;

fn on_result(arg: ?*anyopaque, status: c_int, timeouts: c_int, result: ?*c.ares_addrinfo) callconv(.c) void {
    _ = timeouts;
    const out: *c_int = @ptrCast(@alignCast(arg.?));
    out.* = status;
    if (result) |list| c.ares_freeaddrinfo(list);
}

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const arguments = try init.minimal.args.toSlice(arena);
    if (arguments.len < 4 or arguments.len - 4 > search_max) {
        std.debug.print("usage: probe_cares <port> <ndots> <name> [search ...]\n", .{});
        return error.Usage;
    }
    if (c.ares_library_init(c.ARES_LIB_INIT_ALL) != c.ARES_SUCCESS) return error.CaresInitFailed;
    defer c.ares_library_cleanup();

    var domains: [search_max][*c]u8 = undefined;
    for (arguments[4..], domains[0 .. arguments.len - 4]) |domain, *slot| slot.* = @constCast(domain.ptr);
    var lookups = "b".*;
    var options = std.mem.zeroes(c.ares_options);
    options.ndots = try std.fmt.parseInt(c_int, arguments[2], 10);
    options.domains = &domains;
    options.ndomains = @intCast(arguments.len - 4);
    options.lookups = &lookups;
    options.tries = tries;
    options.timeout = timeout_ms;
    options.evsys = c.ARES_EVSYS_DEFAULT;
    const mask = c.ARES_OPT_NDOTS | c.ARES_OPT_DOMAINS | c.ARES_OPT_LOOKUPS | c.ARES_OPT_TRIES |
        c.ARES_OPT_TIMEOUTMS | c.ARES_OPT_EVENT_THREAD;
    var channel: ?*c.ares_channel_t = null;
    if (c.ares_init_options(&channel, &options, mask) != c.ARES_SUCCESS) return error.CaresInitFailed;
    defer c.ares_destroy(channel);
    const server = try std.fmt.allocPrintSentinel(arena, "127.0.0.1:{s}", .{arguments[1]}, 0);
    if (c.ares_set_servers_ports_csv(channel, server.ptr) != c.ARES_SUCCESS) return error.CaresInitFailed;

    var hints = std.mem.zeroes(c.ares_addrinfo_hints);
    hints.ai_family = c.AF_INET;
    var status: c_int = -1;
    c.ares_getaddrinfo(channel, arguments[3].ptr, null, &hints, on_result, &status);
    if (c.ares_queue_wait_empty(channel, wait_ms_max) != c.ARES_SUCCESS) return error.CaresStuck;
    std.debug.print("ares_getaddrinfo: {d} ({s})\n", .{ status, c.ares_strerror(status) });
}
