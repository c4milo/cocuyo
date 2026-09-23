//! Whether this process may create an io_uring: the control of `tools/epoll_check/run.sh`. The
//! check's claim is that the rotor example resolves where io_uring is refused, so it must first see
//! io_uring refused, or a pass would prove nothing. Linux only.
const std = @import("std");
const linux = std.os.linux;

pub fn main() void {
    var params = std.mem.zeroes(linux.io_uring_params);
    const result = linux.io_uring_setup(1, &params);
    switch (linux.errno(result)) {
        .SUCCESS => {
            std.debug.print("io_uring: allowed\n", .{});
            _ = linux.close(@intCast(result));
        },
        else => |err| std.debug.print("io_uring: refused, {t}\n", .{err}),
    }
}
