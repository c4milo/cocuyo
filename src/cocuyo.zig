//! cocuyo: a DNS resolver library. It builds query bytes and parses response bytes, and owns no
//! socket, no file descriptor, no thread, no timer and no allocator. The caller does the sending
//! and the receiving; cocuyo says what to do next.
//!
//! This file is the public surface and holds no logic: each module of docs/design.md §2 is
//! re-exported here, and the names a consumer reaches for are flattened alongside them as each
//! step of §15 lands them.
pub const core = @import("core");
pub const wire = @import("wire");
pub const resolver = @import("resolver");
pub const resolv_conf = @import("config");

test {
    _ = core;
    _ = wire;
    _ = resolver;
    _ = resolv_conf;
}
