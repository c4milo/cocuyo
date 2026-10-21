//! A lookup's wait for a connection slot (docs/design.md §19 step 13, the stream's rule 12). A
//! lookup that finds no free slot waits while a slot is pending, in `connecting_tcp` and on no
//! connection, and its deadline bounds the wait. In the clear, when no slot is pending, the lookup
//! closes a connection that no lookup is on while its connect is in flight. The drive's end admits
//! each lookup that waits. Over TLS each server has at most one connection that a lookup may join.
//! A TLS configuration has a slot for each server (§21, TLS rule 6). So over TLS a lookup always
//! finds a slot that is free or pending.
//!
//! Free functions over the engine, split out of `io_tcp.zig` by the file-length rule.
const std = @import("std");
const assert = std.debug.assert;
const tcp = @import("io_tcp.zig");
const tls_module = @import("io_tls.zig");

/// Whether a slot is pending: no lookup is on it, and it frees with no lookup leaving it. Its
/// connection closes once its alert or `close_notify` has gone, or once it has closed for
/// `tcp_idle_ns` (docs/design.md §16 decision 49). Or the slot is closed, and the loop holds its
/// memory. That is a cancelled connect's address, or the records buffer that a send reads, a
/// query's or the session's own. See the stream's rules 10 and 12, and §21's TLS rules 3 to 5.
pub fn pending(self: anytype) bool {
    for (self.connections[0..]) |*connection| {
        if (connection.state == .closing) return true;
        if (connection.state == .closed and connection.borrowed()) return true;
    }
    return false;
}

/// In the clear, with no slot free and none pending, the first connection that no lookup is on
/// is closed. Its connect is in flight then, and the close cancels it, as the idle close does. Its
/// slot is pending until that connect's event (the stream's rules 4, 10 and 12).
pub fn make_pending(self: anytype) void {
    assert(!tls_module.speaks(self));
    if (pending(self)) return;
    for (self.connections[0..], 0..) |*connection, at| {
        if (connection.users != 0) continue;
        // A slot that no lookup is on and the loop does not hold is free, and a closed one that
        // the loop holds is pending. What is left of a slot with no lookup is a connect in flight.
        assert(connection.state == .connecting and connection.borrowed());
        tcp.shut(self, @intCast(at));
        assert(pending(self));
        return;
    }
}

/// The lookup waits in `connecting_tcp`, on no connection, until the drive's end admits it or its
/// deadline moves it on (the stream's rule 12).
pub fn wait(self: anytype, index: usize) void {
    assert(self.tcp_connection[index] == null);
    assert(!self.tcp_waiting[index]);
    assert(self.tcp_waiters < self.tcp_waiting.len);
    self.tcp_waiting[index] = true;
    self.tcp_waiters += 1;
}

/// The lookup no longer waits for a slot, if it did.
pub fn unwait(self: anytype, index: usize) void {
    if (!self.tcp_waiting[index]) return;
    assert(self.tcp_waiters >= 1);
    self.tcp_waiting[index] = false;
    self.tcp_waiters -= 1;
}

/// The drive's end admits each lookup that waits for a slot, in the order of the table's slots.
/// The lookup joins its server's connection, or opens one as `want` does. When it can have no
/// slot, or the socket or the connect is refused, it waits for the next drive (the stream's rule
/// 12).
pub fn admit(self: anytype, now_ns: u64) void {
    if (comptime !@TypeOf(self.*).keeps_tcp) return;
    if (self.tcp_waiters == 0) return;
    for (self.tcp_waiting[0..], 0..) |waiting, index| {
        if (!waiting) continue;
        const lookup = self.resolver.lookup_of(self.handles[index]);
        // A lookup leaves the wait at its next poll that acts (`follow`).
        assert(lookup.state == .connecting_tcp and self.tcp_connection[index] == null);
        const at = tcp.attach(self, index, lookup.server_slot(), now_ns) catch continue;
        unwait(self, index);
        // At the drive before, its server had no connection that it could join. A connection that
        // a drive opens is still connecting at the drive's end. So the lookup hears nothing here,
        // and no poll is owed.
        assert(self.connections[at].state != .up);
    }
}
