//! A connection that no lookup may join (docs/design.md §16 decision 54). When a lookup leaves a
//! connection while its own query's send is in flight, and another lookup stays, the drive marks
//! the connection. No lookup joins it again, and the mark stays until the connection ends. The
//! lookups on it end by their answers or by their own deadlines. The last leave ends it at once.
//! A new lookup to that server opens a new connection. When it can have no other slot, it waits
//! for the marked connection's slot (the stream's rule 12; §21, TLS rule 6).
//!
//! Free functions over the engine, split out of `io_tcp.zig` by the file-length rule. Its tests
//! are in `io_tcp_mark_test.zig`.
const std = @import("std");
const assert = std.debug.assert;
const tcp = @import("io_tcp.zig");
const queue_module = @import("io_tcp_queue.zig");
const tls_module = @import("io_tls.zig");

/// The lookup at `index` has left the connection in slot `at`, after `tcp.release` took it off.
/// The shut at the last leave during a query's send came first (decision 53). When a lookup stays,
/// and the query of the lookup that left heads the queue with its send in flight, the connection
/// is marked. The last leave of a marked connection ends it at once (`close_now`).
pub fn leave(self: anytype, at: u8, index: usize, now_ns: u64) void {
    const connection = &self.connections[at];
    // A connection is marked only while it is up. One that is not has no query's send in flight.
    if (connection.state != .up) return assert(!connection.marked);
    if (connection.users == 0) {
        if (connection.marked) close_now(self, at, now_ns);
        return;
    }
    if (left_during_send(self, at, index)) connection.marked = true;
}

/// Whether the lookup at `index` left the connection in slot `at` during its own query's send: its
/// query heads the queue, and that send is in flight (the stream's rule 9). A query that has not
/// started left the queue at the leave, and its buffer came back.
fn left_during_send(self: anytype, at: u8, index: usize) bool {
    // `tcp.release` took the lookup off the connection, and a lookup stays on it.
    assert(self.tcp_connection[index] != at);
    assert(self.connections[at].users > 0);
    if (!queue_module.query_in_flight(self, at)) return false;
    return self.connections[at].queue.first().?.slot == index;
}

/// The last leave of a marked connection, with no query's send in flight. No lookup may join it,
/// so it ends at once, as the idle close ends one, with no wait. In the clear the drive shuts it.
/// Over TLS the peer reads, so the session says `close_notify` first (RFC 9846 §6.1, TLS rule 5).
fn close_now(self: anytype, at: u8, now_ns: u64) void {
    const connection = &self.connections[at];
    assert(connection.marked and connection.users == 0);
    // The shut of decision 53 ended a connection whose query's send was in flight.
    assert(!queue_module.query_in_flight(self, at));
    if (tls_module.speaks(self)) return tls_module.say_close_notify(self, at, now_ns);
    tcp.shut(self, at);
}

/// Whether a marked connection that is up holds a slot. Its lookups leave by their deadlines, and
/// the last leave ends it. So a lookup that can have no other slot waits for that one.
pub fn holds_slot(self: anytype) bool {
    for (self.connections[0..]) |*connection| {
        if (!connection.marked) continue;
        // A mark is set while the connection is up. Its last leave ends it at once (`close_now`).
        assert(connection.state == .up or connection.state == .closing);
        assert(connection.state != .up or connection.users > 0);
        if (connection.state == .up) return true;
    }
    return false;
}

/// Asserts the rule of decision 54 over every connection, after the drive's polls. A marked
/// connection is up with a lookup on it, or it closes: the last leave ended it. And a connection
/// that is up, whose head is a query whose send is in flight, has that query's lookup on it, or
/// it is marked.
pub fn assert_marks(self: anytype) void {
    if (comptime !@TypeOf(self.*).keeps_tcp) return;
    for (self.connections[0..], 0..) |*connection, slot| {
        const at: u8 = @intCast(slot);
        if (connection.marked) assert((connection.state == .up and connection.users > 0) or connection.state == .closing);
        if (connection.state != .up or connection.marked) continue;
        if (!queue_module.query_in_flight(self, at)) continue;
        assert(self.tcp_connection[connection.queue.first().?.slot] == at);
    }
}
