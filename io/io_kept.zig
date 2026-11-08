//! What the engine keeps for a lookup's tries that stay open (docs/design.md §5, Tries kept open;
//! §16 decision 66): the connections a lookup stays on past the deadline that moved it on (§19 step
//! 13, the stream's rules 3 and 5), and the oldest socket each server's open datagram tries went
//! out from (the datagram's rule 4). `follow` and `release` came here from `io_tcp.zig` by the
//! file-length rule, since they decide which connections a lookup is on.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const tcp = @import("io_tcp.zig");
const queue_module = @import("io_tcp_queue.zig");
const mark_module = @import("io_tcp_mark.zig");
const wait_module = @import("io_tcp_wait.zig");

/// The state for each of `lookups` slots.
pub fn Kept(comptime lookups: usize) type {
    return struct {
        /// The connection the slot's lookup stays on at each configured server, for an open try
        /// there. A lookup is on one connection for each server at most (the stream's rule 5).
        conns: [lookups][cocuyo.limits.servers_max]?u8 = @splat(@splat(null)),
        /// The epoch of the oldest socket an open datagram try of the slot's lookup went out from,
        /// for each configured server. The one socket that drains stays open for it.
        epochs: [lookups][cocuyo.limits.servers_max]?u32 = @splat(@splat(null)),

        pub fn forget(self: *@This()) void {
            self.conns = @splat(@splat(null));
            self.epochs = @splat(@splat(null));
        }
    };
}

// Streams.

/// Takes the lookup off each connection it should not be on (the stream's rule 3): its current one
/// unless it streams to that connection's server, and each one it stays on whose try has closed. A
/// connection whose open try is the lookup's own stays: the lookup moves to the next server and its
/// answer may still come. A lookup that waits on such a try again is on that connection again. A
/// lookup that acts no longer waits for a slot (rule 12).
pub fn follow(self: anytype, index: usize, now_ns: u64) void {
    if (comptime !@TypeOf(self.*).keeps_tcp) return;
    wait_module.unwait(self, index);
    const lookup = self.resolver.lookup_of(self.handles[index]);
    if (lookup.is_on_stream() and self.tcp_connection[index] == null) _ = promote(self, index, lookup.server_slot());
    if (self.tcp_connection[index]) |at| {
        const server = self.connections[at].server;
        if (!lookup.is_on_stream() or server != lookup.server_slot()) {
            if (lookup.earlier_try_at(server, .stream) != null) keep(self, index, at, now_ns) else release_current(self, index, now_ns);
        }
    }
    tidy(self, index, now_ns);
}

/// A lookup has ended or been freed: it is off every connection, with its query that waits there.
/// When none stays during a query's send, the shut cancels that send, which a peer that does not
/// read never ends (docs/design.md §16 decision 53). `io_tcp_mark.leave` marks it (decision 54).
pub fn release(self: anytype, index: usize, now_ns: u64) void {
    if (comptime !@TypeOf(self.*).keeps_tcp) return;
    release_current(self, index, now_ns);
    for (&self.kept.conns[index]) |*held| {
        const at = held.* orelse continue;
        held.* = null;
        leave_kept(self, at, now_ns);
    }
}

/// The lookup leaves the connection its current try uses.
fn release_current(self: anytype, index: usize, now_ns: u64) void {
    const at = self.tcp_connection[index] orelse return;
    self.tcp_connection[index] = null;
    queue_module.drop(self, at, index);
    leave(self, at, now_ns);
    mark_module.leave(self, at, index, now_ns);
}

/// One lookup fewer on the connection in slot `at` for its current try. When none stays during a
/// query's send, the shut cancels that send (§16 decision 53), and a keeper hears it ends.
fn leave(self: anytype, at: u8, now_ns: u64) void {
    const connection = &self.connections[at];
    assert(connection.users >= 1);
    connection.users -= 1;
    if (connection.users == 0 and connection.keepers == 0) connection.idle_since_ns = now_ns;
    if (connection.users == 0 and queue_module.query_in_flight(self, at)) shut_telling(self, at, now_ns);
}

/// One keeper fewer on the connection in slot `at`. With no lookup left, it is idle from now.
fn leave_kept(self: anytype, at: u8, now_ns: u64) void {
    const connection = &self.connections[at];
    assert(connection.keepers >= 1);
    connection.keepers -= 1;
    if (connection.users == 0 and connection.keepers == 0) connection.idle_since_ns = now_ns;
}

/// Ends the connection in slot `at`, which the engine closes itself: to make room, or at the last
/// leave during a query's send. Each lookup that stays on it for an open try hears `local` first:
/// no server took part, so its tries there close and no server failed (the stream's rule 5).
pub fn shut_telling(self: anytype, at: u8, now_ns: u64) void {
    tell_failed(self, at, .local, now_ns);
    tcp.shut(self, at);
}

/// The lookup's current connection becomes one it stays on: the query of its open try went out
/// there, so nothing of it waits in the queue. It is a keeper there now, and no user.
fn keep(self: anytype, index: usize, at: u8, now_ns: u64) void {
    const server = self.connections[at].server;
    assert(self.kept.conns[index][server] == null);
    assert(self.connections[at].users >= 1);
    self.kept.conns[index][server] = at;
    self.tcp_connection[index] = null;
    self.connections[at].keepers += 1;
    leave(self, at, now_ns);
    // Its leave as a user is a leave: the last one of a marked connection ends it (decision 54).
    if (self.connections[at].state != .closed) mark_module.leave(self, at, index, now_ns);
}

/// The lookup is on a stream to `server` again, and a connection it stays on goes there: that
/// connection is its current one again (a later pass that waits on its open try, or a retry on the
/// same server). True when there was one.
pub fn promote(self: anytype, index: usize, server: u8) bool {
    const at = self.kept.conns[index][server] orelse return false;
    assert(self.tcp_connection[index] == null);
    self.kept.conns[index][server] = null;
    self.tcp_connection[index] = at;
    const connection = &self.connections[at];
    assert(connection.keepers >= 1);
    connection.keepers -= 1;
    connection.users += 1;
    return true;
}

/// The lookup leaves each connection it stays on whose try has closed: answered, failed, or ended
/// with the lookup. A datagram try that closed owes its socket nothing more.
fn tidy(self: anytype, index: usize, now_ns: u64) void {
    const lookup = self.resolver.lookup_of(self.handles[index]);
    for (&self.kept.conns[index], 0..) |*held, server| {
        const at = held.* orelse continue;
        assert(self.connections[at].server == server);
        if (lookup.earlier_try_at(@intCast(server), .stream) != null) continue;
        held.* = null;
        leave_kept(self, at, now_ns);
    }
}

/// After a message on the connection in slot `at`: each lookup that stays on it whose try there the
/// message closed leaves it, as the poll that follows would (the stream's rule 3). A lookup that
/// still waits has no poll to follow, so the message's end does it. Nothing to do with no keeper.
pub fn tidy_at(self: anytype, at: u8, now_ns: u64) void {
    const connection = &self.connections[at];
    if (connection.keepers == 0) return;
    const server = connection.server;
    for (&self.kept.conns, 0..) |*held, index| {
        if (held[server] != at) continue;
        // A freed slot's handle names no lookup, so the slot is read first, as in `tell_failed`.
        if (self.slots[index].occupied and
            self.resolver.lookup_of(self.handles[index]).earlier_try_at(server, .stream) != null) continue;
        held[server] = null;
        leave_kept(self, at, now_ns);
    }
}

/// The connection in slot `at` failed, for `reason`: each lookup that stays on it for an open try
/// hears so, and is off it (the stream's rule 5). That closes each such try, and the failure is the
/// connection's server's.
pub fn tell_failed(self: anytype, at: u8, reason: cocuyo.Reason, now_ns: u64) void {
    const connection = &self.connections[at];
    const server = connection.server;
    for (&self.kept.conns, 0..) |*held, index| {
        if (held[server] != at) continue;
        held[server] = null;
        assert(connection.keepers >= 1);
        connection.keepers -= 1;
        if (!self.slots[index].occupied) continue;
        self.resolver.on_tcp_failed(self.handles[index], server, keeper_reason(self, index, server, reason), now_ns);
    }
    assert(connection.keepers == 0);
}

/// What a keeper of the connection to `server` hears when that connection ends for `reason`. Its
/// try went out while the connection was up, so it hears `closed`, whatever reason fits the
/// connection's state now: `handshake` for one that closes is no reason of its try's. A close the
/// engine made itself is `local`, which names no server (docs/design.md §19 step 13, the stream's
/// rule 5; the owner's ruling of 2026-11-08, "Keepers hear .closed"). A later pass that waits on
/// its open try there sent nothing, so the drive saw no event for it and it is still a keeper here:
/// it waited on a connection that was up, so a close the engine made is `closed` to it too.
fn keeper_reason(self: anytype, index: usize, server: u8, reason: cocuyo.Reason) cocuyo.Reason {
    const lookup = self.resolver.lookup_of(self.handles[index]);
    const waits_here = lookup.is_on_stream() and lookup.server_slot() == server;
    const heard: cocuyo.Reason = if (reason == .local and !waits_here) .local else .closed;
    assert(heard == .closed or heard == .local);
    return heard;
}

// Datagrams.

/// A datagram of the lookup at `index` went out to `server` from the socket of `epoch`. The oldest
/// socket an open try went out from is the one kept: a later try goes from that one or a newer.
pub fn note_sent(self: anytype, index: usize, server: u8, epoch: u32) void {
    const lookup = self.resolver.lookup_of(self.handles[index]);
    const held = &self.kept.epochs[index][server];
    if (held.* != null and lookup.earlier_try_at(server, .datagram) != null) return;
    held.* = epoch;
}

/// Whether an open earlier datagram try of a lookup went out from `server`'s socket of `epoch`,
/// which then stays open for its answer (the datagram's rule 4).
pub fn owes(self: anytype, server: u8, epoch: u32) bool {
    for (self.slots[0..], 0..) |*slot, index| {
        if (!slot.occupied) continue;
        const held = self.kept.epochs[index][server] orelse continue;
        if (held > epoch) continue;
        if (slot.lookup.earlier_try_at(server, .datagram) != null) return true;
    }
    return false;
}
