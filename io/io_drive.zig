//! Driving the table: what every lookup wants, done (docs/design.md §19 step 13). Free
//! functions over the engine, split out of `engine.zig` so each is scored on its own.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const constants = @import("constants.zig");
const udp = @import("io_udp.zig");
const tcp = @import("io_tcp.zig");
const results_module = @import("io_results.zig");
const send_module = @import("io_send.zig");
const request_module = @import("io_request.zig");
const request_connection = @import("io_request_connection.zig");
const request_tend = @import("io_request_connection_tend.zig");

/// Polls the table for what every lookup wants and does it, until nothing is left: a send out
/// or held, a connection asked for, a request taken, an end handed to `results`. Then every
/// request its lookup left is cancelled, the idle connections close, the sockets and connections
/// are tended, and the timer moves to the soonest deadline (docs/design.md §24, request rules 6,
/// 9 and 11).
///
/// The table offers a lookup once for each thing it has to do (§11, §16 decision 20), so the
/// drive ends when the ready list does. A lookup can be offered again inside one drive, when a
/// connection it asks for is already up or refuses it, and the bound counts that: one drive
/// polls a lookup `drive_polls_per_lookup_max` times at most (the stream's rule 8). A lookup
/// whose end was reported already is the one the drive refuses, and a run of refusals as long as
/// the table is deep ends it as well.
pub fn drive(self: anytype, now_ns: u64) void {
    var polls: usize = 0;
    var refused: usize = 0;
    const polls_max = self.slots.len * constants.drive_polls_per_lookup_max;
    while (polls < polls_max and refused <= self.resolver.in_flight()) : (polls += 1) {
        const event = self.resolver.poll(now_ns, &self.scratch) orelse break;
        if (act(self, event, now_ns)) refused = 0 else refused += 1;
    }
    request_module.cancel_left(self, now_ns);
    tcp.close_idle(self, now_ns);
    request_connection.close_idle(self, &self.quic, now_ns);
    request_connection.close_idle(self, &self.h2, now_ns);
    tcp.tend(self);
    tend_sockets(self);
    request_tend.tend(self, &self.quic, now_ns);
    request_tend.tend(self, &self.h2, now_ns);
    arm_timer(self, now_ns);
}

/// True when the lookup moved on, false when it asked for what it has already been given.
fn act(self: anytype, event: cocuyo.Event, now_ns: u64) bool {
    const index = event.handle.index;
    tcp.follow(self, index, now_ns);
    switch (event.action) {
        .send_udp => |send| send_module.ask(self, index, .{ .udp = .{ .server = send.server, .bytes = send.message_bytes } }, now_ns),
        .connect_tcp => tcp.want(self, index, now_ns),
        .send_tcp => |send| send_module.ask(self, index, .{ .tcp = send.message_bytes }, now_ns),
        .done => |answer| return report(self, index, .{ .answer = answer }, now_ns),
        .failed => |failure| return report(self, index, .{ .failure = failure }, now_ns),
        .wait => unreachable,
        .send_request => |send| request_module.take(self, index, send, now_ns),
    }
    return true;
}

/// Hands one lookup's end to `results`, once. False when it was handed over already and the
/// slot is only waiting for `take`.
///
/// The cache is not written here: the table writes it, through the `Memory` `init` put under it,
/// so what may be remembered is decided in one place for every caller (docs/design.md §20).
fn report(self: anytype, index: usize, outcome: results_module.Outcome, now_ns: u64) bool {
    if (self.reported[index]) return false;
    self.reported[index] = true;
    tcp.release(self, index, now_ns);
    self.results.push(.{ .handle = self.handles[index], .outcome = outcome });
    return true;
}

/// What a drive does last, server by server (docs/design.md §19 step 13, the datagram's rules 1,
/// 4 and 5). A draining socket nothing is owed on is closed, which makes room for a port that
/// has carried its share (`Config.udp_queries_per_port`, c-ares `udp_max_queries`) to be
/// replaced at once, whoever waits on it: the old one drains. A port replaced with nothing owed
/// on it is closed at once. Then each socket with no receive is given one, since a refusal is not
/// a reason to go deaf.
fn tend_sockets(self: anytype) void {
    const tag = @TypeOf(self.*).tag;
    var server: u8 = 0;
    while (server < self.sockets.count) : (server += 1) {
        close_if_drained(self, server);
        if (self.sockets.is_due(server)) self.sockets.rotate(self.loop, self.config, server, tag) catch {};
        close_if_drained(self, server);
        self.sockets.tend(self.loop, server, tag);
    }
}

fn close_if_drained(self: anytype, server: u8) void {
    if (!self.sockets.draining[server].open) return;
    if (drain_owed(self, server)) return;
    self.sockets.close_draining(self.loop, server);
}

/// Whether server `server`'s draining socket is still owed something: the answer to a query that
/// left from it for a lookup still waiting on that server, or the end of a send from it that
/// still holds a slot's buffer.
fn drain_owed(self: anytype, server: u8) bool {
    const epoch = self.sockets.draining[server].epoch;
    for (self.slots[0..], 0..) |*slot, index| {
        const from = self.sent_from[index] orelse continue;
        if (from.server != server or from.epoch != epoch) continue;
        if (self.send_in_flight[index]) return true;
        if (!slot.occupied) continue;
        const lookup = &slot.lookup;
        if (lookup.state == .awaiting_udp and lookup.server_slot() == server) return true;
    }
    return false;
}

/// One rotor timer at the soonest of the table's deadline and each request connection's, moved
/// when that moves (docs/design.md §24, request rule 11).
fn arm_timer(self: anytype, now_ns: u64) void {
    if (self.closing) return;
    const requests_due = earliest(request_tend.next_deadline(&self.quic), request_tend.next_deadline(&self.h2));
    const due = earliest(self.resolver.next_deadline_ns(), requests_due);
    if (due == self.timer_due_ns) return;
    if (self.timer_handle) |handle| {
        self.loop.cancel(handle);
        self.timer_handle = null;
    }
    self.timer_due_ns = due;
    const deadline = due orelse return;
    self.timer_generation +%= 1;
    const operation: rotor.Operation = .{
        .user_data = @TypeOf(self.*).user_data(.timer, self.timer_generation),
        .kind = .{ .timer = .{ .after_ns = deadline -| now_ns } },
    };
    var handles: [1]rotor.Handle = undefined;
    if (self.loop.submit(&.{operation}, &handles) == 1) self.timer_handle = handles[0];
}

fn earliest(a: ?u64, b: ?u64) ?u64 {
    const first = a orelse return b;
    const second = b orelse return a;
    return @min(first, second);
}
