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

/// Polls the table for what every lookup wants and does it, until nothing is left: a send out
/// or held, a connection asked for, an end handed to `results`. Then the idle close, the port
/// rotation, and the timer moved to the soonest deadline.
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
    tcp.close_idle(self, now_ns);
    tcp.tend(self);
    tend_sockets(self);
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

/// What a drive does last, server by server (docs/design.md §19 step 13, the datagram's rules 1
/// and 4). A source port that has carried its share of queries is replaced once no lookup is
/// waiting on its server (`Config.udp_queries_per_port`, c-ares `udp_max_queries`): a port is
/// never taken from a query that is still waiting, because the answer would arrive at a socket
/// that is gone. Then a server with no socket is given one, and a socket with no receive is
/// given one, since a refusal is not a reason to go deaf.
fn tend_sockets(self: anytype) void {
    const tag = @TypeOf(self.*).tag;
    var server: u8 = 0;
    while (server < self.config.servers.len) : (server += 1) {
        const retiring = self.sockets.is_open(server) and self.sockets.is_retiring(server);
        if (retiring and !waiting_on(self, server)) {
            self.sockets.rotate(self.loop, self.config, server, tag) catch {};
        }
        self.sockets.tend(self.loop, self.config, server, tag);
    }
}

/// Whether any lookup is waiting for an answer from server `server`, or has a query on its way
/// there.
fn waiting_on(self: anytype, server: u8) bool {
    for (self.slots[0..], 0..) |*slot, index| {
        if (!slot.occupied) continue;
        const lookup = self.resolver.lookup_of(self.handles[index]);
        if (lookup.server_slot() != server) continue;
        if (self.send_in_flight[index] or lookup.is_waiting()) return true;
    }
    return false;
}

/// One rotor timer at the table's soonest deadline, moved when the deadline moves.
fn arm_timer(self: anytype, now_ns: u64) void {
    if (self.closing) return;
    const due = self.resolver.next_deadline_ns();
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
