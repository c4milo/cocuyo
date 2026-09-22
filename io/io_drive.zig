//! Driving the table: what every lookup wants, done (docs/design.md §19 step 13). Free
//! functions over the engine, split out of `engine.zig` so each is scored on its own.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const constants = @import("constants.zig");
const udp = @import("io_udp.zig");
const results_module = @import("io_results.zig");

/// Polls the table for what every lookup wants and does it: a send queued, an end handed to
/// `results`, and the timer moved to the soonest deadline.
pub fn drive(self: anytype, now_ns: u64) void {
    var polls: usize = 0;
    while (polls < constants.polls_per_drive_max) : (polls += 1) {
        const event = self.resolver.poll(now_ns, &self.scratch) orelse break;
        act(self, event, now_ns);
    }
    arm_timer(self, now_ns);
}

fn act(self: anytype, event: cocuyo.Event, now_ns: u64) void {
    const index = event.handle.index;
    switch (event.action) {
        .send_udp => |send| {
            if (self.send_in_flight[index]) return;
            queue_send(self, index, send, now_ns);
        },
        // TCP comes with the next commit of §19 step 13; until then the answer that needs it
        // is a failure of this server.
        .connect_tcp, .send_tcp => self.resolver.on_tcp_failed(event.handle, now_ns),
        .done => |answer| report(self, index, .{ .answer = answer }, now_ns),
        .failed => |failure| report(self, index, .{ .failure = failure }, now_ns),
        .wait => unreachable,
    }
}

fn queue_send(self: anytype, index: usize, send: anytype, now_ns: u64) void {
    const bytes = send.message_bytes;
    assert(bytes.len <= cocuyo.constants.query_bytes_max);
    @memcpy(self.send_buffers[index][0..bytes.len], bytes);
    self.outbounds[index] = udp.outbound_to(send.server);
    const socket = self.sockets.descriptor_of(self.resolver.lookup_of(self.handles[index]).server_slot());
    const operation: rotor.Operation = .{
        .user_data = @TypeOf(self.*).user_data(.udp_send, index),
        .kind = .{ .send_to = .{
            .socket = socket,
            .buffer = .{ .bytes = self.send_buffers[index][0..bytes.len] },
            .to = &self.outbounds[index],
        } },
    };
    if (self.loop.submit(&.{operation}, &.{}) == 1) {
        self.send_in_flight[index] = true;
    } else {
        self.resolver.on_send_failed(self.handles[index], now_ns);
    }
}

fn report(self: anytype, index: usize, outcome: results_module.Outcome, now_ns: u64) void {
    if (self.reported[index]) return;
    self.reported[index] = true;
    const lookup = self.resolver.lookup_of(self.handles[index]);
    switch (outcome) {
        .answer => self.cache.put(&lookup.question, &lookup.answers, now_ns),
        .failure => |failure| put_negative(self, &lookup.question, failure, now_ns),
    }
    self.results.push(.{ .handle = self.handles[index], .outcome = outcome });
}

fn put_negative(self: anytype, question: *const cocuyo.Question, failure: cocuyo.Failure, now_ns: u64) void {
    const outcome: cocuyo.cache.Outcome = switch (failure.err) {
        cocuyo.Error.NameNotFound => .name_not_found,
        cocuyo.Error.NoData => .no_data,
        else => return,
    };
    self.cache.put_negative(question, outcome, failure.negative_ttl_seconds, now_ns);
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
