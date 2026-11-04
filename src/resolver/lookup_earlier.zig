//! A response to an earlier try that is still open, and a failure of its connection or its
//! request (docs/design.md §5, Tries kept open; §16 decision 66). `spec/lean/Spec/Lookup.lean`
//! is the model: `earlierHeard`, `passed`, `earlierChecked` and `earlierFailed`.
//!
//! The lookup loads the try into its own fields, so that the checks of §7 and the reading of the
//! message are the ones the current try's response gets. The response closes that try. One the
//! lookup acts on moves it as the current try's would: an answer, a CNAME it follows, NXDOMAIN or
//! NODATA. One that would move it on closes that try alone, and names its server as the cause:
//! SERVFAIL, REFUSED, NOTIMP, FORMERR, BADCOOKIE, a bogus message, and TC=1 or a datagram the
//! buffer cut, which name no cause. Then the lookup's own fields come back, as far as the
//! response left them for the current try.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Endpoint = core.Endpoint;
const lookup_module = @import("lookup.zig");
const Lookup = lookup_module.Lookup;
const Verdict = lookup_module.Verdict;
const Reason = lookup_module.Reason;
const tries_module = @import("lookup_tries.zig");
const response_module = @import("lookup_response.zig");
const cut_module = @import("lookup_response_cut.zig");
const failure_module = @import("lookup_failure.zig");
const poll_module = @import("lookup_poll.zig");
const limits = @import("limits.zig");

/// A datagram or a stream's message that the current try did not take: an earlier try's
/// response, read against each try open with its id, the newest first.
/// Out of line: inlined, it cost each datagram the current try refuses 127 instructions
/// (docs/performance.md).
pub noinline fn on_response(self: *Lookup, message: []const u8, from: Endpoint, now_ns: u64) Verdict {
    @branchHint(.cold);
    if (self.is_settled() or self.tries.count == 0) return .ignored;
    // Over DoH or DoQ an answer comes by its transaction (§22, §23).
    if (self.config.sends_requests()) return .ignored;
    const header = response_module.header_of(message) orelse return .ignored;
    var index: usize = self.tries.count;
    while (index > 0) {
        index -= 1;
        if (self.tries.items[index].id != header.id) continue;
        const saved = tries_module.save(self);
        tries_module.load(self, index);
        const accepted = response_module.accepted_header(self, message, from) orelse {
            tries_module.restore(self, &saved);
            continue;
        };
        const epoch = self.tries.epoch;
        return finish(self, index, epoch, &saved, read(self, message, accepted, now_ns));
    }
    assert(index == 0);
    return .ignored;
}

/// A datagram the buffer cut that the current try did not take. One that passes the checks of a
/// cut datagram against an earlier try over UDP closes that try, and moves nothing: its server
/// answered, and the model's TC=1 stands for it (`passed`).
pub fn on_datagram_cut(self: *Lookup, message: []const u8, from: Endpoint, now_ns: u64) Verdict {
    if (self.is_settled() or self.tries.count == 0) return .ignored;
    if (self.config.sends_requests() or self.config.ignore_truncation) return .ignored;
    const header = response_module.header_of(message) orelse return .ignored;
    var index: usize = self.tries.count;
    while (index > 0) {
        index -= 1;
        const kept = &self.tries.items[index];
        if (kept.marks.stream or kept.id != header.id) continue;
        const saved = tries_module.save(self);
        tries_module.load(self, index);
        const matched = cut_module.matches(self, message, from);
        tries_module.restore(self, &saved);
        if (!matched) continue;
        // No sample, no success and no cookie: check 6 did not read a whole message (§7).
        self.tries.remove(index);
        self.see(now_ns);
        return .accepted;
    }
    assert(index == 0);
    return .ignored;
}

/// The answer to an earlier request over DoH or DoQ, which names its try's number.
pub fn on_request_answer(self: *Lookup, transaction: u16, message: []const u8, age_seconds: u32, now_ns: u64) Verdict {
    assert(self.config.sends_requests());
    if (self.is_settled()) return .ignored;
    const index = self.tries.numbered(transaction) orelse return .ignored;
    assert(!self.tries.items[index].marks.stream);
    const saved = tries_module.save(self);
    tries_module.load(self, index);
    const header = response_module.header_of(message) orelse {
        tries_module.restore(self, &saved);
        return .ignored;
    };
    var accepted = response_module.accepted_shape(self, message, header) orelse {
        tries_module.restore(self, &saved);
        return .ignored;
    };
    accepted.age_seconds = age_seconds;
    const epoch = self.tries.epoch;
    return finish(self, index, epoch, &saved, read(self, message, accepted, now_ns));
}

/// An earlier request over DoH or DoQ ended without an answer: it closes that try, and its server
/// is the cause (`earlierFailed`). False when no open try has that number.
pub fn on_request_failed(self: *Lookup, transaction: u16, reason: Reason, now_ns: u64) bool {
    assert(self.config.sends_requests());
    if (self.is_settled()) return false;
    const index = self.tries.numbered(transaction) orelse return false;
    const slot = self.order[self.tries.items[index].position];
    self.tries.remove(index);
    self.servers.record_failure(slot, now_ns);
    failure_module.keep_at(self, slot, .{ .reason = reason });
    return true;
}

/// The connection to `server`, which the lookup is no longer on, failed: it closes each stream try
/// open on it, and its server is the cause (`earlierFailed`). Such a connection was up, since a
/// try went out on it, so it can only have closed.
pub fn on_connection_failed(self: *Lookup, server: u8, reason: Reason, now_ns: u64) void {
    var closed = false;
    for (0..self.config.server_count()) |position| {
        if (self.order[position] != server) continue;
        closed = close_streams_at(self, @intCast(position)) or closed;
    }
    if (!closed) return;
    assert(reason == .closed);
    self.servers.record_failure(server, now_ns);
    failure_module.keep_at(self, server, .{ .reason = reason });
}

/// Closes every stream try open at `position`, whose connection failed. True when one was open.
pub fn close_streams_at(self: *Lookup, position: u8) bool {
    var closed = false;
    var index: usize = self.tries.count;
    while (index > 0) {
        index -= 1;
        const kept = &self.tries.items[index];
        if (!kept.marks.stream or kept.position != position) continue;
        self.tries.remove(index);
        closed = true;
    }
    assert(self.tries.stream_at(position) == null);
    return closed;
}

/// A later pass that reaches a server with an open try of the name over a stream sends no query:
/// the query is still on its connection, and RFC 1035 §4.2.1 asks for a retransmission over UDP
/// alone. The lookup waits on that try again, with the deadline of this pass (`waitOn`). False
/// when no such try is open.
pub fn wait_again(self: *Lookup, now_ns: u64) bool {
    assert(self.config.streams_only());
    const index = self.tries.stream_at(self.server_index) orelse return false;
    // EDNS0 is on again for the pass, as for any server the walk reaches: the flag says what the
    // next query carries (RFC 6891 §6.2.2; the model's `advanceServer`).
    const edns_enabled = self.flags.edns_enabled;
    tries_module.load(self, index);
    self.flags.edns_enabled = edns_enabled;
    self.tries.remove(index);
    assert(self.state == .awaiting_tcp);
    self.waited_from_ns = now_ns;
    poll_module.arm(self, now_ns);
    return true;
}

/// Reads a response to the loaded try as the current try's is read, in the mode that closes the
/// try alone where the current try's would move the lookup on.
fn read(self: *Lookup, message: []const u8, accepted: response_module.Accepted, now_ns: u64) Verdict {
    assert(!self.hearing_earlier);
    self.hearing_earlier = true;
    defer self.hearing_earlier = false;
    return response_module.apply(self, message, accepted, now_ns);
}

/// What a response to the try at `index` left: the try closes when the lookup took the response,
/// and the lookup's own fields come back as far as the response left them for the current try.
/// `epoch` is the tries' before the reading: a reading that moved the lookup to another name closed
/// every try already.
fn finish(self: *Lookup, index: usize, epoch: u8, saved: *const tries_module.Saved, verdict: Verdict) Verdict {
    if (verdict == .ignored) {
        tries_module.restore(self, saved);
        return .ignored;
    }
    if (self.tries.epoch == epoch) self.tries.remove(index) else assert(self.tries.count == 0);
    switch (self.state) {
        // The response closed its try alone, and the lookup waits where it waited.
        .awaiting_udp, .awaiting_tcp => tries_module.restore(self, saved),
        // It waits for the keys the message needs, on the server it was on. A try it waited on
        // stays open, now as an earlier one (`earlierChecked`).
        .awaiting_keys => {
            tries_module.restore_position(self, saved);
            if (saved.state == .awaiting_udp or saved.state == .awaiting_tcp) self.tries.push(try_of(self, saved));
        },
        // A CNAME it follows asks the target on the server the lookup was on (`onReply`). The next
        // search candidate starts the walk over the servers again, and moved the server itself.
        .query_ready, .tcp_needed => if (self.candidate_index == saved.candidate_index) {
            self.server_index = saved.server_index;
            self.flags.edns_enabled = saved.flags.edns_enabled;
        },
        .done, .failed => {},
        // No reading moves a lookup to a connection: a closed try alone gives back the lookup's
        // own state, which may be either, in the first arm.
        .connecting_tcp, .tcp_ready => unreachable,
    }
    assert(self.tries.count <= limits.tries_open_max);
    return .accepted;
}

/// The try the lookup waited on before a response to an earlier one moved it.
fn try_of(self: *const Lookup, saved: *const tries_module.Saved) tries_module.Try {
    assert(saved.state == .awaiting_udp or saved.state == .awaiting_tcp);
    assert(saved.server_index < self.config.server_count());
    return .{
        .sent_at_ns = saved.sent_at_ns,
        .case_seed = saved.transaction.case_seed,
        .cookie_client = saved.cookie_client,
        .id = saved.transaction.id,
        .number = saved.transaction.number,
        .position = saved.server_index,
        .cookie_form = saved.cookie_form,
        .marks = .{
            .stream = saved.state == .awaiting_tcp,
            .edns_enabled = saved.flags.edns_enabled,
            .query_mixed = saved.flags.query_mixed,
            .reply_marked = saved.flags.reply_marked,
        },
    };
}
