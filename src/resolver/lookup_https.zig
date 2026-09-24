//! DNS over HTTPS, the lookup's half (docs/design.md §22): the answer to a request, and the
//! exchange that ended without one. The request is `poll`'s `send_https` (`lookup_poll.zig`).
//!
//! HTTP pairs a response with its request (RFC 8484 §4.1), so of §7's checks the id and the
//! source are HTTP's, and an answer names the transaction it answers instead. The rest of §7
//! stands: the question must be the one asked.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const lookup_module = @import("lookup.zig");
const Lookup = lookup_module.Lookup;
const Verdict = lookup_module.Verdict;
const constants = @import("constants.zig");
const response_module = @import("lookup_response.zig");

comptime {
    // A transaction's number wraps at 65536, further than a lookup goes: for each candidate, CNAME
    // hop, pass and server it draws `transactions_per_server_max` at most, 7560 at the limits.
    const limits = core.constants;
    const most = limits.candidates_max * (limits.cname_hops_max + 1) * limits.attempts_max *
        limits.servers_max * constants.transactions_per_server_max;
    assert(most <= std.math.maxInt(u16));
}

/// The body of a DoH response to `transaction`, and its `Age`. An answer to a transaction the
/// lookup has left is ignored: HTTP delivers late what a datagram would have lost.
pub fn on_https_answer(
    self: *Lookup,
    transaction: u16,
    message: []const u8,
    age_seconds: u32,
    now_ns: u64,
) Verdict {
    self.see(now_ns);
    assert(self.config.uses_https());
    if (!waits_on(self, transaction)) return .ignored;
    const header = response_module.header_of(message) orelse return .ignored;
    const cased = self.cased_name();
    var accepted = response_module.accepted_shape(self, message, header, &cased) orelse return .ignored;
    accepted.age_seconds = age_seconds;
    return response_module.apply(self, message, accepted, &cased, now_ns);
}

/// The exchange of `transaction` ended without an answer: a status that is not 2xx carries none
/// (RFC 8484 §4.2.1), and the driver has retried what HTTP retries. The server failed this
/// transaction, as a connection that failed does, and the lookup moves to the next one.
pub fn on_https_failed(self: *Lookup, transaction: u16, now_ns: u64) void {
    self.see(now_ns);
    assert(self.config.uses_https());
    if (!waits_on(self, transaction)) return;
    self.servers.record_failure(self.server_slot(), now_ns);
    self.next_server(now_ns);
    assert(self.state != .awaiting_udp);
}

/// Whether the lookup waits on the answer to `transaction`.
fn waits_on(self: *const Lookup, transaction: u16) bool {
    return self.state == .awaiting_udp and transaction == self.transaction.number;
}
