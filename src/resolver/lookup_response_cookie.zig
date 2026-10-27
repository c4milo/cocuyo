//! BADCOOKIE: the lookup's answer to a server that wants a fresh server cookie (RFC 7873 §5.3;
//! docs/design.md §5, §19 step 10), and the bound on the retry it asks for (RFC 9520 §3.1; §16
//! decision 58). Split from `lookup_response.zig` by the file-length rule.
const std = @import("std");
const assert = std.debug.assert;
const lookup_module = @import("lookup.zig");
const Lookup = lookup_module.Lookup;
const response = @import("lookup_response.zig");
const bound = @import("lookup_bound.zig");

/// BADCOOKIE (RFC 7873 §5.3): once more with the server cookie just learned, on the transport the
/// lookup is on, which is the server's one retry. Again over UDP, then over TCP; again over a
/// stream, the server will not answer at all (docs/design.md §5, §19 step 10).
pub fn on_bad_cookie(self: *Lookup, now_ns: u64) void {
    if (bad_cookie_fails(self)) {
        self.next_server(now_ns);
    } else if (response.over_stream(self)) {
        // "The client SHOULD retry the request using the new Server Cookie from the response"
        // (RFC 7873 §5.3): a new transaction, on the stream.
        self.flags.cookie_retried = true;
        self.restart(now_ns);
        self.state = .tcp_needed;
    } else if (self.flags.cookie_retried) {
        self.state = .tcp_needed;
    } else {
        self.flags.cookie_retried = true;
        self.restart(now_ns);
    }
    assert(self.state != .awaiting_udp and self.state != .awaiting_tcp);
}

/// Whether BADCOOKIE fails the lookup over: over a stream once the server has had its retry, over
/// DoH or DoQ, where the query carried no cookie, so there is no fresh one to retry with, and when
/// the server has had its queries for the name over the transport of the retry.
pub fn bad_cookie_fails(self: *const Lookup) bool {
    assert(!self.is_settled());
    const transport = cookie_retry(self) orelse return true;
    // "A resolver MUST NOT retry a given query to a server address over a given DNS transport
    // more than twice" (RFC 9520 §3.1).
    return bound.spent(self, transport);
}

/// The transport BADCOOKIE's retry goes over, or null when there is no retry: once more on the
/// transport the lookup is on, then over TCP (RFC 7873 §5.3).
fn cookie_retry(self: *const Lookup) ?bound.Transport {
    if (response.over_stream(self)) {
        return if (self.flags.cookie_retried or self.config.sends_requests()) null else .stream;
    }
    return if (self.flags.cookie_retried) .stream else bound.fresh(self);
}
