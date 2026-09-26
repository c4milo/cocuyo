//! The DNS half of DoH that the engine's two HTTP transports share (docs/design.md §24, DoH over
//! HTTP/3 and DoH over HTTP/2): a server's path template, expanded for each request, and what a
//! response's header section says of its content. It reads no colibri and imports `std` alone, so
//! `cocuyo_quic` and `cocuyo_h2` import it without either importing the other.
pub const template = @import("io_doh_template.zig");
pub const response = @import("io_doh_response.zig");
pub const constants = @import("io_doh_constants.zig");
/// A query read back out of a GET's path, which the test servers do (`io_doh_query.zig`).
pub const query = @import("io_doh_query.zig");

test {
    _ = template;
    _ = response;
    _ = constants;
    _ = query;
}
