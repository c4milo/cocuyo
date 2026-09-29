//! The DNS half of DoH (docs/design.md §24, DoH over HTTP/3 and DoH over colibri's client): a
//! server's path template, expanded for each request, and what a response's header section says of
//! its content. It reads no colibri and imports `std` alone, and `cocuyo_doh` imports it. It stays a
//! module of its own so that its tests run without colibri or chapulin, and under the coverage
//! report.
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
