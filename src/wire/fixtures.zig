//! Hand-written messages, byte for byte, for the tests of this module.
//!
//! A codec's fixtures have to be written by hand. One built by the encoder would prove the decoder
//! agrees with the encoder and nothing about the format, so these are typed out against RFC 1035
//! §4.1 and read back by both sides.
//!
//! This file is exempt from the magic-numbers rule, because it is all numbers and the numbers are
//! the format (tools/lint/magic_numbers.zig). It is test-only: nothing outside a `test` block
//! names it, so nothing here is compiled into a library build.
const core = @import("core");

/// The transaction id every fixture here carries.
pub const id = 0x1234;

/// A query header as a server would see it: id 0x1234, recursion desired, one question, and no
/// other section.
pub const query_header = [_]u8{
    0x12, 0x34, // id
    0x01, 0x00, // recursion desired
    0x00, 0x01, // qdcount 1
    0x00, 0x00, // ancount 0
    0x00, 0x00, // nscount 0
    0x00, 0x00, // arcount 0
};

/// A full query for `example.com` A: the header above, then the question section.
pub const query_a = query_header ++ "\x07example\x03com\x00\x00\x01\x00\x01".*;

comptime {
    if (query_header.len != core.constants.header_bytes) @compileError("the header fixture is not a header");
}
