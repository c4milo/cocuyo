//! An SPKI pin from its text. RFC 7858 §4.2 says an implementation MUST accept a pin written as
//! the base64 of its SHA-256 (RFC 4648 §4), which is how HPKP spells one and how a resolver's
//! operator publishes one (docs/design.md §21). Only that form is read: the standard alphabet,
//! with its padding, and nothing around it.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");

pub const Error = error{MalformedPin};

/// Reads one pin. Anything but the canonical base64 of 32 octets is refused: another length, a
/// character outside RFC 4648 §4's alphabet (so the URL-safe one of §5 too), missing padding, or
/// pad bits that are not zero, which RFC 4648 §3.5 lets a decoder refuse and a pin must, since
/// two texts for one pin would be two pins to a reader comparing text.
pub fn from_base64(text: []const u8) Error!core.Pin {
    const decoder = std.base64.standard.Decoder;
    // The alphabet, the padding and zero pad bits (RFC 4648 §4 and §3.5).
    const decoded_bytes = decoder.calcSizeForSlice(text) catch return Error.MalformedPin;
    // A pin is a SHA-256 (RFC 7858 §4.2): 32 octets, which only a text of 44 characters holds.
    if (decoded_bytes != core.constants.spki_pin_bytes) return Error.MalformedPin;
    var pin: core.Pin = undefined;
    decoder.decode(&pin, text) catch return Error.MalformedPin;
    assert(decoded_bytes == pin.len);
    return pin;
}

// Tests.

const testing = std.testing;

/// The two pins of RFC 7858 Appendix A, and their octets as Python's `base64.b64decode` read
/// them, a decoder that shares nothing with this one.
const appendix_pins = [_][]const u8{
    "FHkyLhvI0n70E47cJlRTamTrnYVcsYdjUGbr79CfAVI=",
    "dFSY3wdPU8L0u/8qECuz5wtlSgnorYV2f66L6GNQg6w=",
};
const appendix_octets = [_][]const u8{
    "1479322e1bc8d27ef4138edc2654536a64eb9d855cb187635066ebefd09f0152",
    "745498df074f53c2f4bbff2a102bb3e70b654a09e8ad85767fae8be8635083ac",
};

test "the pins of RFC 7858 Appendix A read to their octets" {
    for (appendix_pins, appendix_octets) |text, hex| {
        var expected: core.Pin = undefined;
        _ = try std.fmt.hexToBytes(&expected, hex);
        try testing.expectEqualSlices(u8, &expected, &(try from_base64(text)));
    }
}

test "a pin in any other text is refused" {
    const good = appendix_pins[1];
    // Another length: one character short, one over, and the padding left off.
    try testing.expectError(Error.MalformedPin, from_base64(good[0 .. good.len - 1]));
    try testing.expectError(Error.MalformedPin, from_base64(good ++ "A"));
    try testing.expectError(Error.MalformedPin, from_base64("A" ++ good[0 .. good.len - 1]));
    // The URL-safe alphabet: `_` where the standard one has `/`.
    try testing.expectError(Error.MalformedPin, from_base64("dFSY3wdPU8L0u_8qECuz5wtlSgnorYV2f66L6GNQg6w="));
    // Pad bits that are not zero: `J` where `I` ends the first pin.
    try testing.expectError(Error.MalformedPin, from_base64("FHkyLhvI0n70E47cJlRTamTrnYVcsYdjUGbr79CfAVJ="));
    // A space in the middle.
    try testing.expectError(Error.MalformedPin, from_base64("FHkyLhvI0n70E47cJlRTamTrnYVcsYdjUGbr79 fAVI="));
}
