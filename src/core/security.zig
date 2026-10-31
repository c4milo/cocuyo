//! What is known of where an answer came from, and when a lookup relies on a server's word for it
//! (docs/design.md §25, Stage A). Stage A relies on the AD bit of a response. Stage B, which
//! validates in cocuyo, reports through the same type.
const std = @import("std");
const assert = std.debug.assert;
const Transport = @import("config.zig").Transport;

/// What is known of where an answer came from (docs/design.md §25).
pub const Security = enum(u2) {
    /// Nothing was checked: neither stage is on, or a message the lookup acted on lacked AD.
    unchecked,
    /// cocuyo proved the name lies in a zone that is not signed, or under no trust anchor (RFC
    /// 4035 §4.3). Stage B.
    insecure,
    /// The server said it validated: AD on every message the lookup acted on, over a channel the
    /// configuration relies on (RFC 4035 §4.9.3). Stage A.
    authenticated,
    /// cocuyo verified signatures from a trust anchor down to the answer (RFC 4035 §4.3). Stage B.
    secure,
};

/// Whether a configuration relies on the AD bit of a response (docs/design.md §25, Stage A rule 1).
pub const AuthenticatedData = enum(u2) {
    /// The bit means nothing, and no query sets it. The default.
    ignored,
    /// The bit counts from a server over TLS, HTTPS or QUIC, which strict mode authenticated
    /// (docs/design.md §21), and from no other.
    encrypted,
    /// The bit counts from every server. This is for a validating resolver on the loopback, which
    /// `options trust-ad` in a `resolv.conf` names.
    always,

    /// Whether a response over `transport` may be read for its AD bit. "A resolver MUST disregard
    /// the meaning of the CD and AD bits in a response unless the response was obtained by using a
    /// secure channel or the resolver was specifically configured to regard the message header
    /// bits without using a secure channel" (RFC 4035 §4.6).
    pub fn relied_on(self: AuthenticatedData, transport: Transport) bool {
        const relied = switch (self) {
            .ignored => false,
            .encrypted => transport != .cleartext,
            .always => true,
        };
        assert(!relied or self != .ignored);
        return relied;
    }

    /// Whether a query sets AD to ask for the bit (RFC 6840 §5.7): whenever the bit is relied on
    /// from some server (docs/design.md §25, Stage A rule 2).
    pub fn asks(self: AuthenticatedData) bool {
        return self != .ignored;
    }
};

// Tests.

const testing = std.testing;

test "the AD bit counts from no server when ignored, from encrypted ones under encrypted, and from all under always" {
    // RFC 4035 §4.6: a secure channel, or a configuration that says so.
    for (std.enums.values(Transport)) |transport| {
        try testing.expect(!AuthenticatedData.ignored.relied_on(transport));
        try testing.expect(AuthenticatedData.always.relied_on(transport));
        try testing.expectEqual(transport != .cleartext, AuthenticatedData.encrypted.relied_on(transport));
    }
}

test "a query asks for AD unless the bit is ignored" {
    try testing.expect(!AuthenticatedData.ignored.asks());
    try testing.expect(AuthenticatedData.encrypted.asks());
    try testing.expect(AuthenticatedData.always.asks());
}
