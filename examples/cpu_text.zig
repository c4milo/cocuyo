//! What a TLS example states of its CPU (docs/design.md §16 decision 48, as amended on 2026-10-20
//! and on 2026-11-26). It makes the `stdx.crypto.Context` that colibri's TLS takes from it
//! (colibri decision 175), and writes the suite that a handshake chose. The DoT, DoQ and DoH
//! examples share it.
//!
//! An example detects the CPU's features once, at its start, through stdx's `CpuFeatures.detect()`.
//! On arm64, where detection found FEAT_DIT, it sets PSTATE.DIT on its one thread through stdx's
//! `platform.set_data_independent_timing`. stdx then states the timing of the AES instructions to
//! chapulin: on arm64 from the bit, which it reads at each call, and on x86-64 from detection, as
//! the owner ruled for stdx (stdx decision 87 as amended). So a hello offers AES-GCM first where
//! the CPU has the AES and carry-less multiply instructions, on arm64 only where the bit reads as
//! set, and TLS_CHACHA20_POLY1305_SHA256 alone elsewhere.
const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const stdx = @import("stdx");
const platform = stdx.platform;
const CpuFeatures = platform.CpuFeatures;

/// The cipher suites colibri admits (RFC 9846 Appendix B.4): TLS_AES_128_GCM_SHA256 {0x13,0x01},
/// TLS_AES_256_GCM_SHA384 {0x13,0x02} and TLS_CHACHA20_POLY1305_SHA256 {0x13,0x03}.
pub const aes_128_gcm_sha256: u16 = 0x1301;
pub const aes_256_gcm_sha384: u16 = 0x1302;
pub const chacha20_poly1305_sha256: u16 = 0x1303;

/// Whether stdx builds chapulin's host object for this target, which records the suite of each
/// QUIC session (colibri's decision 97, as amended for chapulin 0.2.0). An object for any other
/// target holds TLS_CHACHA20_POLY1305_SHA256 alone.
const host_object = builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .aarch64;

/// The longest line `statement_text` writes: "cpu: aes yes, carry-less multiply yes, dit yes" is
/// 46 octets.
pub const statement_text_bytes_max = 46;

/// The CPU's features of one detection, and on arm64 PSTATE.DIT set on this thread where detection
/// found FEAT_DIT. Each example calls it once, first in `main`, on the thread that drives the
/// engine, and makes its context of the features.
pub fn detect() CpuFeatures {
    const features = CpuFeatures.detect();
    const set = platform.set_data_independent_timing(features, true);
    // Only on arm64 with FEAT_DIT can the example set the mode, and there it does.
    assert(set == (builtin.cpu.arch == .aarch64 and features.dit));
    return features;
}

/// A `std.Random` over `io.randomSecure`, the random source of the example's TLS sessions. Each
/// draw calls the system, which is thread-safe, keeps no state a fork copies, and has no weaker
/// fallback. A draw that fails halts the example, so no session runs on octets the system did not
/// give.
pub const SecureRandom = struct {
    io: std.Io,

    fn fill(pointer: *anyopaque, octets: []u8) void {
        const self: *SecureRandom = @ptrCast(@alignCast(pointer));
        self.io.randomSecure(octets) catch |err| std.debug.panic("no entropy: {t}", .{err});
    }

    /// The source, which points at `self`, so `self` stays where it is while a session draws.
    pub fn random(self: *SecureRandom) std.Random {
        return .{ .ptr = self, .fillFn = fill };
    }
};

/// The context of every TLS session of the example: `features`, and `secure` as the random source
/// (colibri decision 175). `secure` outlives each session.
pub fn context(features: CpuFeatures, secure: *SecureRandom) stdx.crypto.Context {
    return stdx.crypto.init(features, secure.random());
}

/// The line an example prints of what it states, which the live checks and the interop check read:
/// `cpu: aes <yes|no>, carry-less multiply <yes|no>, dit <yes|no>`. `dit` is this thread's
/// PSTATE.DIT, which only arm64 reads.
pub fn statement_text(features: CpuFeatures, buffer: *[statement_text_bytes_max]u8) []const u8 {
    return std.fmt.bufPrint(buffer, "cpu: aes {s}, carry-less multiply {s}, dit {s}", .{
        answer(features.aes),
        answer(features.pclmul or features.pmull),
        answer(platform.data_independent_timing(features)),
    }) catch unreachable;
}

fn answer(value: bool) []const u8 {
    return if (value) "yes" else "no";
}

/// Prints what the example states, on the line `statement_text` writes.
pub fn report(features: CpuFeatures) void {
    var buffer: [statement_text_bytes_max]u8 = undefined;
    std.debug.print("{s}\n", .{statement_text(features, &buffer)});
}

/// The name of the suite a handshake chose, as RFC 9846 Appendix B.4 writes it. Null is a
/// connection the example did not see: none was up when the turn ended.
pub fn suite_text(suite: ?u16) []const u8 {
    const code = suite orelse return "not seen: no connection is up";
    return switch (code) {
        aes_128_gcm_sha256 => "TLS_AES_128_GCM_SHA256",
        aes_256_gcm_sha384 => "TLS_AES_256_GCM_SHA384",
        chacha20_poly1305_sha256 => "TLS_CHACHA20_POLY1305_SHA256",
        else => "not one colibri admits",
    };
}

/// The suite a QUIC session of chapulin's runs, which `session.suite()` reads. Null is a session
/// whose ServerHello named no suite yet.
pub fn quic_suite(session: anytype) ?u16 {
    if (comptime !host_object) return chacha20_poly1305_sha256;
    const chosen = session.suite() orelse return null;
    return @intFromEnum(chosen);
}

// Tests.

const testing = std.testing;

test "an example's features are detection's, and arm64 sets PSTATE.DIT where detection found FEAT_DIT" {
    const detected = CpuFeatures.detect();
    if (comptime builtin.cpu.arch == .aarch64) {
        if (detected.dit) {
            // A test before this one may have set the bit, so the test clears it first.
            try testing.expect(platform.set_data_independent_timing(detected, false));
            try testing.expect(!platform.data_independent_timing(detected));
            try testing.expect(std.meta.eql(detected, detect()));
            try testing.expect(platform.data_independent_timing(detected));
            return;
        }
    }
    try testing.expect(std.meta.eql(detected, detect()));
    try testing.expect(!platform.data_independent_timing(detected));
}

test "the context holds the features it was made of, and draws from the system" {
    var secure: SecureRandom = .{ .io = testing.io };
    const features = CpuFeatures.detect();
    const made = context(features, &secure);
    try testing.expect(std.meta.eql(features, made.features));
    var first: [16]u8 = undefined;
    var second: [16]u8 = undefined;
    made.random.bytes(&first);
    made.random.bytes(&second);
    // Two draws of 128 bits from the system are equal with a chance of 2^-128.
    try testing.expect(!std.mem.eql(u8, &first, &second));
}

test "the statement's line names the AES instructions, the carry-less multiply, then the thread's mode" {
    var buffer: [statement_text_bytes_max]u8 = undefined;
    try testing.expectEqualStrings("cpu: aes no, carry-less multiply no, dit no", statement_text(.none(), &buffer));
    var x86: CpuFeatures = .none();
    x86.aes = true;
    x86.pclmul = true;
    try testing.expectEqualStrings("cpu: aes yes, carry-less multiply yes, dit no", statement_text(x86, &buffer));
    var arm: CpuFeatures = .none();
    arm.aes = true;
    arm.pmull = true;
    try testing.expectEqualStrings("cpu: aes yes, carry-less multiply yes, dit no", statement_text(arm, &buffer));
    // The longest line: the thread's mode reads as set only on arm64 with FEAT_DIT and the bit set.
    const detected = CpuFeatures.detect();
    if (builtin.cpu.arch == .aarch64 and detected.dit and detected.aes and detected.pmull) {
        _ = platform.set_data_independent_timing(detected, true);
        try testing.expectEqual(statement_text_bytes_max, statement_text(detected, &buffer).len);
    }
}

test "the line's dit is the thread's PSTATE.DIT, and not FEAT_DIT alone" {
    var buffer: [statement_text_bytes_max]u8 = undefined;
    var with_dit: CpuFeatures = .none();
    with_dit.dit = true;
    // Only an arm64 core with FEAT_DIT can read the bit, so there the test clears it first.
    if (builtin.cpu.arch == .aarch64) {
        const detected = CpuFeatures.detect();
        if (!detected.dit) return error.SkipZigTest;
        try testing.expect(platform.set_data_independent_timing(detected, false));
    }
    try testing.expectEqualStrings("cpu: aes no, carry-less multiply no, dit no", statement_text(with_dit, &buffer));
}

test "a suite is named as RFC 9846 Appendix B.4 writes it, and a connection not seen says so" {
    try testing.expectEqualStrings("TLS_AES_128_GCM_SHA256", suite_text(0x1301));
    try testing.expectEqualStrings("TLS_AES_256_GCM_SHA384", suite_text(0x1302));
    try testing.expectEqualStrings("TLS_CHACHA20_POLY1305_SHA256", suite_text(0x1303));
    try testing.expectEqualStrings("not one colibri admits", suite_text(0x1304));
    try testing.expectEqualStrings("not seen: no connection is up", suite_text(null));
}

test "a QUIC session's suite is the one its ServerHello named, and none before it" {
    const Suite = enum(u16) { aes_256_gcm_sha384 = 0x1302, _ };
    const Session = struct {
        named: ?Suite,
        fn suite(session: *const @This()) ?Suite {
            return session.named;
        }
    };
    const named: Session = .{ .named = .aes_256_gcm_sha384 };
    const none: Session = .{ .named = null };
    if (host_object) {
        try testing.expectEqual(aes_256_gcm_sha384, quic_suite(&named).?);
        try testing.expectEqual(null, quic_suite(&none));
    } else {
        try testing.expectEqual(chacha20_poly1305_sha256, quic_suite(&named).?);
    }
}
