//! What a TLS example states of its CPU, under the word `cpu` on its command line (docs/design.md
//! §16 decision 48, as amended on 2026-10-20). It also writes the suite that a handshake chose. The
//! DoT, DoQ and DoH examples share it.
//!
//! Without the word, an example states nothing: `not_known` for each answer of the probe, and
//! `not_stated` for the timing. That is the value a consumer passes when it cannot state the mode
//! of its thread. Each hello then offers TLS_CHACHA20_POLY1305_SHA256 alone.
//!
//! With the word first, before the names, an example probes the CPU once, at its start, through
//! stdx's `platform.probe()`. On arm64, where the probe found FEAT_DIT, it sets PSTATE.DIT on its
//! one thread, and reads the bit back. Only when the bit reads as set does it state
//! `data_independent`, with the probe's answers beside it. Elsewhere it states nothing, as without
//! the word. On x86-64 the mode is DOITM, which the operating system sets and no program can read.
//! So a hello offers AES-GCM first only on arm64, and only where the probe found the AES
//! instructions too.
//!
//! The word is off by default. An example is a model that a consumer copies, and `not_stated` is
//! the one value that each program can state truthfully. A program states `data_independent` only
//! for a thread that it put in that mode itself.
const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const platform = @import("platform");

/// The word that turns the statement on. It comes first, before the names. A lookup of the
/// one-label name `cpu` is written `cpu.`, with the root's dot.
pub const word = "cpu";

/// The cipher suites colibri admits (RFC 9846 Appendix B.4): TLS_AES_128_GCM_SHA256 {0x13,0x01},
/// TLS_AES_256_GCM_SHA384 {0x13,0x02} and TLS_CHACHA20_POLY1305_SHA256 {0x13,0x03}.
pub const aes_128_gcm_sha256: u16 = 0x1301;
pub const aes_256_gcm_sha384: u16 = 0x1302;
pub const chacha20_poly1305_sha256: u16 = 0x1303;

/// PSTATE.DIT, bit 24 of Arm's DIT register. The examples name the register S3_3_C4_C2_5, by its
/// op0, op1, CRn, CRm and op2 fields. So an assembler that targets a CPU without FEAT_DIT takes the
/// instructions too. Only a CPU whose probe found FEAT_DIT runs them.
const dit_bit: u64 = 1 << 24;

/// Whether colibri builds chapulin's host object for this target, which records the suite of each
/// QUIC session (colibri's decision 97, as amended for chapulin 0.2.0). An object for any other
/// target holds TLS_CHACHA20_POLY1305_SHA256 alone.
const host_object = builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .aarch64;

/// The longest line `statement_text` writes for a value of the type: "cpu: timing
/// data_independent, aes_clmul not_known, dit not_known" is 64 octets.
pub const statement_text_bytes_max = 64;

/// What the command line says after the program's name: whether the word came first, and the
/// arguments after it.
pub const Arguments = struct {
    stated: bool,
    operands: []const [:0]const u8,
};

/// Reads the word from `arguments`, whose first is the program's name. Only the first argument
/// after the name can be the word, and only when it is the word exactly.
pub fn read(arguments: []const [:0]const u8) Arguments {
    assert(arguments.len >= 1);
    const after = arguments[1..];
    const given: Arguments = if (after.len > 0 and std.mem.eql(u8, after[0], word))
        .{ .stated = true, .operands = after[1..] }
    else
        .{ .stated = false, .operands = after };
    assert(given.operands.len + @intFromBool(given.stated) == after.len);
    return given;
}

/// What an example's command line gives it: what it states of its CPU, and the operands after the
/// word.
pub fn Command(comptime Cpu: type) type {
    return struct {
        cpu: Cpu,
        operands: []const [:0]const u8,
    };
}

/// Reads the word from `arguments`, whose first is the program's name, and states the CPU as the
/// word says. Each example calls it once, first in `main`, on the thread that drives the engine.
/// The example then hands `cpu` to its context, and reads its operands from `operands`.
pub fn command(comptime Cpu: type, arguments: []const [:0]const u8) Command(Cpu) {
    const given = read(arguments);
    const cpu = state(Cpu, given.stated);
    // Without the word the example states no mode.
    assert(given.stated or cpu.timing == .not_stated);
    assert(given.operands.len < arguments.len);
    return .{ .cpu = cpu, .operands = given.operands };
}

/// What an example states without the word: nothing (docs/design.md §16 decision 48).
pub fn nothing(comptime Cpu: type) Cpu {
    return .{ .probe = .{ .aes_clmul = .not_known, .dit = .not_known }, .timing = .not_stated };
}

/// What an example states with the word, from what its probe found and whether PSTATE.DIT read as
/// set after the example set it. With FEAT_DIT and the bit set, it states `data_independent` and
/// the probe. Elsewhere it states nothing, as the owner ruled (§17 question 58).
pub fn statement_of(comptime Cpu: type, probe: platform.Cpu, dit_set: bool) Cpu {
    const independent = probe.dit == .yes and dit_set;
    const cpu: Cpu = if (independent) .{ .probe = probe, .timing = .data_independent } else nothing(Cpu);
    // The mode is stated only beside a probe that found FEAT_DIT.
    assert(cpu.timing == .not_stated or cpu.probe.dit == .yes);
    // Where the mode is not stated, nothing is.
    assert(cpu.timing == .data_independent or std.meta.eql(cpu, nothing(Cpu)));
    return cpu;
}

/// What the example states. Without the word it states nothing. With the word it states what one
/// probe found, and the mode of this thread once the example set it.
pub fn state(comptime Cpu: type, stated: bool) Cpu {
    if (!stated) return nothing(Cpu);
    const probe = platform.probe();
    const cpu = statement_of(Cpu, probe, set_dit(probe));
    // Only on arm64 can the example set a mode and read it back.
    assert(cpu.timing == .not_stated or builtin.cpu.arch == .aarch64);
    return cpu;
}

/// Sets PSTATE.DIT on arm64 where `probe` found FEAT_DIT, and says whether the bit then reads as
/// set. Elsewhere it sets nothing, and says no.
fn set_dit(probe: platform.Cpu) bool {
    if (comptime builtin.cpu.arch != .aarch64) return false;
    if (probe.dit != .yes) return false;
    dit_write(probe, true);
    return dit_read();
}

/// Writes PSTATE.DIT, with Arm's MSR to the DIT register. `probe` is the probe that found FEAT_DIT.
fn dit_write(probe: platform.Cpu, set: bool) void {
    comptime assert(builtin.cpu.arch == .aarch64);
    // A CPU without FEAT_DIT does not have the register, and the instruction would be undefined.
    assert(probe.dit == .yes);
    const value: u64 = if (set) dit_bit else 0;
    asm volatile ("msr s3_3_c4_c2_5, %[value]"
        :
        : [value] "r" (value),
        : .{ .memory = true });
}

/// Whether PSTATE.DIT reads as set, with Arm's MRS from the DIT register.
fn dit_read() bool {
    comptime assert(builtin.cpu.arch == .aarch64);
    const value = asm volatile ("mrs %[value], s3_3_c4_c2_5"
        : [value] "=r" (-> u64),
    );
    return value & dit_bit != 0;
}

/// The line an example prints of what it states, which the live checks and the interop check read:
/// `cpu: timing <timing>, aes_clmul <answer>, dit <answer>`.
pub fn statement_text(cpu: anytype, buffer: *[statement_text_bytes_max]u8) []const u8 {
    return std.fmt.bufPrint(buffer, "cpu: timing {s}, aes_clmul {s}, dit {s}", .{
        @tagName(cpu.timing),
        @tagName(cpu.probe.aes_clmul),
        @tagName(cpu.probe.dit),
    }) catch unreachable;
}

/// Prints what the example states, on the line `statement_text` writes.
pub fn report(cpu: anytype) void {
    var buffer: [statement_text_bytes_max]u8 = undefined;
    std.debug.print("{s}\n", .{statement_text(cpu, &buffer)});
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

/// colibri's `tls.Cpu`, as its `values.zig` declares it. The examples pass the real type, and the
/// gate builds them, so a type that drifts from this one fails that build.
const ColibriCpu = struct {
    probe: platform.Cpu,
    timing: enum { not_stated, data_independent },
};

const answers = [_]platform.Answer{ .yes, .no, .not_known };

test "the word is the first argument after the program's name, and only the word exactly" {
    const with = read(&.{ "dot-rotor", "cpu", "example.com", "192.0.2.1" });
    try testing.expect(with.stated);
    try testing.expectEqual(2, with.operands.len);
    try testing.expectEqualStrings("example.com", with.operands[0]);
    const without = read(&.{ "dot-rotor", "example.com", "192.0.2.1" });
    try testing.expect(!without.stated);
    try testing.expectEqualStrings("example.com", without.operands[0]);
    // The word after the first operand is an operand, as a root certificate's path may be.
    const late = read(&.{ "dot-rotor", "example.com", "cpu" });
    try testing.expect(!late.stated);
    try testing.expectEqual(2, late.operands.len);
    for ([_][:0]const u8{ "cpu.", "cpus", "CPU", "cp" }) |other| {
        const named = read(&.{ "dot-rotor", other });
        try testing.expect(!named.stated);
        try testing.expectEqualStrings(other, named.operands[0]);
    }
    const alone = read(&.{"dot-rotor"});
    try testing.expect(!alone.stated);
    try testing.expectEqual(0, alone.operands.len);
    try testing.expect(read(&.{ "dot-rotor", "cpu" }).stated);
}

test "the command line states the CPU as the word says, and keeps the operands after the word" {
    const with = command(ColibriCpu, &.{ "dot-rotor", "cpu", "example.com", "192.0.2.1" });
    try testing.expectEqual(state(ColibriCpu, true), with.cpu);
    try testing.expectEqual(2, with.operands.len);
    try testing.expectEqualStrings("example.com", with.operands[0]);
    const without = command(ColibriCpu, &.{ "dot-rotor", "example.com", "192.0.2.1" });
    try testing.expectEqual(nothing(ColibriCpu), without.cpu);
    try testing.expectEqual(2, without.operands.len);
    try testing.expectEqualStrings("example.com", without.operands[0]);
    // On arm64 with FEAT_DIT the two values differ, so the test sees which one the word gave.
    if (builtin.cpu.arch == .aarch64 and platform.probe().dit == .yes) {
        try testing.expectEqual(.data_independent, with.cpu.timing);
    }
}

test "without the word an example states nothing, whatever the CPU" {
    const expected: ColibriCpu = .{ .probe = .{ .aes_clmul = .not_known, .dit = .not_known }, .timing = .not_stated };
    try testing.expectEqual(expected, nothing(ColibriCpu));
    try testing.expectEqual(expected, state(ColibriCpu, false));
}

test "with the word the statement is data_independent only where the probe found FEAT_DIT and the bit reads as set, and nothing elsewhere" {
    for (answers) |aes_clmul| {
        for (answers) |dit| {
            const probe: platform.Cpu = .{ .aes_clmul = aes_clmul, .dit = dit };
            for ([_]bool{ true, false }) |dit_set| {
                const independent: ColibriCpu = .{ .probe = probe, .timing = .data_independent };
                const expected = if (dit == .yes and dit_set) independent else nothing(ColibriCpu);
                try testing.expectEqual(expected, statement_of(ColibriCpu, probe, dit_set));
            }
        }
    }
}

test "with the word this host's statement follows its probe, and arm64 sets PSTATE.DIT where the probe found FEAT_DIT" {
    const probe = platform.probe();
    if (comptime builtin.cpu.arch == .aarch64) {
        if (probe.dit == .yes) {
            // A test before this one may have set the bit, so the test clears it first.
            dit_write(probe, false);
            try testing.expect(!dit_read());
            const expected: ColibriCpu = .{ .probe = probe, .timing = .data_independent };
            try testing.expectEqual(expected, state(ColibriCpu, true));
            try testing.expect(dit_read());
            return;
        }
    }
    try testing.expectEqual(nothing(ColibriCpu), state(ColibriCpu, true));
}

test "the set leaves PSTATE.DIT clear where the probe did not find FEAT_DIT, and says no" {
    const without = [_]platform.Answer{ .no, .not_known };
    for (without) |dit| try testing.expect(!set_dit(.{ .aes_clmul = .yes, .dit = dit }));
    if (comptime builtin.cpu.arch != .aarch64) return;
    const host = platform.probe();
    if (host.dit != .yes) return;
    // On a core with FEAT_DIT the test reads the bit. It clears the bit first, and requires it to
    // read as clear, or the test could not see an MSR that the set ran.
    dit_write(host, false);
    try testing.expect(!dit_read());
    for (without) |dit| {
        try testing.expect(!set_dit(.{ .aes_clmul = .yes, .dit = dit }));
        try testing.expect(!dit_read());
    }
}

test "the statement's line names the timing, then each answer of the probe" {
    var buffer: [statement_text_bytes_max]u8 = undefined;
    const independent: ColibriCpu = .{ .probe = .{ .aes_clmul = .yes, .dit = .yes }, .timing = .data_independent };
    try testing.expectEqualStrings("cpu: timing data_independent, aes_clmul yes, dit yes", statement_text(independent, &buffer));
    try testing.expectEqualStrings("cpu: timing not_stated, aes_clmul not_known, dit not_known", statement_text(nothing(ColibriCpu), &buffer));
    const longest: ColibriCpu = .{ .probe = .{ .aes_clmul = .not_known, .dit = .not_known }, .timing = .data_independent };
    try testing.expectEqual(statement_text_bytes_max, statement_text(longest, &buffer).len);
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
