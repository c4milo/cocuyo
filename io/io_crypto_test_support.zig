//! What the sessions' tests state of the CPU (docs/design.md §16 decision 48, as amended on
//! 2026-11-26). A test names a case, and owns the stream that its context's random source draws
//! from, so each run draws what the last drew. The DoT, DoQ and DoH tests share it.
//!
//! The tests reach no stdx (§16 decision 48). At the commit that colibri pins, the context that
//! colibri's TLS takes is a plain struct of the CPU's features and the random source. So a test
//! names both, through the type that colibri's `tls.Client` names, and `CpuFeatures.detect` is a
//! declaration of the features' own type.
//!
//! stdx states the timing of the AES instructions to chapulin on x86-64 from detection, and on
//! arm64 from the thread's PSTATE.DIT, where the features hold FEAT_DIT. So a case that offers
//! AES-GCM sets the bit on arm64, and a case that names the instructions without the timing exists
//! on arm64 alone. Each case names instructions that no test runs: a test that names the AES
//! instructions reads the hello alone.
const std = @import("std");
const builtin = @import("builtin");
const tls = @import("colibri").tls;

/// The consumer's context, as colibri's TLS names it.
pub const Crypto = @FieldType(tls.Client, "crypto");
/// stdx's `platform.CpuFeatures`, as the context names it.
pub const CpuFeatures = @FieldType(Crypto, "features");

/// What a test states of the CPU.
pub const Case = enum {
    /// No instruction: what detection gives on a CPU of neither instruction.
    nothing,
    /// The AES instructions and a carry-less multiply, whose timing stdx states.
    with_aes,
    /// The same instructions on an arm64 core whose features hold no FEAT_DIT, so stdx states no
    /// timing.
    aes_not_stated,
    /// A carry-less multiply and no AES instructions.
    without_aes,
};

/// PSTATE.DIT, bit 24 of Arm's DIT register, which the tests name S3_3_C4_C2_5 by its op0, op1,
/// CRn, CRm and op2 fields. So an assembler that targets a CPU without FEAT_DIT takes the
/// instruction too. Only a core whose detection found FEAT_DIT runs it.
const dit_bit_index: u6 = 24;
const dit_bit: u64 = @as(u64, 1) << dit_bit_index;

/// A stream that `seed_octet` repeated seeds. Never for a network, whose source is a CSPRNG's.
pub fn stream(seed_octet: u8) std.Random.ChaCha {
    return .init(@splat(seed_octet));
}

/// The context of `case`, which draws from `source`. `source` outlives each session of the context.
/// Null for a case that this host cannot state: `with_aes` on an arm64 core without FEAT_DIT, and
/// `aes_not_stated` off arm64, where stdx states the timing of each core.
pub fn crypto(case: Case, source: *std.Random.ChaCha) ?Crypto {
    const features = features_of(case) orelse return null;
    return .{ .features = features, .random = source.random() };
}

/// Whether this host can state `case`. On arm64 a case that offers AES-GCM sets the thread's
/// PSTATE.DIT.
pub fn states(case: Case) bool {
    return features_of(case) != null;
}

fn features_of(case: Case) ?CpuFeatures {
    var features: CpuFeatures = .none();
    switch (case) {
        .nothing => {},
        .with_aes => {
            features.aes = true;
            switch (builtin.cpu.arch) {
                .x86_64 => features.pclmul = true,
                .aarch64 => {
                    if (!CpuFeatures.detect().dit) return null;
                    features.pmull = true;
                    features.dit = true;
                    set_dit();
                },
                else => return null,
            }
        },
        .aes_not_stated => {
            if (builtin.cpu.arch != .aarch64) return null;
            features.aes = true;
            features.pmull = true;
        },
        .without_aes => {
            features.pclmul = builtin.cpu.arch == .x86_64;
            features.pmull = builtin.cpu.arch == .aarch64;
        },
    }
    return features;
}

/// Sets PSTATE.DIT on the calling thread, with Arm's MSR to the DIT register. Its caller found
/// FEAT_DIT, without which the instruction is undefined.
fn set_dit() void {
    if (comptime builtin.cpu.arch != .aarch64) unreachable;
    asm volatile ("msr s3_3_c4_c2_5, %[value]"
        :
        : [value] "r" (dit_bit),
        : .{ .memory = true });
}
