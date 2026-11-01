//! The DNSSEC records the fuzz generator writes (docs/design.md §25, step 6): the fields of NSEC3
//! and NSEC3PARAM, and type maps that hold. Split from `fuzz_generate_records.zig` by the
//! file-length rule.
//!
//! Everything here is a pure function of the generator's stream (CLAUDE.md non-negotiable 4).
const constants = @import("../constants.zig");
const limits = @import("../limits.zig");
const records = @import("fuzz_generate_records.zig");
const Generator = @import("fuzz_generate.zig").Generator;
const Writer = records.Writer;

/// The hash algorithm, the flags, the iterations and a salt, then for NSEC3 a hash and a type map
/// (RFC 5155 §3.2, §4.2).
pub fn write_nsec3(generator: *Generator, writer: *Writer, whole_nsec3: bool) void {
    writer.noise(generator, constants.nsec3_salt_length_offset);
    const salt = generator.below(limits.fuzz_opaque_bytes_max + 1);
    writer.octet(@intCast(salt));
    writer.noise(generator, salt);
    if (!whole_nsec3) return;
    const hash = generator.below(limits.fuzz_opaque_bytes_max + 1);
    writer.octet(@intCast(hash));
    writer.noise(generator, hash);
    write_bitmaps(generator, writer);
}

/// A type map that holds: blocks in increasing windows, each of 1 to 32 octets (RFC 4034 §4.1.2).
pub fn write_bitmaps(generator: *Generator, writer: *Writer) void {
    var window: usize = generator.below(limits.fuzz_windows_max);
    for (0..generator.below(limits.fuzz_windows_max + 1)) |_| {
        const length = 1 + generator.below(limits.bitmap_octets_max);
        writer.octet(@intCast(window));
        writer.octet(@intCast(length));
        writer.noise(generator, length);
        window += 1 + generator.below(limits.fuzz_windows_max);
    }
}
