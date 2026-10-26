//! The limits the codec holds: the bounds of the records it reads and of the fuzz target that
//! writes them (docs/design.md §16 decision 56). Each is named here and never written at the use
//! site (CLAUDE.md non-negotiable 5). The numbers the wire format fixes are in `constants.zig`.
const std = @import("std");
const constants = @import("constants.zig");
const core = @import("core");
const fuzz_generate = @import("fuzz/fuzz_generate.zig");
const fuzz_records = @import("fuzz/fuzz_generate_records.zig");

/// CAA: the tag after the flags and the tag length is at least one octet (RFC 8659 §4.1).
pub const caa_tag_bytes_min: usize = 1;

/// A `<character-string>`: one length octet, then at most that many octets (RFC 1035 §3.3).
pub const character_string_bytes_max: usize = 255;

/// The shape of a record the fuzz generator writes whole (`fuzz/fuzz_generate_records.zig`,
/// docs/design.md §19, step 9's gate): names of up to three labels of up to twelve letters,
/// character-strings of up to twenty octets and up to four of them in a TXT or an ALPN list,
/// opaque fields of up to thirty-two octets, and up to three addresses in an SVCB hint. A record
/// of every type then fits a message several times over. Chosen, not measured.
pub const fuzz_labels_max: usize = 3;
pub const fuzz_label_bytes_max: usize = 12;
pub const fuzz_string_bytes_max: usize = 20;
pub const fuzz_strings_max: usize = 4;
pub const fuzz_opaque_bytes_max: usize = 32;
pub const fuzz_hints_max: usize = 3;

/// The shortest name of the long questions the fuzz generator writes (`fuzz/fuzz_generate.zig`):
/// 64 lengths, from here to the longest name, 255 octets. They hold the fourteen whose question's
/// class lies past octet 255 of the message, from 242 octets on, and fifty shorter. The gate's
/// 4096 seeds over ten strategies give each length about six seeds, by arithmetic, and a test of
/// `fuzz/fuzz.zig` pins that each is reached. Chosen, not measured.
pub const fuzz_question_name_bytes_min: usize = 192;

/// The fewest octets a label other than the root takes in a name: its length octet and one octet
/// (RFC 1035 §3.1). A long question's labels never leave fewer for the next.
pub const label_wire_bytes_min: usize = 2;

/// The COOKIE option's length when it holds a client cookie and a server cookie of 8 to 32 octets
/// (RFC 7873 §4).
pub const cookie_option_long_bytes_min: usize = 16;
pub const cookie_option_long_bytes_max: usize = 40;

/// The most segments a record layout has: NAPTR's fixed part, three strings and a name
/// (`rdata/rdata_layout.zig`).
pub const layout_segments_max: usize = 5;

/// The draws DNS-0x20 takes for one name. A draw that leaves every letter small is drawn again,
/// so that a mixed name carries a capital, and after this many the first letter is made one
/// (`name.mix_case`, docs/design.md §7). One draw leaves a name of L letters all small with chance
/// 2^-L, so the first letter is forced with chance 2^-4L: 1 in 16 for one letter, whose only case
/// with a capital that is, 1 in 256 for two, and 1 in 4096 or less from three on. Chosen, not
/// measured.
pub const case_draws_max: usize = 4;

/// The longest `dns` variable a DoH GET carries (RFC 8484 §6): the largest query without the TCP
/// length prefix, 384 octets, in base64url without padding, four characters for three octets,
/// which is 512 (docs/design.md §22).
pub const dns_variable_bytes_max = std.base64.url_safe_no_pad.Encoder.calcSize(
    core.limits.query_bytes_max - core.constants.tcp_prefix_bytes,
);

/// The longest label of boundary octets the test of `name_case.zig` spells.
pub const case_boundary_label_bytes_max: usize = 2;

/// How many seeds `zig build test` runs. Every seed builds a message of up to 1232 octets, or up to
/// 65535 under the long strategy, and runs six checks over it. This is the largest count that
/// keeps the gate inside a second or two.
pub const fuzz_seed_count: usize = 4096;

/// The smallest message the fuzz generator writes (`fuzz/fuzz_generate.zig`): shorter than a
/// header, so the header check is exercised too.
pub const fuzz_message_bytes_min: usize = 1;

/// The shortest long message of the fuzz generator (`fuzz/fuzz_generate.zig`): the name at its
/// offset, and the answer at the end after it.
pub const fuzz_long_message_bytes_min: usize = fuzz_generate.long_name_at + fuzz_records.question_name.len + fuzz_generate.long_tail_bytes;

/// How many offsets of one message the fuzz check aims the name decoder at
/// (`fuzz/fuzz_check.zig`). Every offset would be thorough and slow; thirty-two spread across
/// the message reaches every structure the generator builds.
pub const fuzz_decode_offsets_max: usize = 32;

/// The octets a question of the longest name occupies, with the header before it
/// (`fuzz/fuzz_check.zig`).
pub const fuzz_question_message_bytes_max: usize = core.constants.header_bytes + core.limits.name_bytes_max + core.constants.question_fixed_bytes;

// A constant with no type is a `comptime_int`, which takes the type of a narrow runtime value it
// meets in a sum. The lint rule reads the shape of each value, and this reads the type, so an
// alias or a call that gives a `comptime_int` is caught here (docs/design.md §16 decision 40).
test "each integer constant here has a type" {
    inline for (@typeInfo(@This()).@"struct".decls) |declaration| {
        const untyped = @TypeOf(@field(@This(), declaration.name)) == comptime_int;
        try std.testing.expectEqualStrings("", if (untyped) declaration.name else "");
    }
}
