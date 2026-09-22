//! The limits this module holds: the shape of a `resolv.conf` rather than anything the protocol
//! fixes.
//!
//! `resolv.conf` has no RFC. Its keywords and its options are what the platform manual pages
//! document — `resolv.conf(5)` on Linux and on macOS — so this module cites a manual page where
//! the rest of cocuyo cites an RFC, and says so (CLAUDE.md non-negotiable 8).
const core = @import("core");

/// The most lines the parser reads from one file. A `resolv.conf` is a handful of lines; the bound
/// is what keeps a file the parser did not write from deciding how long it runs.
pub const lines_max = 256;

/// The most groups an IPv6 address holds (RFC 3596 §2.2 gives the address 128 bits).
pub const address_v6_groups = 8;

/// The hexadecimal digits one group may hold.
pub const address_v6_group_digits_max = 4;

/// The decimal digits one IPv4 octet may hold.
pub const address_v4_octet_digits_max = 3;

/// The dotted quad's octet count (RFC 1035 §3.4.1).
pub const address_v4_octets = core.constants.address_v4_bytes;

comptime {
    if (address_v6_groups * 2 != core.constants.address_v6_bytes) {
        @compileError("the IPv6 groups do not cover the address");
    }
}

/// The nameserver a `resolv.conf` with no `nameserver` line means: the local one. Every platform
/// stub does this, and a `Config` with no server at all would be a configuration no lookup could
/// use (docs/design.md §10).
pub const nameserver_default = [_]u8{ 127, 0, 0, 1 };

/// The keywords a line may start with (`resolv.conf(5)`). `sortlist` is recognised only so that
/// it is skipped by name rather than by falling through.
pub const keyword_nameserver = "nameserver";
pub const keyword_search = "search";
pub const keyword_domain = "domain";
pub const keyword_options = "options";
pub const keyword_sortlist = "sortlist";

/// What separates tokens on a line, and what starts a comment.
pub const token_separators = " \t\r";
pub const comment_starts = "#;";

/// The base an IPv4 octet is written in.
pub const decimal_base = 10;

/// The base an IPv6 group is written in, as a shift: one hexadecimal digit is four bits.
pub const hex_digit_bits = 4;

/// The value the letter `a` stands for in hexadecimal.
pub const hex_alpha_value = 10;

/// The bits in an octet, so a shift by a whole octet names what it shifts by.
pub const octet_bits = @bitSizeOf(u8);

/// The octets one IPv6 group holds.
pub const address_v6_group_bytes = 2;

/// The groups a trailing dotted quad fills (RFC 4291 §2.2 form 3).
pub const groups_per_quad = 2;

/// The `::` of a compressed IPv6 address, in octets (RFC 4291 §2.2 form 2).
pub const double_colon_bytes = 2;

/// The most option tokens one `options` line is read for. A line holds a handful; the bound is
/// what keeps a file the parser did not write from deciding how long it runs.
pub const options_max = 16;
