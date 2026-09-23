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

/// The nameserver a `resolv.conf` with no `nameserver` line means: the local one. Every platform
/// stub does this, and a `Config` with no server at all would be a configuration no lookup could
/// use (docs/design.md §10).
pub const nameserver_default = [_]u8{ 127, 0, 0, 1 };

/// The keywords a line may start with that the parser reads (`resolv.conf(5)`). A line that
/// starts with any other is skipped.
pub const keyword_nameserver = "nameserver";
pub const keyword_search = "search";
pub const keyword_domain = "domain";
pub const keyword_options = "options";

/// What separates tokens on a line, and what starts a comment.
pub const token_separators = " \t\r";
pub const comment_starts = "#;";

/// The most option tokens one `options` line is read for. A line holds a handful; the bound is
/// what keeps a file the parser did not write from deciding how long it runs.
pub const options_max = 16;

/// The hosts file (`hosts(5)`): the most lines read from one, and the character that starts a
/// comment. What the table holds is bounded in `core`, where the table lives.
pub const hosts_lines_max = 4096;
pub const hosts_comment_start = '#';

/// The `use-vc` option of `resolv.conf(5)`: every query over TCP.
pub const option_use_vc = "use-vc";

/// One second in nanoseconds, which a `timeout:` value is multiplied by. It is spelled out
/// because nothing under `src/` may name `std.time` (CLAUDE.md non-negotiable 4).
pub const ns_per_s = 1_000_000_000;
