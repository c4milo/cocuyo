//! wire: the codec. Byte slices in, values out, no state beyond an offset. This is the half of
//! cocuyo that faces an attacker, so it is the half with the fuzz target and most of the mutations
//! (docs/design.md §8 and §13).
//!
//! Every file here is named for what it reads or writes, without the module's own name repeated:
//! the directory already says `wire`.
pub const constants = @import("constants.zig");
pub const integer = @import("integer.zig");
pub const header = @import("header.zig");
pub const name = @import("name.zig");
pub const question = @import("question.zig");
pub const edns = @import("edns.zig");
pub const query = @import("query.zig");
pub const record = @import("record.zig");
pub const record_copy = @import("record_copy.zig");
pub const response = @import("response.zig");
pub const rdata = @import("rdata/rdata.zig");
pub const fuzz = @import("fuzz.zig");
/// The hand-written corpus. Tests read it, and so does `bench/`, because a benchmark over a
/// message the encoder built would measure the encoder's idea of a message rather than a
/// server's.
pub const fixtures = @import("fixtures.zig");

pub const Header = header.Header;
pub const Rcode = constants.Rcode;
pub const message_len = header.message_len;
pub const Query = query.Query;
pub const Record = record.Record;
pub const Answers = response.Answers;
pub const Records = response.Records;
pub const Kept = response.Kept;
pub const Outcome = response.Outcome;

test {
    _ = constants;
    _ = integer;
    _ = header;
    _ = name;
    _ = question;
    _ = edns;
    _ = query;
    _ = record;
    _ = record_copy;
    _ = response;
    _ = rdata;
    _ = fuzz;
    _ = @import("fuzz_generate.zig");
    _ = @import("fuzz_check.zig");
}
