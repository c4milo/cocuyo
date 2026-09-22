//! The addresses the hosts table's tests build their table from. Exempt from the magic-numbers
//! rule by name, like every corpus; test-only.
const address = @import("address.zig");
const Address = address.Address;

/// Two entries for `localhost`, one per family, as a typical file has them.
pub const localhost_v4 = Address.from_v4(.{ 127, 0, 0, 1 });
pub const localhost_v6 = Address.from_v6(.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });

/// Two entries for `db.example`, the IPv4 one aliased `db`, and an address no entry holds.
pub const db_v4 = Address.from_v4(.{ 192, 0, 2, 10 });
pub const db_v6 = Address.from_v6(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 });
pub const unlisted_v4 = Address.from_v4(.{ 192, 0, 2, 99 });

/// The worked examples of RFC 6724 §10.2 that the ordering's tests replay: nine.
pub const ordering_examples = 9;
