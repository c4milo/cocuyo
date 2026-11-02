//! The memory one message's validation writes and reads again, which the key store owns
//! (docs/design.md §17 question 108). ReleaseSafe writes 0xAA over a local declared `undefined`,
//! and on Linux a byte at a time. So the message reader, the signed data's buffers and the lists
//! of verified records live here, set once. Each message writes the counts and the items it reads,
//! and never the whole of it, as §16 decision 34 does for the answers.
const limits = @import("limits.zig");
const canonical = @import("dnssec_canonical.zig");
const Message = @import("dnssec_message.zig").Message;
const denial = @import("dnssec_validate_denial.zig");
const store_keys = @import("dnssec_store_keys.zig");

/// One validation at a time reads it: a message, then the DS or DNSKEY set a walk keeps from it.
pub const Scratch = struct {
    message: Message = undefined,
    buffers: canonical.Buffers = undefined,
    nsecs: denial.Nsecs = .{},
    nsec3s: denial.Nsec3s = .{},
    bases: store_keys.Bases = .{},
    /// The DNSKEY records of a set that match a basis, which its own signature is checked under.
    matched: [limits.zone_keys_max][]const u8 = undefined,
    /// The records of a DS or DNSKEY set the store keeps.
    kept: [@max(limits.zone_keys_max, limits.ds_records_max)][]const u8 = undefined,
};
