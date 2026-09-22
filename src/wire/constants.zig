//! Every number the wire format fixes: the offsets of the header fields, the flag bits, the
//! response codes, and the two bits that tell a label from a compression pointer. Each is named
//! here and never written at the use site (CLAUDE.md non-negotiable 5), with the RFC section that
//! fixes it.
const std = @import("std");

/// Two octets, the width of every count and every integer in the header (RFC 1035 §4.1.1).
pub const u16_bytes = @sizeOf(u16);

/// Four octets, the width of a TTL and of the OPT record's flag field (RFC 1035 §4.1.3).
pub const u32_bytes = @sizeOf(u32);

/// The bits in an octet, so a shift by a whole octet names what it shifts by.
pub const octet_bits = @bitSizeOf(u8);

// The header, RFC 1035 §4.1.1: six two-octet fields in this order.
pub const header_id_offset = 0;
pub const header_flags_offset = 2;
pub const header_qdcount_offset = 4;
pub const header_ancount_offset = 6;
pub const header_nscount_offset = 8;
pub const header_arcount_offset = 10;

/// QR: set in a response (RFC 1035 §4.1.1).
pub const flag_response = 0x8000;

/// OPCODE, four bits (RFC 1035 §4.1.1).
pub const opcode_mask = 0x7800;
pub const opcode_shift = 11;

/// The only opcode cocuyo sends or accepts: a standard query (RFC 1035 §4.1.1).
pub const opcode_query = 0;

/// AA: the answer is authoritative.
pub const flag_authoritative = 0x0400;

/// TC: the message was truncated, which is what sends a lookup to TCP (RFC 1035 §4.1.1).
pub const flag_truncated = 0x0200;

/// RD: recursion desired, which every query cocuyo builds sets, because a stub asks a recursive
/// server to do the walking (RFC 1035 §4.1.1).
pub const flag_recursion_desired = 0x0100;

/// RA: recursion available.
pub const flag_recursion_available = 0x0080;

/// RCODE, the low four bits (RFC 1035 §4.1.1).
pub const rcode_mask = 0x000f;

/// The response codes cocuyo reads. The rest are reported as a malformed message rather than
/// guessed at (RFC 1035 §4.1.1, RFC 6895 §2.3).
pub const Rcode = enum(u8) {
    no_error = 0,
    format_error = 1,
    server_failure = 2,
    name_error = 3,
    not_implemented = 4,
    refused = 5,

    /// The code `bits` names, or null when cocuyo does not know it. A code cocuyo does not know is
    /// a malformed message to its caller rather than a code to guess the meaning of.
    pub fn from_bits(bits: u8) ?Rcode {
        inline for (@typeInfo(Rcode).@"enum".fields) |field| {
            if (field.value == bits) return @enumFromInt(field.value);
        }
        return null;
    }
};

/// The two high bits of a length octet say what follows: `00` a label, `11` a pointer. `01` and
/// `10` are reserved and make a message malformed (RFC 1035 §4.1.4).
pub const label_kind_mask = 0xc0;
pub const label_kind_label = 0x00;
pub const label_kind_pointer = 0xc0;

/// The low fourteen bits of a pointer are the offset it points at (RFC 1035 §4.1.4).
pub const pointer_offset_mask = 0x3fff;

/// A pointer is two octets (RFC 1035 §4.1.4).
pub const pointer_bytes = 2;

comptime {
    const core = @import("core");
    // The header's fields must tile the header exactly, or a parser would read past one of them.
    if (header_arcount_offset + u16_bytes != core.constants.header_bytes) {
        @compileError("the header fields do not tile the header");
    }
    if (label_kind_label | label_kind_pointer != label_kind_mask) {
        @compileError("the label kinds do not cover the kind bits");
    }
    if (pointer_offset_mask | label_kind_mask << octet_bits != 0xffff) {
        @compileError("a pointer's kind bits and offset bits do not cover its two octets");
    }
}
