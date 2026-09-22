//! Hand-written messages, byte for byte, for the tests of this module.
//!
//! A codec's fixtures have to be written by hand. One built by the encoder would prove the decoder
//! agrees with the encoder and nothing about the format, so these are typed out against RFC 1035
//! §4.1 and read back by both sides.
//!
//! This file is exempt from the magic-numbers rule, because it is all numbers and the numbers are
//! the format (tools/lint/magic_numbers.zig). It is test-only: nothing outside a `test` block
//! names it, so nothing here is compiled into a library build.
const core = @import("core");

/// The transaction id every fixture here carries.
pub const id = 0x1234;

/// A query header as a server would see it: id 0x1234, recursion desired, one question, and no
/// other section.
pub const query_header = [_]u8{
    0x12, 0x34, // id
    0x01, 0x00, // recursion desired
    0x00, 0x01, // qdcount 1
    0x00, 0x00, // ancount 0
    0x00, 0x00, // nscount 0
    0x00, 0x00, // arcount 0
};

/// A full query for `example.com` A: the header above, then the question section.
pub const query_a = query_header ++ "\x07example\x03com\x00\x00\x01\x00\x01".*;

comptime {
    if (query_header.len != core.constants.header_bytes) @compileError("the header fixture is not a header");
}

// Answers. Each is a full message: a header, the question echoed back, then the records. The
// owner name of every record is the compression pointer 0xc00c, which points at the question's
// name at offset 12, because that is what a real server sends and it exercises the decoder.

/// The flags a plain answer carries: QR, recursion desired, recursion available.
const answer_flags = [_]u8{ 0x81, 0x80 };

/// `example.com` in wire form, then qtype A and qclass IN.
const question_a = "\x07example\x03com\x00\x00\x01\x00\x01".*;

/// A pointer to the question's name at offset 12 (RFC 1035 §4.1.4).
const owner_pointer = [_]u8{ 0xc0, 0x0c };

/// A: 192.0.2.1, TTL 300. The address is from the documentation range of RFC 5737.
const record_a = owner_pointer ++ [_]u8{
    0x00, 0x01, // type A
    0x00, 0x01, // class IN
    0x00, 0x00, 0x01, 0x2c, // TTL 300
    0x00, 0x04, // rdlength
    0xc0, 0x00, 0x02, 0x01, // 192.0.2.1
};

/// A second A record for the same owner: 192.0.2.2, TTL 300.
const record_a_second = owner_pointer ++ [_]u8{
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x02,
};

/// AAAA: 2001:db8::1, TTL 300 (RFC 3596 §2.2, address from RFC 3849).
const record_aaaa = owner_pointer ++ [_]u8{
    0x00, 0x1c, // type AAAA
    0x00, 0x01, // class IN
    0x00, 0x00, 0x01, 0x2c, // TTL 300
    0x00, 0x10, // rdlength
    0x20, 0x01,
    0x0d, 0xb8,
    0,    0,
    0,    0,
    0,    0,
    0,    0,
    0,    0,
    0,    0x01,
};

/// CNAME: `example.com` is an alias for `host.example.net`, TTL 60.
const record_cname = owner_pointer ++ [_]u8{
    0x00, 0x05, // type CNAME
    0x00, 0x01, // class IN
    0x00, 0x00, 0x00, 0x3c, // TTL 60
    0x00, 0x12, // rdlength: the 18 octets of the name that follows
} ++ "\x04host\x07example\x03net\x00".*;

/// The A record for `host.example.net`, whose owner is spelled out rather than pointed at,
/// because the name it needs is the CNAME's rdata and not the question.
///
/// Its TTL is 300 where the CNAME's is 60, on purpose: with both at 60, a collector reporting the
/// largest TTL rather than the smallest would agree with one reporting the smallest, and no test
/// could tell them apart.
const record_cname_target_a = "\x04host\x07example\x03net\x00".* ++ [_]u8{
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x03,
};

/// An A record for a name nobody asked about. A response may carry extra records and an attacker
/// will try to: the owner-name rule of RFC 5452 §6 is what drops this one.
const record_injected_a = "\x08attacker\x07example\x03com\x00".* ++ [_]u8{
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x09,
};

fn answer_header(ancount: u8) [core.constants.header_bytes]u8 {
    return [_]u8{ 0x12, 0x34 } ++ answer_flags ++ [_]u8{
        0x00, 0x01, // qdcount 1
        0x00, ancount,
        0x00, 0x00, // nscount 0
        0x00, 0x00, // arcount 0
    };
}

/// One A record answering the question.
pub const answer_a = answer_header(1) ++ question_a ++ record_a;

/// Two A records for one name, which is what a round-robin name looks like.
pub const answer_a_twice = answer_header(2) ++ question_a ++ record_a ++ record_a_second;

/// One AAAA record. The question still says A, so this is also the fixture for a record of the
/// wrong type.
pub const answer_aaaa = answer_header(1) ++ question_a ++ record_aaaa;

/// A CNAME and the A record its target owns: the chain a server resolves for you.
pub const answer_cname_then_a = answer_header(2) ++ question_a ++ record_cname ++
    record_cname_target_a;

/// A CNAME with no record for its target: the chain the state machine has to follow itself.
pub const answer_cname_only = answer_header(1) ++ question_a ++ record_cname;

/// An A record for a name nobody asked about, beside the one that was asked about.
pub const answer_injected = answer_header(2) ++ question_a ++ record_injected_a ++ record_a;

/// Five answers promised, one delivered: the count field lying about what follows.
pub const answer_lying_count = answer_header(5) ++ question_a ++ record_a;

/// An rdlength of 400 on a record that holds four octets: the length field reaching past the end.
pub const answer_long_rdlength = answer_header(1) ++ question_a ++ owner_pointer ++ [_]u8{
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c,
    0x01, 0x90, // rdlength 400
    0xc0, 0x00,
    0x02, 0x01,
};

/// An A record whose rdlength is three octets rather than four.
pub const answer_short_address = answer_header(1) ++ question_a ++ owner_pointer ++ [_]u8{
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c,
    0x00, 0x03, // rdlength 3
    0xc0, 0x00,
    0x02,
};

/// NXDOMAIN: the name does not exist (RFC 1035 §4.1.1, rcode 3).
pub const answer_name_error = [_]u8{ 0x12, 0x34, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } ++
    question_a;

/// NOERROR with no answer at all: NODATA, the name exists without a record of this type.
pub const answer_no_data = answer_header(0) ++ question_a;

/// TC set: the answer did not fit, so the lookup goes to TCP (RFC 1035 §4.1.1).
pub const answer_truncated = [_]u8{ 0x12, 0x34, 0x83, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } ++
    question_a;

/// SERVFAIL: the server failed, so the lookup moves to the next server.
pub const answer_server_failure = [_]u8{ 0x12, 0x34, 0x81, 0x82, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } ++
    question_a;

/// FORMERR, which a server too old for EDNS0 answers a query carrying OPT (RFC 6891 §6.2.2).
pub const answer_format_error = [_]u8{ 0x12, 0x34, 0x81, 0x81, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } ++
    question_a;

/// Where the answer section starts in every fixture above: the header and one question.
pub const answer_offset = core.constants.header_bytes + question_a.len;

/// A CNAME whose rdlength counts one octet more than the name it holds. The name decodes fine and
/// stops one octet short of the rdata's end, which leaves an octet a reader would have to guess
/// at: RFC 1035 §3.3 gives the rdata one name and nothing else.
pub const answer_cname_padded_rdata = answer_header(1) ++ question_a ++ owner_pointer ++ [_]u8{
    0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c,
    0x00, 0x13, // rdlength 19, for an 18-octet name
} ++ "\x04host\x07example\x03net\x00".* ++ [_]u8{0x00};

/// A CNAME whose rdlength counts one octet fewer than the name it holds, so the name runs past
/// the rdata and into whatever follows.
pub const answer_cname_short_rdata = answer_header(1) ++ question_a ++ owner_pointer ++ [_]u8{
    0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c,
    0x00, 0x11, // rdlength 17, for an 18-octet name
} ++ "\x04host\x07example\x03net\x00".*;

/// One more A record than a lookup has room for: `addresses_max` is 16, so seventeen records for
/// one name is what sets `truncated`.
pub const answer_a_seventeen = answer_header(core.constants.addresses_max + 1) ++ question_a ++
    (record_a ** (core.constants.addresses_max + 1));

/// An A record whose rdlength counts one octet more than the message holds. The fixture for a
/// bound that is loose by exactly one, which an rdlength of 400 cannot catch.
pub const answer_rdlength_one_past = answer_header(1) ++ question_a ++ owner_pointer ++ [_]u8{
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c,
    0x00, 0x05, // rdlength 5, with four octets to the end of the message
    0xc0, 0x00,
    0x02, 0x01,
};
