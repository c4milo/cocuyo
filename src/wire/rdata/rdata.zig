//! Typed views over a record's rdata, one per type c-ares parses (docs/design.md §19 step 9).
//!
//! Every view reads a self-contained rdata: names inside it are written out in full, which is how
//! the collector stores them, so a view holds slices into what it was given and copies nothing. A
//! caller with rdata straight off a message, where a name may be a compression pointer, decodes
//! the name through `wire.name.decode` with the message in hand.
pub const name = @import("rdata_name.zig");
pub const string = @import("rdata_string.zig");
pub const layout = @import("rdata_layout.zig");
pub const fixtures = @import("fixtures.zig");

pub const Txt = string.Txt;
pub const Hinfo = string.Hinfo;
pub const Mx = @import("rdata_mx.zig").Mx;
pub const Srv = @import("rdata_srv.zig").Srv;
pub const Soa = @import("rdata_soa.zig").Soa;
pub const Naptr = @import("rdata_naptr.zig").Naptr;
pub const Sig = @import("rdata_sig.zig").Sig;
pub const Svcb = @import("rdata_svcb.zig").Svcb;
pub const SvcbParam = @import("rdata_svcb.zig").Param;
pub const Tlsa = @import("rdata_tlsa.zig").Tlsa;
pub const Uri = @import("rdata_uri.zig").Uri;
pub const Caa = @import("rdata_caa.zig").Caa;
pub const Option = @import("rdata_opt.zig").Option;
pub const Options = @import("rdata_opt.zig").Options;

test {
    _ = name;
    _ = string;
    _ = layout;
    _ = @import("rdata_mx.zig");
    _ = @import("rdata_srv.zig");
    _ = @import("rdata_soa.zig");
    _ = @import("rdata_naptr.zig");
    _ = @import("rdata_sig.zig");
    _ = @import("rdata_svcb.zig");
    _ = @import("rdata_tlsa.zig");
    _ = @import("rdata_uri.zig");
    _ = @import("rdata_caa.zig");
    _ = @import("rdata_opt.zig");
}
