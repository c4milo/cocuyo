//! The limits of DoH that `cocuyo_doh` reads (docs/design.md §24, New limits).

/// A DoH request's slot: the HEADERS frame of its GET (docs/design.md §24, New limits). colibri's
/// bound on the frame is 317 octets beside `:authority` and `:path`, an authority takes 259 at
/// most (a 253-octet name and a port), and 960 are left for the path, whose `dns` value takes 512.
/// The bound was read off colibri's HTTP/3; HTTP/2's HEADERS frame is no longer, since its frame
/// header is nine octets and HPACK's literals are no longer than QPACK's.
pub const doh_request_bytes_max = 1536;

/// A DoH connection's answer buffers when the consumer names none: one for each response in
/// flight, each holding an answer at its longest (docs/design.md §24, New limits). Chosen,
/// not measured.
pub const answers_default = 4;
