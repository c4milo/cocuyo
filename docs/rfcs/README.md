# RFCs

Every document cocuyo implements, unmodified from rfc-editor.org. `SHA256SUMS` shows they stay
that way:

```bash
shasum -a 256 -c SHA256SUMS
```

Added on 2026-09-22 for the EDNS0 options a response may carry (docs/design.md §19 step 10):
RFC 5001 for the name server identifier, RFC 7830 for padding, RFC 7871 for the client subnet and
RFC 8914 for the extended errors. Each was checked against `rfc-editor.org/rfc/rfcNNNN.json` that
day: none is obsoleted.

Added on 2026-09-23 for DNS over TLS, which the owner decided in that day: RFC 7858 for the
transport, RFC 8310 for the strict profile and where the name a certificate is checked against
comes from, and RFC 8467 for the padding a query carries. Each was checked against
`rfc-editor.org/rfc/rfcNNNN.json` that day: none is obsoleted. RFC 7858 is updated by RFC 8310,
which is here. RFC 8467 is Experimental, and RFC 8310 §9 points to it for the padding policy.
RFC 9846, TLS 1.3, came the same day for what the engine owes the session it carries. It
obsoletes RFC 8446, and RFC 5077 with it, which is the resumption RFC 8310 §9 cites. RFC 9250,
DNS over QUIC, came the same day too, when the owner put DoQ on the roadmap, and RFC 8484, DoH,
when the owner added DoH over HTTP/3. Both were checked the same way: not obsoleted, not updated.
RFC 4648 came the same day for the base64 an SPKI pin is written in, checked the same way.

Added on 2026-09-24: RFC 8767, whose §4 amends the TTL of RFC 1035 §3.2.1 and §4.1.3. A TTL is a
32-bit unsigned number, its high bit read as positive where RFC 2181 §8 read it as zero, and it
should be capped, at seven days by recommendation. Checked against `rfc-editor.org/rfc/rfc8767.json`
that day: not obsoleted, not updated. RFC 2181 itself is not here: nothing cocuyo does rests on
what RFC 8767 left of its §8.

Read these, never a summary and never another implementation's source. Cite the RFC that *states*
a rule, not one that inherits it, and cite it by section on the line that does the checking
(CLAUDE.md non-negotiable 8).

Every document here was checked against `https://www.rfc-editor.org/rfc-index.xml` on 2026-09-21,
and the ones added since against `rfc-editor.org/rfc/rfcNNNN.json` on 2026-09-22: none is
obsoleted but RFC 2535, and each is the current document for what cocuyo reads it for. The
updates worth knowing about, none of which version one implements:

- RFC 1034 and RFC 1035 are Internet Standards updated by a long list of documents. The ones that
  touch what cocuyo does are here: RFC 3596 for AAAA, RFC 4343 for case, RFC 6891 for EDNS0 and
  RFC 7766 for TCP. RFC 3425 removed IQUERY, which cocuyo never implemented.
- RFC 7766 is updated by RFC 8490, DNS Stateful Operations, and RFC 9103, zone transfer over TLS.
  Neither changes the two-octet length field cocuyo uses, and neither is in scope.
- RFC 4343 is updated by RFC 5890, which is IDNA. cocuyo takes names as the caller spells them and
  does no IDN mapping, so a caller sends A-labels or nothing.
- RFC 2308 is updated by the DNSSEC set (RFC 4033 to 4035), RFC 6604 on the RCODE of a chain,
  RFC 8020, which lets a cache infer NXDOMAIN for every name under one, and RFC 9520, which caches
  resolution failures. cocuyo's cache remembers what a server said and nothing it could infer, so
  none of the three applies; a failure that is not a negative answer carries a TTL of zero and is
  not cached.
- RFC 3849 is updated by RFC 9637, which adds a second documentation prefix, `3fff::/20`. The
  fixtures use the first.
- RFC 2535 is obsoleted by the DNSSEC set, RFC 4033 to 4035, and is here for one thing: the wire
  format of the SIG record, §4.1, which RFC 2931 keeps alive for SIG(0) transaction signatures and
  RFC 4034 §3.1 repeats for RRSIG. cocuyo decodes the fields and verifies nothing.
- RFC 2782 is updated by RFC 6335, the port and service name registry, and RFC 8553, which moves
  the `_service._proto` labels into a registry; neither changes the SRV record's fields.
- RFC 6698 is updated by RFC 7218 (acronyms for the fields), RFC 7671 (operational guidance) and
  RFC 8749 (a name change); none changes the TLSA record's fields.
- RFC 7873 is updated by RFC 9018, which fixes the server cookie's format so that every server
  behind one address computes the same one. A client sees only its length.
- RFC 3597 is updated by the DNSSEC set and by RFC 5395, 6195 and 6895, the IANA procedure
  documents; the decompression rule of §4 stands.

| RFC | Title | What cocuyo reads it for |
| --- | --- | --- |
| 1034 | Domain Names, Concepts and Facilities | §3.6.2, aliases and canonical names: the CNAME chain |
| 2308 | Negative Caching of DNS Queries | §2.2 NODATA takes the SOA minimum too, §5 the negative TTL is the smaller of the SOA's TTL and its MINIMUM field |
| 2535 | Domain Name System Security Extensions | §4.1, the SIG record's fields, the one part RFC 2931 keeps in force (obsoleted otherwise, see above) |
| 2782 | A DNS RR for specifying the location of services (DNS SRV) | the SRV record's fields, and its rule that the target is not compressed |
| 2931 | DNS Request and Transaction Signatures (SIG(0)s) | why the SIG record still exists, and where its format is defined |
| 3403 | Dynamic Delegation Discovery System (DDDS) Part Three | §4.1, the NAPTR record's fields |
| 3597 | Handling of Unknown DNS Resource Record (RR) Types | §4, which types a receiver decompresses names in, and the raw rdata a caller gets for every other type |
| 3849 | IPv6 Address Prefix Reserved for Documentation | `2001:db8::/32`, the addresses the fixtures and the tests spell |
| 4648 | The Base16, Base32, and Base64 Data Encodings | §4 the base64 alphabet a pin is written in, §3.5 the zero pad bits a pin's text must have |
| 4291 | IP Version 6 Addressing Architecture | §2.2 the text form `address_text` parses, `::` included |
| 5737 | IPv4 Address Blocks Reserved for Documentation | `192.0.2.0/24`, the addresses the fixtures and the tests spell |
| 6698 | The DNS-Based Authentication of Named Entities (DANE) TLSA | §2.1, the TLSA record's fields |
| 6724 | Default Address Selection for Internet Protocol Version 6 | §6, the destination address ordering the engine may apply to a `getaddrinfo` answer (§19 step 15) |
| 1035 | Domain Names, Implementation and Specification | the wire format: §4.1 the message, §4.1.4 compression, §2.3.4 the size limits, §2.3.3 character case, §3.5 IN-ADDR.ARPA, §4.2.1 port 53 |
| 3596 | DNS Extensions to Support IPv6 | §2.2 the AAAA record, §2.5 the IP6.ARPA domain |
| 4343 | DNS Case Insensitivity Clarification | what "the same name" means, which is why `Name.equal` folds case and the question compare does not |
| 5452 | Measures for Making DNS More Resilient against Forged Answers | §4 the spoofing scenarios, §5 birthday attacks, §6 accepting only in-domain records, §9.1 the query matching rules, §9.2 extending the id space with ports and case |
| 6335 | IANA Procedures for Service Name and Transport Protocol Port Number Registry | §6, the Dynamic port range the source-port hint is drawn from |
| 6891 | Extension Mechanisms for DNS (EDNS(0)) | §6.1.2 the OPT wire format, §6.1.3 its TTL field, §6.1.4 the flags, §6.2.2 the fallback, §6.2.3 the requestor's payload size |
| 6895 | DNS IANA Considerations | §2.3, which RCODEs exist |
| 7553 | The Uniform Resource Identifier (URI) DNS Resource Record | §4, the URI record's fields |
| 7766 | DNS Transport over TCP, Implementation Requirements | §5 transport selection, §6.2.1 connection reuse and pipelining, §6.2.3 idle timeouts, §8 the two-octet length field |
| 7873 | Domain Name System (DNS) Cookies | §4 the COOKIE option, §4.1 the client cookie, §5.1 sending one, §5.3 what a client does with the response, BADCOOKIE included |
| 7858 | Specification for DNS over Transport Layer Security (TLS) | §3.1 port 853 and no cleartext on it, §3.3 the two-octet length on TLS, §3.4 reuse, pipelining and idle close |
| 8310 | Usage Profiles for DNS over TLS and DNS over DTLS | §5 the strict profile and its hard failure, §6.6 authentication under it, §7 the authentication domain name, §8.1 the PKIX check against it, §9 the TLS profile |
| 8467 | Padding Policies for Extension Mechanisms for DNS (EDNS(0)) | §4.1, queries padded to a multiple of 128 octets |
| 8484 | DNS Queries over HTTPS (DoH) | §5.2 HTTP/2 the minimum recommended version, so HTTP/3 carries DoH as it is; the rest is read when DoH's DNS half lands |
| 8482 | Providing Minimal-Sized Responses to DNS Queries That Have QTYPE=ANY | §4, what an ANY question may get back, a synthesized HINFO included |
| 8659 | DNS Certification Authority Authorization (CAA) Resource Record | §4.1, the CAA record's fields |
| 9250 | DNS over Dedicated QUIC Connections | §4.1 the ALPN token `doq` and UDP port 853, §5.1 authentication as DoT's, the strict profile a SHOULD, §5.2 fallback by usage profile; on the roadmap, not yet implemented |
| 9846 | The Transport Layer Security (TLS) Protocol Version 1.3 | §5.3 each record's nonce is its sequence number, so records go out in the order they were sealed; §6.1 a `close_notify` before a party closes its write side |
| 9018 | Interoperable Domain Name System (DNS) Server Cookies | §3, the server cookie's length, which is all a client reads of it |
| 9460 | Service Binding and Parameter Specification via the DNS (SVCB and HTTPS) | §2.2 the record's fields, §7 the parameters, §2.2 the uncompressed target |
| 9499 | DNS Terminology | the vocabulary this repository uses in prose; it obsoletes RFC 8499, which is why 8499 is not here |

Two things cocuyo implements are not RFCs and are cited as what they are:

- **DNS-0x20** is `draft-vixie-dnsext-dns0x20`, which expired without becoming an RFC. The
  practice it describes is recommended in RFC 5452 §9.2 in general terms, so the code cites
  RFC 5452 §9.2 for the mechanism and names the draft only where the draft's own spelling matters.
- **`resolv.conf`** has no RFC. Its options are what the platform manual pages document, so
  `src/config/` cites the behaviour it matches and says plainly that the source is a manual page
  rather than a standard.
