# RFCs

Every document cocuyo implements, unmodified from rfc-editor.org. `SHA256SUMS` shows they stay
that way:

```bash
shasum -a 256 -c SHA256SUMS
```

Read these, never a summary and never another implementation's source. Cite the RFC that *states*
a rule, not one that inherits it, and cite it by section on the line that does the checking
(CLAUDE.md non-negotiable 8).

| RFC | Title | What cocuyo reads it for |
| --- | --- | --- |
| 1034 | Domain Names, Concepts and Facilities | §3.6.2, aliases and canonical names: the CNAME chain |
| 1035 | Domain Names, Implementation and Specification | the wire format: §4.1 the message, §4.1.4 compression, §2.3.4 the size limits, §2.3.3 character case, §3.5 IN-ADDR.ARPA, §4.2.1 port 53 |
| 3596 | DNS Extensions to Support IPv6 | §2.2 the AAAA record, §2.5 the IP6.ARPA domain |
| 4343 | DNS Case Insensitivity Clarification | what "the same name" means, which is why `Name.equal` folds case and the question compare does not |
| 5452 | Measures for Making DNS More Resilient against Forged Answers | §4 the spoofing scenarios, §5 birthday attacks, §6 accepting only in-domain records, §9.1 the query matching rules, §9.2 extending the id space with ports and case |
| 6335 | IANA Procedures for Service Name and Transport Protocol Port Number Registry | §6, the Dynamic port range the source-port hint is drawn from |
| 6891 | Extension Mechanisms for DNS (EDNS(0)) | §6.1.2 the OPT wire format, §6.1.3 its TTL field, §6.1.4 the flags, §6.2.2 the fallback, §6.2.3 the requestor's payload size |
| 6895 | DNS IANA Considerations | §2.3, which RCODEs exist |
| 7766 | DNS Transport over TCP, Implementation Requirements | §5 transport selection, §6.2.1 connection reuse, §8 the two-octet length field |
| 8499 | DNS Terminology | the vocabulary this repository uses in prose |
| 791 | Internet Protocol | §3.1, the 32-bit address an A record carries |

Two things cocuyo implements are not RFCs and are cited as what they are:

- **DNS-0x20** is `draft-vixie-dnsext-dns0x20`, which expired without becoming an RFC. The
  practice it describes is recommended in RFC 5452 §9.2 in general terms, so the code cites
  RFC 5452 §9.2 for the mechanism and names the draft only where the draft's own spelling matters.
- **`resolv.conf`** has no RFC. Its options are what the platform manual pages document, so
  `src/config/` cites the behaviour it matches and says plainly that the source is a manual page
  rather than a standard.
