# DigWhy

Every line of `dig` output, decoded the way an operator reads it: the status that
matters, the flags that say whether the answer is authoritative or cached, the
difference between NXDOMAIN and NODATA, CNAME chains drawn out, and what a null MX
(`0 .`) actually means (RFC 7505: "this domain accepts no email").

## Files

- `index.html` - landing page
- `app.html` - the decoder (paste dig output, or load one of the built-in captures)
- `engine.js` - dig-output parser + explanations (UMD: browser global `DigWhy`, CommonJS for tests)
- `test/corpus/*.txt` - 11 live-captured dig outputs (dig 9.18, @8.8.8.8, Oct 2026):
  a-basic, cname-chain, nxdomain, nodata-mx (example.com's null MX), mx, ptr, dnssec, txt, ns, soa, caa
- `test/oracle.py` - independent Python parser of the same format
- `test/run_tests.js` - cross-checks engine.js against the oracle on every corpus file
  (version, opcode, status, id, flags, counts, EDNS, all sections, query time, server,
  message size) plus explanation sanity checks: 160 checks, 0 disagreements

Run the tests:

    node test/run_tests.js

Everything is client-side JavaScript; nothing leaves the browser.

## Scope

Covers the standard long-format dig reply. Multi-query output, `+short`, and
non-QUERY opcodes are out of scope. TTL annotations assume `aa`-flag semantics;
without `aa` the app notes TTLs are cached and counting down.
