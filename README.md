<div align="center">
  <h1>grip</h1>
  <h4>tls handshake inspector + fingerprinter</h4>
  <br>
  <a href="https://github.com/yourpwnguy/grip">
    <img src="https://img.shields.io/badge/rust-1.88+-ff9e64?labelColor=1C2325&style=for-the-badge">
  </a>
  <a href="https://github.com/yourpwnguy/grip/issues">
    <img src="https://img.shields.io/github/issues/yourpwnguy/grip?color=ff9e64&labelColor=1C2325&style=for-the-badge">
  </a>
  <a href="https://github.com/yourpwnguy/grip/stargazers">
    <img src="https://img.shields.io/github/stars/yourpwnguy/grip?color=fab387&labelColor=1C2325&style=for-the-badge">
  </a>
  <a href="./LICENSE">
    <img src="https://img.shields.io/github/license/yourpwnguy/grip?color=FCA2AA&labelColor=1C2325&style=for-the-badge">
  </a>
  <br>
  <br>
</div>

---

## why does this exist?

because the existing workflow for TLS fingerprinting is annoying.

say you want to know what TLS fingerprint a host exposes, or you want to identify what clients are talking on your network. here is what you do today:

you could run `openssl s_client -connect example.com:443` and stare at the output. it shows you the certificate and the negotiated cipher, but it does not give you a JA3 or JA4 string. it does not tell you what fingerprint a Chrome client would produce versus curl.

you could use Wireshark or `tshark -Y tls.handshake.type==1` to pull ClientHellos from a capture. but then you need to parse the bytes yourself. Wireshark shows you the fields, but you still have to extract the cipher suites, filter GREASE, sort them, hash them to get a JA4. there is the [FoxIO ja4](https://github.com/FoxIO-LLC/ja4) Python tool that computes fingerprints from pcap, but it gives you a string with no context about what the server negotiated or what the certificate looks like.

you could use `testssl.sh` or `sslscan` to enumerate a server, but those are server scanners. they tell you what the server supports, not what a specific client fingerprint looks like.

none of these give you the full picture in one place: the handshake as it happened on the wire, the negotiated parameters, the certificate chain, and the JA3/JA4/JA4S fingerprints with client identification. if you want all of that, you end up piping three tools together and writing a parser.

**grip does it in one command.** you point it at a hostname and it builds a real TLS ClientHello, sends it, parses the ServerHello byte by byte, grabs the certificate chain, and fingerprints everything. or you point it at a pcap file and it reassembles TCP streams, extracts every ClientHello, groups them by source IP, and ranks them. two modes, one binary.

the name is literal. you grip the handshake and pull it apart.

---

## what it does

grip has two modes that do fundamentally different things:

### live mode

you give it a hostname, it connects and does a real TLS handshake. not through rustls, not through openssl. it builds the ClientHello byte by byte, sends it over a raw TCP socket, reads the ServerHello response, and parses every field itself. then it computes JA3/JA4/JA4S fingerprints and checks them against a built-in database of known clients.

the one exception: for TLS 1.3, the Certificate message is encrypted under the handshake keys. grip cannot read it from the raw bytes. so it opens a second connection via rustls with webpki-roots to fetch the certificate chain. this is a deliberate fallback, not a shortcut. the handshake bytes you see are the real bytes the client sent. the certificate comes from a verified secondary connection. the fallback is capped at 5 seconds and respects `--no-verify`.

### pcap mode

you give it a pcap file. grip does proper TCP stream reassembly, not just packet scanning. a TLS ClientHello can span multiple TCP segments, so you cannot just look for `0x16 0x03` in each packet. grip groups packets by four tuple (src_ip, src_port, dst_ip, dst_port), reassembles them in sequence number order handling overlaps and gaps, then walks the reassembled byte stream looking for TLS records. if you skip reassembly you will miss fragmented ClientHellos and produce wrong fingerprints.

after extraction it groups handshakes by source IP, deduplicates, and shows a ranked table with fingerprint, client identification, and hit count.

---

## installation

### from source

```bash
git clone https://github.com/yourpwnguy/grip.git
cd grip/
cargo install --path .
```

### using cargo

when it is on crates.io:

```bash
cargo install grip
```

### pre-built binaries

check the [releases page](https://github.com/yourpwnguy/grip/releases) for pre-built binaries for linux, macos, and windows. each release is around 4 MB, stripped and LTO optimized.

---

## usage

### basic live scan

```bash
grip example.com
```

connects to example.com:443, does the handshake, parses everything, prints a report. takes about 0.2 seconds.

### with custom port

```bash
grip example.com:8443
```

### json output

for scripting, piping to jq, or feeding into a siem:

```bash
grip --format json example.com
```

### show specific fingerprints

by default grip shows all three. use flags to filter:

```bash
grip --ja4 example.com
grip --ja3 example.com
grip --ja4s example.com
grip --all-fp example.com
```

### quiet mode

just the fingerprint string, nothing else. useful for piping into other tools:

```bash
grip --quiet example.com
```

### pcap analysis

```bash
grip --pcap capture.pcap
```

shows a ranked table of every unique client fingerprint found in the capture.

### with certificate chain

for TLS 1.3 where the cert is encrypted in the raw capture:

```bash
grip --cert-chain example.com
```

### skip certificate verification

for inspecting certs that fail verification:

```bash
grip --no-verify expired.badssl.com
```

### raw hex dump

see the actual bytes of the ClientHello and ServerHello:

```bash
grip --raw example.com
```

### verbose mode

extra telemetry: handshake timing, bytes sent and received, resolved IPs, GREASE count:

```bash
grip --verbose example.com
```

### identify known clients

match fingerprints against the built-in database (FoxIO JA4 mapping plus grip's own probe):

```bash
grip --lookup example.com
grip --pcap capture.pcap --lookup
```

in live mode the client is the probe itself, so this reports `grip`. in pcap mode it names observed clients (Chromium, Python, Go, known malware) or `unclassified` on a miss. without the flag the row is hidden in live mode and shows `—` in pcap tables.

### filter pcap by IP

```bash
grip --pcap capture.pcap --filter 192.168.1.5
```

### unique client listing

```bash
grip --pcap capture.pcap --unique
```

### sort pcap results

```bash
grip --pcap capture.pcap --sort-by count
grip --pcap capture.pcap --sort-by ip
grip --pcap capture.pcap --sort-by fingerprint
```

---

## example output

### live mode

```
$ grip example.com
  grip  ·  live handshake  example.com:443 ──────────────────────────────────────────────────────

  negotiated ───────────────────────────────────────────────────────────────────────────────────────
    tls version      TLS 1.3
    cipher suite     TLS_AES_128_GCM_SHA256  0x1301
    key exchange     X25519
    sni              example.com  hostname
    offered          TLS 1.3 · TLS 1.2

  certificate ──────────────────────────────────────────────────────────────────────────────────────
    subject          CN=example.com
    issuer           C=US, O=SSL Corporation, CN=Cloudflare TLS Issuing ECC CA 3
    sans             example.com  *.example.com
    expires          2026-10-27   (34 days)
    sha-256          6153a96fd1a6ab7f4d438fc34932484299d0729d9140b3a126bb2f9c07b02200
    ct logs          1 sct embedded

  fingerprints ─────────────────────────────────────────────────────────────────────────────────────
    ja3              d879bc8777862a634eecc81a0d21e701
    ja4              t13d1305h2_bda08f0cbb17_c83d862dc2aa
    ja4s             t13d020000_1301_1acd28cc39f1
```

### live mode with verbose and cert chain

```
$ grip --verbose --cert-chain --all-fp example.com
resolve    querying dns for example.com, sni example.com
receive    TLS 1.3, 95 B in, 65 ms
fingerprint ja4 t13d1305h2_bda08f0cbb17_c83d862dc2aa
certificate 4 in chain, leaf CN=example.com
  grip  ·  live handshake  example.com:443 ──────────────────────────────────────────────────────

  negotiated ───────────────────────────────────────────────────────────────────────────────────────
    tls version      TLS 1.3
    cipher suite     TLS_AES_128_GCM_SHA256  0x1301
    key exchange     X25519
    sni              example.com  hostname
    offered          TLS 1.3 · TLS 1.2

  certificate ──────────────────────────────────────────────────────────────────────────────────────
    subject          CN=example.com
    issuer           C=US, O=SSL Corporation, CN=Cloudflare TLS Issuing ECC CA 3
    sans             example.com  *.example.com
    expires          2026-10-27   (34 days)
    sha-256          6153a96fd1a6ab7f4d438fc34932484299d0729d9140b3a126bb2f9c07b02200
    ct logs          1 sct embedded + 3 intermediates
    chain 1          C=US, O=SSL Corporation, CN=Cloudflare TLS Issuing ECC CA 3
                     └─ f15f29abef73aa4dd9ab754baeae3685bdd3874b46b525071177628685718026
    chain 2          C=US, O=SSL Corporation, CN=SSL.com TLS Transit ECC CA R2
                     └─ 5d1bc399274e649e1c72697de91a54ad725088c5221cb61e17ee9c290bc42a92
    chain 3          C=US, O=SSL Corporation, CN=SSL.com TLS ECC Root CA 2022
                     └─ ba06d3d3e348fce7478cc84b422d0e638e9e221ef1a0b53adc14cc70e04b8ab8

  fingerprints ─────────────────────────────────────────────────────────────────────────────────────
    ja3              d879bc8777862a634eecc81a0d21e701
    ja4              t13d1305h2_bda08f0cbb17_c83d862dc2aa
    ja4s             t13d020000_1301_1acd28cc39f1

  telemetry ────────────────────────────────────────────────────────────────────────────────────────
    handshake        65 ms
    bytes            205 out  95 in
    grease           0 filtered
    resolved         [2606:4700:90c5:72db:f2ef:bac:ef6b:ff98]:443 104.20.23.154:443
                     172.66.147.243:443

  ◆  65 ms
```

### json output

```json
{
  "target": "example.com:443",
  "negotiated": {
    "tls_version": "TLS 1.3",
    "offered_versions": [
      "TLS 1.3",
      "TLS 1.2"
    ],
    "cipher_suite": "TLS_AES_128_GCM_SHA256",
    "cipher_hex": "0x1301",
    "key_exchange": "X25519",
    "alpn": null,
    "sni": "example.com",
    "sni_is_ip": false
  },
  "certificate": {
    "subject": "CN=example.com",
    "issuer": "C=US, O=SSL Corporation, CN=Cloudflare TLS Issuing ECC CA 3",
    "sans": [
      "example.com",
      "*.example.com"
    ],
    "expires": "2026-10-27   (34 days)",
    "sha256": "61:53:a9:6f:d1:a6:ab:7f:4d:43:8f:c3:49:32:48:42:99:d0:72:9d:91:40:b3:a1:26:bb:2f:9c:07:b0:22:00",
    "ct_logs": "1 sct embedded"
  },
  "cert_chain": null,
  "fingerprints": {
    "ja3": "d879bc8777862a634eecc81a0d21e701",
    "ja4": "t13d1305h2_bda08f0cbb17_c83d862dc2aa",
    "ja4s": "t13d020000_1301_1acd28cc39f1",
    "lookup": null
  },
  "raw": null,
  "verbose_info": null
}
```

---

## how it works

### the bytes matter

when you call a TLS library's connect function and ask for the certificate, the library builds its own ClientHello. cipher suites, extension order, GREASE values, all of that is the library's choice. if you are trying to understand what is actually on the wire, you need the real bytes.

grip reads raw bytes off the TCP socket and parses every field itself. the TLS record layer, the handshake header, the version field (which lies, more on that below), the random, the session ID, the cipher suites, every extension. the raw bytes are the source of truth.

### the version field lies to you

TLS 1.3 ClientHellos write `0x0303` (TLS 1.2) in the legacy version field. the actual version is hidden inside the `supported_versions` extension (`0x002b`). if you read the top level version field to determine TLS version, you will fingerprint every TLS 1.3 client as TLS 1.2. this trips everyone up the first time they build a TLS parser. grip handles this correctly by checking `supported_versions` when present.

### GREASE values

Defined in RFC 8701. browsers insert fake reserved values (`0x0a0a`, `0x1a1a`, `0x2a2a`, and so on up to `0xfafa`) into cipher suites and extensions to test that servers do not choke on unknown values. JA4 strips these before computing fingerprints. the order of operations matters: you sort cipher suites numerically after removing GREASE. sort first, then remove, and you get the wrong fingerprint for some clients. grip filters GREASE before sorting.

### JA3 computation

The older format, originally by Salesforce. it is an MD5 hash of a comma delimited string:

```
{TLSVersion},{CipherSuites},{Extensions},{EllipticCurves},{PointFormats}
```

output: `cd08e31494f9531f560d64c695473da9`

simple, widely supported, but has known collision issues and does not encode enough information for modern differentiation.

### JA4 computation

The newer format by FoxIO. three parts separated by underscores:

```
t13d1305h2_bda08f0cbb17_c83d862dc2aa
│││││││└── first two chars of first ALPN value
│││││└──── number of extensions (2 digits, excluding SNI and ALPN)
│││└────── number of cipher suites (2 digits, excluding GREASE)
││└─────── d = SNI present (domain), i = IP address
│└──────── negotiated TLS version (13 = 1.3, 12 = 1.2)
└───────── protocol (t = TLS, q = QUIC, d = DTLS)
```

part 2 is SHA256 truncated to 12 hex chars of cipher suites sorted numerically, comma separated, GREASE removed.
part 3 is SHA256 truncated to 12 hex chars of extensions sorted numerically plus signature algorithms, comma separated.

JA4 is human readable by design. you can look at `t13d1305h2` and know it is TLS 1.3, domain facing, 13 extensions, 5 cipher suites, ALPN starts with "h2".

References: [FoxIO JA4 spec](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md) and [JA3 spec](https://github.com/salesforce/ja3).

### JA4S computation

Same idea but from the ServerHello. what cipher suite did the server pick, what extensions did it send back. different server software produces different JA4S values. a Cloudflare edge server has a different JA4S than nginx, which differs from Apache. grip computes JA4S from the raw ServerHello bytes.

### certificate handling

For TLS 1.2, the Certificate message is plaintext. grip reads it directly from the raw bytes. For TLS 1.3, it is encrypted under the handshake keys. grip cannot read it from the capture, so it falls back to a rustls connection with webpki-roots, capped at a 5 second budget. the raw handshake bytes you see are still the real bytes. the certificate comes from a verified secondary connection.

### pcap TCP reassembly

This is the hard part of pcap mode. the process:

1. parse the pcap global header (magic number, version, snaplen, link type)
2. parse each packet record (timestamp, captured length, original length, data)
3. strip link layer headers (Ethernet and others) to get IP packets
4. parse IP and TCP headers to extract the four tuple (src_ip, src_port, dst_ip, dst_port)
5. group packets by four tuple, which equals one TCP stream
6. reassemble segments in sequence number order, handling overlaps and gaps
7. walk the reassembled byte stream looking for TLS records (`0x16 0x03`)
8. parse each TLS record to extract the ClientHello

if you skip step 6 and just scan raw packets, you will miss fragmented ClientHellos and get wrong fingerprints.

### the live handshake

For live mode, grip builds a ClientHello using `ClientHelloBuilder`. the builder handles GREASE injection, extension ordering, SNI, ALPN, supported versions, key share, and signature algorithms. the resulting bytes are sent over a raw TCP connection. the ServerHello response is read in a tight loop with a 400ms poll timeout so grip stops as soon as it has enough data. for TLS 1.3, that is right after the ServerHello, not after the full handshake.

---

## project structure

```
src/
  cli/                    command line parsing, validation, live/pcap dispatch
    args.rs               clap derive structs
    validate.rs           input validation (timeout, port, SNI, flag combos)
    run/
      mod.rs              entry point, mode dispatch
      live.rs             live probe orchestration
      pcap.rs             pcap analysis orchestration
      helpers.rs          report building, width, palette
  tls/                    raw TLS parsing (hand-rolled, no TLS library)
    record.rs             TLS record layer (content type, version, length, payload)
    version.rs            TLS version detection (the lying version field)
    cipher.rs             cipher suite ID to IANA name mapping
    grease.rs             GREASE detection and filtering
    client_hello.rs       ClientHello parsing (random, session ID, ciphers, extensions)
    server_hello.rs       ServerHello parsing (selected cipher, extensions, version)
    certificate.rs        certificate chain parsing (X.509, SANs, SHA-256, CT logs)
    builder.rs            ClientHello construction (manual byte building)
    extensions/           extension parsers
      mod.rs              Extension enum, parse_extensions dispatcher
      sni.rs              SNI (0x0000) parsing
      alpn.rs             ALPN (0x0010) parsing
      versions.rs         Supported Versions (0x002b) parsing
      key_share.rs        Key Share (0x0033) parsing
      common.rs           shared helpers (u16 lists, u8 lists)
  fp/                     fingerprint computation
    ja3.rs                JA3 MD5 hash
    ja4.rs                JA4 structured hash (three parts)
    ja4s.rs               JA4S server fingerprint
    lookup.rs             client identification against embedded JA4 DB
  pcap/                   pcap file handling
    reader.rs             pcap global header + record parsing
    tcp.rs                TCP packet parsing (IP, TCP headers, four tuple)
    reassembly.rs         TCP stream reassembly (sequence number ordering)
    extractor.rs          ClientHello extraction from reassembled streams
  net/                    live network probe
    connect/
      mod.rs              probe orchestration (resolve, connect, drive, parse)
      dial.rs             DNS resolution + TCP connection with timeout
      raw.rs              TLS handshake driver (send ClientHello, read response)
      cert_fetch.rs       rustls fallback for TLS 1.3 certificate retrieval
  output/                 rendering and output formats
    model.rs              DTOs (LiveReport, PcapReport, Fingerprints, etc.)
    human/                human-readable terminal output
      mod.rs              dispatcher
      live.rs             live report rendering
      pcap.rs             pcap table rendering
      raw.rs              raw hex dump rendering
      quiet.rs            single-value output for piping
    json.rs               JSON serialization
    hex.rs                hexdump utility
    writer.rs             output writer abstraction
  ui/                     design system
    theme.rs              truecolor palette, gradients, glyphs
    mascot.rs             Nib, the grip mark glyph
    panel.rs              section headers, key/value rows, wrapping
  db/                     built-in fingerprint database
    known.rs              PHF map of known JA4 fingerprints (generated at build time)
  error.rs                error types (thiserror)
assets/
  fingerprints.csv      known JA4/JA3 fingerprints (FoxIO mapping snapshot + grip self)
scripts/
  import_ja4_mapping.py refresh fingerprints.csv from upstream (`just update-db`)
```

---

## how fast is it?

- **live mode**: around 0.2 seconds end to end (DNS resolve plus TCP connect plus TLS handshake plus parse plus cert fallback)
- **release binary**: around 3.8 MB stripped with LTO and codegen-units=1
- **pcap mode**: reassembles TCP streams in memory, processes thousands of handshakes per second
- **no async runtime**: blocking I/O is fine for a tool that makes one connection and exits

---

## limitations

**TLS only.** grip parses TLS handshakes. it does not do HTTP parsing, certificate transparency monitoring, or traffic classification beyond the TLS layer.

**no deep packet inspection.** grip sees the handshake and stops. it does not follow the encrypted stream or decrypt application data.

**cert fallback requires network.** for TLS 1.3 live mode, the certificate is encrypted in the raw capture. grip falls back to a rustls connection to fetch it. if you are offline or behind a firewall that blocks the connection, you will not get the cert.

**JA4 client DB is static.** the built-in fingerprint database is compiled at build time from `assets/fingerprints.csv`. refresh it from the upstream FoxIO mapping with `just update-db` (runs `scripts/import_ja4_mapping.py`), then rebuild.

**no QUIC or HTTP3.** JA4 supports QUIC fingerprinting but grip does not parse QUIC packets yet.

**no live capture.** pcap mode reads files. live packet capture via libpcap binding is on the roadmap.

---

## roadmap

### probably soon

- `--diff` mode: compare two pcaps and show new or changed fingerprints
- shell completions for bash, zsh, fish
- `--summary` flag for one liner output
- JA4S server fingerprint lookup against known server DB

### maybe eventually

- QUIC and HTTP3 fingerprinting (JA4Q)
- live packet capture mode (libpcap binding)
- PCAPNG support (currently only classic pcap)
- custom ClientHello crafting (send specific cipher suites to probe server behavior)
- IPv6 pcap reassembly

### if there is demand

- web UI for team dashboards
- siem integration (CEF, syslog)
- plugin system for custom fingerprint databases
- continuous monitoring mode (watch a network interface, fingerprint every new connection)

---

## development

### prerequisites

- rust 1.88 or later (edition 2024)
- just (command runner, optional but recommended)

### common commands

```bash
just check          # run tests plus clippy plus fmt check
just test           # run all tests
just clippy         # run clippy with strict warnings
just fmt            # auto-format code
just build          # debug build
just release        # optimized release build
just bench          # run benchmarks
just stats          # show project statistics
```

### architecture

see [docs/architecture.md](docs/architecture.md) for the full spec.

the key design decisions:

- **strictly one way dependency direction**: `cli -> net/pcap -> output -> fp -> tls -> error`. no cycles, no back arrows.
- **pure functional core**: `tls` and `fp` are `&[u8]` in, structured data out. no I/O, no network, no file system. testable with canned byte arrays.
- **no unsafe**: `#![forbid(unsafe_code)]` across the entire crate.
- **raw bytes are truth**: the TLS parser reads raw bytes. rustls is only used for certificate fallback, never for fingerprinting.
- **custom UI system**: truecolor gradients, responsive sections, word wrapping with no truncation. designed for this tool, not a generic library.

---

## contributing

open issues for bugs or feature requests. pull requests are welcome for fixes and new features. if you are adding a new TLS extension to the parser, add a test with the raw bytes. if you are adding a new client to the fingerprint database, add it to `assets/fingerprints.csv` (or refresh the whole DB from upstream with `just update-db`).

---

## license

MIT
