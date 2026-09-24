# `grip` — Architecture & Project Structure (v0.1.0)

> Source of truth: `idea.md`. This document does **not** expand scope — it turns that spec into a buildable, modular, idiomatic Rust design.

## 0. Principles

1. **Raw bytes own the truth.** No `rustls`/`native-tls` handshake. We speak TCP and parse TLS records manually. The only delegation allowed is ASN.1/X.509 via `x509-parser` — hand-rolling ASN.1 is a security liability, not a purity win.
2. **Core has no I/O.** `tls` + `fp` are pure functions over `&[u8]` / structs. They compile without `std::net`, `std::fs`, or `clap`. This makes them testable, fuzzable, and reusable.
3. **Dependency direction is one-way.** `cli → app → net/pcap → output → fp → tls → error`. Never cycles. Enforced by `pub(crate)` visibility and module hierarchy. No globals, no singletons.
4. **KISS over enterprise.** Single Cargo package with `src/lib.rs` + `src/main.rs` for v0.1.0. Internal modules act as package boundaries. Workspace split is a *future* 2-line change, not a day-0 tax.
5. **Files < ~100 lines where natural.** One responsibility per file. Split because the domain demands it, not to hit a number.
6. **Every public item documented.** `///` docs must explain *what, why, invariants, algorithm, errors, security* — not just signature.

---

## 1. Recommended Directory Structure

**Single-crate layout** (idiomatic for a v0.1.0 CLI that needs testability):

```
grip/
├── Cargo.toml
├── build.rs                  # embed fingerprint DB via phf_codegen (optional)
├── idea.md
├── docs/
│   └── architecture.md       # this file
├── assets/
│   └── fingerprints.csv      # source for known DB (Chrome, Firefox, curl…)
├── tests/
│   ├── fixtures/
│   │   ├── client_hellos/    # .bin raw ClientHellos (Chrome120, curl, Go…)
│   │   ├── server_hellos/    # .bin raw ServerHellos
│   │   └── pcaps/            # tiny pcaps: single-flow, fragmented, ooo, multi-flow
│   ├── integration_live.rs   # ignored by default, hits local test server
│   ├── integration_pcap.rs
│   └── snapshots/            # insta snapshots for human/json output
├── benches/
│   └── parse_bench.rs        # criterion: ClientHello parse + JA4 throughput
├── fuzz/
│   └── fuzz_targets/
│       ├── client_hello.rs
│       ├── record.rs
│       └── pcap_reader.rs
└── src/
    ├── lib.rs                # re-exports core, defines crate-level docs
    ├── main.rs               # 20 lines: parse args, call cli::run, map exit code
    ├── error.rs              # GripError + GripResult
    ├── tls/                  # ── DOMAIN: raw TLS parsing ──
    │   ├── mod.rs
    │   ├── record.rs         # TLS record layer (ContentType, TlsRecord)
    │   ├── client_hello.rs   # ClientHello struct + parse
    │   ├── server_hello.rs   # ServerHello struct + parse
    │   ├── extensions.rs     # Extension enum + per-extension parsers
    │   ├── version.rs        # TlsVersion, legacy vs real version logic
    │   ├── cipher.rs         # cipher suite constants & display
    │   ├── grease.rs         # is_grease(), filter helpers (RFC 8701)
    │   ├── certificate.rs    # CertificateChain parsing (wraps x509-parser)
    │   └── builder.rs        # ClientHelloBuilder (live mode byte crafting)
    ├── fp/                   # ── DOMAIN: fingerprint computation ──
    │   ├── mod.rs
    │   ├── ja3.rs
    │   ├── ja4.rs
    │   ├── ja4s.rs
    │   └── lookup.rs         # known DB lookup (phf map)
    ├── pcap/                 # ── INFRA: pcap file → ClientHellos ──
    │   ├── mod.rs
    │   ├── reader.rs         # pcap global header + packet iteration
    │   ├── tcp.rs            # FlowKey, TcpSegment, 5-tuple
    │   ├── reassembly.rs     # sequence-ordered reassembly, gap handling
    │   └── extractor.rs      # walk reassembled stream → TlsRecords → ClientHellos
    ├── net/                  # ── INFRA: live TCP ──
    │   ├── mod.rs
    │   └── connect.rs        # TcpStream connect, send ClientHello, recv ServerHello/Certs
    ├── db/                   # ── DATA ──
    │   ├── mod.rs
    │   └── known.rs          # include!(concat!(env!("OUT_DIR"), "/known_db.rs"))
    ├── output/               # ── PRESENTATION (depends on domain, not vice versa) ──
    │   ├── mod.rs            # Report types + Renderer trait
    │   ├── model.rs          # LiveReport, PcapReport, ClientEntry (Serialize)
    │   ├── human.rs          # pretty terminal (sections, wrapping, colors)
    │   ├── json.rs           # JSON serialization
    │   ├── hex.rs            # hex dump formatting
    │   └── writer.rs         # OutputWriter: stdout vs file, --quiet
    ├── cli/                  # ── INTERFACE: clap + orchestration ──
    │   ├── mod.rs
    │   ├── args.rs           # Cli, Mode, Format, SortBy (clap derive)
    │   ├── validate.rs       # cross-field validation
    │   └── run.rs            # dispatch live vs pcap, wire everything
    └── util/
        ├── mod.rs
        ├── hex.rs            # hex encode helpers
        └── time.rs           # expiry → "77 days" formatting
```

**Why not a workspace with `crates/grip-core` + `crates/grip-cli` on day 1?**
For a single binary ≤5k LoC, a workspace adds publish/versioning friction and slower `cargo check` without giving harder encapsulation than `pub(crate)` already provides. The module tree above is *workspace-ready*: moving `tls`+`fp`+`db` into `crates/grip-core` later is a `cargo new` + `mod` → `pub use` change, zero architectural rewrite. Document the split trigger: >5k LoC or second binary (e.g., `grips` server).

**Line-count discipline:** `record.rs` (~60 lines), `grease.rs` (~40), `ja3.rs` (~50), `ja4.rs` (~90), `reader.rs` (~90), `reassembly.rs` (~100). Larger files (`client_hello.rs`, `extractor.rs`, `human.rs`) naturally sit at 100–150 lines — do not artificially split them.

---

## 2. Responsibility of Every Package/Module

### `src/lib.rs`
Crate root. `#![deny(missing_docs)]`, crate-level `//!` docs explaining the two modes and the raw-byte invariant. Re-exports `error`, `tls`, `fp`, `pcap`, `net`, `output`, `cli` as `pub mod` with tight visibility. No logic.

### `src/main.rs`
Thin adapter. `fn main() -> ExitCode` that:
1. `let cli = Cli::parse();`
2. `if let Err(e) = cli::run(cli) { eprintln!("{}", e.display()); ExitCode::FAILURE }`
No business logic — testable via `cli::run`.

### `src/error.rs`
Single error type for the whole crate. Uses `thiserror`. No `anyhow` in library code.

```rust
#[derive(Debug, thiserror::Error)]
pub enum GripError {
    #[error("I/O error: {0}")] Io(#[from] std::io::Error),
    #[error("TLS parse error at offset {offset}: {kind}")] Parse { offset: usize, kind: ParseKind },
    #[error("pcap error: {0}")] Pcap(String),
    #[error("network error: {0}")] Network(String),
    #[error("timeout after {0}s connecting to {1}")] Timeout(u64, String),
    #[error("invalid argument: {0}")] InvalidArg(String),
    // ...
}
pub type GripResult<T> = Result<T, GripError>;
```

`ParseKind` is a non-exhaustive enum (`UnexpectedEof`, `InvalidContentType(u8)`, `BadLength`, `GreaseLogic`, …) for precise diagnostics. Implements `miette::Diagnostic` for pretty CLI errors without pulling `miette` into `tls`.

### `src/tls/`

| File | Responsibility | Key invariant |
|---|---|---|
| `record.rs` | Parse 5-byte header + payload. Validate `length <= 16384` (RFC 8446 §5.1). Return `TlsRecord { content_type, legacy_version, payload }` or `Parse::BadLength`. | Never panics on short slice; checks `buf.len() >= 5 + length`. |
| `version.rs` | `enum TlsVersion { Ssl30, Tls10, Tls11, Tls12, Tls13, Unknown(u16) }`. Function `real_version(legacy: u16, exts: &[Extension]) -> TlsVersion` reads `supported_versions (0x002b)` first, falls back to legacy. | TLS 1.3 is **never** inferred from `0x0303` alone. |
| `cipher.rs` | Constants (`TLS_AES_128_GCM_SHA256 = 0x1301` …), `fn name(id: u16) -> &'static str`, `fn is_grease` delegation. | Display is infallible. |
| `grease.rs` | `const GREASE_VALUES: [u16; 16] = [0x0a0a, 0x1a1a, …, 0xfafa]`; `pub fn is_grease(v: u16) -> bool`, `pub fn filter_grease<'a>(vals: &[u16]) -> Vec<u16>`. Also `is_grease_ext(u16)` for extension types. | Filter **before** sort — enforced by `fp` call order, documented with test. |
| `extensions.rs` | `enum Extension { Sni(String), SupportedGroups(Vec<u16>), EcPointFormats(Vec<u8>), SignatureAlgorithms(Vec<u16>), Alpn(Vec<String>), SupportedVersions(Vec<u16>), KeyShare(Vec<KeyShareEntry>), Unknown(u16, Vec<u8>) }` + `parse_extensions(&[u8]) -> Vec<Extension>`. Linear walk: `type(2) + len(2) + data`. | Unknown extensions preserved as `Unknown` — never error on future extension. SNI validation: must be valid hostname or IP literal. |
| `client_hello.rs` | `struct ClientHello { legacy_version, random, session_id, cipher_suites, compression_methods, extensions, raw: Vec<u8> }`. `pub fn parse(buf: &[u8]) -> GripResult<ClientHello>` that calls `record::parse` then handshake parsing. Helpers `sni()`, `alpn()`, `supported_versions()`. | All length prefixes checked; `cipher_suites.len() % 2 == 0`; extensions length exactly consumed. `raw` kept for `--raw` and hashing. |
| `server_hello.rs` | `struct ServerHello { legacy_version, random, session_id, cipher_suite: u16, compression_method: u8, extensions: Vec<Extension>, raw: Vec<u8> }`. Handles TLS 1.3 HelloRetryRequest via `random == [0xCF,21,…]` sentinel. | Distinguishes ServerHello vs HelloRetryRequest. |
| `certificate.rs` | `struct CertificateChain(Vec<CertInfo>)`, `struct CertInfo { subject, issuer, sans, not_after, sha256_fingerprint, sct_count }`. Wraps `x509-parser` for ASN.1; computes `SHA256(der)`, extracts `1.3.6.1.4.1.11129.2.4.2` (SCT) extension. | No hand-rolled ASN.1. Rejects chains > 10 certs or cert > 16 KiB to bound memory. |
| `builder.rs` | `struct ClientHelloBuilder` with chainable setters `with_sni`, `with_ciphers`, `with_groups`, etc. `fn build(&self) -> Vec<u8>` that serializes **all length prefixes correctly** (record len, handshake len 24-bit, cipher_suites len, extensions len). Provides `default_chrome_like()` for live mode. | Single place where lengths are computed — tested against golden bytes that `parse` round-trips. |

### `src/fp/`

Pure functions. No I/O, no allocation beyond fingerprint strings. Each file <100 lines.

| File | Computes | Algorithm note |
|---|---|---|
| `ja3.rs` | `pub fn compute_ja3(ch: &ClientHello) -> String` → `md5("TLSVersion,Ciphers,Extensions,EllipticCurves,PointFormats")` with GREASE-filtered, **original order preserved** (JA3 does not sort). | Uses `md5` crate. Version is `real_version`. Extensions list excludes GREASE but keeps order. |
| `ja4.rs` | `pub struct Ja4(String)` + `compute_ja4(ch: &ClientHello) -> Ja4`. Three parts: `t13d1516h2` tag + `_` + `sha256(sorted_ciphers)[:12]` + `_` + `sha256(sorted_exts + sigalgs)[:12]`. | **Order: filter GREASE → sort → hash.** Tag counts exclude SNI/ALPN and exclude GREASE. First ALPN chars lowercased, `00` if none. Protocol `t` for v0.1.0 (q/d deferred). |
| `ja4s.rs` | `compute_ja4s(sh: &ServerHello) -> Ja4s`. Parses ServerHello extensions. | Analogous tag; no GREASE in server; extensions sorted. |
| `lookup.rs` | `pub fn lookup(ja4: &str) -> Option<&'static str>` via `phf::Map` generated at build time from `assets/fingerprints.csv`. | Zero runtime CSV parsing. `build.rs` codegens `known_db.rs`. |

All fingerprint types are newtypes (`struct Ja4(String)`) with `Display`, `AsRef<str>`, `Serialize`.

### `src/pcap/`

| File | Responsibility |
|---|---|
| `reader.rs` | Parse pcap global header (magic → endian, version, snaplen, network `DLT_RAW`/`EN10MB`/`LINUX_SLL`). Iterate `PcapRecord { ts_sec, ts_usec, incl_len, orig_len, data: &[u8] }`. Handles both micro/nano timestamps and LE/BE magic (`0xa1b2c3d4`, `0xd4c3b2a1`, `0xa1b23c4d`, `0x4d3cb2a1`). Validates `incl_len <= orig_len` and caps at snaplen. |
| `tcp.rs` | `FlowKey { src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16 }` (hashable), `TcpSegment { seq: u32, payload: Vec<u8> }`. Parses IPv4 + TCP headers from link-layer payload. Skips non-TCP. Handles IP fragmentation? No — v0.1.0 documents "no IP fragment reassembly, requires unfragmented captures". |
| `reassembly.rs` | `struct Reassembler { flows: HashMap<FlowKey, FlowState> }`, `struct FlowState { segments: BTreeMap<u32, Vec<u8>>, next_expected: Option<u32> }`. Inserts segments by `seq`, coalesces contiguous run from `ISN`, exposes `fn reassembled(&self, key: &FlowKey) -> Option<Vec<u8>>` or streaming iterator. Handles out-of-order, duplicates, overlaps (keep first-seen). Drops gaps — logs warning. |
| `extractor.rs` | `fn extract_client_hellos(stream: &[u8]) -> Vec<ClientHello>` — scans for `0x16 0x03 0x??` record headers, validates length, delegates to `tls::client_hello::parse`. Tolerates multiple records per stream; skips non-Handshake records. |

### `src/net/`

| File | Responsibility |
|---|---|
| `connect.rs` | `pub fn probe(target: &str, port: u16, sni: Option<&str>, timeout: Duration) -> GripResult<ProbeResult>` where `ProbeResult { client_hello_raw, server_hello: ServerHello, cert_chain: CertificateChain, negotiated: NegotiatedInfo }`. Steps: `TcpStream::connect_timeout`, `set_read_timeout`, build ClientHello via `tls::builder::ClientHelloBuilder`, `write_all`, loop `read` until ServerHello + Certificate records received or timeout. Parses raw bytes via `tls::*`. |

`net` is the *only* module that touches `std::net`. No async in v0.1.0 (see decisions).

### `src/db/`

`known.rs` — `pub static KNOWN_JA4: phf::Map<&'static str, &'static str>` etc. Generated file not hand-edited. `mod.rs` exposes `lookup_ja3`, `lookup_ja4`.

### `src/output/`

| File | Responsibility |
|---|---|
| `model.rs` | Serializable DTOs: `LiveReport { target, negotiated, certificate, fingerprints: Fingerprints, raw: Option<RawHex> }`, `PcapReport { file, total_handshakes, unique_clients, clients: Vec<ClientEntry> }`, `ClientEntry { ip, ja4, client_name, count }`. All `#[derive(Serialize)]`. |
| `human.rs` | `fn render_live(report: &LiveReport, w: &mut dyn Write, p: Palette, width: usize)`, `fn render_pcap(report: &PcapReport, w: &mut dyn Write, p: Palette, width: usize)`. Titled sections and key/value rows via `ui::panel`, truecolor via `ui::theme::Palette` with `NO_COLOR`/`FORCE_COLOR`/`is_terminal` checks. Long values wrap, never truncate. No business logic — pure formatting. |
| `json.rs` | `fn render_json<T: Serialize>(v: &T, w: &mut dyn Write) -> GripResult<()>` using `serde_json::to_writer_pretty`. |
| `hex.rs` | `fn hexdump(data: &[u8], w: &mut dyn Write)` — `0000  16 03 01 …` with ASCII gutter, like `idea.md` raw mode. |
| `writer.rs` | `enum OutputWriter { Stdout, File(File) }` + `fn writer_for(path: Option<&Path>) -> Box<dyn Write>`; handles `--quiet` (only fingerprint) and `anstream::AutoStream` wrapping. |

### `src/cli/`

| File | Responsibility |
|---|---|
| `args.rs` | `#[derive(Parser)] struct Cli { target: Option<String>, #[arg(long)] pcap: Option<PathBuf>, #[arg(short, long, default_value_t=443)] port: u16, #[arg(long)] sni: Option<String>, #[arg(long, default_value_t=10)] timeout: u64, #[arg(long)] ja3: bool, ... }`. `enum Mode { Live { target }, Pcap { file } }` derived via `validate()`. `enum Format { Human, Json }`, `enum SortBy { Ip, Fingerprint, Count }`. |
| `validate.rs` | `fn validate(cli: &Cli) -> GripResult<Mode>` — mutual exclusion (`target` vs `--pcap`), port 1..65535, timeout >0, SNI hostname regex, `--filter` requires `--pcap`, `--unique`/`--sort-by` requirements. Returns typed `Mode`. |
| `run.rs` | `pub fn run(cli: Cli) -> GripResult<()>` — match `Mode`, call `net::probe` or `pcap::reader+reassembly+extractor`, compute fingerprints, lookup, build `output::model`, dispatch to `output::{human,json,hex}::render` via `Renderer` strategy. Handles `-o` file creation and exit codes. |

### `src/util/`

`hex.rs` (`to_colon_hex`, `sha256_hex`), `time.rs` (`format_expiry(not_after: SystemTime) -> String` like `2026-11-15 (77 days)`). Tiny, well-tested.

### `build.rs`

Reads `assets/fingerprints.csv`, generates `phf` maps into `$OUT_DIR/known_db.rs`. Fails build on duplicate JA4.

---

## 3. Dependency & Data Flow

### Dependency Direction (strict, acyclic)

```
                 ┌─────────────┐
                 │   main.rs   │
                 └──────┬──────┘
                        │ uses
                 ┌──────▼──────┐
                 │  cli::{args,validate,run} │
                 └──────┬──────┘
                        │ orchestrates
        ┌───────────────┼────────────────┐
        │               │                │
  ┌─────▼─────┐   ┌─────▼─────┐   ┌─────▼─────┐
  │   net     │   │   pcap    │   │  output   │
  └─────┬─────┘   └─────┬─────┘   └─────┬─────┘
        │               │               │ formats
        │               │               │
        └───────┬───────┘               │
                │                       │
          ┌─────▼─────┐           ┌─────▼─────┐
          │    fp     │◄──────────│    db     │
          └─────┬─────┘           └───────────┘
                │ uses
          ┌─────▼─────┐
          │    tls    │
          └─────┬─────┘
                │
          ┌─────▼─────┐
          │   error   │
          │   util    │
          └───────────┘
```

* `tls` and `fp` import only `error`, `util`, and external crates (`sha2`, `md5`, `x509-parser`). Never `std::net`/`std::fs`/`clap`.
* `output` imports `tls`+`fp`+`db` models but never reverse.
* `cli` is the only crate importing `clap`.
* `net` and `pcap` are siblings — neither depends on the other.

Enforcement: `tls`/`fp` have `#![deny(unused)]` and no `std::net` import allowed (CI `rg` check). `pub(crate)` for internal helpers.

### Data Flow

**Live mode** `grip example.com`:
```
Cli::parse
  → validate() → Mode::Live{target}
  → net::connect::probe(target, port, sni, timeout)
      → tls::builder::ClientHelloBuilder::default_chrome_like().with_sni(sni).build() → Vec<u8>
      → TcpStream::write_all(ClientHello bytes)
      → loop read → Vec<u8> raw_server_bytes
      → tls::record::parse → tls::server_hello::parse → ServerHello
      → tls::certificate::parse_chain → CertificateChain
  → tls::client_hello::parse(client_hello_raw) → ClientHello (for fingerprinting our own hello)
  → fp::ja3::compute_ja3 / fp::ja4::compute_ja4 / fp::ja4s::compute_ja4s
  → db::lookup
  → output::model::LiveReport { negotiated, cert, fps, raw }
  → output::writer → output::human|json|hex → stdout or file
```

**Pcap mode** `grip --pcap capture.pcap`:
```
Cli::parse → Mode::Pcap{file}
  → pcap::reader::PcapReader::open(file) → iterator<Item=PcapRecord>
  → for each record: pcap::tcp::parse_ipv4_tcp → FlowKey + TcpSegment
  → pcap::reassembly::Reassembler::insert(key, segment)  // BTreeMap by seq
  → for each FlowKey: reassembler.reassembled(key) → Vec<u8> contiguous stream
  → pcap::extractor::extract_client_hellos(stream) → Vec<ClientHello>
  → for each ClientHello: fp::ja4::compute_ja4 → Ja4
  → aggregation: HashMap<(IpAddr, Ja4), count> + HashMap<Ja4, client_name via lookup>
  → output::model::PcapReport { total, unique, Vec<ClientEntry> }
  → sort_by(SortBy) → dedup if --unique → filter if --filter
  → output::human|json
```

Both flows converge at `output::model` — the CLI never formats inline.

### Concurrency Model (v0.1.0)

* **Live mode:** synchronous, single connection. `std::net::TcpStream` with `connect_timeout` + `set_read_timeout`. No threads, no `tokio`. Rationale: one handshake, low latency, no benefit from async; keeps binary small and stack traces simple.
* **Pcap mode:** single-threaded streaming. `PcapReader` is an iterator yielding `GripResult<PcapRecord>` without loading the whole file. Reassembly buffers per-flow in `HashMap<FlowKey, BTreeMap<...>>` — bounded by `max_flows` (default 10k) and `max_stream_bytes` (default 1 MiB per flow) to avoid OOM on adversarial pcaps. Future: `rayon` parallelization per-flow is a non-breaking additive change (`par_iter` over `flows`).

---

## 4. Important Interfaces / Types & Why They Exist

### Core domain types (newtypes + enums prevent misuse)

```rust
// tls/version.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion { Tls12, Tls13, /* … */ Unknown(u16) }

// tls/record.rs
#[derive(Debug)] pub enum ContentType { Handshake=0x16, Alert=0x15, ChangeCipherSpec=0x14, ApplicationData=0x17, Unknown(u8) }
pub struct TlsRecord { pub content_type: ContentType, pub legacy_version: u16, pub payload: Vec<u8> }

// tls/client_hello.rs
pub struct ClientHello {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,      // GREASE still present; fp filters
    pub compression_methods: Vec<u8>,
    pub extensions: Vec<Extension>,
    pub raw: Vec<u8>,                 // original bytes for --raw / hashing
}
impl ClientHello {
    pub fn parse(buf: &[u8]) -> GripResult<Self>;
    pub fn real_version(&self) -> TlsVersion; // reads supported_versions ext
    pub fn sni(&self) -> Option<&str>;
}

// tls/extensions.rs
pub enum Extension { Sni(String), SupportedGroups(Vec<u16>), /* … */, Unknown(u16, Vec<u8>) }

// fp/ja4.rs
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)] pub struct Ja4(pub String);
impl Ja4 { pub fn as_str(&self) -> &str; }
pub fn compute_ja4(ch: &ClientHello) -> Ja4;

// pcap/tcp.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)] pub struct FlowKey { pub src: Ipv4Addr, pub src_port: u16, pub dst: Ipv4Addr, pub dst_port: u16 }

// output/model.rs
#[derive(Serialize)] pub struct LiveReport { pub target: String, pub negotiated: NegotiatedInfo, pub certificate: CertSummary, pub fingerprints: Fingerprints, pub raw: Option<RawHex> }
```

**Why newtypes for JA3/JA4/JA4S?** Prevents mixing `ja3 == ja4` bugs, allows `impl Display` with validation (`Ja4` must match `t13…_…_…` regex), and provides a single place to document the spec.

**Why `Extension::Unknown`?** Forward compatibility — new TLS extensions must not break parsing. The parser is *permissive* on unknown, *strict* on malformed lengths.

**Why `ClientHello.raw`?** `--raw` hex dump and fingerprint hashing need the original bytes; recomputing from struct would risk length-prefix bugs.

### Traits (minimal, only where they earn their keep)

```rust
// output/mod.rs — Strategy pattern for rendering
pub trait Renderer {
    fn render(&self, report: &dyn Serialize, writer: &mut dyn Write) -> GripResult<()>;
}
pub struct HumanRenderer; pub struct JsonRenderer;
impl Renderer for HumanRenderer { … }

// pcap/reader.rs — Iterator abstraction for testability
pub trait PacketSource: Iterator<Item = GripResult<PcapRecord>> {}
impl PacketSource for PcapReader<File> {}
// Tests inject Vec<PcapRecord> as source without touching FS.
```

*No* `Fingerprinter` trait with dynamic dispatch — `compute_ja3`/`compute_ja4` are free functions. A trait would be premature abstraction for 3 functions that never need swapping at runtime. If QUIC support lands, add `compute_ja4_quic` as a new function, not a trait.

*No* generic `Parser<T>` trait — each parser is a plain `fn parse(&[u8]) -> GripResult<T>`; the type system already distinguishes them.

---

## 5. Design Patterns — Only Where They Help

| Pattern | Where | Why |
|---|---|---|
| **Newtype** | `Ja3(String)`, `Ja4(String)`, `Ja4s(String)`, `FlowKey` | Type safety, single formatting/validation site. |
| **Builder** | `ClientHelloBuilder` | Handshake byte construction has 4 nested length prefixes (record, handshake, cipher_suites, extensions). Builder computes lengths in one place, prevents off-by-one. Also enables future `--custom-ciphers` probing without API break. |
| **Strategy** | `Renderer` (`HumanRenderer` vs `JsonRenderer`) | CLI `run` selects renderer by `--format` without `if format==` scattered through code. Closed set of 2, so `enum` dispatch is also fine — choose trait for testability (mock writer). |
| **Iterator / Pipeline** | `PcapReader → Reassembler → Extractor` | Streaming, lazy, bounded memory; each stage is independently testable with `Vec<u8>` input. |
| **BTreeMap for ordering** | `Reassembler.segments: BTreeMap<u32, Vec<u8>>` | Sequence numbers naturally ordered; `BTreeMap` gives O(log n) insert and sorted iteration for reassembly without manual sorting. |
| **PHF (perfect hash) for DB** | `db/known.rs` | O(1) lookup, zero runtime CSV parse, compile-time duplicate detection. |
| **DTO (model.rs)** | `LiveReport`, `PcapReport` | Decouples domain structs (`ClientHello`) from presentation. Domain can evolve without breaking JSON schema; `Serialize` only on DTOs. |

Explicitly **not** used: Factory, Abstract Factory, Dependency Injection container, Repository, Unit-of-Work — all would be enterprise bullshit for a stateless CLI.

---

## 6. Key Architectural Decisions & Tradeoffs

| Decision | Choice | Alternative | Tradeoff |
|---|---|---|---|
| **Single crate vs workspace** | Single package, `lib.rs`+`main.rs` | `crates/grip-core` + `crates/grip-cli` workspace | Pro: faster `cargo check`, simpler `cargo install`, KISS. Con: weaker physical isolation (mitigated by `pub(crate)`). Migration path documented. |
| **Sync `std::net` vs `tokio`** | `std::net::TcpStream` + timeouts | `tokio::net::TcpStream` async | Sync is ~20 lines, no runtime, trivial stack traces, `cargo tree` stays small. Tokio would help for concurrent scanning of many hosts — not in v0.1.0 scope (single `target`). If `grip --targets file` lands, add `tokio` then. |
| **Hand-rolled TLS parsing vs `tls-parser` crate** | Hand-roll record + ClientHello/ServerHello, delegate only X.509 | Use `tls-parser` for everything | Spec requires "everything reads raw bytes — no TLS library doing the work". Hand-rolling is the *product*. X.509 is the exception because ASN.1 is a known vuln surface and `x509-parser` is audited. |
| **X.509 via `x509-parser`** | Yes | Hand-roll ASN.1 | Security: `x509-parser` handles BER/DER edge cases, OID parsing, SCT extraction. Hand-rolling would be a CVE factory. |
| **GREASE handling** | `grease::is_grease` checks `0x0a0a + n*0x1111`, filter before sort | Sort then filter | Filtering before sort is mandated by JA4 spec; doing it wrong yields wrong fingerprints for Chrome (which inserts `0x0a0a` etc.). Unit test `grease_sort_order` guards regression. |
| **Version resolution** | `real_version()` reads `supported_versions` ext first | Use `legacy_version` field | Legacy field lies for TLS 1.3 (always `0x0303`). Reading it would mislabel every modern client. |
| **Pcap parsing** | Manual pcap header + IPv4/TCP parsing, no `libpcap` | Bind `libpcap`/`pnet` | No C dependency, works on any host, `cargo install` stays self-contained. Manual IPv4/TCP is ~80 lines and fully testable. `libpcap` deferred to `v0.2` live capture. |
| **TCP reassembly strategy** | `BTreeMap<seq, payload>` per flow, coalesce contiguous from ISN | Full TCP state machine (SACK, window scaling) | v0.1.0 only needs contiguous ClientHello bytes; full TCP would be 500+ lines for no fingerprint gain. Gaps are reported as warnings, not errors — partial ClientHellos are skipped rather than producing garbage fingerprints. |
| **Fingerprint hashing** | `sha2` + `md5` crates (pure Rust) | `openssl`/`ring` | Pure Rust keeps `cargo install` portable (no OpenSSL headers). `sha2` is audited and `md5` is only for JA3 (legacy). |
| **Output colors** | `anstream` + `owo-colors` with `NO_COLOR` + `is_terminal` | `colored`/`crossterm` | `anstream` respects `NO_COLOR`/`FORCE_COLOR` and strips colors when piped/redirected to file — required for `| jq` and `-o file`. |
| **Error reporting** | `thiserror` + `miette` for CLI diagnostics | `anyhow` everywhere | Library code needs typed errors for tests (`Error::Parse{offset}`); `anyhow` erases that. CLI layer converts to `miette` for pretty `Error: TLS parse error at offset 42`. |
| **DB embedding** | `phf_codegen` in `build.rs` | Runtime CSV parse or `HashMap::from_iter` | Compile-time perfect hash, O(1), no runtime I/O, duplicate JA4 detection at build time. |

**Invariants that must hold (and are tested):**
* `record::parse` never reads beyond `buf.len()`; `length` checked against `16384 + 5`.
* `client_hello::parse` rejects `cipher_suites.len() % 2 != 0`.
* `extensions::parse` exactly consumes `extensions_len` bytes — trailing bytes = error.
* `fp::ja4` asserts `cipher_suites_filtered_sorted == filter_grease(cipher_suites).sorted()`.
* `reassembly::insert` caps `segments.len()` per flow and total `flows.len()`; adversarial pcap cannot OOM.

---

## 7. Testing Strategy

### Unit tests (co-located, `#[cfg(test)]` in each file)

* **Golden bytes:** `tests/fixtures/client_hellos/*.bin` — real captures from Chrome 120, Firefox 121, curl 7.88, Go 1.21, Python-requests. Each file has a companion `.json` with expected `cipher_suites`, `extensions`, `ja3`, `ja4`, `ja4s`. Test: `parse(bytes).unwrap() == expected`.
* **Record layer:** truncated header, bad length, unknown content type, `length > 16384` → `Err`.
* **GREASE:** `is_grease(0x0a0a)==true`, `is_grease(0x0303)==false`, `filter_grease([0x0a0a,0x1301,0x1a1a])==[0x1301]`. Sort-order test: `ja4(ch_with_grease) == ja4(ch_without_grease_but_sorted)`.
* **Version:** `legacy 0x0303` + `supported_versions [0x0304]` → `Tls13`; no ext → `Tls12`.
* **Builder:** `ClientHelloBuilder::default().build()` then `parse` round-trips; length prefixes match `buf.len()`.
* **Certificate:** self-signed cert with 2 SANs + SCT, expired cert → `format_expiry` shows negative days.

### Integration tests (`tests/`)

* `integration_pcap.rs`: opens `tests/fixtures/pcaps/*.pcap` (generated via `scapy`), runs full pipeline, asserts `PcapReport` counts. Cases: single flow, fragmented ClientHello (2 segments), out-of-order, duplicate seq, multi-flow, truncated pcap.
* `integration_live.rs`: `#[ignore]` — spins up `tests/tls_server.rs` (tiny `rustls` server on `127.0.0.1:0`), probes it, asserts `LiveReport` fields. Run with `cargo test -- --ignored`.

### Snapshot tests

* `insta` for `output::human::render_live` and `render_pcap` — golden `.snap` files checked into git. Color stripped for snapshot (`NO_COLOR=1`).

### Property / fuzz tests

* `cargo fuzz` targets: `client_hello`, `record`, `pcap_reader` — each feeds arbitrary `&[u8]` to `parse`, asserts **never panics**, only `Ok` or `Err(GripError::Parse)`. Run in CI nightly.
* `proptest` for `ClientHelloBuilder`: random cipher suites + extensions → `build` → `parse` → fields equal (round-trip).

### Coverage & CI

* `cargo test` + `cargo fmt --check` + `cargo clippy -- -D warnings` on every push.
* `cargo deny check` for dependency audit.
* Coverage via `cargo llvm-cov` — target 80% on `tls`+`fp`; `net`/`pcap` integration covers the rest.

---

## 8. Performance Considerations

* **Zero-copy where possible:** Parsers take `&[u8]` and return slices or `Vec<u16>` of copied IDs. No `String` allocation for unknown extensions — keep `Vec<u8>`. `ClientHello.raw` is the only `Vec<u8>` clone of the input.
* **SmallVec for extensions:** Most ClientHellos have ≤20 extensions; `SmallVec<[Extension; 16]>` avoids heap allocation for the common case (consider if `extensions: SmallVec` shows up in benchmarks).
* **Streaming pcap:** `PcapReader` yields one `PcapRecord` at a time; file never fully loaded. `Reassembler` stores only TCP payload bytes (not full packets) and caps per-flow bytes at 1 MiB.
* **Hashing:** `sha2` processes sorted cipher suite strings (≤ ~80 bytes) — negligible. No need for `rayon` in v0.1.0 single-flow live mode. Pcap fingerprinting is embarrassingly parallel per-flow — future `rayon::par_iter` over `flows` gives near-linear speedup.
* **Avoid `format!` in hot loop:** Fingerprint computation builds strings via `write!` into pre-allocated `String::with_capacity`.
* **Benchmarks:** `criterion` bench `parse_client_hello` (10k iterations) and `pcap_pipeline` (1k flows). Guard against regressions >10% in CI.

---

## 9. Security Considerations

* **No `unsafe`.** `#![forbid(unsafe_code)]` at crate root. The only `unsafe` allowed would be in dependencies (`x509-parser` uses safe Rust).
* **Length validation is security-critical.** Every `u16`/`u24` length is checked against remaining slice before slicing. `record.length <= 16384`, `handshake.length <= 1<<24`, `incl_len <= snaplen`. Violations → `GripError::Parse`, never panic or OOB read.
* **Bounded allocations.** `max_record_len`, `max_cert_chain_len` (10 certs), `max_pcap_flows` (10k), `max_stream_bytes` (1 MiB) prevent OOM on adversarial inputs. `Vec::with_capacity` capped.
* **No secret handling.** `ClientHello.random` is public bytes, not a key. No private keys ever loaded. No `zeroize` needed.
* **Certificate verification.** `--no-verify` is explicit; default verifies expiry and SAN matching via `x509-parser` + `webpki` roots (or `rustls-native-certs`). Document that verification is *best-effort* — we parse certs, not validate full chain to root in v0.1.0 (call out in `--help`).
* **Input isolation.** Pcap file path is not trusted; `reader.rs` uses `File::open` with no symlink following beyond OS default, no `include_str!` of pcap. Live mode target is DNS-resolved via `ToSocketAddrs` with timeout — no injection into shell.
* **Fuzzing as security gate.** `cargo fuzz` runs in CI; any panic or ASAN finding blocks merge. Treat `Panic` on malformed pcap as P1 bug.
* **Supply chain.** `cargo deny` + `cargo audit` in CI; minimize deps (see `Cargo.toml` minimal set). No `openssl` to avoid C vulns.
* **Output sanitization.** SNI/hostname from ClientHello is untrusted; `human.rs` escapes control chars and truncates at 256 chars before printing.

---

## 10. CLI / UI Architecture (Polished without Contaminating Core)

**Goals:** responsive, readable, scriptable. Colors when TTY, plain when piped. Human-first default, JSON for `| jq`.

* **`clap` derive in `cli/args.rs` only.** Core never imports `clap`. `Cli` → `validate()` → `Mode` is the boundary. Tests construct `Cli { target: Some("…"), pcap: None, … }` without invoking clap.
* **Renderer trait in `output/mod.rs`.** `cli::run` selects renderer:
  ```rust
  let renderer: Box<dyn Renderer> = match cli.format {
      Format::Human => Box::new(HumanRenderer { color: atty::is(Stream::Stdout) }),
      Format::Json  => Box::new(JsonRenderer),
  };
  renderer.render(&report, &mut writer)?;
  ```
  `HumanRenderer` uses `anstream` for auto color, `unicode-width` for alignment, `indicatif` **not** needed (single handshake is instant; pcap shows `3 unique clients · 47 total handshakes` summary). No spinner to avoid contaminating stdout for piping.
* **No business logic in rendering.** `HumanRenderer` takes `&LiveReport` DTO; it does not call `fp::compute`. This keeps `output` testable with canned DTOs.
* **Responsiveness:** `net::probe` prints nothing until done — handshake is <100ms. For pcap, `reader` streams; `--filter` and `--sort-by` are applied after aggregation (in-memory `Vec<ClientEntry>` ≤10k entries). No progress bar needed for v0.1.0 (files <100 MiB).
* **Error presentation:** `cli::run` returns `GripError`; `main.rs` maps to `miette::Report` for pretty `Error: …` with `help:` suggestion (e.g., `hint: try --port 8443`). Exit codes: `0` success, `1` parse/network error, `2` invalid args (from clap).
* **`--quiet` and `-o`:** `writer.rs` handles both. `--quiet` delegates to `JsonRenderer` or minimal `HumanRenderer::render_quiet` (prints `ja4\n` only). `-o` opens file *before* network/pcap work so permission errors fail fast.

---

## 11. Configuration

No config file in v0.1.0. All state via CLI flags (see `idea.md` full CLI). Defaults: `port 443`, `timeout 10s`, `--all-fp` in live mode, `--format human`, `--sort-by count` in pcap. Environment: respects `NO_COLOR`, `FORCE_COLOR`, `RUST_LOG` (via `tracing` if added later — not in v0.1.0, use `eprintln!` for warnings).

---

## 12. What Explicitly Does NOT Exist in v0.1.0

Per `idea.md` roadmap, plus additional scope cuts to keep v0.1.0 shippable:

* ✗ Live pcap capture (`libpcap`/`AF_PACKET` binding) — file-based pcap only.
* ✗ QUIC / HTTP/3 fingerprinting (JA4 `q` protocol) — TLS `t` only.
* ✗ DTLS support.
* ✗ IPv6 pcap reassembly (IPv4 only; IPv6 packets skipped with warning).
* ✗ Custom ClientHello crafting beyond SNI override (no `--ciphers`/`--groups` probe mode yet; `ClientHelloBuilder` is internal).
* ✗ IP fragment reassembly (requires unfragmented captures).
* ✗ Full TCP state machine (no SACK, window scaling, RST handling).
* ✗ Async / `tokio` runtime.
* ✗ Config file (`~/.config/grip.toml`) — CLI flags only.
* ✗ Colored `miette` fancy reports with source spans — simple `Display` errors.
* ✗ Daemon / server mode, REST API.
* ✗ Plugin system, WASM, dynamic fingerprint DB updates — DB is compile-time embedded.
* ✗ `cargo install` with `openssl` feature — pure Rust only.

Any PR adding these before v0.1.0 ships is out of scope and should be closed with a link to this section.

---

## 13. Future Extensibility (No Rewrite Needed)

* **Workspace split:** Move `tls`+`fp`+`db` to `crates/grip-core` (library), `cli`+`net`+`pcap`+`output` to `crates/grip-cli`. `Cargo.toml` workspace with `[workspace.dependencies]` for shared versions.
* **QUIC/DTLS:** Add `tls::quic.rs` + `fp::ja4_quic.rs`; `Extension` already has `Unknown` for new transports; `Ja4` protocol char becomes `q`/`d`.
* **Live capture:** Add `pcap/live.rs` behind `features = ["live-capture"]` that depends on `pcap` crate; `PacketSource` trait already abstracts file vs live.
* **Parallel pcap:** Change `extractor::extract_all(flows)` to `flows.par_iter().map(extract).collect()` — one line.
* **Custom probing:** Expose `ClientHelloBuilder` via `grip --ciphers 0x1301,0xc02b --groups x25519` by adding clap flags that wire to builder setters.

---

## 14. Dependency Set (Minimal, Audited)

```toml
[dependencies]
clap = { version = "4", features = ["derive"] }
thiserror = "2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"          # SHA256 for JA4
md5 = "0.7"            # MD5 for JA3 only
x509-parser = "0.16"   # cert parsing, no hand-rolled ASN.1
phf = { version = "0.11", features = ["macros"] }
anstream = "0.6"       # auto color + NO_COLOR
owo-colors = "4"       # optional, for human.rs colors
chrono = "0.4"         # expiry formatting

[build-dependencies]
phf_codegen = "0.11"
csv = "1"

[dev-dependencies]
insta = "1"
criterion = "0.5"
proptest = "1"
```

No `tokio`, `reqwest`, `rustls`, `openssl`, `pnet` in v0.1.0 — keeps `cargo tree` ≤30 crates and `cargo install` <30s.

---

## 15. Documentation Expectations (From Day 1)

* `#![deny(missing_docs)]` + `#![warn(clippy::doc_markdown)]`.
* Every `pub` item has `///` with: what it does, why it exists, algorithm steps, invariants, `# Errors`, `# Security`, `# Examples`.
* `lib.rs` has `//!` crate docs with live/pcap examples and `cargo test` instructions.
* `README.md` mirrors `idea.md` example outputs verbatim — checked by snapshot test.

---

*This architecture delivers `idea.md` exactly — live TLS inspection + pcap fingerprinting, JA3/JA4/JA4S, GREASE, raw hex, human/JSON — on a foundation that is KISS for v0.1.0 but scales to QUIC, live capture, and parallel pcap without a rewrite.*
