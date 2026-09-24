#!/usr/bin/env python3
"""Regenerate assets/fingerprints.csv from FoxIO's ja4plus-mapping.csv.

Source: https://github.com/FoxIO-LLC/ja4/blob/main/ja4plus-mapping.csv
(bundled in the BSD-3-Clause `ja4plus` PyPI package; mapping data used here
under those terms — see README "fingerprint database" section).

What it does:
- keeps rows whose JA4 is a TCP client fingerprint (starts with 't');
  QUIC ('q...') rows are skipped — grip parses TCP TLS only.
- labels each fingerprint from Application / Library / Device / OS.
- merges duplicate JA4s (e.g. stock GoLang vs Sliver Agent share one),
  joining labels so genuinely ambiguous fingerprints stay honest.
- appends grip's own probe fingerprints so live `--lookup` identifies
  the probe itself instead of reporting "unclassified".

Usage:
    python3 scripts/import_ja4_mapping.py [mapping.csv|URL]
    just update-db
"""

import csv
import sys
import urllib.request

SOURCE_URL = (
    "https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/ja4plus-mapping.csv"
)

# grip's own ClientHello, computed by grip itself (see fp::lookup tests).
# SNI variant (hostname targets) and no-SNI variant (IP targets): JA4
# excludes SNI/ALPN values from its hashes, so only the d/i marker differs.
GRIP_SELF_ROWS = [
    {
        "ja3": "d879bc8777862a634eecc81a0d21e701",
        "ja4": "t13d1305h2_bda08f0cbb17_c83d862dc2aa",
        "ja4s": "",
        "client": "grip",
    },
    {
        "ja3": "ed329d72cdf273628e26e8e6f17110a9",
        "ja4": "t13i1305h2_bda08f0cbb17_c83d862dc2aa",
        "ja4s": "",
        "client": "grip",
    },
]


def load_mapping(source: str) -> list[dict]:
    if source.startswith("http"):
        with urllib.request.urlopen(source) as r:
            text = r.read().decode("utf-8")
        lines = text.splitlines()
    else:
        with open(source, newline="") as f:
            lines = f.read().splitlines()
    return list(csv.DictReader(lines))


def label(row: dict) -> str:
    parts = [row.get(k, "").strip() for k in ("Application", "Library", "Device", "OS")]
    return " / ".join(p for p in parts if p)


def prune(names: list[str]) -> list[str]:
    """Drop a label whose `/`-components are all covered by another label.

    E.g. ["Sliver Agent / GoLang", "GoLang"] -> ["Sliver Agent / GoLang"]:
    the bare library name adds no information. Genuinely different
    claimants (WinINET vs GoLang) are kept.
    """
    comp = [set(n.split(" / ")) for n in names]
    return [
        n
        for i, n in enumerate(names)
        if not any(i != j and comp[i] <= comp[j] for j in range(len(names)))
    ]


def main() -> int:
    source = sys.argv[1] if len(sys.argv) > 1 else SOURCE_URL
    rows = load_mapping(source)

    # Group labels by JA4; Application-bearing labels first so a shared
    # fingerprint (e.g. Go stdlib vs Sliver) leads with the specific one.
    grouped: dict[str, list[tuple[str, str, str]]] = {}
    order: list[str] = []
    skipped = 0
    for row in rows:
        ja4 = (row.get("ja4") or "").strip()
        if not ja4.startswith("t"):
            skipped += 1
            continue
        name = label(row)
        if not name:
            skipped += 1
            continue
        if ja4 not in grouped:
            grouped[ja4] = []
            order.append(ja4)
        grouped[ja4].append((name, (row.get("ja4s") or "").strip(), row.get("Application", "").strip()))

    out_rows: list[dict] = []
    for ja4 in order:
        indexed = list(enumerate(grouped[ja4]))
        indexed.sort(key=lambda p: (not p[1][2], p[0]))
        entries = [p[1] for p in indexed]
        names = prune(list(dict.fromkeys(e[0] for e in entries)))
        ja4s = next((e[1] for e in entries if e[1]), "")
        out_rows.append({"ja3": "", "ja4": ja4, "ja4s": ja4s, "client": ", ".join(names)})

    out_rows.extend(GRIP_SELF_ROWS)

    with open("assets/fingerprints.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["ja3", "ja4", "ja4s", "client"])
        w.writeheader()
        w.writerows(out_rows)

    print(f"source: {source}")
    print(f"imported {len(out_rows) - len(GRIP_SELF_ROWS)} JA4 fingerprints "
          f"(+{len(GRIP_SELF_ROWS)} grip self), skipped {skipped} non-TCP rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
