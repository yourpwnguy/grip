#![allow(missing_docs)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use grip::fp::{compute_ja3, compute_ja4};
use grip::tls::{ClientHello, ClientHelloBuilder};

fn bench_parse(c: &mut Criterion) {
    let bytes = ClientHelloBuilder::new()
        .with_sni(Some("example.com".to_string()))
        .build();
    c.bench_function("parse_client_hello", |b| {
        b.iter(|| {
            let ch = ClientHello::parse(black_box(&bytes)).unwrap();
            black_box(ch)
        });
    });
    c.bench_function("ja4", |b| {
        let ch = ClientHello::parse(&bytes).unwrap();
        b.iter(|| {
            let ja4 = compute_ja4(black_box(&ch));
            black_box(ja4)
        });
    });
    c.bench_function("ja3", |b| {
        let ch = ClientHello::parse(&bytes).unwrap();
        b.iter(|| {
            let ja3 = compute_ja3(black_box(&ch));
            black_box(ja3)
        });
    });
}

criterion_group!(benches, bench_parse);
criterion_main!(benches);
