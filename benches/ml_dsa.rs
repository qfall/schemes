// Copyright 2026 Jan Niklas Siemer
//
// This file is part of qFALL-schemes.
//
// qfall-schemes is free software: you can redistribute it and/or modify it under
// the terms of the Mozilla Public License Version 2.0 as published by the
// Mozilla Foundation. See <https://mozilla.org/en-US/MPL/2.0/>.

use criterion::*;
use qfall_schemes::signature::MLDSA;
use qfall_schemes::signature::SignatureScheme;

/// Performs a full-cycle of key_gen, sign, vfy with [`MLDSA`].
fn mldsa_cycle(ml_dsa: &mut MLDSA) {
    let (pk, sk) = ml_dsa.key_gen();
    let msg = String::from("benchmark message");
    let sig = ml_dsa.sign(msg.clone(), &sk, &pk);
    let _ = ml_dsa.vfy(msg, &sig, &pk);
}

/// Benchmark [mldsa_cycle] with [MLDSA::ml_dsa_44].
///
/// This benchmark can be run with for example:
/// - `cargo criterion ML-DSA\ cycle\ 44`
/// - `cargo bench --bench benchmarks ML-DSA\ cycle\ 44`
/// - `cargo flamegraph --bench benchmarks -- --bench ML-DSA\ cycle\ 44`
fn bench_mldsa_cycle_44(c: &mut Criterion) {
    let mut ml_dsa = MLDSA::ml_dsa_44();

    c.bench_function("ML-DSA cycle 44", |b| b.iter(|| mldsa_cycle(&mut ml_dsa)));
}

/// Benchmark [MLDSA::key_gen] with [MLDSA::ml_dsa_44].
fn bench_mldsa_gen_44(c: &mut Criterion) {
    let mut ml_dsa = MLDSA::ml_dsa_44();

    c.bench_function("ML-DSA key_gen 44", |b| b.iter(|| ml_dsa.key_gen()));
}

/// Benchmark [MLDSA::sign] with [MLDSA::ml_dsa_44].
fn bench_mldsa_sign_44(c: &mut Criterion) {
    let mut ml_dsa = MLDSA::ml_dsa_44();
    let (pk, sk) = ml_dsa.key_gen();
    let msg = String::from("benchmark message");

    c.bench_function("ML-DSA sign 44", |b| {
        b.iter(|| ml_dsa.sign(msg.clone(), &sk, &pk))
    });
}

/// Benchmark [MLDSA::vfy] with [MLDSA::ml_dsa_44].
fn bench_mldsa_vfy_44(c: &mut Criterion) {
    let mut ml_dsa = MLDSA::ml_dsa_44();
    let (pk, sk) = ml_dsa.key_gen();
    let msg = String::from("benchmark message");
    let sig = ml_dsa.sign(msg.clone(), &sk, &pk);

    c.bench_function("ML-DSA vfy 44", |b| {
        b.iter(|| ml_dsa.vfy(msg.clone(), &sig, &pk))
    });
}

/// Benchmark [mldsa_cycle] with [MLDSA::ml_dsa_65].
///
/// This benchmark can be run with for example:
/// - `cargo criterion ML-DSA\ cycle\ 65`
/// - `cargo bench --bench benchmarks ML-DSA\ cycle\ 65`
/// - `cargo flamegraph --bench benchmarks -- --bench ML-DSA\ cycle\ 65`
fn bench_mldsa_cycle_65(c: &mut Criterion) {
    let mut ml_dsa = MLDSA::ml_dsa_65();

    c.bench_function("ML-DSA cycle 65", |b| b.iter(|| mldsa_cycle(&mut ml_dsa)));
}

/// Benchmark [MLDSA::key_gen] with [MLDSA::ml_dsa_65].
fn bench_mldsa_gen_65(c: &mut Criterion) {
    let mut ml_dsa = MLDSA::ml_dsa_65();

    c.bench_function("ML-DSA key_gen 65", |b| b.iter(|| ml_dsa.key_gen()));
}

/// Benchmark [MLDSA::sign] with [MLDSA::ml_dsa_65].
fn bench_mldsa_sign_65(c: &mut Criterion) {
    let mut ml_dsa = MLDSA::ml_dsa_65();
    let (pk, sk) = ml_dsa.key_gen();
    let msg = String::from("benchmark message");

    c.bench_function("ML-DSA sign 65", |b| {
        b.iter(|| ml_dsa.sign(msg.clone(), &sk, &pk))
    });
}

/// Benchmark [MLDSA::vfy] with [MLDSA::ml_dsa_65].
fn bench_mldsa_vfy_65(c: &mut Criterion) {
    let mut ml_dsa = MLDSA::ml_dsa_65();
    let (pk, sk) = ml_dsa.key_gen();
    let msg = String::from("benchmark message");
    let sig = ml_dsa.sign(msg.clone(), &sk, &pk);

    c.bench_function("ML-DSA vfy 65", |b| {
        b.iter(|| ml_dsa.vfy(msg.clone(), &sig, &pk))
    });
}

/// Benchmark [mldsa_cycle] with [MLDSA::ml_dsa_87].
///
/// This benchmark can be run with for example:
/// - `cargo criterion ML-DSA\ cycle\ 87`
/// - `cargo bench --bench benchmarks ML-DSA\ cycle\ 87`
/// - `cargo flamegraph --bench benchmarks -- --bench ML-DSA\ cycle\ 87`
fn bench_mldsa_cycle_87(c: &mut Criterion) {
    let mut ml_dsa = MLDSA::ml_dsa_87();

    c.bench_function("ML-DSA cycle 87", |b| b.iter(|| mldsa_cycle(&mut ml_dsa)));
}

/// Benchmark [MLDSA::key_gen] with [MLDSA::ml_dsa_87].
fn bench_mldsa_gen_87(c: &mut Criterion) {
    let mut ml_dsa = MLDSA::ml_dsa_87();

    c.bench_function("ML-DSA key_gen 87", |b| b.iter(|| ml_dsa.key_gen()));
}

/// Benchmark [MLDSA::sign] with [MLDSA::ml_dsa_87].
fn bench_mldsa_sign_87(c: &mut Criterion) {
    let mut ml_dsa = MLDSA::ml_dsa_87();
    let (pk, sk) = ml_dsa.key_gen();
    let msg = String::from("benchmark message");

    c.bench_function("ML-DSA sign 87", |b| {
        b.iter(|| ml_dsa.sign(msg.clone(), &sk, &pk))
    });
}

/// Benchmark [MLDSA::vfy] with [MLDSA::ml_dsa_87].
fn bench_mldsa_vfy_87(c: &mut Criterion) {
    let mut ml_dsa = MLDSA::ml_dsa_87();
    let (pk, sk) = ml_dsa.key_gen();
    let msg = String::from("benchmark message");
    let sig = ml_dsa.sign(msg.clone(), &sk, &pk);

    c.bench_function("ML-DSA vfy 87", |b| {
        b.iter(|| ml_dsa.vfy(msg.clone(), &sig, &pk))
    });
}

criterion_group!(
    benches,
    bench_mldsa_cycle_44,
    bench_mldsa_gen_44,
    bench_mldsa_sign_44,
    bench_mldsa_vfy_44,
    bench_mldsa_cycle_65,
    bench_mldsa_gen_65,
    bench_mldsa_sign_65,
    bench_mldsa_vfy_65,
    bench_mldsa_cycle_87,
    bench_mldsa_gen_87,
    bench_mldsa_sign_87,
    bench_mldsa_vfy_87,
);
