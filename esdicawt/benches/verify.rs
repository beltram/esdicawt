use crate::crypto::ed25519::{Ed25519Holder, Ed25519Issuer, Ed25519Verifier};
use ciborium::{Value, value::Error};
use cose_key::keyset::CoseKeySet;
use criterion::{BatchSize, BenchmarkGroup, BenchmarkId, Criterion, criterion_group, criterion_main, measurement::WallTime};
use esdicawt::{
    Holder, HolderParams, Issuer, IssuerParams, SdCwtVerified, ShallowVerifierParams, StatusParams, Verifier, VerifierParams,
    spec::{CwtAny, Select, SelectExt},
};
use itertools::Itertools;
use std::{collections::HashMap, hint::black_box};

#[path = "../tests/crypto.rs"]
mod crypto;

fn issue_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Issuer");
    for i in (0usize..1000).step_by(300) {
        bench_issuer::<sha2::Sha256>(&mut group, "SHA-256", i);
        // bench_issuer::<sha2::Sha384>(&mut group, "SHA-384", i);
        // bench_issuer::<sha2::Sha512>(&mut group, "SHA-512", i);
        // bench_issuer::<blake3::Hasher>(&mut group, "Blake3", i);
    }
    group.finish();
}

fn bench_issuer<H: digest::Digest + Clone>(group: &mut BenchmarkGroup<WallTime>, name: &str, i: usize) {
    let (mut rng, issuer, params, ..) = issuer::<H>(&i);
    group.bench_with_input(BenchmarkId::new(name, i), &params, |b, params| {
        // the params are consumed by the issuer so a fresh copy is supplied (untimed) to each iteration
        b.iter_batched(
            || params.clone(),
            |params| black_box(&issuer).issue_cwt(black_box(&mut rng), params).unwrap(),
            BatchSize::LargeInput,
        )
    });
}

fn holder_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Holder");
    for i in (0usize..1000).step_by(300) {
        bench_holder::<sha2::Sha256>(&mut group, "SHA-256", i);
        // bench_holder::<sha2::Sha384>(&mut group, "SHA-384", i);
        // bench_holder::<sha2::Sha512>(&mut group, "SHA-512", i);
        // bench_holder::<blake3::Hasher>(&mut group, "Blake3", i);
    }
    group.finish();
}

fn bench_holder<H: digest::Digest + Clone>(group: &mut BenchmarkGroup<WallTime>, name: &str, i: usize) {
    let (holder, sd_cwt, _) = holder::<H>(&i);
    group.bench_with_input(BenchmarkId::new(name, i), &sd_cwt, |b, sd_cwt| {
        // the SD-CWT and params are consumed by the holder so fresh ones are supplied (untimed) to each iteration
        b.iter_batched(
            || (sd_cwt.clone(), holder_params()),
            |(sd_cwt, params)| black_box(&holder).new_presentation(sd_cwt, params).unwrap(),
            BatchSize::LargeInput,
        )
    });
}

fn verifier_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Verifier");
    for i in (0usize..1000).step_by(300) {
        bench_verifier::<sha2::Sha256>(&mut group, "SHA-256", i);
        // bench_verifier::<sha2::Sha384>(&mut group, "SHA-384", i);
        // bench_verifier::<sha2::Sha512>(&mut group, "SHA-512", i);
        // bench_verifier::<blake3::Hasher>(&mut group, "Blake3", i);
    }
    group.finish();
}

fn bench_verifier<H: digest::Digest + Clone>(group: &mut BenchmarkGroup<WallTime>, name: &str, i: usize) {
    // verification does not consume its inputs so they are built once, outside of the measured routine
    let (verifier, sd_kbt, params, cks) = verifier::<H>(&i);
    group.bench_with_input(BenchmarkId::new(name, i), &sd_kbt, |b, sd_kbt| {
        b.iter(|| black_box(&verifier).verify_sd_kbt(black_box(sd_kbt), black_box(&params), None, black_box(&cks)).unwrap())
    });
}

fn verifier_batch_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Verifier Batch");
    for (nb_claims, nb_sd_kbt) in [10usize, 100, 1000].iter().cartesian_product((1usize..1000).step_by(300)) {
        let id = BenchmarkId::new("SHA-256", format!("{nb_sd_kbt} SD-KBT with {nb_claims} claims"));
        bench_verifier_batch::<sha2::Sha256>(&mut group, id, *nb_claims, nb_sd_kbt);
    }
    group.finish();
}

fn bench_verifier_batch<H: digest::Digest + Clone>(group: &mut BenchmarkGroup<WallTime>, id: BenchmarkId, nb_claims: usize, nb_sd_kbt: usize) {
    // verification does not consume its inputs so the batch is built once, outside of the measured routine
    let (verifier, sd_kbts, params, cks) = verifier_batch::<H>(nb_claims, nb_sd_kbt);
    let batch = sd_kbts.iter().map(|sd_kbt| (sd_kbt.as_slice(), &params, None)).collect::<Vec<_>>();
    assert!(verifier.verify_sd_kbt_batch(&batch, &cks).into_iter().all(|r| r.is_ok()));

    // one function per claims count so that each gets its own "time vs. batch size" series
    group.bench_with_input(id, &batch, |b, batch| {
        b.iter(|| black_box(&verifier).verify_sd_kbt_batch(black_box(batch), black_box(&cks)))
    });
}

#[allow(dead_code)]
fn shallow_verifier_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Shallow Verifier");
    for i in (1usize..1000).step_by(300) {
        bench_shallow_verifier::<sha2::Sha256>(&mut group, "SHA-256", i);
        // bench_shallow_verifier::<sha2::Sha384>(&mut group, "SHA-384", i);
        // bench_shallow_verifier::<sha2::Sha512>(&mut group, "SHA-512", i);
        // bench_shallow_verifier::<blake3::Hasher>(&mut group, "Blake3", i);
    }
    group.finish();
}

#[allow(dead_code)]
fn bench_shallow_verifier<H: digest::Digest + Clone>(group: &mut BenchmarkGroup<WallTime>, name: &str, i: usize) {
    // verification does not consume its inputs so they are built once, outside of the measured routine
    let (verifier, sd_kbt, params, cks) = shallow_verifier::<H>(&i);
    group.bench_with_input(BenchmarkId::new(name, i), &sd_kbt, |b, sd_kbt| {
        b.iter(|| {
            black_box(&verifier)
                .shallow_verify_sd_kbt(black_box(sd_kbt), black_box(&params), None, black_box(&cks))
                .unwrap()
        })
    });
}

fn issuer<H: digest::Digest + Clone>(
    nb_claims: &usize,
) -> (
    rand::rngs::OsRng,
    Ed25519Issuer<VarSizePayload, H>,
    IssuerParams<'_, VarSizePayload>,
    CoseKeySet,
    Ed25519Holder<VarSizePayload, H>,
) {
    let mut rng = rand::rngs::OsRng::default();
    let issuer = Ed25519Issuer::<VarSizePayload, H>::new(ed25519_dalek::SigningKey::generate(&mut rng));
    let cks = CoseKeySet::builder().with_signing_key(issuer.signer()).unwrap().build();
    let holder = Ed25519Holder::<VarSizePayload, H>::new(ed25519_dalek::SigningKey::generate(&mut rng));
    let issuer_params = IssuerParams {
        protected_claims: None,
        unprotected_claims: None,
        payload: Some(VarSizePayload::new(*nb_claims)),
        issuer: "",
        subject: None,
        audience: None,
        expiry: None,
        with_not_before: false,
        with_issued_at: false,
        cti: None,
        cnonce: None,
        artificial_time: None,
        leeway: Default::default(),
        key_location: "",
        holder_confirmation_key: (&holder.verifying_key).try_into().unwrap(),
        status: StatusParams {
            status_list_bit_index: 0,
            uri: "https://example.com/statuslists/1".parse().unwrap(),
        },
    };
    (rng, issuer, issuer_params, cks, holder)
}

fn holder<H: digest::Digest + Clone>(nb_claims: &usize) -> (Ed25519Holder<VarSizePayload, H>, SdCwtVerified<VarSizePayload, H>, CoseKeySet) {
    let (mut rng, issuer, issuer_params, cks, holder) = issuer::<H>(nb_claims);
    let sd_cwt = issuer.issue_cwt(&mut rng, issuer_params).unwrap();

    let sd_cwt = holder.verify_sd_cwt(&sd_cwt.to_cbor_bytes().unwrap(), Default::default(), &cks).unwrap();
    (holder, sd_cwt, cks)
}

fn holder_params() -> HolderParams<'static> {
    HolderParams {
        presentation: Default::default(),
        audience: "",
        cnonce: None,
        expiry: None,
        with_not_before: false,
        artificial_time: None,
        time_verification: Default::default(),
        leeway: Default::default(),
        extra_kbt_protected: None,
        extra_kbt_unprotected: None,
        extra_kbt_payload: None,
    }
}

fn verifier<H: digest::Digest + Clone>(nb_claims: &usize) -> (Ed25519Verifier<VarSizePayload>, Vec<u8>, VerifierParams<'_>, CoseKeySet) {
    let (holder, sd_cwt, cks) = holder::<H>(nb_claims);

    let sd_kbt = holder.new_presentation_raw(sd_cwt, holder_params()).unwrap();

    let verifier = Ed25519Verifier::<VarSizePayload>::new();

    let params = VerifierParams {
        expected_subject: None,
        expected_issuer: None,
        expected_audience: None,
        expected_kbt_audience: &[],
        expected_cnonce: None,
        sd_cwt_leeway: Default::default(),
        sd_kbt_leeway: Default::default(),
        sd_cwt_time_verification: Default::default(),
        sd_kbt_time_verification: Default::default(),
        artificial_time: None,
    };

    (verifier, sd_kbt, params, cks)
}

fn verifier_batch<H: digest::Digest + Clone>(nb_claims: usize, nb_sd_kbt: usize) -> (Ed25519Verifier<VarSizePayload>, Vec<Vec<u8>>, VerifierParams<'static>, CoseKeySet) {
    let (mut rng, issuer, issuer_params, cks, holder) = issuer::<H>(&nb_claims);

    let mut sd_kbts = Vec::with_capacity(nb_sd_kbt);
    for _ in 0..nb_sd_kbt {
        let sd_cwt = issuer.issue_cwt(&mut rng, issuer_params.clone()).unwrap();
        let sd_cwt = holder.verify_sd_cwt(&sd_cwt.to_cbor_bytes().unwrap(), Default::default(), &cks).unwrap();
        let sd_kbt = holder.new_presentation_raw(sd_cwt, holder_params()).unwrap();
        sd_kbts.push(sd_kbt);
    }

    let verifier = Ed25519Verifier::<VarSizePayload>::new();
    let params = VerifierParams {
        expected_subject: None,
        expected_issuer: None,
        expected_audience: None,
        expected_kbt_audience: &[],
        expected_cnonce: None,
        sd_cwt_leeway: Default::default(),
        sd_kbt_leeway: Default::default(),
        sd_cwt_time_verification: Default::default(),
        sd_kbt_time_verification: Default::default(),
        artificial_time: None,
    };

    (verifier, sd_kbts, params, cks)
}

fn shallow_verifier<H: digest::Digest + Clone>(i: &usize) -> (Ed25519Verifier<VarSizePayload>, Vec<u8>, ShallowVerifierParams, CoseKeySet) {
    let (holder, sd_cwt, cks) = holder::<H>(i);

    let sd_kbt = holder.new_presentation_raw(sd_cwt, holder_params()).unwrap();

    let verifier = Ed25519Verifier::<VarSizePayload>::new();

    let params = ShallowVerifierParams {
        sd_cwt_leeway: Default::default(),
        sd_kbt_leeway: Default::default(),
        sd_cwt_time_verification: Default::default(),
        sd_kbt_time_verification: Default::default(),
        artificial_time: None,
    };

    (verifier, sd_kbt, params, cks)
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct VarSizePayload(HashMap<String, String>);

impl VarSizePayload {
    fn new(len: usize) -> Self {
        let map = (0..len).map(|_| (rand_str(6), rand_str(6))).collect::<HashMap<String, String>>();
        Self(map)
    }
}

impl Select for VarSizePayload {
    fn select(mut self) -> Result<Value, Error> {
        self.select_all()
    }
}

fn rand_str(size: usize) -> String {
    use rand::Rng as _;
    rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(size)
        .map(char::from)
        .collect::<String>()
}

criterion_group!(benches, issue_bench, holder_bench, verifier_bench, verifier_batch_bench /*, shallow_verifier_bench*/);
criterion_main!(benches);
