use crate::fmk::ed25519::{Ed25519Holder, Ed25519Issuer, Ed25519Verifier};
use ciborium::{Value, value::Error};
use cose_key_set::CoseKeySet;
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use esdicawt::{Holder, HolderParams, Issuer, IssuerParams, SdCwtVerified, Verifier, VerifierParams};
use esdicawt_spec::{CwtAny, Select, SelectExt};
use rand::prelude::ThreadRng;
use std::{collections::HashMap, hint::black_box};

#[path = "../tests/fmk.rs"]
mod fmk;

fn issue_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Issuer");
    for i in (0usize..1000).step_by(300) {
        group.bench_with_input(BenchmarkId::new("SHA-256", i), &i, |b, i| {
            b.iter_batched(
                || issuer::<sha2::Sha256>(i),
                |(mut rng, issuer, params, ..)| black_box(issuer.issue_cwt(&mut rng, params).unwrap()),
                BatchSize::LargeInput,
            )
        });
        group.bench_with_input(BenchmarkId::new("SHA-384", i), &i, |b, i| {
            b.iter_batched(
                || issuer::<sha2::Sha384>(i),
                |(mut rng, issuer, params, ..)| black_box(issuer.issue_cwt(&mut rng, params).unwrap()),
                BatchSize::LargeInput,
            )
        });
        group.bench_with_input(BenchmarkId::new("SHA-512", i), &i, |b, i| {
            b.iter_batched(
                || issuer::<sha2::Sha512>(i),
                |(mut rng, issuer, params, ..)| black_box(issuer.issue_cwt(&mut rng, params).unwrap()),
                BatchSize::LargeInput,
            )
        });
        group.bench_with_input(BenchmarkId::new("Blake3", i), &i, |b, i| {
            b.iter_batched(
                || issuer::<blake3::Hasher>(i),
                |(mut rng, issuer, params, ..)| black_box(issuer.issue_cwt(&mut rng, params).unwrap()),
                BatchSize::LargeInput,
            )
        });
    }
    group.finish();
}

fn holder_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Holder");
    for i in (0usize..1000).step_by(300) {
        group.bench_with_input(BenchmarkId::new("SHA-256", i), &i, |b, i| {
            b.iter_batched(
                || holder::<sha2::Sha256>(i),
                |(holder, params, sd_cwt, ..)| black_box(holder.new_presentation(sd_cwt, params).unwrap()),
                BatchSize::LargeInput,
            )
        });
        group.bench_with_input(BenchmarkId::new("SHA-384", i), &i, |b, i| {
            b.iter_batched(
                || holder::<sha2::Sha384>(i),
                |(holder, params, sd_cwt, ..)| black_box(holder.new_presentation(sd_cwt, params).unwrap()),
                BatchSize::LargeInput,
            )
        });
        group.bench_with_input(BenchmarkId::new("SHA-512", i), &i, |b, i| {
            b.iter_batched(
                || holder::<sha2::Sha512>(i),
                |(holder, params, sd_cwt, ..)| black_box(holder.new_presentation(sd_cwt, params).unwrap()),
                BatchSize::LargeInput,
            )
        });
        group.bench_with_input(BenchmarkId::new("Blake3", i), &i, |b, i| {
            b.iter_batched(
                || holder::<blake3::Hasher>(i),
                |(holder, params, sd_cwt, ..)| black_box(holder.new_presentation(sd_cwt, params).unwrap()),
                BatchSize::LargeInput,
            )
        });
    }
    group.finish();
}

fn verifier_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Verifier");
    for i in (0usize..1000).step_by(300) {
        group.bench_with_input(BenchmarkId::new("SHA-256", i), &i, |b, i| {
            b.iter_batched(
                || verifier::<sha2::Sha256>(i),
                |(verifier, sd_kbt, params, cks, ..)| black_box(verifier.verify_sd_kbt(&sd_kbt, params, None, &cks).unwrap()),
                BatchSize::LargeInput,
            )
        });
        group.bench_with_input(BenchmarkId::new("SHA-384", i), &i, |b, i| {
            b.iter_batched(
                || verifier::<sha2::Sha384>(i),
                |(verifier, sd_kbt, params, cks, ..)| black_box(verifier.verify_sd_kbt(&sd_kbt, params, None, &cks).unwrap()),
                BatchSize::LargeInput,
            )
        });
        group.bench_with_input(BenchmarkId::new("SHA-512", i), &i, |b, i| {
            b.iter_batched(
                || verifier::<sha2::Sha512>(i),
                |(verifier, sd_kbt, params, cks, ..)| black_box(verifier.verify_sd_kbt(&sd_kbt, params, None, &cks).unwrap()),
                BatchSize::LargeInput,
            )
        });
        group.bench_with_input(BenchmarkId::new("Blake3", i), &i, |b, i| {
            b.iter_batched(
                || verifier::<blake3::Hasher>(i),
                |(verifier, sd_kbt, params, cks, ..)| black_box(verifier.verify_sd_kbt(&sd_kbt, params, None, &cks).unwrap()),
                BatchSize::LargeInput,
            )
        });
    }
    group.finish();
}

fn shallow_verifier_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Shallow Verifier");
    for i in (0usize..1000).step_by(300) {
        group.bench_with_input(BenchmarkId::new("SHA-256", i), &i, |b, i| {
            b.iter_batched(
                || verifier::<sha2::Sha256>(i),
                |(verifier, sd_kbt, params, cks, ..)| black_box(verifier.verify_sd_kbt(&sd_kbt, params, None, &cks).unwrap()),
                BatchSize::LargeInput,
            )
        });
        group.bench_with_input(BenchmarkId::new("SHA-384", i), &i, |b, i| {
            b.iter_batched(
                || verifier::<sha2::Sha384>(i),
                |(verifier, sd_kbt, params, cks, ..)| black_box(verifier.verify_sd_kbt(&sd_kbt, params, None, &cks).unwrap()),
                BatchSize::LargeInput,
            )
        });
        group.bench_with_input(BenchmarkId::new("SHA-512", i), &i, |b, i| {
            b.iter_batched(
                || verifier::<sha2::Sha512>(i),
                |(verifier, sd_kbt, params, cks, ..)| black_box(verifier.verify_sd_kbt(&sd_kbt, params, None, &cks).unwrap()),
                BatchSize::LargeInput,
            )
        });
        group.bench_with_input(BenchmarkId::new("Blake3", i), &i, |b, i| {
            b.iter_batched(
                || verifier::<blake3::Hasher>(i),
                |(verifier, sd_kbt, params, cks, ..)| black_box(verifier.verify_sd_kbt(&sd_kbt, params, None, &cks).unwrap()),
                BatchSize::LargeInput,
            )
        });
    }
    group.finish();
}

fn issuer<H: digest::Digest + Clone>(
    i: &usize,
) -> (
    ThreadRng,
    Ed25519Issuer<VarSizePayload, H>,
    IssuerParams<VarSizePayload>,
    CoseKeySet,
    Ed25519Holder<VarSizePayload, H>,
) {
    let mut rng = rand::thread_rng();
    let issuer = Ed25519Issuer::<VarSizePayload, H>::new(ed25519_dalek::SigningKey::generate(&mut rng));
    let cks = CoseKeySet::new(issuer.signer()).unwrap();
    let holder = Ed25519Holder::<VarSizePayload, H>::new(ed25519_dalek::SigningKey::generate(&mut rng));
    let issuer_params = IssuerParams {
        protected_claims: None,
        unprotected_claims: None,
        payload: Some(VarSizePayload::new(*i)),
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
    };
    (rng, issuer, issuer_params, cks, holder)
}

fn holder<H: digest::Digest + Clone>(i: &usize) -> (Ed25519Holder<VarSizePayload, H>, HolderParams, SdCwtVerified<VarSizePayload, H>, CoseKeySet) {
    let (mut rng, issuer, issuer_params, cks, holder) = issuer::<H>(i);
    let sd_cwt = issuer.issue_cwt(&mut rng, issuer_params).unwrap();

    let sd_cwt = holder.verify_sd_cwt(&sd_cwt.to_cbor_bytes().unwrap(), Default::default(), &cks).unwrap();
    let holder_params = HolderParams {
        presentation: Default::default(),
        audience: "",
        cnonce: None,
        expiry: None,
        with_not_before: false,
        artificial_time: None,
        extra_kbt_protected: None,
        extra_kbt_unprotected: None,
        extra_kbt_payload: None,
    };
    (holder, holder_params, sd_cwt, cks)
}

fn verifier<H: digest::Digest + Clone>(i: &usize) -> (Ed25519Verifier<VarSizePayload>, Vec<u8>, VerifierParams, CoseKeySet) {
    let (holder, holder_params, sd_cwt, cks) = holder::<H>(i);

    let sd_kbt = holder.new_presentation_raw(sd_cwt, holder_params).unwrap();

    let verifier = Ed25519Verifier::<VarSizePayload>::new();

    let params = VerifierParams {
        expected_subject: None,
        expected_issuer: None,
        expected_audience: None,
        expected_kbt_audience: None,
        expected_cnonce: None,
        sd_cwt_leeway: Default::default(),
        sd_kbt_leeway: Default::default(),
        sd_cwt_time_verification: Default::default(),
        sd_kbt_time_verification: Default::default(),
        artificial_time: None,
    };

    (verifier, sd_kbt, params, cks)
}

/*fn verify_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Verify");
    group.bench_function(BenchmarkId::new("SHA-256", 0), |b| {
        b.iter_batched(
            || {
                let issuer = Ed25519Issuer::<Payload, sha2::Sha256>::new(ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()));
                let holder = Ed25519Holder::<Payload, sha2::Sha256>::new(ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()));

                let payload = Payload {
                    most_recent_inspection_passed: true,
                    inspector_license_number: Some("ABCD-123456".into()),
                    inspection_dates: vec![1549560720, 1612560720, 17183928],
                    inspection_location: OidcAddressClaim {
                        country: Some("us".into()),
                        region: Some("ca".into()),
                        postal_code: Some("94188".into()),
                        ..Default::default()
                    },
                };

                let issuer_params = IssuerParams {
                    protected_claims: None,
                    unprotected_claims: None,
                    payload: Some(payload),
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
                };

                let sd_cwt = issuer.issue_cwt(&mut rand::thread_rng(), issuer_params).unwrap();

                // let verifier = Ed25519Verifier;
                0
            },
            |_| black_box(()),
            BatchSize::SmallInput,
        )
    });
    group.finish();
}*/

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

criterion_group!(benches, issue_bench, holder_bench, verifier_bench, shallow_verifier_bench);
criterion_main!(benches);
