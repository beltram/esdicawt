//! Pluggable AEAD for encrypted disclosures.
//!
//! See https://datatracker.ietf.org/doc/html/draft-ietf-spice-sd-cwt#name-encrypted-disclosures
use crate::spec::aead::AeadAlgorithm;

/// Output of an AEAD encryption
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AeadSealed {
    pub nonce: Vec<u8>,
    /// The encryption algorithm's ciphertext, without the authentication tag
    pub ciphertext: Vec<u8>,
    /// The authentication tag
    pub tag: Vec<u8>,
}

/// Used by a Holder to encrypt disclosures for a target Verifier
pub trait DisclosureEncryptor {
    /// The AEAD algorithm from the [IANA AEAD Algorithms registry](https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml)
    fn algorithm(&self) -> AeadAlgorithm;

    /// Encrypts the plaintext with [Self::algorithm].
    ///
    /// Implementations MUST:
    /// * use a unique, random nonce of N_MIN octets
    /// * use a zero-length associated data
    fn encrypt(&self, plaintext: &[u8]) -> Result<AeadSealed, Box<dyn core::error::Error + Send + Sync>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CborPath, DisclosureEncryption, Holder, HolderParams, Issuer, IssuerParams, Presentation, SdCwtHolderError, SdCwtHolderValidationError, SdCwtVerifierError, StatusParams,
        TimeArg, Verifier,
        spec::{
            COSE_HEADER_KCWT, COSE_HEADER_SD_AEAD, COSE_HEADER_SD_AEAD_ENCRYPTED_CLAIMS, COSE_HEADER_SD_CLAIMS, CwtAny, EsdicawtSpecError, NoClaims, Salt, SdCwtClaim,
            aead::{AeadEncryptedDisclosure, AeadKeyContext, disclosure_from_plaintext, disclosure_to_plaintext},
            blinded_claims::{SaltedClaim, SaltedElement, SaltedEntry},
            inlined_cbor::InlinedCbor,
            key_binding::KbtCwt,
            reexports::coset::{self, TaggedCborSerializable as _},
            sd,
        },
        test_utils::{Ed25519Holder, Ed25519Issuer},
    };
    use aes_gcm::{
        Aes128Gcm, Nonce, Tag,
        aead::{AeadInPlace as _, KeyInit as _},
    };
    use ciborium::{Value, cbor};
    use cose_key::keyset::CoseKeySet;
    use ed25519_dalek::Signer as _;
    use std::convert::Infallible;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    const KEY: [u8; 16] = [0x11; 16];
    const OTHER_KEY: [u8; 16] = [0x22; 16];

    fn seal(key: &[u8; 16], nonce: &[u8; 12], plaintext: &[u8]) -> AeadSealed {
        let mut buffer = plaintext.to_vec();
        let tag = Aes128Gcm::new_from_slice(key)
            .unwrap()
            .encrypt_in_place_detached(&Nonce::from(*nonce), b"", &mut buffer)
            .unwrap();
        AeadSealed {
            nonce: nonce.to_vec(),
            ciphertext: buffer,
            tag: tag.to_vec(),
        }
    }

    fn open(key: &[u8; 16], encrypted: &AeadEncryptedDisclosure) -> Option<Vec<u8>> {
        let nonce = <[u8; 12]>::try_from(encrypted.nonce.as_slice()).ok()?;
        let tag = <[u8; 16]>::try_from(encrypted.tag.as_slice()).ok()?;
        let mut buffer = encrypted.ciphertext.to_vec();
        Aes128Gcm::new_from_slice(key)
            .unwrap()
            .decrypt_in_place_detached(&Nonce::from(nonce), b"", &mut buffer, &Tag::from(tag))
            .ok()?;
        Some(buffer)
    }

    fn encrypted(key: &[u8; 16], plaintext: &[u8]) -> AeadEncryptedDisclosure {
        let AeadSealed { nonce, ciphertext, tag } = seal(key, &[7; 12], plaintext);
        AeadEncryptedDisclosure {
            nonce: nonce.into(),
            ciphertext: ciphertext.into(),
            tag: tag.into(),
            key_context: None,
        }
    }

    struct TestEncryptor {
        key: [u8; 16],
        alg: AeadAlgorithm,
        tag_len: usize,
        fail: bool,
    }

    impl TestEncryptor {
        fn new(key: [u8; 16]) -> Self {
            Self {
                key,
                alg: AeadAlgorithm::AES_128_GCM,
                tag_len: 16,
                fail: false,
            }
        }
    }

    impl DisclosureEncryptor for TestEncryptor {
        fn algorithm(&self) -> AeadAlgorithm {
            self.alg
        }

        fn encrypt(&self, plaintext: &[u8]) -> Result<AeadSealed, Box<dyn core::error::Error + Send + Sync>> {
            if self.fail {
                return Err("encryption failure".into());
            }
            let mut nonce = [0u8; 12];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
            let mut sealed = seal(&self.key, &nonce, plaintext);
            sealed.tag.truncate(self.tag_len);
            Ok(sealed)
        }
    }

    /// Only supports AEAD_AES_128_GCM and tries all of its keys
    #[derive(Default)]
    struct AeadVerifier {
        keys: Vec<[u8; 16]>,
    }

    impl AeadVerifier {
        fn with_key(key: [u8; 16]) -> Self {
            Self { keys: vec![key] }
        }
    }

    impl Verifier for AeadVerifier {
        type Error = Infallible;
        type HolderSignature = ed25519_dalek::Signature;
        type HolderVerifier = ed25519_dalek::VerifyingKey;
        type IssuerProtectedClaims = NoClaims;
        type IssuerUnprotectedClaims = NoClaims;
        type IssuerPayloadClaims = Value;
        type KbtPayloadClaims = NoClaims;
        type KbtProtectedClaims = NoClaims;
        type KbtUnprotectedClaims = NoClaims;

        fn decrypt_disclosure(&self, alg: AeadAlgorithm, encrypted: &AeadEncryptedDisclosure) -> Option<Vec<u8>> {
            if alg != AeadAlgorithm::AES_128_GCM {
                return None;
            }
            self.keys.iter().find_map(|key| open(key, encrypted))
        }
    }

    fn payload() -> Value {
        cbor!({
            sd!("name") => "Alice Smith",
            sd!("age") => 42,
            "address" => { sd!("city") => "Paris", "country" => "FR" },
            sd!("nested") => { sd!("inner") => "secret", "visible" => true },
            "array" => ["a", sd!("b")],
        })
        .unwrap()
    }

    const NB_DISCLOSURES: usize = 6;

    fn fully_disclosed() -> Value {
        cbor!({
            "name" => "Alice Smith",
            "age" => 42,
            "address" => { "city" => "Paris", "country" => "FR" },
            "nested" => { "inner" => "secret", "visible" => true },
            "array" => ["a", "b"],
        })
        .unwrap()
    }

    fn path(p: &[&str]) -> Vec<CborPath> {
        p.iter().map(|s| CborPath::Str(s.to_string())).collect()
    }

    fn encrypt_paths<'a>(encryptor: &'a dyn DisclosureEncryptor, paths: Vec<Vec<CborPath>>) -> DisclosureEncryption<'a> {
        DisclosureEncryption {
            encryptor,
            key_context: None,
            select: Box::new(move |p| paths.iter().any(|expected| expected == p)),
        }
    }

    struct Context {
        holder: Ed25519Holder<Value, NoClaims>,
        holder_signing_key: ed25519_dalek::SigningKey,
        cks: CoseKeySet,
        sd_cwt: Vec<u8>,
    }

    fn issue() -> Context {
        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let issuer_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let issuer = Ed25519Issuer::<Value>::new(issuer_signing_key.clone());
        let params = IssuerParams {
            protected_claims: None,
            unprotected_claims: None,
            payload: Some(payload()),
            subject: Some("https://example.com/u/alice.smith"),
            issuer: "https://example.com/i/acme.io",
            audience: Default::default(),
            cti: Default::default(),
            cnonce: Default::default(),
            expiry: None,
            with_not_before: true,
            with_issued_at: true,
            leeway: core::time::Duration::from_secs(1),
            key_location: "https://auth.acme.io/issuer.cwk",
            holder_confirmation_key: (&holder_signing_key.verifying_key()).try_into().unwrap(),
            artificial_time: None,
            status: StatusParams {
                status_list_bit_index: 0,
                uri: "https://example.com/statuslists/1".parse().unwrap(),
            },
        };
        let sd_cwt = issuer.issue_cwt(&mut rand::thread_rng(), params).unwrap().to_cbor_bytes().unwrap();
        let cks = CoseKeySet::builder().with_signing_key(&issuer_signing_key).unwrap().build();
        let holder = Ed25519Holder::<Value, NoClaims>::new(holder_signing_key.clone());
        Context {
            holder,
            holder_signing_key,
            cks,
            sd_cwt,
        }
    }

    fn holder_params<'a>(presentation: Presentation, encryption: Option<DisclosureEncryption<'a>>) -> HolderParams<'a> {
        HolderParams {
            presentation,
            audience: "https://example.com/r/alice-bob-group",
            cnonce: None,
            expiry: Some(TimeArg::Relative(core::time::Duration::from_secs(3600))),
            with_not_before: false,
            artificial_time: None,
            time_verification: Default::default(),
            leeway: Default::default(),
            extra_kbt_protected: None,
            extra_kbt_unprotected: None,
            extra_kbt_payload: None,
            encryption,
        }
    }

    type TestKbt = KbtCwt<Value, sha2::Sha256>;

    impl Context {
        fn try_present(&self, presentation: Presentation, encryption: Option<DisclosureEncryption>) -> Result<Vec<u8>, SdCwtHolderError<Infallible>> {
            let sd_cwt = self.holder.verify_sd_cwt(&self.sd_cwt, Default::default(), &self.cks).unwrap();
            self.holder.new_presentation_raw(sd_cwt, holder_params(presentation, encryption))
        }

        fn present(&self, encryption: Option<DisclosureEncryption>) -> Vec<u8> {
            self.try_present(Presentation::Full, encryption).unwrap()
        }

        fn verify(&self, verifier: &AeadVerifier, sd_kbt: &[u8]) -> Result<Value, SdCwtVerifierError<Infallible>> {
            let verified = verifier.verify_sd_kbt(sd_kbt, &Default::default(), Some(&self.holder_signing_key.verifying_key()), &self.cks)?;
            Ok(sorted(verified.claimset.unwrap()))
        }

        /// Alters the unprotected header of the SD-CWT inside the SD-KBT then signs the SD-KBT again
        fn tamper(&self, sd_kbt: &[u8], f: impl FnOnce(&mut HeaderMap)) -> Vec<u8> {
            let coset::CoseSign1 {
                protected, unprotected, payload, ..
            } = coset::CoseSign1::from_tagged_slice(sd_kbt).unwrap();
            let mut protected = protected.header;
            let (_, kcwt) = protected.rest.iter_mut().find(|(l, _)| *l == coset::Label::Int(COSE_HEADER_KCWT)).unwrap();
            let mut f = Some(f);
            edit_sd_cwt_unprotected(kcwt, &mut |unprotected| (f.take().unwrap())(unprotected));
            coset::CoseSign1Builder::new()
                .protected(protected)
                .unprotected(unprotected)
                .payload(payload.unwrap())
                .create_signature(&[], |tbs| self.holder_signing_key.sign(tbs).to_bytes().to_vec())
                .build()
                .to_tagged_vec()
                .unwrap()
        }
    }

    type HeaderMap = Vec<(Value, Value)>;

    fn edit_sd_cwt_unprotected(sd_cwt: &mut Value, f: &mut dyn FnMut(&mut HeaderMap)) {
        match sd_cwt {
            Value::Tag(_, inner) => edit_sd_cwt_unprotected(inner, f),
            // with the 'backward' feature the SD-CWT is wrapped in a bstr
            Value::Bytes(bytes) => {
                let mut inner = Value::from_cbor_bytes(bytes).unwrap();
                edit_sd_cwt_unprotected(&mut inner, f);
                *bytes = inner.to_cbor_bytes().unwrap();
            }
            Value::Array(sd_cwt) => f(sd_cwt.get_mut(1).unwrap().as_map_mut().unwrap()),
            _ => unreachable!(),
        }
    }

    fn label(map: &mut [(Value, Value)], label: i64) -> Option<&mut Value> {
        map.iter_mut().find(|(k, _)| *k == Value::from(label)).map(|(_, v)| v)
    }

    fn sorted(value: Value) -> Value {
        match value {
            Value::Map(map) => {
                let mut map = map.into_iter().map(|(k, v)| (k, sorted(v))).collect::<Vec<_>>();
                map.sort_by_key(|(k, _)| k.to_cbor_bytes().unwrap());
                Value::Map(map)
            }
            Value::Array(array) => Value::Array(array.into_iter().map(sorted).collect()),
            v => v,
        }
    }

    fn decode(sd_kbt: &[u8]) -> TestKbt {
        TestKbt::from_cbor_bytes(sd_kbt).unwrap()
    }

    fn encrypted_disclosures(sd_kbt: &[u8]) -> Vec<AeadEncryptedDisclosure> {
        decode(sd_kbt).sd_cwt().unwrap().encrypted_disclosures().map(|e| e.to_vec()).unwrap_or_default()
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_match_draft_test_vector() {
        // see draft-ietf-spice-sd-cwt/examples/aead-key.txt and draft-ietf-spice-sd-cwt/examples/aead-claim-array.edn
        let key: [u8; 16] = hex::decode("a061c27a3273721e210d031863ad81b6").unwrap().try_into().unwrap();
        let nonce: [u8; 12] = hex::decode("95d0040fe650e5baf51c907c").unwrap().try_into().unwrap();
        let ciphertext = hex::decode("563a7d9f0f65d40b751fbc3fcc408e8fe27c375b60a4727b1f1e9572c07992eb5ec5a9").unwrap();
        let tag = hex::decode("9f4d37da32187528416ed7ee95e0625f").unwrap();

        // see draft-ietf-spice-sd-cwt/examples/first-disclosure.edn
        let salt: [u8; 16] = hex::decode("bae611067bb823486797da1ebbb52f83").unwrap().try_into().unwrap();
        let disclosure = SaltedEntry::Claim(SaltedClaim {
            salt: Salt(salt),
            value: Value::from("ABCD-123456"),
            name: SdCwtClaim::Int(501),
        });
        let disclosure = InlinedCbor::from_bytes(disclosure.to_cbor_bytes().unwrap());
        let plaintext = disclosure_to_plaintext(&disclosure).unwrap();

        // encryption
        let sealed = seal(&key, &nonce, &plaintext);
        assert_eq!(sealed.ciphertext, ciphertext);
        assert_eq!(sealed.tag, tag);

        // decryption
        let encrypted = AeadEncryptedDisclosure {
            nonce: nonce.to_vec().into(),
            ciphertext: ciphertext.into(),
            tag: tag.into(),
            key_context: None,
        };
        let decrypted = open(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
        assert_eq!(disclosure_from_plaintext(&decrypted).unwrap(), disclosure);
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_reveal_encrypted_disclosures_with_key() {
        let ctx = issue();
        let encryptor = TestEncryptor::new(KEY);
        let encryption = DisclosureEncryption {
            encryptor: &encryptor,
            key_context: None,
            select: Box::new(|p| p == path(&["name"]).as_slice() || p == [CborPath::Str("array".into()), CborPath::Index(1)]),
        };
        let sd_kbt = ctx.present(Some(encryption));

        let kbt = decode(&sd_kbt);
        let sd_cwt = kbt.sd_cwt().unwrap();
        assert_eq!(sd_cwt.encrypted_disclosures().unwrap().len(), 2);
        assert_eq!(sd_cwt.disclosures().unwrap().len(), NB_DISCLOSURES - 2);
        assert_eq!(sd_cwt.sd_unprotected.sd_aead, Some(AeadAlgorithm::AES_128_GCM));

        let claimset = ctx.verify(&AeadVerifier::with_key(KEY), &sd_kbt).unwrap();
        assert_eq!(claimset, sorted(fully_disclosed()));

        // also when the Verifier has many keys
        let verifier = AeadVerifier { keys: vec![OTHER_KEY, KEY] };
        assert_eq!(ctx.verify(&verifier, &sd_kbt).unwrap(), sorted(fully_disclosed()));

        // same as a plaintext presentation
        let plaintext_claimset = ctx.verify(&AeadVerifier::default(), &ctx.present(None)).unwrap();
        assert_eq!(claimset, plaintext_claimset);
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_keep_encrypted_disclosures_redacted_without_key() {
        let ctx = issue();
        let encryptor = TestEncryptor::new(KEY);
        let encryption = DisclosureEncryption {
            encryptor: &encryptor,
            key_context: None,
            select: Box::new(|p| p == path(&["name"]).as_slice() || p == [CborPath::Str("array".into()), CborPath::Index(1)]),
        };
        let sd_kbt = ctx.present(Some(encryption));

        let expected = sorted(
            cbor!({
                "age" => 42,
                "address" => { "city" => "Paris", "country" => "FR" },
                "nested" => { "inner" => "secret", "visible" => true },
                "array" => ["a"],
            })
            .unwrap(),
        );
        // no key
        assert_eq!(ctx.verify(&AeadVerifier::default(), &sd_kbt).unwrap(), expected);
        // wrong key
        assert_eq!(ctx.verify(&AeadVerifier::with_key(OTHER_KEY), &sd_kbt).unwrap(), expected);
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_encrypt_all_disclosures() {
        let ctx = issue();
        let encryptor = TestEncryptor::new(KEY);
        let encryption = DisclosureEncryption {
            encryptor: &encryptor,
            key_context: None,
            select: Box::new(|_| true),
        };
        let sd_kbt = ctx.present(Some(encryption));

        let kbt = decode(&sd_kbt);
        let sd_cwt = kbt.sd_cwt().unwrap();
        // an empty 'sd_claims' is invalid
        assert!(sd_cwt.disclosures().is_none());
        assert_eq!(sd_cwt.encrypted_disclosures().unwrap().len(), NB_DISCLOSURES);

        assert_eq!(ctx.verify(&AeadVerifier::with_key(KEY), &sd_kbt).unwrap(), sorted(fully_disclosed()));

        let expected = sorted(cbor!({ "address" => { "country" => "FR" }, "array" => ["a"] }).unwrap());
        assert_eq!(ctx.verify(&AeadVerifier::default(), &sd_kbt).unwrap(), expected);
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_also_encrypt_disclosures_nested_in_encrypted_ones() {
        let ctx = issue();
        let encryptor = TestEncryptor::new(KEY);
        let sd_kbt = ctx.present(Some(encrypt_paths(&encryptor, vec![path(&["nested"])])));

        // 'nested' and 'inner'
        assert_eq!(encrypted_disclosures(&sd_kbt).len(), 2);

        assert_eq!(ctx.verify(&AeadVerifier::with_key(KEY), &sd_kbt).unwrap(), sorted(fully_disclosed()));

        // 'inner' is not an orphan disclosure for a Verifier not able to decrypt 'nested'
        let expected = sorted(
            cbor!({
                "name" => "Alice Smith",
                "age" => 42,
                "address" => { "city" => "Paris", "country" => "FR" },
                "array" => ["a", "b"],
            })
            .unwrap(),
        );
        assert_eq!(ctx.verify(&AeadVerifier::default(), &sd_kbt).unwrap(), expected);
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_encrypt_disclosure_nested_in_plaintext_one() {
        let ctx = issue();
        let encryptor = TestEncryptor::new(KEY);
        let sd_kbt = ctx.present(Some(encrypt_paths(&encryptor, vec![path(&["nested", "inner"]), path(&["address", "city"])])));

        assert_eq!(encrypted_disclosures(&sd_kbt).len(), 2);
        assert_eq!(ctx.verify(&AeadVerifier::with_key(KEY), &sd_kbt).unwrap(), sorted(fully_disclosed()));

        let expected = sorted(
            cbor!({
                "name" => "Alice Smith",
                "age" => 42,
                "address" => { "country" => "FR" },
                "nested" => { "visible" => true },
                "array" => ["a", "b"],
            })
            .unwrap(),
        );
        assert_eq!(ctx.verify(&AeadVerifier::default(), &sd_kbt).unwrap(), expected);
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_only_encrypt_presented_disclosures() {
        let ctx = issue();
        let encryptor = TestEncryptor::new(KEY);
        let encryption = DisclosureEncryption {
            encryptor: &encryptor,
            key_context: None,
            select: Box::new(|_| true),
        };
        let sd_kbt = ctx
            .try_present(Presentation::Path(Box::new(|p| p == path(&["name"]).as_slice())), Some(encryption))
            .unwrap();

        assert!(decode(&sd_kbt).sd_cwt().unwrap().disclosures().is_none());
        assert_eq!(encrypted_disclosures(&sd_kbt).len(), 1);

        let expected = sorted(
            cbor!({
                "name" => "Alice Smith",
                "address" => { "country" => "FR" },
                "array" => ["a"],
            })
            .unwrap(),
        );
        assert_eq!(ctx.verify(&AeadVerifier::with_key(KEY), &sd_kbt).unwrap(), expected);
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_carry_key_context() {
        let ctx = issue();
        let encryptor = TestEncryptor::new(KEY);
        let key_contexts = [
            AeadKeyContext::Uint(42),
            AeadKeyContext::Text("verifier-key".into()),
            AeadKeyContext::Thumbprint(vec![0xab; 32].into()),
        ];
        for key_context in key_contexts {
            let encryption = DisclosureEncryption {
                encryptor: &encryptor,
                key_context: Some(key_context.clone()),
                select: Box::new(|_| true),
            };
            let sd_kbt = ctx.present(Some(encryption));
            let encrypted = encrypted_disclosures(&sd_kbt);
            assert_eq!(encrypted.len(), NB_DISCLOSURES);
            assert!(encrypted.iter().all(|e| e.key_context.as_ref() == Some(&key_context)));
            assert_eq!(ctx.verify(&AeadVerifier::with_key(KEY), &sd_kbt).unwrap(), sorted(fully_disclosed()));
        }
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_not_add_aead_headers_when_nothing_encrypted() {
        let ctx = issue();
        let encryptor = TestEncryptor::new(KEY);
        let encryption = DisclosureEncryption {
            encryptor: &encryptor,
            key_context: None,
            select: Box::new(|_| false),
        };
        let sd_kbt = ctx.present(Some(encryption));
        let kbt = decode(&sd_kbt);
        let sd_cwt = kbt.sd_cwt().unwrap();
        assert!(sd_cwt.encrypted_disclosures().is_none());
        assert!(sd_cwt.sd_unprotected.sd_aead.is_none());
        assert_eq!(sd_cwt.disclosures().unwrap().len(), NB_DISCLOSURES);
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_omit_empty_sd_claims() {
        let ctx = issue();
        let sd_kbt = ctx.try_present(Presentation::None, None).unwrap();
        let kbt = decode(&sd_kbt);
        let sd_cwt = kbt.sd_cwt().unwrap();
        assert!(sd_cwt.disclosures().is_none());
        assert!(sd_cwt.encrypted_disclosures().is_none());

        // undisclosed claims are removed
        let expected = sorted(cbor!({ "address" => { "country" => "FR" }, "array" => ["a"] }).unwrap());
        assert_eq!(ctx.verify(&AeadVerifier::default(), &sd_kbt).unwrap(), expected);
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn holder_should_reject_forbidden_algorithm() {
        let ctx = issue();
        let mut encryptor = TestEncryptor::new(KEY);
        // AEAD_AES_128_GCM_8
        encryptor.alg = AeadAlgorithm(5);
        let encryption = encrypt_paths(&encryptor, vec![path(&["name"])]);
        let err = ctx.try_present(Presentation::Full, Some(encryption)).unwrap_err();
        std::assert_matches!(err, SdCwtHolderError::SpecError(EsdicawtSpecError::ForbiddenAeadAlgorithm(5)));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn holder_should_reject_short_tag() {
        let ctx = issue();
        let mut encryptor = TestEncryptor::new(KEY);
        encryptor.tag_len = 12;
        let encryption = encrypt_paths(&encryptor, vec![path(&["name"])]);
        let err = ctx.try_present(Presentation::Full, Some(encryption)).unwrap_err();
        std::assert_matches!(err, SdCwtHolderError::SpecError(EsdicawtSpecError::InvalidAeadTagLength { alg: 1, len: 12 }));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn holder_should_propagate_encryption_error() {
        let ctx = issue();
        let mut encryptor = TestEncryptor::new(KEY);
        encryptor.fail = true;
        let encryption = encrypt_paths(&encryptor, vec![path(&["name"])]);
        let err = ctx.try_present(Presentation::Full, Some(encryption)).unwrap_err();
        std::assert_matches!(err, SdCwtHolderError::EncryptionError(_));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn holder_should_reject_issued_sd_cwt_with_aead_headers() {
        let ctx = issue();
        let encrypted = Value::serialized(&vec![encrypted(&KEY, &[0x41, 0x00])]).unwrap();
        for (label, value) in [(COSE_HEADER_SD_AEAD_ENCRYPTED_CLAIMS, encrypted), (COSE_HEADER_SD_AEAD, Value::from(1))] {
            // the unprotected header is not signed by the Issuer
            let mut sign1 = coset::CoseSign1::from_tagged_slice(&ctx.sd_cwt).unwrap();
            sign1.unprotected.rest.push((coset::Label::Int(label), value));
            let sd_cwt = sign1.to_tagged_vec().unwrap();

            let err = ctx.holder.verify_sd_cwt(&sd_cwt, Default::default(), &ctx.cks).unwrap_err();
            std::assert_matches!(err, SdCwtHolderError::ValidationError(SdCwtHolderValidationError::UnexpectedEncryptedDisclosures));
        }
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn verifier_should_default_to_aes_128_gcm() {
        let ctx = issue();
        let encryptor = TestEncryptor::new(KEY);
        let sd_kbt = ctx.present(Some(encrypt_paths(&encryptor, vec![path(&["name"])])));
        let sd_kbt = ctx.tamper(&sd_kbt, |unprotected| unprotected.retain(|(k, _)| *k != Value::from(COSE_HEADER_SD_AEAD)));
        assert!(decode(&sd_kbt).sd_cwt().unwrap().sd_unprotected.sd_aead.is_none());

        assert_eq!(ctx.verify(&AeadVerifier::with_key(KEY), &sd_kbt).unwrap(), sorted(fully_disclosed()));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn verifier_should_skip_unsupported_algorithm() {
        let ctx = issue();
        let encryptor = TestEncryptor::new(KEY);
        let sd_kbt = ctx.present(Some(encrypt_paths(&encryptor, vec![path(&["name"])])));
        // AEAD_AES_256_GCM, not supported by the test Verifier
        let sd_kbt = ctx.tamper(&sd_kbt, |unprotected| *label(unprotected, COSE_HEADER_SD_AEAD).unwrap() = Value::from(2));

        let claimset = ctx.verify(&AeadVerifier::with_key(KEY), &sd_kbt).unwrap();
        assert!(!claimset.as_map().unwrap().iter().any(|(k, _)| *k == Value::from("name")));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn verifier_should_reject_forbidden_algorithm() {
        let ctx = issue();
        let encryptor = TestEncryptor::new(KEY);
        let sd_kbt = ctx.present(Some(encrypt_paths(&encryptor, vec![path(&["name"])])));
        // AEAD_AES_128_GCM_8
        let sd_kbt = ctx.tamper(&sd_kbt, |unprotected| *label(unprotected, COSE_HEADER_SD_AEAD).unwrap() = Value::from(5));

        // even when unable to decrypt
        let err = ctx.verify(&AeadVerifier::default(), &sd_kbt).unwrap_err();
        std::assert_matches!(err, SdCwtVerifierError::SpecError(EsdicawtSpecError::ForbiddenAeadAlgorithm(5)));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn verifier_should_reject_short_tag() {
        let ctx = issue();
        let encryptor = TestEncryptor::new(KEY);
        let sd_kbt = ctx.present(Some(encrypt_paths(&encryptor, vec![path(&["name"])])));
        let sd_kbt = ctx.tamper(&sd_kbt, |unprotected| {
            let encrypted = label(unprotected, COSE_HEADER_SD_AEAD_ENCRYPTED_CLAIMS).unwrap().as_array_mut().unwrap();
            let tag = encrypted.first_mut().unwrap().as_array_mut().unwrap().get_mut(2).unwrap().as_bytes_mut().unwrap();
            tag.truncate(12);
        });

        let err = ctx.verify(&AeadVerifier::default(), &sd_kbt).unwrap_err();
        std::assert_matches!(err, SdCwtVerifierError::SpecError(EsdicawtSpecError::InvalidAeadTagLength { alg: 1, len: 12 }));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn verifier_should_reject_disclosure_both_in_plaintext_and_encrypted() {
        let ctx = issue();
        let sd_kbt = ctx.present(None);
        let disclosure = decode(&sd_kbt).sd_cwt().unwrap().disclosures().unwrap().first().unwrap().clone();
        let plaintext = disclosure_to_plaintext(&disclosure).unwrap();
        let sd_kbt = ctx.tamper(&sd_kbt, |unprotected| {
            unprotected.push((
                Value::from(COSE_HEADER_SD_AEAD_ENCRYPTED_CLAIMS),
                Value::serialized(&vec![encrypted(&KEY, &plaintext)]).unwrap(),
            ));
        });

        let err = ctx.verify(&AeadVerifier::with_key(KEY), &sd_kbt).unwrap_err();
        std::assert_matches!(err, SdCwtVerifierError::SpecError(EsdicawtSpecError::DuplicateDisclosure));

        // not detectable when unable to decrypt
        ctx.verify(&AeadVerifier::default(), &sd_kbt).unwrap();
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn verifier_should_reject_encrypted_orphan_disclosure() {
        let ctx = issue();
        let sd_kbt = ctx.present(None);
        let orphan = SaltedEntry::Element(SaltedElement {
            salt: Salt::empty(),
            value: Value::from("orphan"),
        });
        let plaintext = disclosure_to_plaintext(&InlinedCbor::from_bytes(orphan.to_cbor_bytes().unwrap())).unwrap();
        let sd_kbt = ctx.tamper(&sd_kbt, |unprotected| {
            unprotected.push((
                Value::from(COSE_HEADER_SD_AEAD_ENCRYPTED_CLAIMS),
                Value::serialized(&vec![encrypted(&KEY, &plaintext)]).unwrap(),
            ));
        });

        let err = ctx.verify(&AeadVerifier::with_key(KEY), &sd_kbt).unwrap_err();
        std::assert_matches!(err, SdCwtVerifierError::OrphanDisclosure);
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn verifier_should_reject_invalid_decrypted_disclosure() {
        let ctx = issue();
        let sd_kbt = ctx.present(None);
        let disclosure = decode(&sd_kbt).sd_cwt().unwrap().disclosures().unwrap().first().unwrap().clone();
        // the raw disclosure, not wrapped in a bstr
        let plaintext = disclosure.to_bytes().unwrap().to_vec();
        let sd_kbt = ctx.tamper(&sd_kbt, |unprotected| {
            unprotected.push((
                Value::from(COSE_HEADER_SD_AEAD_ENCRYPTED_CLAIMS),
                Value::serialized(&vec![encrypted(&KEY, &plaintext)]).unwrap(),
            ));
        });

        let err = ctx.verify(&AeadVerifier::with_key(KEY), &sd_kbt).unwrap_err();
        std::assert_matches!(err, SdCwtVerifierError::SpecError(EsdicawtSpecError::InvalidDecryptedDisclosure));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn verifier_should_reject_empty_arrays() {
        let ctx = issue();
        let sd_kbt = ctx.present(None);
        let empty_encrypted = ctx.tamper(&sd_kbt, |unprotected| {
            unprotected.push((Value::from(COSE_HEADER_SD_AEAD_ENCRYPTED_CLAIMS), Value::Array(vec![])))
        });
        assert!(ctx.verify(&AeadVerifier::with_key(KEY), &empty_encrypted).is_err());

        let empty_sd_claims = ctx.tamper(&sd_kbt, |unprotected| *label(unprotected, COSE_HEADER_SD_CLAIMS).unwrap() = Value::Array(vec![]));
        assert!(ctx.verify(&AeadVerifier::default(), &empty_sd_claims).is_err());
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn tamper_should_produce_valid_tokens() {
        // ensures the failures above are not caused by the tampering itself
        let ctx = issue();
        let sd_kbt = ctx.present(None);
        let sd_kbt = ctx.tamper(&sd_kbt, |_| {});
        assert_eq!(ctx.verify(&AeadVerifier::default(), &sd_kbt).unwrap(), sorted(fully_disclosed()));
    }
}
