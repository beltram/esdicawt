//! Encrypted disclosures with the AEAD of the [Holder](crate::Holder) and the [Verifier](crate::Verifier) from the [aead] crate.
//!
//! See https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html#name-encrypted-disclosures
use crate::{
    CborPath, SdCwtHolderError, SdCwtHolderResult, SdCwtVerifierError,
    holder::traverse::traverse_all_cbor_paths_in_salted_array,
    spec::{
        CustomClaims,
        aead::{AeadAlgorithm, AeadEncryptedArray, AeadEncryptedDisclosure, AeadKeyContext, disclosure_from_plaintext, disclosure_to_plaintext},
        blinded_claims::SaltedArray,
        issuance::SdUnprotected,
    },
    verifier::DecryptDisclosures,
};
use ::aead::{AeadInPlace, Nonce, Tag, generic_array::typenum::Unsigned as _};
use ciborium::Value;
use std::{borrow::Cow, rc::Rc};

/// Which of the presented disclosures get encrypted.
/// They are then moved from `sd_claims` to `sd_aead_encrypted_claims`.
///
/// See https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html#name-encrypted-disclosures
pub struct DisclosureEncryption {
    /// Optional context added to every encrypted disclosure to help the Verifier select the correct key
    pub key_context: Option<AeadKeyContext>,
    /// The presented disclosures whose path, from the root of the payload, is accepted by the function get encrypted,
    /// along with the disclosures nested in them
    #[allow(clippy::type_complexity)]
    pub select: Box<dyn Fn(&[CborPath]) -> bool>,
}

impl DisclosureEncryption {
    /// Moves the selected disclosures from `sd_claims` to `sd_aead_encrypted_claims`, encrypted with `key` which
    /// implements `alg`
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn try_encrypt<A: AeadInPlace, Extra: CustomClaims, E: core::error::Error + Send + Sync>(
        &self,
        alg: AeadAlgorithm,
        key: &A,
        csprng: &mut dyn rand_core::CryptoRngCore,
        payload: &Value,
        unprotected: &mut SdUnprotected<Extra>,
        hasher: &Rc<dyn digest::DynDigest>,
    ) -> SdCwtHolderResult<(), E> {
        alg.check_tag_len(A::TagSize::USIZE)?;
        let Some(disclosures) = unprotected.sd_claims.as_mut() else { return Ok(()) };
        let selected = {
            let hashed_disclosures = disclosures.digested_detached_hasher(hasher)?;
            // paths start at the root of the payload, hence disclosures not reachable from it are never encrypted
            let cbor_paths = traverse_all_cbor_paths_in_salted_array::<E>(payload, &hashed_disclosures, hasher)?;
            let encrypted_paths = cbor_paths.iter().filter(|(path, _)| (self.select)(path)).map(|(path, _)| path.clone()).collect::<Vec<_>>();
            // the disclosures nested in an encrypted one are also encrypted. Otherwise, a Verifier unable to decrypt the
            // parent would consider them orphans and reject the whole presentation
            cbor_paths
                .into_iter()
                .filter_map(|(path, salted)| encrypted_paths.iter().any(|encrypted| path.starts_with(encrypted)).then_some(salted))
                .collect::<Vec<_>>()
        };
        // salts being unique, comparing the decoded disclosures is enough. This preserves the raw bytes of the disclosures
        let encrypted = disclosures
            .extract_if(.., |d| d.to_value().is_ok_and(|d| selected.contains(d)))
            .map(|disclosure| {
                // a unique, random nonce of N_MIN octets
                let mut nonce = Nonce::<A>::default();
                csprng.fill_bytes(&mut nonce);
                let (ciphertext, tag) = seal(key, &nonce, disclosure_to_plaintext(&disclosure)?).map_err(SdCwtHolderError::EncryptionError)?;
                Ok(AeadEncryptedDisclosure {
                    nonce: nonce.to_vec(),
                    ciphertext,
                    tag,
                    key_context: self.key_context.clone(),
                })
            })
            .collect::<SdCwtHolderResult<Vec<_>, E>>()?;

        if let Some(encrypted) = AeadEncryptedArray::new(encrypted) {
            unprotected.sd_aead_encrypted_claims = Some(encrypted);
            unprotected.sd_aead = Some(alg);
        }
        Ok(())
    }
}

impl std::fmt::Debug for DisclosureEncryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DisclosureEncryption").field("key_context", &self.key_context).finish_non_exhaustive()
    }
}

/// The key a Verifier decrypts the encrypted disclosures with
pub struct DisclosureDecryption<'a, A: AeadInPlace> {
    /// The algorithm `key` implements
    pub alg: AeadAlgorithm,
    pub key: &'a A,
    /// Only the encrypted disclosures with this key context are decrypted with `key`
    pub key_context: Option<&'a AeadKeyContext>,
}

impl<A: AeadInPlace> DecryptDisclosures for DisclosureDecryption<'_, A> {
    /// Appends the encrypted disclosures `key` is for to the plaintext ones, so that they are processed as if they were
    /// in `sd_claims`.
    /// See https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html#name-kbt-and-sd-cwt-verifier-val
    fn decrypt<'d, Extra: CustomClaims, E: core::error::Error + Send + Sync>(
        &self,
        unprotected: &SdUnprotected<Extra>,
        disclosures: &'d SaltedArray,
    ) -> Result<Cow<'d, SaltedArray>, SdCwtVerifierError<E>> {
        let Some(encrypted_disclosures) = &unprotected.sd_aead_encrypted_claims else {
            return Ok(Cow::Borrowed(disclosures));
        };
        let alg = unprotected.sd_aead.unwrap_or_default();
        // the encrypted disclosures with another algorithm are ignored
        let supported = alg == self.alg;
        let mut disclosures = disclosures.clone();
        for encrypted in encrypted_disclosures.iter() {
            // the encrypted disclosures for another key are ignored. Failing to decrypt the others invalidates the SD-CWT
            if supported && encrypted.key_context.as_ref() == self.key_context {
                let plaintext = open(self.key, encrypted).map_err(SdCwtVerifierError::DecryptionError)?;
                disclosures.push(disclosure_from_plaintext(&plaintext)?);
            }
        }
        Ok(Cow::Owned(disclosures))
    }
}

/// Returns the ciphertext and the authentication tag. The associated data is zero-length
fn seal<A: AeadInPlace>(key: &A, nonce: &Nonce<A>, mut plaintext: Vec<u8>) -> ::aead::Result<(Vec<u8>, Vec<u8>)> {
    let tag = key.encrypt_in_place_detached(nonce, b"", &mut plaintext)?;
    Ok((plaintext, tag.to_vec()))
}

/// Reverse of [seal]. A nonce or a tag of the wrong length is a decryption failure
fn open<A: AeadInPlace>(key: &A, encrypted: &AeadEncryptedDisclosure) -> ::aead::Result<Vec<u8>> {
    let nonce = exact::<Nonce<A>>(&encrypted.nonce).ok_or(::aead::Error)?;
    let tag = exact::<Tag<A>>(&encrypted.tag).ok_or(::aead::Error)?;
    let mut plaintext = encrypted.ciphertext.clone();
    key.decrypt_in_place_detached(&nonce, b"", &mut plaintext, &tag)?;
    Ok(plaintext)
}

/// [None] when of the wrong length
fn exact<T: Default + std::ops::DerefMut<Target = [u8]>>(bytes: &[u8]) -> Option<T> {
    let mut array = T::default();
    (array.len() == bytes.len()).then(|| {
        array.copy_from_slice(bytes);
        array
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CborPath, DisclosureEncryption, Holder, HolderParams, Issuer, IssuerParams, KbtIatOrCti, Presentation, SdCwtHolderError, SdCwtHolderValidationError, SdCwtVerifierError,
        StatusParams, TimeArg, Verifier, VerifierParams,
        spec::{
            COSE_HEADER_KCWT, COSE_HEADER_SD_AEAD, COSE_HEADER_SD_AEAD_ENCRYPTED_CLAIMS, CwtAny, EsdicawtSpecError, NoClaims, Salt, SdCwtClaim, SdHashAlg,
            aead::{AeadEncryptedDisclosure, AeadKeyContext, disclosure_from_plaintext, disclosure_to_plaintext},
            blinded_claims::{SaltedClaim, SaltedElement, SaltedEntry},
            inlined_cbor::InlinedCbor,
            issuance::SdCwtIssued,
            key_binding::KbtCwt,
            reexports::coset::{self, TaggedCborSerializable as _},
            sd,
        },
        test_utils::{Ed25519Holder, Ed25519Issuer},
    };
    use ::aead::{
        AeadCore, KeyInit as _,
        consts::{U0, U12, U16},
    };
    use ciborium::{Value, cbor};
    use cose_key::keyset::CoseKeySet;
    use ed25519_dalek::Signer as _;
    use std::convert::Infallible;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    const SUBJECT: &str = "https://example.com/u/alice.smith";
    const KEY: [u8; 16] = [0x11; 16];
    const OTHER_KEY: [u8; 16] = [0x22; 16];

    fn cipher(key: [u8; 16]) -> aes_gcm::Aes128Gcm {
        aes_gcm::Aes128Gcm::new(&key.into())
    }

    fn encrypted(key: [u8; 16], plaintext: &[u8]) -> AeadEncryptedDisclosure {
        let nonce = [7; 12];
        let (ciphertext, tag) = seal(&cipher(key), &nonce.into(), plaintext.to_vec()).unwrap();
        AeadEncryptedDisclosure {
            nonce: nonce.to_vec(),
            ciphertext,
            tag,
            key_context: None,
        }
    }

    /// Only supports AEAD_AES_128_GCM
    struct AeadVerifier;

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
        type Aead = aes_gcm::Aes128Gcm;

        fn aead_algorithm(&self) -> AeadAlgorithm {
            AeadAlgorithm::AES_128_GCM
        }
    }

    /// Fails to encrypt
    struct FailingCipher;

    impl AeadCore for FailingCipher {
        type NonceSize = U12;
        type TagSize = U16;
        type CiphertextOverhead = U0;
    }

    impl AeadInPlace for FailingCipher {
        fn encrypt_in_place_detached(&self, _: &Nonce<Self>, _: &[u8], _: &mut [u8]) -> ::aead::Result<Tag<Self>> {
            Err(::aead::Error)
        }

        fn decrypt_in_place_detached(&self, _: &Nonce<Self>, _: &[u8], _: &mut [u8], _: &Tag<Self>) -> ::aead::Result<()> {
            Err(::aead::Error)
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

    fn encrypt_if(select: impl Fn(&[CborPath]) -> bool + 'static) -> DisclosureEncryption {
        DisclosureEncryption {
            key_context: None,
            select: Box::new(select),
        }
    }

    fn encrypt_paths(paths: Vec<Vec<CborPath>>) -> DisclosureEncryption {
        encrypt_if(move |p| paths.iter().any(|expected| expected == p))
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
            subject: SUBJECT.into(),
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

    fn holder_params(presentation: Presentation) -> HolderParams<'static> {
        HolderParams {
            presentation,
            audience: "https://example.com/r/alice-bob-group",
            cnonce: None,
            iat_or_cti: KbtIatOrCti::Iat {
                expiry: Some(TimeArg::Relative(core::time::Duration::from_secs(3600))),
                with_not_before: false,
                cti: None,
            },
            artificial_time: None,
            time_verification: Default::default(),
            leeway: Default::default(),
            extra_kbt_protected: None,
            extra_kbt_unprotected: None,
            extra_kbt_payload: None,
        }
    }

    type TestKbt = KbtCwt<Value, sha2::Sha256>;

    fn verifier_params() -> VerifierParams<'static> {
        VerifierParams {
            expected_subject: SUBJECT,
            ..Default::default()
        }
    }

    impl Context {
        /// Encrypts with [KEY]
        fn try_present(&self, presentation: Presentation, encryption: Option<DisclosureEncryption>) -> Result<Vec<u8>, SdCwtHolderError<Infallible>> {
            let sd_cwt = self.holder.verify_sd_cwt(&self.sd_cwt, Default::default(), &self.cks).unwrap();
            match encryption {
                Some(encryption) => self
                    .holder
                    .new_encrypted_presentation_raw(&mut rand::thread_rng(), sd_cwt, holder_params(presentation), &encryption, &cipher(KEY)),
                None => self.holder.new_presentation_raw(sd_cwt, holder_params(presentation)),
            }
        }

        /// Encrypts the disclosures of the issued SD-CWT with an arbitrary AEAD_AES_128_GCM implementation
        fn try_encrypt(&self, encryption: &DisclosureEncryption, key: &impl AeadInPlace) -> SdCwtHolderResult<(), Infallible> {
            let mut sd_cwt = SdCwtIssued::<Value, sha2::Sha256>::from_cbor_bytes(&self.sd_cwt).unwrap();
            let payload = sd_cwt.payload.upcast_value().unwrap();
            let hasher = crate::default_digest(SdHashAlg::Sha256).unwrap();
            encryption.try_encrypt(AeadAlgorithm::AES_128_GCM, key, &mut rand::thread_rng(), &payload, &mut sd_cwt.sd_unprotected, &hasher)
        }

        fn present(&self, encryption: Option<DisclosureEncryption>) -> Vec<u8> {
            self.try_present(Presentation::Full, encryption).unwrap()
        }

        /// Without a key
        fn verify(&self, sd_kbt: &[u8]) -> Result<Value, SdCwtVerifierError<Infallible>> {
            let verified = AeadVerifier.verify_sd_kbt(sd_kbt, &verifier_params(), Some(&self.holder_signing_key.verifying_key()), &self.cks)?;
            Ok(sorted(verified.claimset.unwrap()))
        }

        /// With a key for the encrypted disclosures with `key_context`
        fn decrypt(&self, sd_kbt: &[u8], key: [u8; 16], key_context: Option<&AeadKeyContext>) -> Result<Value, SdCwtVerifierError<Infallible>> {
            let holder_verifier = self.holder_signing_key.verifying_key();
            let verified = AeadVerifier.verify_encrypted_sd_kbt(sd_kbt, &verifier_params(), Some(&holder_verifier), &self.cks, &cipher(key), key_context)?;
            Ok(sorted(verified.claimset.unwrap()))
        }

        /// Adds a disclosure encrypted with [KEY] to the SD-KBT
        fn with_encrypted(&self, sd_kbt: &[u8], plaintext: &[u8]) -> Vec<u8> {
            let encrypted = Value::serialized(&vec![encrypted(KEY, plaintext)]).unwrap();
            self.tamper(sd_kbt, |unprotected| unprotected.push((Value::from(COSE_HEADER_SD_AEAD_ENCRYPTED_CLAIMS), encrypted)))
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
        let (sealed, sealed_tag) = seal(&cipher(key), &nonce.into(), plaintext.clone()).unwrap();
        assert_eq!(sealed, ciphertext);
        assert_eq!(sealed_tag, tag);

        // decryption
        let encrypted = AeadEncryptedDisclosure {
            nonce: nonce.to_vec(),
            ciphertext,
            tag,
            key_context: None,
        };
        let decrypted = open(&cipher(key), &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
        assert_eq!(disclosure_from_plaintext(&decrypted).unwrap(), disclosure);
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_reveal_encrypted_disclosures_with_key() {
        let ctx = issue();
        let encryption = encrypt_if(|p| p == path(&["name"]).as_slice() || p == [CborPath::Str("array".into()), CborPath::Index(1)]);
        let sd_kbt = ctx.present(Some(encryption));

        let kbt = decode(&sd_kbt);
        let sd_cwt = kbt.sd_cwt().unwrap();
        assert_eq!(sd_cwt.encrypted_disclosures().unwrap().len(), 2);
        assert_eq!(sd_cwt.disclosures().unwrap().len(), NB_DISCLOSURES - 2);
        assert_eq!(sd_cwt.sd_unprotected.sd_aead, Some(AeadAlgorithm::AES_128_GCM));

        let claimset = ctx.decrypt(&sd_kbt, KEY, None).unwrap();
        assert_eq!(claimset, sorted(fully_disclosed()));

        // same as a plaintext presentation
        let plaintext_claimset = ctx.verify(&ctx.present(None)).unwrap();
        assert_eq!(claimset, plaintext_claimset);
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_keep_encrypted_disclosures_redacted_without_key() {
        let ctx = issue();
        let encryption = encrypt_if(|p| p == path(&["name"]).as_slice() || p == [CborPath::Str("array".into()), CborPath::Index(1)]);
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
        assert_eq!(ctx.verify(&sd_kbt).unwrap(), expected);
        // only a key for another key context
        assert_eq!(ctx.decrypt(&sd_kbt, KEY, Some(&AeadKeyContext::Uint(1))).unwrap(), expected);
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_encrypt_all_disclosures() {
        let ctx = issue();
        let encryption = encrypt_if(|_| true);
        let sd_kbt = ctx.present(Some(encryption));

        let kbt = decode(&sd_kbt);
        let sd_cwt = kbt.sd_cwt().unwrap();
        // an empty 'sd_claims' is invalid
        assert!(sd_cwt.disclosures().is_none());
        assert_eq!(sd_cwt.encrypted_disclosures().unwrap().len(), NB_DISCLOSURES);

        assert_eq!(ctx.decrypt(&sd_kbt, KEY, None).unwrap(), sorted(fully_disclosed()));

        let expected = sorted(cbor!({ "address" => { "country" => "FR" }, "array" => ["a"] }).unwrap());
        assert_eq!(ctx.verify(&sd_kbt).unwrap(), expected);
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_also_encrypt_disclosures_nested_in_encrypted_ones() {
        let ctx = issue();
        let sd_kbt = ctx.present(Some(encrypt_paths(vec![path(&["nested"])])));

        // 'nested' and 'inner'
        assert_eq!(encrypted_disclosures(&sd_kbt).len(), 2);

        assert_eq!(ctx.decrypt(&sd_kbt, KEY, None).unwrap(), sorted(fully_disclosed()));

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
        assert_eq!(ctx.verify(&sd_kbt).unwrap(), expected);
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_encrypt_disclosure_nested_in_plaintext_one() {
        let ctx = issue();
        let sd_kbt = ctx.present(Some(encrypt_paths(vec![path(&["nested", "inner"]), path(&["address", "city"])])));

        assert_eq!(encrypted_disclosures(&sd_kbt).len(), 2);
        assert_eq!(ctx.decrypt(&sd_kbt, KEY, None).unwrap(), sorted(fully_disclosed()));

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
        assert_eq!(ctx.verify(&sd_kbt).unwrap(), expected);
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_only_encrypt_presented_disclosures() {
        let ctx = issue();
        let encryption = encrypt_if(|_| true);
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
        assert_eq!(ctx.decrypt(&sd_kbt, KEY, None).unwrap(), expected);
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_carry_key_context() {
        let ctx = issue();
        let key_contexts = [
            AeadKeyContext::Uint(0),
            AeadKeyContext::Text("verifier-key".into()),
            AeadKeyContext::Thumbprint([0xab; 32].into()),
        ];
        for key_context in key_contexts {
            let encryption = DisclosureEncryption {
                key_context: Some(key_context.clone()),
                ..encrypt_if(|_| true)
            };
            let sd_kbt = ctx.present(Some(encryption));
            let encrypted = encrypted_disclosures(&sd_kbt);
            assert_eq!(encrypted.len(), NB_DISCLOSURES);
            assert!(encrypted.iter().all(|e| e.key_context.as_ref() == Some(&key_context)));
            assert_eq!(ctx.decrypt(&sd_kbt, KEY, Some(&key_context)).unwrap(), sorted(fully_disclosed()));
            // no key for that key context
            assert_eq!(
                ctx.decrypt(&sd_kbt, KEY, None).unwrap(),
                sorted(cbor!({ "address" => { "country" => "FR" }, "array" => ["a"] }).unwrap())
            );
        }
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_not_add_aead_headers_when_nothing_encrypted() {
        let ctx = issue();
        let encryption = encrypt_if(|_| false);
        let sd_kbt = ctx.present(Some(encryption));
        let kbt = decode(&sd_kbt);
        let sd_cwt = kbt.sd_cwt().unwrap();
        assert!(sd_cwt.encrypted_disclosures().is_none());
        assert!(sd_cwt.sd_unprotected.sd_aead.is_none());
        assert_eq!(sd_cwt.disclosures().unwrap().len(), NB_DISCLOSURES);
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn holder_should_reject_short_tag() {
        // AEAD_AES_128_GCM with a 12 octets tag
        let key = aes_gcm::AesGcm::<aes_gcm::aes::Aes128, U12, U12>::new(&KEY.into());
        let err = issue().try_encrypt(&encrypt_paths(vec![path(&["name"])]), &key).unwrap_err();
        std::assert_matches!(err, SdCwtHolderError::SpecError(EsdicawtSpecError::InvalidAeadTagLength { alg: 1, len: 12 }));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn holder_should_propagate_encryption_error() {
        let err = issue().try_encrypt(&encrypt_paths(vec![path(&["name"])]), &FailingCipher).unwrap_err();
        std::assert_matches!(err, SdCwtHolderError::EncryptionError(_));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn holder_should_reject_issued_sd_cwt_with_aead_headers() {
        let ctx = issue();
        let encrypted = Value::serialized(&vec![encrypted(KEY, &[0x41, 0x00])]).unwrap();
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
        let sd_kbt = ctx.present(Some(encrypt_paths(vec![path(&["name"])])));
        let sd_kbt = ctx.tamper(&sd_kbt, |unprotected| unprotected.retain(|(k, _)| *k != Value::from(COSE_HEADER_SD_AEAD)));
        assert!(decode(&sd_kbt).sd_cwt().unwrap().sd_unprotected.sd_aead.is_none());

        assert_eq!(ctx.decrypt(&sd_kbt, KEY, None).unwrap(), sorted(fully_disclosed()));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn verifier_should_skip_unsupported_algorithm() {
        let ctx = issue();
        let sd_kbt = ctx.present(Some(encrypt_paths(vec![path(&["name"])])));
        // AEAD_AES_256_GCM, not supported by the test Verifier
        let sd_kbt = ctx.tamper(&sd_kbt, |unprotected| *label(unprotected, COSE_HEADER_SD_AEAD).unwrap() = Value::from(2));

        let claimset = ctx.decrypt(&sd_kbt, KEY, None).unwrap();
        assert!(!claimset.as_map().unwrap().iter().any(|(k, _)| *k == Value::from("name")));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn verifier_should_reject_forbidden_algorithm() {
        let ctx = issue();
        let sd_kbt = ctx.present(Some(encrypt_paths(vec![path(&["name"])])));
        // AEAD_AES_128_GCM_8
        let sd_kbt = ctx.tamper(&sd_kbt, |unprotected| *label(unprotected, COSE_HEADER_SD_AEAD).unwrap() = Value::from(5));

        // even when unable to decrypt
        let err = ctx.verify(&sd_kbt).unwrap_err();
        // it cannot even be decoded
        std::assert_matches!(err, SdCwtVerifierError::SpecError(EsdicawtSpecError::CborDeserializationError(_)));
        assert!(format!("{err:?}").contains("The AEAD algorithm 5 MUST NOT be used"));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn verifier_should_reject_undecryptable_disclosure_with_known_key() {
        let ctx = issue();
        let sd_kbt = ctx.present(Some(encrypt_paths(vec![path(&["name"])])));

        let err = ctx.decrypt(&sd_kbt, OTHER_KEY, None).unwrap_err();
        std::assert_matches!(err, SdCwtVerifierError::DecryptionError(_));

        // also with a nonce of the wrong length
        let sd_kbt = ctx.tamper(&sd_kbt, |unprotected| {
            let encrypted = label(unprotected, COSE_HEADER_SD_AEAD_ENCRYPTED_CLAIMS).unwrap().as_array_mut().unwrap();
            encrypted
                .first_mut()
                .unwrap()
                .as_array_mut()
                .unwrap()
                .first_mut()
                .unwrap()
                .as_bytes_mut()
                .unwrap()
                .truncate(8);
        });
        let err = ctx.decrypt(&sd_kbt, KEY, None).unwrap_err();
        std::assert_matches!(err, SdCwtVerifierError::DecryptionError(_));

        // ignored without that key
        let claimset = ctx.verify(&sd_kbt).unwrap();
        assert!(!claimset.as_map().unwrap().iter().any(|(k, _)| *k == Value::from("name")));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn verifier_should_reject_short_tag() {
        let ctx = issue();
        let sd_kbt = ctx.present(Some(encrypt_paths(vec![path(&["name"])])));
        let sd_kbt = ctx.tamper(&sd_kbt, |unprotected| {
            let encrypted = label(unprotected, COSE_HEADER_SD_AEAD_ENCRYPTED_CLAIMS).unwrap().as_array_mut().unwrap();
            let tag = encrypted.first_mut().unwrap().as_array_mut().unwrap().get_mut(2).unwrap().as_bytes_mut().unwrap();
            tag.truncate(12);
        });

        // even when unable to decrypt, it cannot even be decoded
        let err = ctx.verify(&sd_kbt).unwrap_err();
        std::assert_matches!(err, SdCwtVerifierError::SpecError(EsdicawtSpecError::CborDeserializationError(_)));
        assert!(format!("{err:?}").contains("An authentication tag of 12 octets is not allowed for the AEAD algorithm 1"));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn verifier_should_reject_disclosure_both_in_plaintext_and_encrypted() {
        let ctx = issue();
        let sd_kbt = ctx.present(None);
        let disclosure = decode(&sd_kbt).sd_cwt().unwrap().disclosures().unwrap().first().unwrap().clone();
        let plaintext = disclosure_to_plaintext(&disclosure).unwrap();
        let sd_kbt = ctx.with_encrypted(&sd_kbt, &plaintext);

        let err = ctx.decrypt(&sd_kbt, KEY, None).unwrap_err();
        std::assert_matches!(err, SdCwtVerifierError::SpecError(EsdicawtSpecError::DuplicateDisclosure));

        // not detectable when unable to decrypt
        ctx.verify(&sd_kbt).unwrap();
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
        let sd_kbt = ctx.with_encrypted(&sd_kbt, &plaintext);

        let err = ctx.decrypt(&sd_kbt, KEY, None).unwrap_err();
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
        let sd_kbt = ctx.with_encrypted(&sd_kbt, &plaintext);

        let err = ctx.decrypt(&sd_kbt, KEY, None).unwrap_err();
        std::assert_matches!(err, SdCwtVerifierError::SpecError(EsdicawtSpecError::InvalidDecryptedDisclosure));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn verifier_should_reject_empty_encrypted_claims() {
        let ctx = issue();
        let sd_kbt = ctx.present(None);
        let empty_encrypted = ctx.tamper(&sd_kbt, |unprotected| {
            unprotected.push((Value::from(COSE_HEADER_SD_AEAD_ENCRYPTED_CLAIMS), Value::Array(vec![])))
        });
        assert!(ctx.decrypt(&empty_encrypted, KEY, None).is_err());
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn tamper_should_produce_valid_tokens() {
        // ensures the failures above are not caused by the tampering itself
        let ctx = issue();
        let sd_kbt = ctx.present(None);
        let sd_kbt = ctx.tamper(&sd_kbt, |_| {});
        assert_eq!(ctx.verify(&sd_kbt).unwrap(), sorted(fully_disclosed()));
    }
}
