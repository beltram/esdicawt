pub mod error;

/// A COSE KEy Set as defined in [RFC 8152](https://datatracker.ietf.org/doc/html/rfc8152#section-7)
#[derive(serde::Serialize, serde::Deserialize)]
pub struct CoseKeySet(Vec<cose_key::CoseKey>);

impl CoseKeySet {
    pub fn builder() -> CoseKeySetBuilder {
        CoseKeySetBuilder::default()
    }
}

#[derive(Default)]
pub struct CoseKeySetBuilder {
    keys: Vec<cose_key::CoseKey>,
}

impl CoseKeySetBuilder {
    pub fn push(&mut self, key: impl TryInto<cose_key::CoseKey, Error: Into<error::CoseKeySetError>>) -> Result<(), error::CoseKeySetError> {
        self.keys.push(key.try_into().map_err(Into::into)?);
        Ok(())
    }

    pub fn build(self) -> CoseKeySet {
        CoseKeySet(self.keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::{Value, cbor};
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_support_ed25519_keys() {
        let key_a = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()).verifying_key();
        let key_b = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()).verifying_key();

        let mut builder = CoseKeySet::builder();
        builder.push(key_a).unwrap();
        builder.push(key_b).unwrap();
        let keyset = builder.build();

        Value::serialized(&keyset).unwrap();
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_support_p256_keys() {
        let key_a = *p256::ecdsa::SigningKey::random(&mut rand::thread_rng()).verifying_key();
        let key_b = *p256::ecdsa::SigningKey::random(&mut rand::thread_rng()).verifying_key();

        let mut builder = CoseKeySet::builder();
        builder.push(key_a).unwrap();
        builder.push(key_b).unwrap();
        let keyset = builder.build();

        Value::serialized(&keyset).unwrap();
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_work_on_rfc_appendix_1() {
        use coset::iana;

        let (meriadoc, meriadoc_x, meriadoc_y, meriadoc_kid) = {
            let x = hex::decode("65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d").unwrap();
            let y = hex::decode("1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c").unwrap();
            let kid = b"meriadoc.brandybuck@buckland.example".to_vec();
            let key = coset::CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x.clone(), y.clone())
                .key_id(kid.clone())
                .build();
            let key = cose_key::CoseKey::from(key);
            (key, Value::Bytes(x), Value::Bytes(y), Value::Bytes(kid))
        };

        let (peregrin, peregrin_x, peregrin_y, peregrin_kid) = {
            let x = hex::decode("98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280").unwrap();
            let y = hex::decode("f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb").unwrap();
            let kid = b"peregrin.took@tuckborough.example".to_vec();
            let key = coset::CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x.clone(), y.clone())
                .key_id(kid.clone())
                .build();
            let key = cose_key::CoseKey::from(key);
            (key, Value::Bytes(x), Value::Bytes(y), Value::Bytes(kid))
        };

        let (bilbo, bilbo_x, bilbo_y, bilbo_kid) = {
            let x = hex::decode("0072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad").unwrap();
            let y = hex::decode("01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475").unwrap();
            let kid = b"bilbo.baggins@hobbiton.example".to_vec();
            let key = coset::CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_521, x.clone(), y.clone())
                .key_id(kid.clone())
                .build();
            let key = cose_key::CoseKey::from(key);
            (key, Value::Bytes(x), Value::Bytes(y), Value::Bytes(kid))
        };

        let (eleven, eleven_x, eleven_y, eleven_kid) = {
            let x = hex::decode("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff").unwrap();
            let y = hex::decode("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e").unwrap();
            let kid = b"11".to_vec();
            let key = coset::CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x.clone(), y.clone())
                .key_id(kid.clone())
                .build();
            let key = cose_key::CoseKey::from(key);
            (key, Value::Bytes(x), Value::Bytes(y), Value::Bytes(kid))
        };

        let mut builder = CoseKeySet::builder();
        builder.push(meriadoc).unwrap();
        builder.push(peregrin).unwrap();
        builder.push(bilbo).unwrap();
        builder.push(eleven).unwrap();
        let keyset = Value::serialized(&builder.build()).unwrap();

        let expected = cbor!([
            { 1 => 2, 2 => meriadoc_kid, -1 => 1 ,-2 => meriadoc_x ,-3 => meriadoc_y },
            { 1 => 2, 2 => peregrin_kid, -1 => 1 ,-2 => peregrin_x ,-3 => peregrin_y },
            { 1 => 2, 2 => bilbo_kid, -1 => 3 ,-2 => bilbo_x ,-3 => bilbo_y },
            { 1 => 2, 2 => eleven_kid, -1 => 1 ,-2 => eleven_x ,-3 => eleven_y },
        ])
        .unwrap();
        assert_eq!(expected, keyset);
    }
}
