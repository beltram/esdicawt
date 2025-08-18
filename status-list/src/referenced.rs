use crate::BitIndex;

/// Status claim in a ReferencedToken
/// see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-11#section-6.3
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StatusClaim {
    #[serde(rename = "status_list")]
    status_list: StatusListClaim,
}

impl StatusClaim {
    pub fn new(idx: BitIndex, uri: url::Url) -> Self {
        Self {
            status_list: StatusListClaim { idx, uri },
        }
    }

    pub fn get(&self) -> (BitIndex, &url::Url) {
        (self.status_list.idx, &self.status_list.uri)
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StatusListClaim {
    #[serde(rename = "idx")]
    idx: BitIndex,
    #[serde(rename = "uri")]
    uri: url::Url,
}

#[cfg(test)]
mod tests {
    use crate::{CborAny as _, issuer::cose::tests::rfc_signer, referenced::StatusClaim};
    use coset::{CborSerializable, TaggedCborSerializable, iana::CwtClaimName};
    use signature::Signer;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_match_draft_example() {
        let expected = "d28443a10126a1044231325866a502653132333435017368747470733a2f2f6578616d706c652e636f6d061a648c5bea041a8898dfea19ffffa16b7374617475735f6c697374a2636964780063757269782168747470733a2f2f6578616d706c652e636f6d2f7374617475736c697374732f3158409a70f3b9020bf7cf2a33d62d7b9de1722ce9e968fe1ed02a707d3285b7c8a11b7cfe7828ac83367fc7b1686689af64e9e24b596b78b88704944ba2418b8142ef";

        let signer = rfc_signer();

        let protected = coset::HeaderBuilder::new().algorithm(coset::iana::Algorithm::ES256).build();
        let unprotected = coset::HeaderBuilder::new().key_id(b"12".to_vec()).build();

        let status = StatusClaim::new(0, "https://example.com/statuslists/1".parse().unwrap());

        let payload = coset::cwt::ClaimsSetBuilder::new()
            .issued_at(coset::cwt::Timestamp::WholeSeconds(1686920170))
            .expiration_time(coset::cwt::Timestamp::WholeSeconds(2291720170))
            .subject("12345".into())
            .issuer("https://example.com".into())
            .claim(CwtClaimName::Status, status.to_cbor_value().unwrap())
            .build()
            .to_vec()
            .unwrap();

        let cwt = coset::CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(payload)
            .create_signature(&[], |tbs| {
                let (signature, _) = signer.sign(tbs);
                signature.to_bytes().to_vec()
            })
            .build();

        let actual_claim_set = coset::cwt::ClaimsSet::from_slice(cwt.payload.unwrap().as_slice()).unwrap();

        let expected_payload = coset::CoseSign1::from_tagged_slice(&hex::decode(expected).unwrap()).unwrap().payload.unwrap();
        let expected_claim_set = coset::cwt::ClaimsSet::from_slice(&expected_payload[..]).unwrap();

        assert_eq!(actual_claim_set, expected_claim_set);
    }
}
