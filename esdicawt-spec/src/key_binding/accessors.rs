use crate::{COSE_HEADER_KCWT, CustomClaims, EsdicawtSpecError, EsdicawtSpecResult, Select, issuance::SdCwtIssued, key_binding::KbtCwt};
use ciborium::Value;

impl<
    IssuerPayloadClaims: Select,
    Hasher: digest::Digest + Clone,
    PayloadClaims: CustomClaims,
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    ProtectedClaims: CustomClaims,
    UnprotectedClaims: CustomClaims,
> KbtCwt<IssuerPayloadClaims, Hasher, PayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, ProtectedClaims, UnprotectedClaims>
{
    /// Get the SD-CWT wrapped by this SD-KBT
    pub fn sd_cwt(&self) -> EsdicawtSpecResult<&SdCwtIssued<IssuerPayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims>> {
        Ok(&self.protected.to_value()?.kcwt)
    }

    /// Get the SD-CWT wrapped by this SD-KBT
    pub fn generic_sd_cwt(&self) -> EsdicawtSpecResult<SdCwtIssued<Value, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims>> {
        let sd_kbt_protected = self.protected.upcast_value()?;
        let kcwt = sd_kbt_protected
            .into_map()?
            .into_iter()
            .find_map(|(k, v)| matches!(k, Value::Integer(i) if i == COSE_HEADER_KCWT.into()).then_some(v))
            .ok_or(EsdicawtSpecError::ImplementationError("Invalid SD-KBT, missing kcwt"))?;

        let sd_cwt = kcwt.deserialized::<SdCwtIssued<Value, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims>>();

        #[cfg(feature = "backward")]
        let sd_cwt = sd_cwt.or_else(|_| {
            kcwt.deserialized::<crate::key_binding::InlinedCbor<SdCwtIssued<Value, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims>>>()?
                .try_into_value()
        });

        Ok(sd_cwt?)
    }

    /// Whether this SD-KBT comes from a draft-08 implementation, which computed the Redacted Claim Hashes over the raw
    /// disclosure instead of wrapping it in a bstr. Since the whole SD-CWT uses the same one, only the first disclosure
    /// is checked. `None` when there is no disclosure to tell.
    #[cfg(feature = "backward")]
    pub fn is_draft_08(&self) -> Option<bool> {
        use crate::{blinded_claims::SaltedEntry, redacted_claims::ToRedacted as _};

        let Some(disclosures) = self.disclosures().ok()? else { return None };
        let Some(first) = disclosures.iter().next().transpose().ok()? else { return None };

        // the Redacted Claim Hash is either in the payload or nested in another disclosure
        let payload = self.sd_cwt().ok()?.payload.upcast_value().ok()?;
        let mut values = vec![&payload];
        for disclosure in disclosures.iter() {
            match disclosure.ok()? {
                SaltedEntry::Claim(claim) => values.push(&claim.value),
                SaltedEntry::Element(element) => values.push(&element.value),
                SaltedEntry::Decoy(_) => {}
            }
        }

        // Whether `digest` is a Redacted Claim Key or a Redacted Claim Element at any depth of `value`
        fn contains_redacted_hash(value: &Value, digest: &[u8]) -> bool {
            let is_digest = |v: &Value| matches!(v, Value::Bytes(b) if b == digest);
            match value {
                Value::Tag(crate::REDACTED_CLAIM_ELEMENT_TAG, v) => is_digest(v),
                Value::Tag(_, v) => contains_redacted_hash(v, digest),
                Value::Array(array) => array.iter().any(|v| contains_redacted_hash(v, digest)),
                Value::Map(map) => map.iter().any(|(k, v)| match k {
                    Value::Simple(crate::CWT_LABEL_REDACTED_TAG) => matches!(v, Value::Array(hashes) if hashes.iter().any(is_digest)),
                    _ => contains_redacted_hash(v, digest),
                }),
                _ => false,
            }
        }

        let is_redacted = |digest: &[u8]| values.iter().any(|v| contains_redacted_hash(v, digest));

        if is_redacted(&first.to_redacted::<Hasher>().ok()?) {
            Some(false)
        } else if is_redacted(&first.old_to_redacted::<Hasher>().ok()?) {
            Some(true)
        } else {
            None
        }
    }

    /// SD-KBT expiration, different from SD-CWT one !!!
    pub fn exp(&self) -> EsdicawtSpecResult<Option<u64>> {
        Ok(self.payload.to_value()?.expiration.map(|e| e as u64))
    }

    /// SD-KBT issued at, different from SD-CWT one !!!
    pub fn iat(&self) -> EsdicawtSpecResult<Option<u64>> {
        Ok(self.payload.to_value()?.iat_or_cti.iat().map(|i| i as u64))
    }

    /// SD-KBT CWT ID, different from SD-CWT one !!!
    pub fn cti(&self) -> EsdicawtSpecResult<Option<&[u8]>> {
        Ok(self.payload.to_value()?.iat_or_cti.cti())
    }

    /// SD-KBT not before, different from SD-CWT one !!!
    pub fn nbf(&self) -> EsdicawtSpecResult<Option<u64>> {
        Ok(self.payload.to_value()?.not_before.map(|e| e as u64))
    }

    /// SD-KBT audience, different from SD-CWT one !!!
    pub fn audience(&self) -> EsdicawtSpecResult<&str> {
        Ok(&self.payload.to_value()?.audience)
    }

    /// SD-KBT client nonce, different from SD-CWT one !!!
    pub fn client_nonce(&self) -> EsdicawtSpecResult<Option<&[u8]>> {
        Ok(self.payload.to_value()?.cnonce.as_deref().map(|b| &b[..]))
    }

    /// Signature algorithm of the SD-KBT, not the SD-CWT one !!!
    pub fn alg(&self) -> Option<coset::iana::Algorithm> {
        match *self.protected.to_value().ok()?.alg {
            coset::Algorithm::Assigned(alg) => Some(alg),
            _ => None,
        }
    }

    #[cfg(feature = "status")]
    pub fn status(&self) -> EsdicawtSpecResult<Option<status_list::StatusClaim>> {
        Ok(self.sd_cwt()?.status())
    }
}
