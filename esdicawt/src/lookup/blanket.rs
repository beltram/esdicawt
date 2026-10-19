use crate::{
    Query, SdCwtVerified, TokenQuery,
    any_digest::AnyDigest,
    query,
    spec::{CustomClaims, EsdicawtSpecResult, Select, issuance::SdCwtIssued, key_binding::KbtCwt, verified::KbtCwtVerified},
};
use ciborium::Value;
use esdicawt_spec::blinded_claims::{SaltedArray, SaltedArrayHashing};

impl<PayloadClaims: Select, Hasher: digest::Digest + digest::FixedOutputReset + Clone + 'static, ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims> TokenQuery
    for SdCwtIssued<PayloadClaims, Hasher, ProtectedClaims, UnprotectedClaims>
{
    fn query(&self, token_query: Query) -> EsdicawtSpecResult<Option<Value>> {
        let payload = self.payload.upcast_value()?;
        // an absent 'sd_claims' is equivalent to no disclosure
        let no_disclosures = SaltedArray::default();
        let disclosures = self.disclosures().unwrap_or(&no_disclosures);
        let hasher = super::sd_alg_hasher::<Hasher>(self.protected.to_value()?.sd_alg());
        query(&mut disclosures.to_verify()?, &payload, token_query, hasher)
    }
}

impl<PayloadClaims: Select, Hasher: digest::Digest + digest::FixedOutputReset + Clone + 'static, ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims> TokenQuery
    for SdCwtVerified<PayloadClaims, Hasher, ProtectedClaims, UnprotectedClaims>
{
    fn query(&self, token_query: Query) -> EsdicawtSpecResult<Option<Value>> {
        let payload = self.payload.upcast_value()?;
        // an absent 'sd_claims' is equivalent to no disclosure
        let no_disclosures = SaltedArray::default();
        let disclosures = self.disclosures().unwrap_or(&no_disclosures);
        let hasher = super::sd_alg_hasher::<Hasher>(self.protected.to_value()?.sd_alg());
        query(&mut disclosures.to_verify()?, &payload, token_query, hasher)
    }
}

impl<
    IssuerPayloadClaims: Select,
    Hasher: digest::Digest + digest::FixedOutputReset + Clone + 'static,
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    KbtProtectedClaims: CustomClaims,
    KbtUnprotectedClaims: CustomClaims,
    KbtPayloadClaims: CustomClaims,
> TokenQuery for KbtCwt<IssuerPayloadClaims, Hasher, KbtPayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, KbtProtectedClaims, KbtUnprotectedClaims>
{
    fn query(&self, token_query: Query) -> EsdicawtSpecResult<Option<Value>> {
        self.generic_sd_cwt()?.query(token_query)
    }
}

impl<
    IssuerPayloadClaims: Select,
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    KbtProtectedClaims: CustomClaims,
    KbtUnprotectedClaims: CustomClaims,
    KbtPayloadClaims: CustomClaims,
> TokenQuery for KbtCwtVerified<IssuerPayloadClaims, KbtPayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, KbtProtectedClaims, KbtUnprotectedClaims>
{
    fn query(&self, token_query: Query) -> EsdicawtSpecResult<Option<Value>> {
        if let Some(Ok(claimset)) = self.claimset.as_ref().map(|cs| cs.to_cbor_value()) {
            // the claimset has no redacted claims left, so nothing is hashed
            query(
                &mut SaltedArrayHashing::SaltedArrayToVerify(Default::default()),
                &claimset,
                token_query,
                std::rc::Rc::new(AnyDigest),
            )
        } else {
            Ok(None)
        }
    }
}
