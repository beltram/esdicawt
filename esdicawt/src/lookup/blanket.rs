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
        query::<Hasher>(&mut disclosures.to_verify()?, &payload, token_query)
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
        query::<Hasher>(&mut disclosures.to_verify()?, &payload, token_query)
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
            query::<AnyDigest>(&mut SaltedArrayHashing::SaltedArrayToVerify(Default::default()), &claimset, token_query)
        } else {
            Ok(None)
        }
    }
}
