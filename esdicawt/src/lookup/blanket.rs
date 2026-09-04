use crate::{
    Query, SdCwtVerified, TokenQuery,
    any_digest::AnyDigest,
    query,
    spec::{CustomClaims, EsdicawtSpecResult, Select, issuance::SdCwtIssued, key_binding::KbtCwt, verified::KbtCwtVerified},
};
use ciborium::Value;

impl<PayloadClaims: Select, Hasher: digest::Digest + digest::FixedOutputReset + Clone + 'static, ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims> TokenQuery
    for SdCwtIssued<PayloadClaims, Hasher, ProtectedClaims, UnprotectedClaims>
{
    fn query(&self, token_query: Query) -> EsdicawtSpecResult<Option<Value>> {
        let payload = self.payload.upcast_value()?;
        self.disclosures().map(|d| query::<Hasher>(&mut d.to_verify()?, &payload, token_query)).unwrap_or(Ok(None))
    }
}

impl<PayloadClaims: Select, Hasher: digest::Digest + digest::FixedOutputReset + Clone + 'static, ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims> TokenQuery
    for SdCwtVerified<PayloadClaims, Hasher, ProtectedClaims, UnprotectedClaims>
{
    fn query(&self, token_query: Query) -> EsdicawtSpecResult<Option<Value>> {
        let payload = self.0.payload.upcast_value()?;
        self.0
            .disclosures()
            .map(|d| query::<Hasher>(&mut d.to_verify()?, &payload, token_query))
            .unwrap_or(Ok(None))
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
            query::<AnyDigest>(&mut Default::default(), &claimset, token_query)
        } else {
            Ok(None)
        }
    }
}
