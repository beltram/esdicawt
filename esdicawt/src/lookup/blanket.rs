use crate::{Query, SdCwtVerified, TokenQuery, any_digest::AnyDigest, lookup::query_inner};
use ciborium::Value;
use esdicawt_spec::{
    CustomClaims, CwtAny, EsdicawtSpecResult, Select,
    issuance::{SdCwtIssued, SdCwtIssuedTagged},
    key_binding::{KbtCwt, KbtCwtTagged},
    verified::KbtCwtVerified,
};

impl<PayloadClaims: Select, Hasher: digest::Digest + Clone, ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims> TokenQuery
    for SdCwtIssuedTagged<PayloadClaims, Hasher, ProtectedClaims, UnprotectedClaims>
{
    fn query(&mut self, token_query: Query) -> EsdicawtSpecResult<Option<Value>> {
        self.0.query(token_query)
    }
}

impl<PayloadClaims: Select, Hasher: digest::Digest + Clone, ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims> TokenQuery
    for SdCwtIssued<PayloadClaims, Hasher, ProtectedClaims, UnprotectedClaims>
{
    fn query(&mut self, token_query: Query) -> EsdicawtSpecResult<Option<Value>> {
        let payload = self.payload.to_value()?.to_cbor_value()?;
        let mut query = token_query.0;
        query.reverse();
        self.disclosures_mut()
            .map(|d| {
                let mut salted_array = d.to_verify()?;
                query_inner::<Hasher>(&mut salted_array, &payload, query)
            })
            .unwrap_or(Ok(None))
    }
}

impl<PayloadClaims: Select, Hasher: digest::Digest + Clone, ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims> TokenQuery
    for SdCwtVerified<PayloadClaims, Hasher, ProtectedClaims, UnprotectedClaims>
{
    fn query(&mut self, token_query: Query) -> EsdicawtSpecResult<Option<Value>> {
        let payload = self.0.0.payload.to_value()?.to_cbor_value()?;
        let mut query = token_query.0;
        query.reverse();
        self.0
            .0
            .disclosures_mut()
            .map(|d| {
                let mut salted_array = d.to_verify()?;
                query_inner::<Hasher>(&mut salted_array, &payload, query)
            })
            .unwrap_or(Ok(None))
    }
}

impl<
    IssuerPayloadClaims: Select,
    Hasher: digest::Digest + Clone,
    KbtPayloadClaims: CustomClaims,
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    KbtProtectedClaims: CustomClaims,
    KbtUnprotectedClaims: CustomClaims,
> TokenQuery for KbtCwtTagged<IssuerPayloadClaims, Hasher, KbtPayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, KbtProtectedClaims, KbtUnprotectedClaims>
{
    fn query(&mut self, token_query: Query) -> EsdicawtSpecResult<Option<Value>> {
        self.0.query(token_query)
    }
}

impl<
    IssuerPayloadClaims: Select,
    Hasher: digest::Digest + Clone,
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    KbtProtectedClaims: CustomClaims,
    KbtUnprotectedClaims: CustomClaims,
    KbtPayloadClaims: CustomClaims,
> TokenQuery for KbtCwt<IssuerPayloadClaims, Hasher, KbtPayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, KbtProtectedClaims, KbtUnprotectedClaims>
{
    fn query(&mut self, token_query: Query) -> EsdicawtSpecResult<Option<Value>> {
        self.protected.to_value_mut()?.kcwt.to_value_mut()?.0.query(token_query)
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
    fn query(&mut self, token_query: Query) -> EsdicawtSpecResult<Option<Value>> {
        if let Some(Ok(claimset)) = self.claimset.as_mut().map(|cs| cs.to_cbor_value()) {
            let mut query = token_query.0;
            query.reverse();
            query_inner::<AnyDigest>(&mut Default::default(), &claimset, query)
        } else {
            Ok(None)
        }
    }
}
